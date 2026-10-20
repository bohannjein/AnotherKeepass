//! Auto-Type: type username/password into another application.
//! Global shortcut → match the active window against open entries (title, URL host,
//! KeePass window associations) → type the entry's sequence. Several matches (or
//! "always ask") hand a picker to the UI; the target window is remembered meanwhile.

use std::{sync::Mutex, thread, time::Duration};

use enigo::{Direction, Enigo, Key, Keyboard, Settings};
use keepass::db::{fields, Entry, EntryId};
use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager, Runtime};
use tauri_plugin_global_shortcut::{GlobalShortcutExt, ShortcutState};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{desktop, vault::Vaults};

pub const DEFAULT_SEQUENCE: &str = "{USERNAME}{TAB}{PASSWORD}{ENTER}";

/// Window that was active when the shortcut fired (Windows HWND as isize).
#[derive(Default)]
pub struct Target(pub Mutex<Option<isize>>);

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Candidate {
    vault: String,
    id: String,
    title: String,
    username: String,
    sequence: String,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct Pick {
    window_title: String,
    candidates: Vec<Candidate>,
}

// ---------------------------------------------------------------- matching

/// KeePass association patterns: case-insensitive, `*` wildcard.
fn wildcard(pattern: &str, text: &str) -> bool {
    let (p, t) = (pattern.to_lowercase(), text.to_lowercase());
    let parts: Vec<&str> = p.split('*').collect();
    if parts.len() == 1 {
        return p == t;
    }
    let mut pos = 0;
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        match t[pos..].find(part) {
            Some(at) if i > 0 || at == 0 => pos += at + part.len(),
            _ => return false,
        }
    }
    parts.last().is_some_and(|l| l.is_empty()) || pos == t.len()
}

/// "https://www.github.com/login" → "github.com"
fn host(url: &str) -> Option<String> {
    let rest = url.split("://").nth(1).unwrap_or(url);
    let h = rest.split(['/', '?', '#', ':']).next()?.trim_start_matches("www.").to_lowercase();
    (h.contains('.')).then_some(h)
}

/// The sequence to type if this entry matches the window, else None.
pub fn match_entry(e: &Entry, window: &str, by_title: bool, by_url: bool) -> Option<String> {
    let at = e.autotype.as_ref();
    if at.is_some_and(|a| !a.enabled) {
        return None;
    }
    let default_seq = at.and_then(|a| a.default_sequence.clone()).filter(|s| !s.is_empty()).unwrap_or_else(|| DEFAULT_SEQUENCE.into());
    if let Some(a) = at.and_then(|a| a.associations.iter().find(|a| wildcard(&a.window, window))) {
        return Some(if a.sequence.is_empty() { default_seq } else { a.sequence.clone() });
    }
    let w = window.to_lowercase();
    let title = e.get_title().unwrap_or_default().trim().to_lowercase();
    let title_hit = by_title && title.len() >= 3 && w.contains(&title);
    let url_hit = by_url && e.get_url().and_then(host).is_some_and(|h| w.contains(&h) || w.contains(h.split('.').next().unwrap_or("~")));
    (title_hit || url_hit).then_some(default_seq)
}

fn candidates<R: Runtime>(app: &AppHandle<R>, window: &str) -> Vec<Candidate> {
    let p = desktop::prefs(app);
    let now = chrono::Utc::now().naive_utc();
    let map = app.state::<Vaults>();
    let Ok(map) = map.0.lock() else { return vec![] };
    let mut out = Vec::new();
    for (vid, v) in map.iter() {
        let bin = v.db().recycle_bin().map(|g| g.id());
        for e in v.db().iter_all_entries() {
            if Some(e.parent().id()) == bin || (p.at_hide_expired && e.times.expires == Some(true) && e.times.expiry < now) {
                continue;
            }
            if let Some(sequence) = match_entry(&e, window, p.at_match_title, p.at_match_url) {
                out.push(Candidate {
                    vault: vid.clone(),
                    id: e.id().to_string(),
                    title: e.get_title().unwrap_or_default().into(),
                    username: e.get_username().unwrap_or_default().into(),
                    sequence,
                });
            }
        }
    }
    out
}

// ---------------------------------------------------------------- sequence → actions

pub enum Action {
    Text(Zeroizing<String>),
    Key(Key),
    Delay(u64),
    CharDelay(u64),
}

/// Parses KeePass placeholders; `{S:Name}` reads any string field.
pub fn compile(seq: &str, e: &Entry) -> Result<Vec<Action>, String> {
    let field = |name: &str| Zeroizing::new(e.get(name).unwrap_or_default().to_string());
    let mut out = Vec::new();
    let mut rest = seq;
    while !rest.is_empty() {
        if let Some(stripped) = rest.strip_prefix('{') {
            let end = stripped.find('}').ok_or("autotype_sequence")?;
            let token = &stripped[..end];
            rest = &stripped[end + 1..];
            let upper = token.to_uppercase();
            let (name, arg) = upper.split_once([' ', '=']).map_or((upper.as_str(), ""), |(a, b)| (a, b.trim()));
            out.push(match name {
                "USERNAME" => Action::Text(field(fields::USERNAME)),
                "PASSWORD" => Action::Text(field(fields::PASSWORD)),
                "TITLE" => Action::Text(field(fields::TITLE)),
                "URL" => Action::Text(field(fields::URL)),
                "NOTES" => Action::Text(field(fields::NOTES)),
                "TOTP" => Action::Text(Zeroizing::new(
                    crate::vault::totp_code(e, fields::OTP).map_err(|_| "totp")?,
                )),
                "TAB" => Action::Key(Key::Tab),
                "ENTER" => Action::Key(Key::Return),
                "SPACE" => Action::Key(Key::Space),
                "BACKSPACE" | "BS" => Action::Key(Key::Backspace),
                "ESC" => Action::Key(Key::Escape),
                "DELAY" if token.contains('=') => Action::CharDelay(arg.parse().map_err(|_| "autotype_sequence")?),
                "DELAY" => Action::Delay(arg.parse().map_err(|_| "autotype_sequence")?),
                _ if upper.starts_with("S:") => Action::Text(field(&token[2..])),
                _ => return Err(format!("autotype_sequence:{token}")),
            });
        } else {
            let end = rest.find('{').unwrap_or(rest.len());
            out.push(Action::Text(Zeroizing::new(rest[..end].to_string())));
            rest = &rest[end..];
        }
    }
    Ok(out)
}

fn type_actions(actions: Vec<Action>, start_delay: u64, mut char_delay: u64) -> Result<(), String> {
    thread::sleep(Duration::from_millis(start_delay));
    let mut kb = Enigo::new(&Settings::default()).map_err(|e| format!("autotype:{e}"))?;
    for a in actions {
        match a {
            Action::Text(t) => {
                for c in t.chars() {
                    kb.text(&c.to_string()).map_err(|e| format!("autotype:{e}"))?;
                    thread::sleep(Duration::from_millis(char_delay));
                }
            }
            Action::Key(k) => {
                kb.key(k, Direction::Click).map_err(|e| format!("autotype:{e}"))?;
                thread::sleep(Duration::from_millis(char_delay));
            }
            Action::Delay(ms) => thread::sleep(Duration::from_millis(ms)),
            Action::CharDelay(ms) => char_delay = ms,
        }
    }
    Ok(())
}

// ---------------------------------------------------------------- platform: active window

#[cfg(windows)]
fn foreground() -> (Option<isize>, String) {
    use windows_sys::Win32::UI::WindowsAndMessaging::{GetForegroundWindow, GetWindowTextW};
    unsafe {
        let h = GetForegroundWindow();
        let mut buf = [0u16; 512];
        let n = GetWindowTextW(h, buf.as_mut_ptr(), buf.len() as i32);
        (Some(h as isize), String::from_utf16_lossy(&buf[..n.max(0) as usize]))
    }
}

#[cfg(windows)]
fn focus(h: isize) {
    use windows_sys::Win32::UI::WindowsAndMessaging::SetForegroundWindow;
    unsafe { SetForegroundWindow(h as _) };
}

// ponytail: active-window title on Linux/macOS not wired (X11 _NET_ACTIVE_WINDOW / NSWorkspace)
#[cfg(not(windows))]
fn foreground() -> (Option<isize>, String) { (None, String::new()) }
#[cfg(not(windows))]
fn focus(_h: isize) {}

// ---------------------------------------------------------------- flow

pub fn register_shortcut<R: Runtime>(app: &AppHandle<R>, shortcut: &str) -> Result<(), String> {
    let gs = app.global_shortcut();
    gs.unregister_all().map_err(|e| e.to_string())?;
    if shortcut.trim().is_empty() {
        return Ok(());
    }
    // the settings page records "Meta" for the Windows key
    let normalized = shortcut.replace("Meta", "Super");
    gs.on_shortcut(normalized.as_str(), |app, _, e| {
        if e.state == ShortcutState::Pressed {
            on_hotkey(app);
        }
    })
    .map_err(|e| e.to_string())
}

fn on_hotkey<R: Runtime>(app: &AppHandle<R>) {
    let (hwnd, title) = foreground();
    if let Ok(mut t) = app.state::<Target>().0.lock() {
        *t = hwnd;
    }
    if app.state::<Vaults>().0.lock().map(|m| m.is_empty()).unwrap_or(true) {
        desktop::show_main(app); // locked: user unlocks first, then presses the shortcut again
        return;
    }
    let found = candidates(app, &title);
    let p = desktop::prefs(app);
    if found.len() == 1 && !p.at_always_ask {
        let c = found[0].clone();
        let app = app.clone();
        thread::spawn(move || {
            if let Err(e) = perform(&app, &c.vault, &c.id, Some(c.sequence), true) {
                let _ = app.emit("akp-autotype-error", e);
            }
        });
        return;
    }
    let _ = app.emit("akp-autotype-pick", Pick { window_title: title, candidates: found });
    desktop::show_main(app);
}

/// Type an entry. `to_target`: refocus the window captured by the hotkey; otherwise
/// minimize ourselves so the previously active window gets the keystrokes.
pub fn perform<R: Runtime>(app: &AppHandle<R>, vault: &str, id: &str, sequence: Option<String>, to_target: bool) -> Result<(), String> {
    let actions = {
        let map = app.state::<Vaults>();
        let map = map.0.lock().map_err(|_| "lock")?;
        let v = map.get(vault).ok_or("vault_closed")?;
        let e = v.db().entry(EntryId::from(Uuid::parse_str(id).map_err(|_| "not_found")?)).ok_or("not_found")?;
        let seq = sequence.unwrap_or_else(|| {
            e.autotype.as_ref().and_then(|a| a.default_sequence.clone()).filter(|s| !s.is_empty()).unwrap_or_else(|| DEFAULT_SEQUENCE.into())
        });
        compile(&seq, &e)?
    };
    let p = desktop::prefs(app);
    if let Some(w) = desktop::main_window(app) {
        let _ = w.minimize();
    }
    if to_target {
        if let Some(h) = app.state::<Target>().0.lock().ok().and_then(|t| *t) {
            focus(h);
        }
    }
    type_actions(actions, p.at_start_delay.max(100), p.at_char_delay)
}

#[tauri::command]
pub fn autotype_perform(app: AppHandle, vault: String, id: String, sequence: Option<String>) -> Result<(), String> {
    // picker answer: type into the window that was active when the hotkey fired
    thread::spawn(move || perform(&app, &vault, &id, sequence, true).map_err(|e| { let _ = app.emit("akp-autotype-error", e); }));
    Ok(())
}

#[tauri::command]
pub fn autotype_entry(app: AppHandle, vault: String, id: String) -> Result<(), String> {
    // from our own window: we minimize, Windows activates the previous window
    thread::spawn(move || perform(&app, &vault, &id, None, false).map_err(|e| { let _ = app.emit("akp-autotype-error", e); }));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use keepass::{db::AutoTypeAssociation, Database};

    fn entry(title: &str, url: &str) -> (Database, EntryId) {
        let mut db = Database::new();
        let mut root = db.root_mut();
        let mut e = root.add_entry();
        e.set_unprotected(fields::TITLE, title);
        e.set_unprotected(fields::USERNAME, "bob");
        e.set_protected(fields::PASSWORD, "p{w}");
        e.set_unprotected(fields::URL, url);
        let id = e.id();
        (db, id)
    }

    #[test]
    fn matching() {
        assert!(wildcard("*Firefox", "GitHub - Mozilla Firefox"));
        assert!(wildcard("github*", "GitHub - Mozilla Firefox"));
        assert!(wildcard("*hub*fox", "GitHub - Mozilla Firefox"));
        assert!(!wildcard("*Chrome", "GitHub - Mozilla Firefox"));
        assert_eq!(host("https://www.github.com/login?x=1").as_deref(), Some("github.com"));
        assert_eq!(host("intranet"), None);

        let (db, id) = entry("GitHub", "https://github.com");
        let e = db.entry(id).unwrap();
        assert!(match_entry(&e, "Sign in to GitHub · GitHub — Mozilla Firefox", true, false).is_some());
        assert!(match_entry(&e, "github.com/login - Chrome", false, true).is_some());
        assert!(match_entry(&e, "Editor", true, true).is_none());
        assert!(match_entry(&e, "Sign in to GitHub", false, false).is_none());

        // association with its own sequence wins
        let (mut db, id) = entry("x", "");
        db.entry_mut(id).unwrap().autotype = Some(keepass::db::AutoType {
            enabled: true,
            default_sequence: None,
            data_transfer_obfuscation: Default::default(),
            associations: vec![AutoTypeAssociation { window: "*Portal*".into(), sequence: "{PASSWORD}{ENTER}".into() }],
        });
        assert_eq!(match_entry(&db.entry(id).unwrap(), "Kundenportal Nord", true, true).as_deref(), Some("{PASSWORD}{ENTER}"));
    }

    #[test]
    fn sequence_compiles() {
        let (db, id) = entry("Mail", "");
        let e = db.entry(id).unwrap();
        let a = compile("{USERNAME}{TAB}{PASSWORD}{ENTER}", &e).unwrap();
        assert!(matches!(&a[0], Action::Text(t) if t.as_str() == "bob"));
        assert!(matches!(a[1], Action::Key(Key::Tab)));
        assert!(matches!(&a[2], Action::Text(t) if t.as_str() == "p{w}")); // braces in values are typed literally
        assert!(matches!(a[3], Action::Key(Key::Return)));
        let b = compile("user: {S:UserName}{DELAY 200}{DELAY=10}x", &e).unwrap();
        assert!(matches!(&b[0], Action::Text(t) if t.as_str() == "user: "));
        assert!(matches!(&b[1], Action::Text(t) if t.as_str() == "bob"));
        assert!(matches!(b[2], Action::Delay(200)));
        assert!(matches!(b[3], Action::CharDelay(10)));
        assert!(compile("{NOPE}", &e).is_err());
        assert!(compile("{USERNAME", &e).is_err());
    }
}
