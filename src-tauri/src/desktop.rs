//! Desktop integration: tray, single instance, autostart, window behaviour, locking on
//! session events. Options mirror the settings page; the UI pushes them via `desktop_apply`
//! and they are kept in `<config>/desktop.json` so they apply before the UI has loaded.

use std::{fs, path::PathBuf, sync::{Mutex, atomic::{AtomicBool, Ordering}}};

use serde::{Deserialize, Serialize};
use tauri::{
    menu::{Menu, MenuItem, PredefinedMenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    AppHandle, Emitter, Manager, Runtime, WebviewWindow, WindowEvent,
};
use tauri_plugin_autostart::ManagerExt as _;

use crate::vault::Vaults;

pub const IDENTIFIER: &str = "app.anotherkeepass.desktop";
/// Passed by the autostart entry so we can tell a login start from a manual one.
pub const AUTOSTART_ARG: &str = "--autostart";
const TRAY_ID: &str = "main";

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct DesktopPrefs {
    pub single_instance: bool,
    pub autostart: bool,
    pub start_minimized: bool,
    pub tray_icon: bool,
    pub hide_to_tray: bool,
    pub lock_on_minimize: bool,
    pub lock_on_session: bool,
    pub lock_on_user_switch: bool,
    pub at_shortcut: String,
    pub at_start_delay: u64,
    pub at_char_delay: u64,
    pub at_always_ask: bool,
    pub at_match_title: bool,
    pub at_match_url: bool,
    pub at_hide_expired: bool,
    pub at_relock: bool,
    pub quick_unlock: bool,
    pub tray_style: String,
    pub at_remember: u64,
    pub auto_reload: bool,
    /// tray menu texts in the UI language: show, lock, quit
    pub tray_labels: [String; 3],
    // browser integration (KeePassXC-Browser protocol)
    pub browser_enabled: bool,
    pub b_chrome: bool,
    pub b_firefox: bool,
    pub b_chromium: bool,
    pub b_edge: bool,
    pub b_brave: bool,
    pub b_vivaldi: bool,
    pub b_tor: bool,
    pub b_unlock: bool,
    pub b_match_scheme: bool,
    pub b_best_match: bool,
    pub b_allow_expired: bool,
    pub b_search_all: bool,
    pub b_no_access_confirm: bool,
    pub b_update_no_confirm: bool,
    pub b_kph: bool,
    pub b_update_manifests: bool,
    pub b_custom_proxy: bool,
    pub b_proxy_path: String,
    pub backup_before_save: bool,
    pub backup_path: String,
}

impl Default for DesktopPrefs {
    fn default() -> Self {
        Self {
            single_instance: true,
            autostart: false,
            start_minimized: false,
            tray_icon: true,
            hide_to_tray: false,
            lock_on_minimize: false,
            lock_on_session: true,
            lock_on_user_switch: true,
            at_shortcut: String::new(),
            at_start_delay: 500,
            at_char_delay: 25,
            at_always_ask: true,
            at_match_title: true,
            at_match_url: true,
            at_hide_expired: false,
            at_relock: false,
            quick_unlock: false,
            tray_style: "colorful".into(),
            at_remember: 10,
            auto_reload: true,
            tray_labels: ["Show".into(), "Lock all".into(), "Quit".into()],
            browser_enabled: false,
            b_chrome: false,
            b_firefox: false,
            b_chromium: false,
            b_edge: false,
            b_brave: false,
            b_vivaldi: false,
            b_tor: false,
            b_unlock: true,
            b_match_scheme: true,
            b_best_match: false,
            b_allow_expired: false,
            b_search_all: false,
            b_no_access_confirm: false,
            b_update_no_confirm: false,
            b_kph: false,
            b_update_manifests: true,
            b_custom_proxy: false,
            b_proxy_path: String::new(),
            backup_before_save: false,
            backup_path: "{DB_FILENAME}.old.kdbx".into(),
        }
    }
}

#[derive(Default)]
pub struct Desktop {
    pub prefs: Mutex<DesktopPrefs>,
}

/// Same folder Tauri uses for app config, resolved without an AppHandle so it works
/// before the builder runs (needed for the single-instance decision).
pub fn config_path() -> Option<PathBuf> {
    config_file()
}

fn config_file() -> Option<PathBuf> {
    #[cfg(windows)]
    let base = std::env::var_os("APPDATA").map(PathBuf::from);
    #[cfg(target_os = "macos")]
    let base = std::env::var_os("HOME").map(|h| PathBuf::from(h).join("Library/Application Support"));
    #[cfg(all(unix, not(target_os = "macos")))]
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")));
    base.map(|b| b.join(IDENTIFIER).join("desktop.json"))
}

pub fn load_prefs() -> DesktopPrefs {
    config_file()
        .and_then(|p| fs::read(p).ok())
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

fn save_prefs(p: &DesktopPrefs) -> Result<(), String> {
    let path = config_file().ok_or("no config dir")?;
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    fs::write(path, serde_json::to_vec_pretty(p).map_err(|e| e.to_string())?).map_err(|e| e.to_string())
}

pub fn apply_backup(p: &DesktopPrefs) {
    if let Ok(mut b) = crate::vault::BACKUP_PATTERN.lock() {
        *b = (p.backup_before_save && !p.backup_path.trim().is_empty()).then(|| p.backup_path.trim().to_string());
    }
}

pub fn prefs<R: Runtime>(app: &AppHandle<R>) -> DesktopPrefs {
    app.state::<Desktop>().prefs.lock().map(|p| p.clone()).unwrap_or_default()
}

pub fn main_window<R: Runtime>(app: &AppHandle<R>) -> Option<WebviewWindow<R>> {
    app.get_webview_window("main")
}

/// Set when the browser extension or Auto-Type opened the window to get a vault unlocked;
/// only then "minimize after unlock" applies (not when the user opened the window).
static UNLOCK_REQUESTED: AtomicBool = AtomicBool::new(false);

pub fn show_for_unlock<R: Runtime>(app: &AppHandle<R>) {
    UNLOCK_REQUESTED.store(true, Ordering::Relaxed);
    show_main(app);
}

#[tauri::command]
pub fn window_after_unlock(app: AppHandle) {
    if UNLOCK_REQUESTED.swap(false, Ordering::Relaxed) {
        window_minimize(app);
    }
}

/// Native window handle for system dialogs (Windows Hello) that should sit on our window.
pub fn main_hwnd<R: Runtime>(app: &AppHandle<R>) -> isize {
    #[cfg(windows)]
    if let Some(h) = main_window(app).and_then(|w| w.hwnd().ok()) {
        return h.0 as isize;
    }
    let _ = app;
    0
}

pub fn show_main<R: Runtime>(app: &AppHandle<R>) {
    if let Some(w) = main_window(app) {
        let _ = w.unminimize();
        let _ = w.show();
        let _ = w.set_focus();
    }
}

/// Drop every open vault (zeroizes keys and protected values) and tell the UI.
pub fn lock_all<R: Runtime>(app: &AppHandle<R>) {
    if let Ok(mut v) = app.state::<Vaults>().0.lock() {
        crate::vault::lock_vaults(&mut v);
    }
    crate::browser_server::notify("database-locked");
    let _ = app.emit("akp-locked", ());
}

// ---------------------------------------------------------------- tray

fn build_tray_menu<R: Runtime>(app: &AppHandle<R>, labels: &[String; 3]) -> tauri::Result<Menu<R>> {
    Menu::with_items(app, &[
        &MenuItem::with_id(app, "show", &labels[0], true, None::<&str>)?,
        &MenuItem::with_id(app, "lock", &labels[1], true, None::<&str>)?,
        &PredefinedMenuItem::separator(app)?,
        &MenuItem::with_id(app, "quit", &labels[2], true, None::<&str>)?,
    ])
}

/// Tray icon for the chosen style. Monochrome = just the shield (the dark part of the app
/// icon), cropped to fill the square, in white (dark taskbar) or black (light taskbar).
fn tray_image<R: Runtime>(app: &AppHandle<R>, style: &str) -> Option<tauri::image::Image<'static>> {
    let icon = app.default_window_icon()?;
    let (w, h, px) = (icon.width() as usize, icon.height() as usize, icon.rgba());
    let color: u8 = match style {
        "monoLight" => 255,
        "monoDark" => 0,
        _ => return Some(icon.clone().to_owned()),
    };
    let dark = |x: usize, y: usize| {
        let p = &px[(y * w + x) * 4..][..4];
        p[3] > 128 && (p[0] as u32 + p[1] as u32 + p[2] as u32) < 3 * 110
    };
    let (mut x0, mut y0, mut x1, mut y1) = (w, h, 0, 0);
    for y in 0..h {
        for x in 0..w {
            if dark(x, y) {
                (x0, y0, x1, y1) = (x0.min(x), y0.min(y), x1.max(x), y1.max(y));
            }
        }
    }
    if x0 > x1 {
        return Some(icon.clone().to_owned());
    }
    let side = (x1 - x0).max(y1 - y0) + 1;
    let (ox, oy) = ((side - (x1 - x0 + 1)) / 2, (side - (y1 - y0 + 1)) / 2);
    let mut out = vec![0u8; side * side * 4];
    for y in y0..=y1 {
        for x in x0..=x1 {
            if dark(x, y) {
                let i = ((y - y0 + oy) * side + (x - x0 + ox)) * 4;
                out[i..i + 4].copy_from_slice(&[color, color, color, 255]);
            }
        }
    }
    Some(tauri::image::Image::new_owned(out, side as u32, side as u32))
}

pub fn create_tray<R: Runtime>(app: &AppHandle<R>, p: &DesktopPrefs) -> tauri::Result<()> {
    let tray = TrayIconBuilder::with_id(TRAY_ID)
        .icon(tray_image(app, &p.tray_style).ok_or(tauri::Error::InvalidIcon(std::io::Error::other("no icon")))?)
        .tooltip("AnotherKeepass")
        .menu(&build_tray_menu(app, &p.tray_labels)?)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, e| match e.id().as_ref() {
            "show" => show_main(app),
            "lock" => lock_all(app),
            "quit" => app.exit(0),
            _ => {}
        })
        .on_tray_icon_event(|tray, e| {
            // left click toggles the window
            if let TrayIconEvent::Click { button: MouseButton::Left, button_state: MouseButtonState::Up, .. } = e {
                let app = tray.app_handle();
                match main_window(app) {
                    Some(w) if w.is_visible().unwrap_or(false) && !w.is_minimized().unwrap_or(false) => { let _ = w.hide(); }
                    _ => show_main(app),
                }
            }
        })
        .build(app)?;
    tray.set_visible(p.tray_icon)?;
    Ok(())
}

// ---------------------------------------------------------------- window behaviour

pub fn on_window_event<R: Runtime>(window: &tauri::Window<R>, event: &WindowEvent) {
    let app = window.app_handle();
    let p = prefs(app);
    match event {
        // with a tray icon × only hides the window (like Proton Pass); quitting goes through the tray menu
        WindowEvent::CloseRequested { api, .. } if p.tray_icon => {
            log::info!("close -> tray");
            api.prevent_close();
            let _ = window.hide();
        }
        WindowEvent::Resized(_) if window.is_minimized().unwrap_or(false) => {
            if p.lock_on_minimize {
                lock_all(app);
            }
            if p.hide_to_tray && p.tray_icon {
                let _ = window.hide();
            }
        }
        _ => {}
    }
}

/// Window starts hidden (tauri.conf.json) so "start minimized" doesn't flash.
pub fn initial_show<R: Runtime>(app: &AppHandle<R>, p: &DesktopPrefs) {
    let Some(w) = main_window(app) else { return };
    // "start minimized" is for the login autostart only; a manual start always shows the window
    let autostarted = std::env::args().any(|a| a == AUTOSTART_ARG);
    if !(p.start_minimized && autostarted) {
        show_main(app);
    } else if !p.tray_icon {
        let _ = w.show();
        let _ = w.minimize();
    } // with tray: stay hidden, the tray icon brings it back
}

// ---------------------------------------------------------------- apply from UI

#[tauri::command]
pub fn desktop_apply(app: AppHandle, prefs: DesktopPrefs) -> Result<Vec<String>, String> {
    let old = {
        let state = app.state::<Desktop>();
        let mut cur = state.prefs.lock().map_err(|_| "lock")?;
        std::mem::replace(&mut *cur, prefs.clone())
    };
    log::info!(
        "desktop_apply tray={} hide_to_tray={} start_minimized={} browser={}",
        prefs.tray_icon, prefs.hide_to_tray, prefs.start_minimized, prefs.browser_enabled
    );
    save_prefs(&prefs).inspect_err(|e| log::error!("desktop.json: {e}"))?;
    apply_backup(&prefs);
    crate::vault::quick_unlock_enable(prefs.quick_unlock);
    let mut problems = Vec::new();

    if let Some(tray) = app.tray_by_id(TRAY_ID) {
        let _ = tray.set_visible(prefs.tray_icon);
        if old.tray_style != prefs.tray_style {
            let _ = tray.set_icon(tray_image(&app, &prefs.tray_style));
        }
        if old.tray_labels != prefs.tray_labels {
            if let Ok(menu) = build_tray_menu(&app, &prefs.tray_labels) {
                let _ = tray.set_menu(Some(menu));
            }
        }
    }
    let autolaunch = app.autolaunch();
    // enable() also rewrites entries from older versions that lack AUTOSTART_ARG
    if prefs.autostart || autolaunch.is_enabled().unwrap_or(false) {
        let r = if prefs.autostart { autolaunch.enable() } else { autolaunch.disable() };
        if let Err(e) = r {
            problems.push(format!("autostart:{e}"));
        }
    }
    if prefs.browser_enabled {
        if let Err(e) = crate::browser_server::start(app.state::<std::sync::Arc<crate::browser_server::AppHost>>().inner().clone()) {
            problems.push(e);
        }
    }
    problems.extend(crate::browser_server::sync_manifests(&prefs));
    if old.at_shortcut != prefs.at_shortcut {
        if let Err(e) = crate::autotype::register_shortcut(&app, &prefs.at_shortcut) {
            problems.push(format!("shortcut:{e}"));
        }
    }
    if !problems.is_empty() {
        log::warn!("desktop_apply problems: {problems:?}");
    }
    Ok(problems)
}

/// UI errors and timings end up in the same log file.
#[tauri::command]
pub fn ui_log(level: String, message: String) {
    match level.as_str() {
        "error" => log::error!("ui: {message}"),
        "warn" => log::warn!("ui: {message}"),
        _ => log::info!("ui: {message}"),
    }
}

#[tauri::command]
pub fn window_minimize(app: AppHandle) {
    if let Some(w) = main_window(&app) {
        let _ = w.minimize();
    }
}

// ---------------------------------------------------------------- session lock (Windows)

pub fn on_session_event<R: Runtime>(app: &AppHandle<R>, code: u32) {
    const WTS_CONSOLE_DISCONNECT: u32 = 0x2;
    const WTS_REMOTE_DISCONNECT: u32 = 0x4;
    const WTS_SESSION_LOCK: u32 = 0x7;
    let p = prefs(app);
    let lock = (code == WTS_SESSION_LOCK && p.lock_on_session)
        || ((code == WTS_CONSOLE_DISCONNECT || code == WTS_REMOTE_DISCONNECT) && p.lock_on_user_switch);
    if lock {
        lock_all(app);
    }
}

#[cfg(windows)]
pub fn watch_session(app: AppHandle) {
    use std::sync::OnceLock;
    use windows_sys::Win32::{
        Foundation::{HWND, LPARAM, LRESULT, WPARAM},
        System::{LibraryLoader::GetModuleHandleW, RemoteDesktop::WTSRegisterSessionNotification},
        UI::WindowsAndMessaging::{
            CreateWindowExW, DefWindowProcW, DispatchMessageW, GetMessageW, RegisterClassW, TranslateMessage, HWND_MESSAGE,
            MSG, WNDCLASSW,
        },
    };
    const WM_WTSSESSION_CHANGE: u32 = 0x02B1;
    const NOTIFY_FOR_THIS_SESSION: u32 = 0;
    static APP: OnceLock<AppHandle> = OnceLock::new();

    unsafe extern "system" fn proc(h: HWND, msg: u32, w: WPARAM, l: LPARAM) -> LRESULT {
        if msg == WM_WTSSESSION_CHANGE {
            if let Some(app) = APP.get() {
                on_session_event(app, w as u32);
            }
        }
        unsafe { DefWindowProcW(h, msg, w, l) }
    }

    let _ = APP.set(app);
    // a hidden message-only window receives the session notifications
    std::thread::spawn(|| unsafe {
        let class: Vec<u16> = "AnotherKeepassSession\0".encode_utf16().collect();
        let hinst = GetModuleHandleW(std::ptr::null());
        let wc = WNDCLASSW { lpfnWndProc: Some(proc), hInstance: hinst, lpszClassName: class.as_ptr(), ..std::mem::zeroed() };
        RegisterClassW(&wc);
        let hwnd = CreateWindowExW(0, class.as_ptr(), class.as_ptr(), 0, 0, 0, 0, 0, HWND_MESSAGE, std::ptr::null_mut(), hinst, std::ptr::null());
        if hwnd.is_null() || WTSRegisterSessionNotification(hwnd, NOTIFY_FOR_THIS_SESSION) == 0 {
            log::warn!("session lock notifications unavailable");
            return;
        }
        let mut msg: MSG = std::mem::zeroed();
        while GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) > 0 {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    });
}

// ponytail: Linux/macOS screen-lock signals (logind D-Bus / NSWorkspace) not wired yet
#[cfg(not(windows))]
pub fn watch_session(_app: AppHandle) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefs_roundtrip_and_defaults() {
        // unknown/missing keys fall back to defaults (UI may send a subset)
        let p: DesktopPrefs = serde_json::from_str(r#"{"trayIcon":false,"atShortcut":"Ctrl+Alt+A"}"#).unwrap();
        assert!(!p.tray_icon);
        assert_eq!(p.at_shortcut, "Ctrl+Alt+A");
        assert!(p.lock_on_session);
        assert_eq!(p.at_start_delay, 500);
        let back: DesktopPrefs = serde_json::from_slice(&serde_json::to_vec(&p).unwrap()).unwrap();
        assert_eq!(back, p);
        assert!(config_file().unwrap().ends_with(PathBuf::from(IDENTIFIER).join("desktop.json")));
    }
}
