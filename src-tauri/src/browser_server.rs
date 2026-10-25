//! Local socket server for the browser extension, plus the app side of `browser::Host`
//! (user confirmations, UI refresh) and native-messaging manifest registration.
//! Uses KeePassXC's socket name, so KeePassXC's own keepassxc-proxy reaches us too.

use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc,
    },
    time::Duration,
};

use serde_json::{Value, json};
use tauri::{AppHandle, Emitter, Manager};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::broadcast,
};

use crate::{
    browser::{self, Ask, BrowserPrefs, Host, Session},
    desktop,
    vault::{VaultDto, Vaults},
};

// ---------------------------------------------------------------- socket name

#[cfg(windows)]
pub fn pipe_name() -> String {
    // same pipe as KeePassXC 2.7 (checked against an installed KeePassXC), so keepassxc-proxy finds us;
    // AKP_PIPE_NAME overrides it for tests next to a running KeePassXC
    std::env::var("AKP_PIPE_NAME")
        .unwrap_or_else(|_| format!(r"\\.\pipe\org.keepassxc.KeePassXC.BrowserServer_{}", std::env::var("USERNAME").unwrap_or_default()))
}

#[cfg(unix)]
pub fn socket_path() -> std::path::PathBuf {
    let base = std::env::var_os("XDG_RUNTIME_DIR").map(std::path::PathBuf::from).unwrap_or_else(std::env::temp_dir);
    base.join("app/org.keepassxc.KeePassXC/org.keepassxc.KeePassXC.BrowserServer")
}

// ---------------------------------------------------------------- notifications

static NOTIFY: OnceLock<broadcast::Sender<String>> = OnceLock::new();

/// "database-locked" / "database-unlocked" go unencrypted to every connected extension.
pub fn notify(action: &str) {
    if let Some(tx) = NOTIFY.get() {
        let _ = tx.send(json!({ "action": action }).to_string());
    }
}

// ---------------------------------------------------------------- app host

pub struct AppHost {
    app: AppHandle,
    pending: Mutex<HashMap<u64, mpsc::Sender<Option<Value>>>>,
    next: AtomicU64,
    pub active: Mutex<Option<String>>,
    started: AtomicBool,
}

impl AppHost {
    pub fn new(app: AppHandle) -> Self {
        Self { app, pending: Mutex::default(), next: AtomicU64::new(1), active: Mutex::default(), started: AtomicBool::new(false) }
    }
}

impl Host for AppHost {
    fn vaults(&self) -> &Vaults {
        self.app.state::<Vaults>().inner()
    }
    fn prefs(&self) -> BrowserPrefs {
        let p = desktop::prefs(&self.app);
        BrowserPrefs {
            enabled: p.browser_enabled,
            unlock: p.b_unlock,
            match_scheme: p.b_match_scheme,
            best_match: p.b_best_match,
            allow_expired: p.b_allow_expired,
            search_all: p.b_search_all,
            no_access_confirm: p.b_no_access_confirm,
            update_no_confirm: p.b_update_no_confirm,
            kph: p.b_kph,
            skip_basic_auth: p.b_skip_basic_auth,
            localhost_passkeys: p.b_localhost_passkeys,
        }
    }
    fn active_vault(&self) -> Option<String> {
        self.active.lock().ok()?.clone()
    }
    fn ask(&self, ask: Ask) -> Option<Value> {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = mpsc::channel();
        self.pending.lock().ok()?.insert(id, tx);
        let payload = match ask {
            Ask::Associate => json!({ "id": id, "kind": "associate" }),
            Ask::Access { host, entries } => json!({ "id": id, "kind": "access", "host": host, "entries": entries }),
            Ask::Update { title, username } => json!({ "id": id, "kind": "update", "title": title, "username": username }),
            Ask::Delete { title, username } => json!({ "id": id, "kind": "delete", "title": title, "username": username }),
            Ask::PasskeyRegister { rp_id, username, existing } => {
                json!({ "id": id, "kind": "passkeyRegister", "rpId": rp_id, "username": username, "existing": existing })
            }
            Ask::PasskeyGet { rp_id, entries } => json!({ "id": id, "kind": "passkeyGet", "rpId": rp_id, "entries": entries }),
        };
        let _ = self.app.emit("akp-browser-ask", payload);
        desktop::show_main(&self.app);
        // the extension waits as well; give the user two minutes
        let answer = rx.recv_timeout(Duration::from_secs(120)).ok().flatten();
        self.pending.lock().ok()?.remove(&id);
        answer
    }
    fn vault_changed(&self, dto: VaultDto) {
        let _ = self.app.emit("akp-vault-updated", dto);
    }
    fn lock_all(&self) {
        desktop::lock_all(&self.app);
    }
    fn show_window(&self) {
        desktop::show_for_unlock(&self.app);
    }
    fn autotype_search(&self, search: &str) {
        crate::autotype::request(&self.app, search);
    }
}

#[tauri::command]
pub fn browser_answer(host: tauri::State<'_, Arc<AppHost>>, id: u64, answer: Option<Value>) {
    if let Some(tx) = host.pending.lock().ok().and_then(|mut p| p.remove(&id)) {
        let _ = tx.send(answer);
    }
}

#[tauri::command]
pub fn browser_set_active(host: tauri::State<'_, Arc<AppHost>>, vault: Option<String>) {
    if let Ok(mut a) = host.active.lock() {
        *a = vault;
    }
}

// ---------------------------------------------------------------- server

/// Start once; returns a readable problem if the socket is taken (e.g. KeePassXC running).
pub fn start(host: Arc<AppHost>) -> Result<(), String> {
    if host.started.swap(true, Ordering::SeqCst) {
        return Ok(());
    }
    let tx = NOTIFY.get_or_init(|| broadcast::channel(16).0).clone();
    let first = listen_first().map_err(|e| {
        host.started.store(false, Ordering::SeqCst);
        format!("browser:{e}")
    })?;
    tauri::async_runtime::spawn(accept_loop(first, host, tx));
    Ok(())
}

/// Enter a tokio runtime for socket creation: the current one (tests) or Tauri's.
fn with_runtime<T>(f: impl FnOnce() -> T) -> T {
    match tokio::runtime::Handle::try_current() {
        Ok(_) => f(),
        Err(_) => {
            let _guard = tauri::async_runtime::handle().inner().enter();
            f()
        }
    }
}

#[cfg(windows)]
type Listener = tokio::net::windows::named_pipe::NamedPipeServer;
#[cfg(unix)]
type Listener = tokio::net::UnixListener;

/// Pipe instance that only the current user (and SYSTEM) can open; remote clients refused.
#[cfg(windows)]
fn create_pipe(first: bool) -> std::io::Result<Listener> {
    create_pipe_named(&pipe_name(), first)
}

#[cfg(windows)]
fn create_pipe_named(name: &str, first: bool) -> std::io::Result<Listener> {
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
    let sd = crate::hardening::security_descriptor("D:P(A;;GA;;;OW)(A;;GA;;;SY)").map_err(std::io::Error::other)?;
    let mut sa =
        SECURITY_ATTRIBUTES { nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32, lpSecurityDescriptor: sd, bInheritHandle: 0 };
    let r = unsafe {
        tokio::net::windows::named_pipe::ServerOptions::new()
            .first_pipe_instance(first)
            .reject_remote_clients(true)
            .create_with_security_attributes_raw(name, &mut sa as *mut _ as *mut std::ffi::c_void)
    };
    unsafe { windows_sys::Win32::Foundation::LocalFree(sd as _) };
    r
}

#[cfg(windows)]
fn listen_first() -> std::io::Result<Listener> {
    // first_pipe_instance fails if someone (KeePassXC) already serves this name
    with_runtime(|| create_pipe(true))
}

#[cfg(unix)]
fn listen_first() -> std::io::Result<Listener> {
    let path = socket_path();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    if std::os::unix::net::UnixStream::connect(&path).is_ok() {
        return Err(std::io::Error::new(std::io::ErrorKind::AddrInUse, "socket in use"));
    }
    let _ = std::fs::remove_file(&path);
    let l = with_runtime(|| tokio::net::UnixListener::bind(&path))?;
    // KeePassXC also links the classic path for older proxies
    if let Some(runtime) = path.parent().and_then(|p| p.parent()).and_then(|p| p.parent()) {
        let legacy = runtime.join("org.keepassxc.KeePassXC.BrowserServer");
        let _ = std::fs::remove_file(&legacy);
        let _ = std::os::unix::fs::symlink(&path, legacy);
    }
    Ok(l)
}

#[cfg(windows)]
async fn accept_loop(mut server: Listener, host: Arc<dyn Host>, tx: broadcast::Sender<String>) {
    loop {
        if server.connect().await.is_err() {
            continue;
        }
        let conn = server;
        server = match create_pipe(false) {
            Ok(s) => s,
            Err(e) => {
                log::error!("browser pipe: {e}");
                return;
            }
        };
        tokio::spawn(serve(conn, host.clone(), tx.subscribe()));
    }
}

#[cfg(unix)]
async fn accept_loop(listener: Listener, host: Arc<dyn Host>, tx: broadcast::Sender<String>) {
    while let Ok((conn, _)) = listener.accept().await {
        tokio::spawn(serve(conn, host.clone(), tx.subscribe()));
    }
}

/// One connection = one extension session. Messages are raw JSON (no framing), like KeePassXC.
async fn serve<S>(mut conn: S, host: Arc<dyn Host>, mut notes: broadcast::Receiver<String>)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let session = Arc::new(Mutex::new(Session::default()));
    let mut buf = Vec::new();
    let mut chunk = vec![0u8; 64 * 1024];
    loop {
        tokio::select! {
            n = conn.read(&mut chunk) => {
                let n = match n { Ok(0) | Err(_) => return, Ok(n) => n };
                buf.extend_from_slice(&chunk[..n]);
                if buf.len() > 4 * 1024 * 1024 { buf.clear(); continue; } // garbage guard
                let req: Value = match serde_json::from_slice(&buf) {
                    Ok(v) => { buf.clear(); v }
                    Err(e) if e.is_eof() => continue, // message split over reads
                    Err(_) => { buf.clear(); continue; }
                };
                if !host.prefs().enabled {
                    return; // integration switched off: behave like no app is listening
                }
                let (h, s) = (host.clone(), session.clone());
                // handlers may wait for the user (association / access dialogs)
                let reply = tokio::task::spawn_blocking(move || {
                    let mut s = s.lock().unwrap_or_else(|p| p.into_inner());
                    browser::handle(&*h, &mut s, &req)
                }).await.unwrap_or_else(|_| json!({ "error": "internal" }));
                if conn.write_all(reply.to_string().as_bytes()).await.is_err() {
                    return;
                }
            }
            note = notes.recv() => {
                if let Ok(n) = note
                    && conn.write_all(n.as_bytes()).await.is_err() { return; }
            }
        }
    }
}

// ---------------------------------------------------------------- native messaging manifests

const HOST_NAME: &str = "org.keepassxc.keepassxc_browser";
const CHROMIUM_ORIGINS: [&str; 2] = [
    "chrome-extension://oboonakemofpalcgghocfoadofidjkkk/", // Chrome Web Store
    "chrome-extension://pdffhmdngciaglkoonimfcmckehcpafo/", // Edge Add-ons
];
const FIREFOX_ID: &str = "keepassxc-browser@keepassxc.org";

/// Register (or remove) our exe as native-messaging host for the enabled browsers.
/// Previous values (usually KeePassXC's) are backed up and restored when switched off.
#[cfg(windows)]
pub fn sync_manifests(p: &desktop::DesktopPrefs) -> Vec<String> {
    use winreg::{RegKey, enums::HKEY_CURRENT_USER};
    let mut problems = Vec::new();
    let Some(dir) = std::env::var_os("LOCALAPPDATA").map(|d| std::path::PathBuf::from(d).join("AnotherKeepass")) else {
        return vec!["manifest:no LOCALAPPDATA".into()];
    };
    let exe = if p.b_custom_proxy && !p.b_proxy_path.trim().is_empty() {
        std::path::PathBuf::from(p.b_proxy_path.trim())
    } else {
        std::env::current_exe().unwrap_or_default()
    };
    let backup_file = dir.join("manifest-backup.json");
    let mut backup: HashMap<String, String> =
        std::fs::read(&backup_file).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
    let on = p.browser_enabled && p.b_update_manifests;
    // (registry key, firefox?, enabled)
    let targets = [
        (r"Software\Google\Chrome\NativeMessagingHosts", false, p.b_chrome || p.b_vivaldi || p.b_brave),
        (r"Software\Chromium\NativeMessagingHosts", false, p.b_chromium),
        (r"Software\Microsoft\Edge\NativeMessagingHosts", false, p.b_edge),
        (r"Software\Mozilla\NativeMessagingHosts", true, p.b_firefox || p.b_tor),
    ];
    let _ = std::fs::create_dir_all(&dir);
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    for (base, firefox, enabled) in targets {
        let key_path = format!(r"{base}\{HOST_NAME}");
        let file = dir.join(if firefox { "native-firefox.json" } else { "native-chromium.json" });
        let current: Option<String> = hkcu.open_subkey(&key_path).ok().and_then(|k| k.get_value("").ok());
        let ours = current.as_deref() == Some(file.to_string_lossy().as_ref());
        if on && enabled {
            let manifest = if firefox {
                json!({ "name": HOST_NAME, "description": "AnotherKeepass browser integration", "path": exe, "type": "stdio", "allowed_extensions": [FIREFOX_ID] })
            } else {
                json!({ "name": HOST_NAME, "description": "AnotherKeepass browser integration", "path": exe, "type": "stdio", "allowed_origins": CHROMIUM_ORIGINS })
            };
            let bytes = serde_json::to_vec_pretty(&manifest).unwrap_or_default();
            if std::fs::read(&file).ok().as_ref() != Some(&bytes)
                && let Err(e) = std::fs::write(&file, &bytes)
            {
                problems.push(format!("manifest:{e}"));
                continue;
            }
            if !ours {
                if let Some(prev) = current {
                    backup.insert(key_path.clone(), prev);
                }
                match hkcu.create_subkey(&key_path) {
                    Ok((k, _)) => {
                        let _ = k.set_value("", &file.to_string_lossy().to_string());
                    }
                    Err(e) => problems.push(format!("manifest:{e}")),
                }
            }
        } else if ours {
            // switched off: give the slot back to whoever had it (e.g. KeePassXC)
            match backup.remove(&key_path) {
                Some(prev) => {
                    if let Ok(k) = hkcu.open_subkey_with_flags(&key_path, winreg::enums::KEY_SET_VALUE) {
                        let _ = k.set_value("", &prev);
                    }
                }
                None => {
                    let _ = hkcu.delete_subkey(&key_path);
                }
            }
        }
    }
    let _ = std::fs::write(&backup_file, serde_json::to_vec(&backup).unwrap_or_default());
    problems
}

// ponytail: Linux/macOS manifest files (~/.config/google-chrome/NativeMessagingHosts …) not written yet
#[cfg(not(windows))]
pub fn sync_manifests(_p: &desktop::DesktopPrefs) -> Vec<String> {
    Vec::new()
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use crate::browser::tests::{TestHost, test_vault};

    /// our pipe: only this user; a client sees the server as "me" and the owner as trusted
    #[test]
    fn pipe_is_ours() {
        use std::os::windows::io::AsRawHandle;
        let name = format!(r"\\.\pipe\akp-own-{}", uuid::Uuid::new_v4().simple());
        with_runtime(|| {
            let _server = create_pipe_named(&name, true).unwrap();
            let client = tokio::net::windows::named_pipe::ClientOptions::new().open(&name).unwrap();
            assert!(crate::hardening::pipe_server_is_me(client.as_raw_handle() as _));
            drop(client);
            let _second = create_pipe_named(&name, false).unwrap();
            use std::os::windows::fs::OpenOptionsExt;
            let f = std::fs::OpenOptions::new().access_mode(0x8000_0000 | 0x4000_0000 | 0x0002_0000).open(&name).unwrap();
            assert!(crate::hardening::pipe_owner_trusted(f.as_raw_handle() as _), "owner check accepts our own pipe");
            Ok::<_, std::io::Error>(())
        })
        .unwrap();
        // a second "first instance" (squatting the name) is refused
        with_runtime(|| {
            let _a = create_pipe_named(&name, true).unwrap();
            assert!(create_pipe_named(&name, true).is_err());
            Ok::<_, std::io::Error>(())
        })
        .unwrap();
    }

    /// Real named pipe + tweetnacl client (scripts/browser-e2e.cjs), like the extension behind a proxy.
    /// Needs node and the npm dev dependencies:  cargo test --lib browser_pipe_e2e -- --ignored
    #[test]
    #[ignore]
    fn browser_pipe_e2e() {
        let name = format!(r"\\.\pipe\akp-e2e-{}", uuid::Uuid::new_v4().simple());
        // SAFETY: set before any other thread of this test reads the environment
        unsafe { std::env::set_var("AKP_PIPE_NAME", &name) };
        let (vaults, _) = test_vault();
        let host: Arc<dyn Host> = Arc::new(TestHost {
            vaults,
            prefs: BrowserPrefs { enabled: true, match_scheme: true, ..Default::default() },
            answer_access: true,
        });
        let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
        rt.block_on(async {
            let first = listen_first().unwrap();
            let tx = NOTIFY.get_or_init(|| broadcast::channel(16).0).clone();
            tokio::spawn(accept_loop(first, host, tx));
            let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../scripts/browser-e2e.cjs");
            let out = tokio::process::Command::new("node").arg(script).env("AKP_PIPE_NAME", &name).output().await.unwrap();
            let text = String::from_utf8_lossy(&out.stdout).to_string() + &String::from_utf8_lossy(&out.stderr);
            println!("{text}");
            assert!(out.status.success(), "{text}");
        });
    }
}
