//! Vault lifecycle: create, open (file or Vaultwarden account), sync link, lock, close, Windows Hello quick unlock.

use super::*;

/// Link a .kdbx vault with an open Vaultwarden account (None = unlink) and sync right away.
#[tauri::command]
pub fn sync_link(state: tauri::State<'_, Vaults>, vault: String, remote: Option<String>) -> R<VaultDto> {
    if remote.as_deref().is_some_and(|r| !crate::bitwarden::is_remote(r)) || crate::bitwarden::is_remote(&vault) {
        return Err("sync_link".into());
    }
    mutate(&state, &vault, |db| {
        crate::sync::set_link(db, remote.as_deref());
        Ok(())
    })
}

pub(crate) fn ensure_recycle_bin(db: &mut Database) -> GroupId {
    if let Some(bin) = db.recycle_bin() {
        return bin.id();
    }
    let id = {
        let mut root = db.root_mut();
        let mut g = root.add_group();
        g.name = "Recycle Bin".into();
        g.set_icon_builtin(43); // KeePass trash icon
        g.enable_autotype = Some(false);
        g.enable_searching = Some(false);
        g.id()
    };
    db.meta.recyclebin_enabled = Some(true);
    db.meta.recyclebin_uuid = Some(id.uuid());
    db.meta.recyclebin_changed = Some(Times::now());
    id
}

// ---------------------------------------------------------------- commands: vaults

/// Strong defaults for new files (the crate default uses only 1 MiB Argon2 memory).
pub(crate) fn new_config() -> DatabaseConfig {
    let mut c = DatabaseConfig::default();
    c.kdf_config = KdfConfig::Argon2id { iterations: 10, memory: 64 * 1024 * 1024, parallelism: 2, version: argon2::Version::Version13 };
    c
}

#[tauri::command]
pub fn vault_create(
    state: tauri::State<'_, Vaults>,
    path: String,
    name: String,
    password: Option<String>,
    keyfile: Option<String>,
) -> R<VaultDto> {
    let key = make_key(password.as_deref(), keyfile.as_deref())?;
    let mut db = Database::with_config(new_config());
    db.meta.database_name = Some(name.clone());
    db.meta.generator = Some("AnotherKeepass".into());
    db.meta.history_max_items = Some(10);
    db.root_mut().name = name;
    ensure_recycle_bin(&mut db);
    let mut v = OpenVault { path: PathBuf::from(&path), db, key, remote: None };
    write_db(&mut v)?;
    let d = dto(&path, &v);
    state.0.lock().map_err(|_| "lock")?.insert(path, v);
    Ok(d)
}

#[tauri::command]
pub async fn vault_open(
    app: tauri::AppHandle,
    state: tauri::State<'_, Vaults>,
    path: String,
    password: Option<String>,
    keyfile: Option<String>,
    two_factor_provider: Option<u8>,
    two_factor_code: Option<String>,
) -> R<VaultDto> {
    if crate::bitwarden::is_remote(&path) {
        return open_remote(state, path, password.unwrap_or_default(), two_factor_provider.zip(two_factor_code)).await;
    }
    let key = make_key(password.as_deref(), keyfile.as_deref())?;
    open_with(app, state, path, key, true).await
}

/// Vaultwarden account: log in (network) and decrypt into an in-memory vault.
pub(super) async fn open_remote(
    state: tauri::State<'_, Vaults>,
    path: String,
    password: String,
    second: Option<(u8, String)>,
) -> R<VaultDto> {
    if password.is_empty() {
        return Err("empty_key".into());
    }
    let p = path.clone();
    let (db, remote) = tauri::async_runtime::spawn_blocking(move || crate::bitwarden::open(&p, &password, second))
        .await
        .map_err(|e| format!("open:{e}"))??;
    let v = OpenVault { path: PathBuf::from(&path), db, key: DatabaseKey::new().with_password("remote"), remote: Some(Box::new(remote)) };
    let mut map = state.0.lock().map_err(|_| "lock")?;
    map.insert(path.clone(), v);
    crate::sync::after_change(&mut map, &path);
    let d = dto(&path, map.get(&path).ok_or("vault_closed")?);
    drop(map);
    crate::browser_server::notify("database-unlocked");
    Ok(d)
}

/// Vaultwarden: fetch the server state now.
#[tauri::command]
pub async fn vault_sync(state: tauri::State<'_, Vaults>, vault: String) -> R<VaultDto> {
    with_vault(&state, &vault, |v| {
        let title = v.db.meta.database_name.clone().unwrap_or_default();
        let r = v.remote.as_mut().ok_or("not_remote")?;
        v.db = crate::bitwarden::pull(r, &title)?;
        Ok(())
    })?;
    let mut map = state.0.lock().map_err(|_| "lock")?;
    crate::sync::after_change(&mut map, &vault);
    Ok(dto(&vault, map.get(&vault).ok_or("vault_closed")?))
}

/// Vaultwarden email 2FA: send the login code.
#[tauri::command]
pub async fn bw_send_email(path: String, password: String) -> R<()> {
    tauri::async_runtime::spawn_blocking(move || crate::bitwarden::send_email_code(&path, &password)).await.map_err(|e| e.to_string())?
}

/// Vaultwarden: close and forget this device's token and offline copy.
#[tauri::command]
pub fn bw_sign_out(state: tauri::State<'_, Vaults>, path: String) -> R<()> {
    state.0.lock().map_err(|_| "lock")?.remove(&path);
    crate::bitwarden::forget(&path);
    Ok(())
}

/// `second_factor`: in "password and Windows Hello" mode ask Hello once the key is known to be right.
pub(super) async fn open_with(
    app: tauri::AppHandle,
    state: tauri::State<'_, Vaults>,
    path: String,
    key: DatabaseKey,
    second_factor: bool,
) -> R<VaultDto> {
    // Argon2 takes ~1 s: run it off the main thread
    let p = path.clone();
    let k = key.clone();
    let started = std::time::Instant::now();
    let (db, shared) = tauri::async_runtime::spawn_blocking(move || -> R<(Database, bool)> {
        let mut f = fs::File::open(&p).map_err(|e| format!("io:{e}"))?;
        let mut db = Database::open(&mut f, k).map_err(|e| match e {
            keepass::db::DatabaseOpenError::Key(_) => "wrong_key".to_string(),
            other => format!("open:{other}"),
        })?;
        let shared = crate::keeshare::import_all(&mut db, Path::new(&p));
        for c in crate::keeshare::watched(&db, Path::new(&p)) {
            stamp(&c);
        }
        Ok((db, shared))
    })
    .await
    .map_err(|e| format!("open:{e}"))??;
    log::info!("vault opened: {} entries, {} ms (key derivation + decrypt)", db.num_entries(), started.elapsed().as_millis());
    if second_factor && HELLO_BOTH.load(std::sync::atomic::Ordering::Relaxed) {
        let hwnd = crate::desktop::main_hwnd(&app);
        let ok = tauri::async_runtime::spawn_blocking(move || {
            // no Hello on this PC (any more): don't lock the user out, the password was right
            !crate::hello::available() || crate::hello::verify(hwnd, "AnotherKeepass")
        })
        .await
        .unwrap_or(false);
        if !ok {
            return Err("hello_cancel".into());
        }
    }
    let mut v = OpenVault { path: PathBuf::from(&path), db, key, remote: None };
    if shared {
        write_db(&mut v)?; // KeeShare import changed the folder
    }
    stamp(&v.path);
    let mut map = state.0.lock().map_err(|_| "lock")?;
    map.insert(path.clone(), v);
    crate::sync::after_change(&mut map, &path);
    let d = dto(&path, map.get(&path).ok_or("vault_closed")?);
    drop(map);
    crate::browser_server::notify("database-unlocked");
    // after the UI got the listing: SSH keys to the agent, an Auto-Type may be waiting for this unlock
    let app2 = app.clone();
    std::thread::spawn(move || {
        use tauri::Manager;
        let state = app2.state::<Vaults>();
        if let Some(v) = state.0.lock().ok().as_ref().and_then(|m| m.get(&path)) {
            crate::ssh::on_unlock(&path, v);
        }
        std::thread::sleep(std::time::Duration::from_millis(300));
        crate::autotype::after_unlock(&app2);
    });
    Ok(d)
}

/// Which remembered vault files still exist (moved/deleted ones are dropped from the list).
#[tauri::command]
pub fn paths_exist(paths: Vec<String>) -> Vec<bool> {
    paths.iter().map(|p| crate::bitwarden::is_remote(p) || Path::new(p).is_file()).collect()
}

#[tauri::command]
pub fn vault_close(state: tauri::State<'_, Vaults>, id: String) -> R<()> {
    let mut map = state.0.lock().map_err(|_| "lock")?;
    if let Some(v) = map.get_mut(&id) {
        save_used(v);
    }
    map.remove(&id); // drop zeroizes key + protected values
    drop(map);
    crate::ssh::on_lock(&id);
    if let Some(keys) = QUICK_KEYS.lock().map_err(|_| "lock")?.as_mut() {
        keys.remove(&id); // closing on purpose = no quick unlock for it
    }
    Ok(())
}

#[tauri::command]
pub fn vault_lock_all(state: tauri::State<'_, Vaults>) -> R<()> {
    lock_vaults(&mut *state.0.lock().map_err(|_| "lock")?);
    Ok(())
}

// ---------------------------------------------------------------- quick unlock (Windows Hello)

/// Set from the settings ("Quick unlock").
pub static QUICK_UNLOCK: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
/// ponytail: keys of locked vaults stay in this process (zeroized on drop/quit) and Windows Hello
/// only gates their use — like KeePassXC's quick unlock; a TPM-bound key would need KeyCredentialManager.
pub(super) static QUICK_KEYS: Mutex<Option<HashMap<String, DatabaseKey>>> = Mutex::new(None);

/// Lock = drop every open vault; with quick unlock on, keep the keys for Windows Hello.
pub fn lock_vaults(map: &mut HashMap<String, OpenVault>) {
    if let Ok(mut q) = QUICK_KEYS.lock() {
        if QUICK_UNLOCK.load(std::sync::atomic::Ordering::Relaxed) {
            let keys = q.get_or_insert_with(HashMap::new);
            for (id, v) in map.iter().filter(|(_, v)| v.remote.is_none()) {
                keys.insert(id.clone(), v.key.clone());
            }
        } else {
            *q = None;
        }
    }
    for (id, v) in map.iter_mut() {
        save_used(v);
        crate::ssh::on_lock(id);
    }
    map.clear();
}

/// Turning the option off forgets every kept key at once.
/// "Password and Windows Hello": every unlock with the master password also needs Hello.
pub static HELLO_BOTH: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub fn quick_unlock_enable(on: bool) {
    QUICK_UNLOCK.store(on, std::sync::atomic::Ordering::Relaxed);
    if !on && let Ok(mut q) = QUICK_KEYS.lock() {
        *q = None;
    }
}

pub(super) fn quick_key(path: &str) -> Option<DatabaseKey> {
    QUICK_KEYS.lock().ok()?.as_ref()?.get(path).cloned()
}

#[tauri::command]
pub async fn quick_unlock_available(path: String) -> bool {
    quick_key(&path).is_some() && tauri::async_runtime::spawn_blocking(crate::hello::available).await.unwrap_or(false)
}

#[tauri::command]
pub async fn vault_quick_unlock(app: tauri::AppHandle, state: tauri::State<'_, Vaults>, path: String, message: String) -> R<VaultDto> {
    let key = quick_key(&path).ok_or("no_quick")?;
    let hwnd = crate::desktop::main_hwnd(&app);
    if !tauri::async_runtime::spawn_blocking(move || crate::hello::verify(hwnd, &message)).await.unwrap_or(false) {
        return Err("hello_cancel".into());
    }
    open_with(app, state, path, key, false).await
}

#[tauri::command]
pub fn vault_change_key(state: tauri::State<'_, Vaults>, id: String, password: Option<String>, keyfile: Option<String>) -> R<()> {
    let key = make_key(password.as_deref(), keyfile.as_deref())?;
    with_vault(&state, &id, |v| {
        v.key = key;
        v.db.meta.master_key_changed = Some(Times::now());
        write_db(v)
    })
}

#[tauri::command]
pub fn vault_rename(state: tauri::State<'_, Vaults>, id: String, name: String) -> R<VaultDto> {
    mutate(&state, &id, |db| {
        db.meta.database_name = Some(name);
        db.meta.database_name_changed = Some(Times::now());
        Ok(())
    })
}
