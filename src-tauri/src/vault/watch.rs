//! External changes to open .kdbx files (cloud sync, KeePassXC): reload when unchanged here.

use super::*;

// ---------------------------------------------------------------- external changes (cloud sync, KeePassXC)

/// Modification time of each vault file as we last read or wrote it.
pub(super) static STAMPS: Mutex<Option<HashMap<PathBuf, std::time::SystemTime>>> = Mutex::new(None);

pub(super) fn mtime(p: &Path) -> Option<std::time::SystemTime> {
    fs::metadata(p).and_then(|m| m.modified()).ok()
}

pub(crate) fn stamp(p: &Path) {
    if let (Ok(mut s), Some(t)) = (STAMPS.lock(), mtime(p)) {
        s.get_or_insert_with(HashMap::new).insert(p.to_path_buf(), t);
    }
}

/// Polls open vault files; when one changed on disk (Dropbox, Nextcloud, KeePassXC …) and
/// "auto reload" is on, re-reads it with the stored key. We save every edit at once, so the
/// only local state is an open edit form, and saving that afterwards lands in the fresh file.
pub fn watch_files(app: tauri::AppHandle) {
    use tauri::{Emitter, Manager};
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(std::time::Duration::from_secs(2));
            if !crate::desktop::prefs(&app).auto_reload {
                continue;
            }
            // KeeShare containers changed by others → import into the vault that shares them
            let containers: Vec<(String, PathBuf)> = {
                let state = app.state::<Vaults>();
                let Ok(map) = state.0.lock() else { continue };
                let stamps = STAMPS.lock().ok().and_then(|s| s.clone()).unwrap_or_default();
                map.iter()
                    .flat_map(|(id, v)| crate::keeshare::watched(&v.db, &v.path).into_iter().map(move |c| (id.clone(), c)))
                    .filter(|(_, c)| matches!((mtime(c), stamps.get(c)), (Some(now), Some(seen)) if now != *seen))
                    .collect()
            };
            for (id, c) in containers {
                stamp(&c);
                let state = app.state::<Vaults>();
                let Ok(mut map) = state.0.lock() else { continue };
                let Some(v) = map.get_mut(&id) else { continue };
                if crate::keeshare::import_all(&mut v.db, &v.path.clone()) {
                    if let Err(e) = write_db(v) {
                        log::warn!("keeshare save: {e}");
                        continue;
                    }
                    log::info!("keeshare: imported changes");
                    let _ = app.emit("akp-vault-updated", dto(&id, v));
                }
            }
            let changed: Vec<(String, PathBuf, DatabaseKey)> = {
                let state = app.state::<Vaults>();
                let Ok(map) = state.0.lock() else { continue };
                let stamps = STAMPS.lock().ok().and_then(|s| s.clone()).unwrap_or_default();
                map.iter()
                    .filter(|(_, v)| matches!((mtime(&v.path), stamps.get(&v.path)), (Some(now), Some(seen)) if now != *seen))
                    .map(|(id, v)| (id.clone(), v.path.clone(), v.key.clone()))
                    .collect()
            };
            for (id, path, key) in changed {
                stamp(&path); // also on failure: don't retry a broken file every 2 s
                // key derivation outside the lock, the UI keeps working meanwhile
                let db = fs::File::open(&path)
                    .map_err(|e| e.to_string())
                    .and_then(|mut f| Database::open(&mut f, key).map_err(|e| e.to_string()));
                let db = match db {
                    Ok(db) => db,
                    Err(e) => {
                        log::warn!("reload after external change failed: {e}");
                        continue;
                    }
                };
                let state = app.state::<Vaults>();
                let Ok(mut map) = state.0.lock() else { continue };
                let Some(v) = map.get_mut(&id) else { continue };
                v.db = db;
                log::info!("vault reloaded after external change");
                let _ = app.emit("akp-vault-updated", dto(&id, v));
                let _ = app.emit("akp-vault-reloaded", ());
            }
        }
    });
}
