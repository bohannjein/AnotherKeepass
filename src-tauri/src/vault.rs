//! KDBX vault backend. Every open .kdbx lives here; the UI only ever gets entry
//! metadata. Protected values (passwords, hidden fields, OTP secrets) leave this
//! process only on explicit reveal/edit, and copies go straight to the clipboard.

use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    sync::Mutex,
};

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use chrono::{NaiveDate, NaiveDateTime};
use keepass::{
    config::{DatabaseConfig, DatabaseVersion, InnerCipherConfig, KdfConfig},
    db::{fields, EntryId, GroupId, Times, Value},
    Database, DatabaseKey,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// custom-data keys we own; KeePassXC ignores them but keeps them
const CD_TYPE: &str = "AnotherKeepass.Type";
const CD_KINDS: &str = "AnotherKeepass.Kinds";

pub struct OpenVault {
    path: PathBuf,
    db: Database,
    key: DatabaseKey,
}

impl OpenVault {
    pub fn db(&self) -> &Database {
        &self.db
    }
    pub fn db_mut(&mut self) -> &mut Database {
        &mut self.db
    }
    /// write to disk (temp file + rename, KDBX 4)
    pub fn persist(&mut self) -> R<()> {
        write_db(self)
    }
    /// fresh listing for the UI
    pub fn listing(&self, id: &str) -> VaultDto {
        dto(id, self)
    }
    pub fn trash_entry(&mut self, id: EntryId) -> R<()> {
        let bin = ensure_recycle_bin(&mut self.db);
        let mut e = self.db.entry_mut(id).ok_or("not_found")?;
        e.move_to(bin).map_err(|_| "not_found")?;
        e.times.location_changed = Some(Times::now());
        Ok(())
    }
    #[cfg(test)]
    pub fn new_for_test(path: PathBuf, db: Database) -> Self {
        Self { path, db, key: make_key(Some("pw"), None).unwrap() }
    }
}

/// Current TOTP code of a field (used by Auto-Type's {TOTP}).
pub fn totp_code(e: &keepass::db::Entry, field: &str) -> R<String> {
    Ok(totp_of(e, field)?.value_now().map_err(|_| "totp")?.code)
}

#[derive(Default)]
pub struct Vaults(pub Mutex<HashMap<String, OpenVault>>);

// ---------------------------------------------------------------- DTOs

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct VaultDto {
    id: String,
    name: String,
    path: String,
    root: String,
    recycle_bin: Option<String>,
    /// "KDBX 3.1" files get upgraded to KDBX 4 on the next save
    format: String,
    folders: Vec<FolderDto>,
    items: Vec<ItemDto>,
    /// custom icon id → image bytes (base64), for icons the entries use
    icons: HashMap<String, String>,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct FolderDto {
    id: String,
    name: String,
    parent: Option<String>,
    /// KeeShare kind ("import" | "export" | "sync") when the folder is shared
    share: Option<String>,
}

/// One entry string. `value` is None for protected strings (fetch via reveal).
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct FieldDto {
    name: String,
    value: Option<String>,
    protected: bool,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ItemDto {
    id: String,
    folder: String,
    trashed: bool,
    fields: Vec<FieldDto>,
    tags: Vec<String>,
    custom_data: HashMap<String, String>,
    attachments: Vec<AttachmentDto>,
    modified: Option<String>,
    expires: Option<String>,
    history: Vec<String>,
    /// custom icon id (KeePass custom icon, e.g. a website favicon)
    icon: Option<String>,
}

#[derive(Serialize, Clone)]
pub struct AttachmentDto {
    name: String,
    size: usize,
}

/// Edit payload. A protected field with `value: None` keeps its stored value.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ItemInput {
    id: Option<String>,
    folder: String,
    fields: Vec<FieldDto>,
    tags: Vec<String>,
    custom_data: HashMap<String, String>,
    expires: Option<String>,
    keep_attachments: Vec<String>,
    add_attachments: Vec<NewAttachment>,
}

#[derive(Deserialize)]
pub struct NewAttachment {
    name: String,
    base64: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TotpDto {
    code: String,
    remaining: u64,
    period: u64,
}

// ---------------------------------------------------------------- helpers

type R<T> = Result<T, String>;

fn parse_uuid(s: &str) -> R<Uuid> {
    Uuid::parse_str(s).map_err(|_| "not_found".to_string())
}

fn make_key(password: Option<&str>, keyfile: Option<&str>) -> R<DatabaseKey> {
    let mut key = DatabaseKey::new();
    if let Some(p) = password.filter(|p| !p.is_empty()) {
        key = key.with_password(p);
    }
    if let Some(k) = keyfile.filter(|k| !k.is_empty()) {
        let mut f = fs::File::open(k).map_err(|e| format!("keyfile:{e}"))?;
        key = key.with_keyfile(&mut f).map_err(|e| format!("keyfile:{e}"))?;
    }
    if key.is_empty() {
        return Err("empty_key".into());
    }
    Ok(key)
}

fn fmt_time(t: &NaiveDateTime) -> String {
    t.format("%Y-%m-%dT%H:%M:%S").to_string()
}

/// KDBX 3.1 files (KeePass 2.x before 2.35, KeePassXC with AES-KDF) can be read but only
/// KDBX 4 can be written. Like KeePassXC we upgrade on first save, after a one-time backup.
fn upgrade_to_kdbx4(v: &mut OpenVault) -> R<()> {
    match v.db.config.version {
        DatabaseVersion::KDB4(_) => Ok(()),
        DatabaseVersion::KDB3(_) => {
            let backup = PathBuf::from(format!("{}.kdbx3-backup", v.path.display()));
            if !backup.exists() {
                fs::copy(&v.path, &backup).map_err(|e| format!("io:{e}"))?;
            }
            v.db.config.version = DatabaseVersion::KDB4(1);
            v.db.config.inner_cipher_config = InnerCipherConfig::ChaCha20; // KDF (AES or Argon2) stays as chosen
            Ok(())
        }
        _ => Err("unsupported_format".into()), // KeePass 1.x .kdb
    }
}

/// "Backup before saving" pattern from the settings (None = off), e.g. "{DB_FILENAME}.old.kdbx".
pub static BACKUP_PATTERN: Mutex<Option<String>> = Mutex::new(None);

/// Resolve a KeePassXC-style backup pattern next to the vault: {DB_FILENAME}, {TIME:yyyyMMdd_HHmmss}.
fn backup_target(vault: &Path, pattern: &str) -> Option<PathBuf> {
    let stem = vault.file_stem()?.to_string_lossy();
    let mut name = pattern.replace("{DB_FILENAME}", &stem);
    while let Some(start) = name.find("{TIME:") {
        let end = start + name[start..].find('}')?;
        let fmt = name[start + 6..end]
            .replace("yyyy", "%Y").replace("MM", "%m").replace("dd", "%d")
            .replace("HH", "%H").replace("mm", "%M").replace("ss", "%S");
        name.replace_range(start..=end, &chrono::Local::now().format(&fmt).to_string());
    }
    let name = name.replace("{TIME}", &chrono::Local::now().format("%Y%m%d%H%M%S").to_string());
    let p = Path::new(&name);
    Some(if p.is_absolute() { p.to_path_buf() } else { vault.parent()?.join(p) })
}

/// Write via temp file + rename so a crash never leaves a half-written database.
fn write_db(v: &mut OpenVault) -> R<()> {
    upgrade_to_kdbx4(v)?;
    let pattern = BACKUP_PATTERN.lock().ok().and_then(|p| p.clone());
    if let Some(target) = pattern.and_then(|p| backup_target(&v.path, &p)).filter(|_| v.path.is_file()) {
        if let Err(e) = fs::copy(&v.path, &target) {
            log::warn!("backup before save failed: {e}");
        }
    }
    let mut buf = Vec::new();
    v.db.save(&mut buf, v.key.clone()).map_err(|e| format!("save:{e}"))?;
    let tmp = v.path.with_extension("kdbx.tmp");
    fs::write(&tmp, &buf).map_err(|e| format!("io:{e}"))?;
    fs::rename(&tmp, &v.path).map_err(|e| format!("io:{e}"))?;
    stamp(&v.path);
    crate::keeshare::export_all(&v.db, &v.path);
    Ok(())
}

// ---------------------------------------------------------------- external changes (cloud sync, KeePassXC)

/// Modification time of each vault file as we last read or wrote it.
static STAMPS: Mutex<Option<HashMap<PathBuf, std::time::SystemTime>>> = Mutex::new(None);

fn mtime(p: &Path) -> Option<std::time::SystemTime> {
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
    std::thread::spawn(move || loop {
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
    });
}

fn dto(id: &str, v: &OpenVault) -> VaultDto {
    let db = &v.db;
    let root = db.root().id();
    let bin = db.recycle_bin().map(|g| g.id());
    // walk up the parents: anything below the recycle bin counts as trashed
    let in_bin = |mut g: Option<GroupId>| -> bool {
        while let Some(id) = g {
            if Some(id) == bin {
                return true;
            }
            g = db.group(id).and_then(|x| x.parent().map(|p| p.id()));
        }
        false
    };

    let folders = db
        .iter_all_groups()
        .filter(|g| g.id() != root && !in_bin(Some(g.id())))
        .map(|g| FolderDto {
            id: g.id().to_string(),
            name: g.name.clone(),
            parent: g.parent().filter(|p| p.id() != root).map(|p| p.id().to_string()),
            share: crate::keeshare::group_share(db, g.id()).map(|s| s.kind),
        })
        .collect();

    let items = db
        .iter_all_entries()
        .map(|e| {
            let fields = e
                .fields
                .iter()
                .map(|(name, val)| FieldDto {
                    name: name.clone(),
                    value: if val.is_protected() { None } else { Some(val.get().clone()) },
                    protected: val.is_protected(),
                })
                .collect();
            let custom_data = e
                .custom_data
                .iter()
                .filter(|(k, _)| k.starts_with("AnotherKeepass."))
                .filter_map(|(k, item)| match &item.value {
                    Some(keepass::db::CustomDataValue::String(s)) => Some((k.clone(), s.clone())),
                    _ => None,
                })
                .collect();
            ItemDto {
                icon: e.custom_icon().map(|i| i.id().to_string()),
                id: e.id().to_string(),
                folder: e.parent().id().to_string(),
                trashed: in_bin(Some(e.parent().id())),
                fields,
                tags: e.tags.clone(),
                custom_data,
                attachments: e
                    .attachments_named()
                    .map(|(name, a)| AttachmentDto { name: name.to_string(), size: a.data.get().len() })
                    .collect(),
                modified: e.times.last_modification.as_ref().map(fmt_time),
                expires: (e.times.expires == Some(true)).then(|| fmt_time(&e.times.expiry)),
                history: e
                    .history
                    .as_ref()
                    .map(|h| {
                        h.get_entries()
                            .iter()
                            .map(|old| old.times.last_modification.as_ref().map(fmt_time).unwrap_or_default())
                            .collect()
                    })
                    .unwrap_or_default(),
            }
        })
        .collect();

    VaultDto {
        id: id.to_string(),
        name: db.meta.database_name.clone().unwrap_or_else(|| {
            v.path.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default()
        }),
        path: v.path.to_string_lossy().into_owned(),
        root: root.to_string(),
        recycle_bin: bin.map(|b| b.to_string()),
        format: match db.config.version {
            DatabaseVersion::KDB4(m) => format!("KDBX 4.{m}"),
            DatabaseVersion::KDB3(m) => format!("KDBX 3.{m}"),
            _ => "KDB".into(),
        },
        folders,
        items,
        icons: db.iter_all_custom_icons().map(|i| (i.id().to_string(), B64.encode(&i.data))).collect(),
    }
}

/// Set (Some png) or clear (None) the icons of several entries, one write for all.
/// Same image bytes share one custom icon, like KeePassXC does.
#[tauri::command]
pub fn entry_icons_set(state: tauri::State<'_, Vaults>, vault: String, icons: Vec<(String, Option<String>)>) -> R<VaultDto> {
    mutate(&state, &vault, |db| {
        for (id, data) in icons {
            let eid = EntryId::from(parse_uuid(&id)?);
            let data = data.map(|b| B64.decode(b).map_err(|_| "bad_icon")).transpose()?;
            let existing = data.as_ref().and_then(|d| db.iter_all_custom_icons().find(|i| &i.data == d).map(|i| i.id()));
            let mut e = db.entry_mut(eid).ok_or("not_found")?;
            match (data, existing) {
                (None, _) => e.set_icon_none(),
                (Some(_), Some(icon)) => e.set_icon_custom(icon).map_err(|_| "not_found")?,
                (Some(d), None) => {
                    e.set_icon_custom_new(d);
                }
            }
        }
        Ok(())
    })
}

fn with_vault<T>(state: &Vaults, id: &str, f: impl FnOnce(&mut OpenVault) -> R<T>) -> R<T> {
    let mut map = state.0.lock().map_err(|_| "lock".to_string())?;
    let v = map.get_mut(id).ok_or("vault_closed")?;
    f(v)
}

/// Mutate, persist, and return the fresh listing.
/// KeeShare setting of a folder (None = not shared).
#[tauri::command]
pub fn keeshare_get(state: tauri::State<'_, Vaults>, vault: String, group: String) -> R<Option<crate::keeshare::Share>> {
    with_vault(&state, &vault, |v| Ok(crate::keeshare::group_share(&v.db, crate::keeshare::parse_group(&group)?)))
}

/// Share / unshare a folder. Import and sync pull the container right away (wrong password
/// or missing file for an import-only share is an error); the save afterwards exports.
#[tauri::command]
pub fn keeshare_set(state: tauri::State<'_, Vaults>, vault: String, group: String, share: Option<crate::keeshare::Share>) -> R<VaultDto> {
    with_vault(&state, &vault, |v| {
        let g = crate::keeshare::parse_group(&group)?;
        crate::keeshare::set_group_share(&mut v.db, g, share.as_ref())?;
        if let Some(s) = share.as_ref().filter(|s| s.kind != "export") {
            let path = crate::keeshare::container_path(&v.path, s);
            if path.is_file() || s.kind == "import" {
                crate::keeshare::import_one(&mut v.db, g, &v.path, s)?;
            }
            stamp(&path);
        }
        write_db(v)?;
        Ok(dto(&vault, v))
    })
}

/// Change one entry (no history version), persist, return the listing.
pub fn mutate_entry(state: &Vaults, vault: &str, id: &str, f: impl FnOnce(&mut keepass::db::EntryMut<'_>)) -> R<VaultDto> {
    mutate(state, vault, |db| {
        let mut e = db.entry_mut(EntryId::from(parse_uuid(id)?)).ok_or("not_found")?;
        f(&mut e);
        Ok(())
    })
}

fn mutate(state: &Vaults, id: &str, f: impl FnOnce(&mut Database) -> R<()>) -> R<VaultDto> {
    with_vault(state, id, |v| {
        f(&mut v.db)?;
        write_db(v)?;
        Ok(dto(id, v))
    })
}

fn ensure_recycle_bin(db: &mut Database) -> GroupId {
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

fn trim_history(db: &mut Database, id: EntryId) {
    let max = db.meta.history_max_items.unwrap_or(10).max(0) as usize;
    if let Some(mut e) = db.entry_mut(id) {
        let too_long = e.history.as_ref().is_some_and(|h| h.get_entries().len() > max);
        if too_long {
            // History has no truncate: rebuild it newest-first from the kept versions
            let kept: Vec<_> = e.history.as_ref().map(|h| h.get_entries()[..max].to_vec()).unwrap_or_default();
            let mut h = keepass::db::History::default();
            for old in kept.into_iter().rev() {
                h.add_entry(old);
            }
            e.history = Some(h);
        }
    }
    db.remove_unused_attachments();
}

fn parse_expiry(s: &str) -> Option<NaiveDateTime> {
    NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S")
        .ok()
        .or_else(|| NaiveDate::parse_from_str(s, "%Y-%m-%d").ok().and_then(|d| d.and_hms_opt(23, 59, 59)))
}

// ---------------------------------------------------------------- commands: vaults

/// Strong defaults for new files (the crate default uses only 1 MiB Argon2 memory).
pub(crate) fn new_config() -> DatabaseConfig {
    let mut c = DatabaseConfig::default();
    c.kdf_config = KdfConfig::Argon2id {
        iterations: 10,
        memory: 64 * 1024 * 1024,
        parallelism: 2,
        version: argon2::Version::Version13,
    };
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
    let mut v = OpenVault { path: PathBuf::from(&path), db, key };
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
) -> R<VaultDto> {
    let key = make_key(password.as_deref(), keyfile.as_deref())?;
    open_with(app, state, path, key).await
}

async fn open_with(app: tauri::AppHandle, state: tauri::State<'_, Vaults>, path: String, key: DatabaseKey) -> R<VaultDto> {
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
    let mut v = OpenVault { path: PathBuf::from(&path), db, key };
    if shared {
        write_db(&mut v)?; // KeeShare import changed the folder
    }
    stamp(&v.path);
    let d = dto(&path, &v);
    state.0.lock().map_err(|_| "lock")?.insert(path.clone(), v);
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
    paths.iter().map(|p| Path::new(p).is_file()).collect()
}

#[tauri::command]
pub fn vault_close(state: tauri::State<'_, Vaults>, id: String) -> R<()> {
    state.0.lock().map_err(|_| "lock")?.remove(&id); // drop zeroizes key + protected values
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
static QUICK_KEYS: Mutex<Option<HashMap<String, DatabaseKey>>> = Mutex::new(None);

/// Lock = drop every open vault; with quick unlock on, keep the keys for Windows Hello.
pub fn lock_vaults(map: &mut HashMap<String, OpenVault>) {
    if let Ok(mut q) = QUICK_KEYS.lock() {
        if QUICK_UNLOCK.load(std::sync::atomic::Ordering::Relaxed) {
            let keys = q.get_or_insert_with(HashMap::new);
            for (id, v) in map.iter() {
                keys.insert(id.clone(), v.key.clone());
            }
        } else {
            *q = None;
        }
    }
    for id in map.keys() {
        crate::ssh::on_lock(id);
    }
    map.clear();
}

/// Turning the option off forgets every kept key at once.
pub fn quick_unlock_enable(on: bool) {
    QUICK_UNLOCK.store(on, std::sync::atomic::Ordering::Relaxed);
    if !on {
        if let Ok(mut q) = QUICK_KEYS.lock() {
            *q = None;
        }
    }
}

fn quick_key(path: &str) -> Option<DatabaseKey> {
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
    open_with(app, state, path, key).await
}

#[tauri::command]
pub fn vault_change_key(
    state: tauri::State<'_, Vaults>,
    id: String,
    password: Option<String>,
    keyfile: Option<String>,
) -> R<()> {
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

// ---------------------------------------------------------------- commands: entries

/// Writes the edit payload into an entry (history is handled by the caller).
fn apply_item(e: &mut keepass::db::EntryMut<'_>, item: &ItemInput, is_new: bool) -> R<()> {
    let old: HashMap<String, Value<String>> = std::mem::take(&mut e.fields);
    for f in &item.fields {
        let value = match (&f.value, old.get(&f.name)) {
            (Some(v), _) => v.clone(),
            (None, Some(prev)) => prev.get().clone(), // unchanged secret
            (None, None) => String::new(),
        };
        if f.protected {
            e.set_protected(f.name.clone(), value);
        } else {
            e.set_unprotected(f.name.clone(), value);
        }
    }
    if !e.fields.contains_key(fields::TITLE) {
        e.set_unprotected(fields::TITLE, "");
    }
    e.tags = item.tags.clone();
    e.custom_data.retain(|k, _| !k.starts_with("AnotherKeepass."));
    for (k, v) in item.custom_data.iter().filter(|(k, _)| *k == CD_TYPE || *k == CD_KINDS) {
        e.custom_data.insert(
            k.clone(),
            keepass::db::CustomDataItem {
                value: Some(keepass::db::CustomDataValue::String(v.clone())),
                last_modification_time: Some(Times::now()),
            },
        );
    }
    match item.expires.as_deref().and_then(parse_expiry) {
        Some(t) => {
            e.times.expires = Some(true);
            e.times.expiry = t;
        }
        None => e.times.expires = Some(false),
    }
    let names: Vec<String> = e.as_ref().attachments_named().map(|(n, _)| n.to_string()).collect();
    for n in names.iter().filter(|n| !item.keep_attachments.contains(n)) {
        e.remove_attachment_by_name(n);
    }
    for a in &item.add_attachments {
        let data = B64.decode(&a.base64).map_err(|_| "attachment")?;
        e.add_attachment(a.name.clone(), Value::protected(data));
    }
    let now = Times::now();
    e.times.last_modification = Some(now);
    e.times.last_access = Some(now);
    if is_new {
        e.times.creation = Some(now);
    }
    Ok(())
}

/// Create or update an entry; returns its id.
fn save_item(db: &mut Database, item: &ItemInput) -> R<String> {
    let folder = GroupId::from_uuid(parse_uuid(&item.folder)?);
    if db.group(folder).is_none() {
        return Err("not_found".into());
    }
    let (id, is_new) = match &item.id {
        Some(id) => (EntryId::from(parse_uuid(id)?), false),
        None => (db.group_mut(folder).ok_or("not_found")?.add_entry().id(), true),
    };
    let mut e = db.entry_mut(id).ok_or("not_found")?;
    if e.as_ref().parent().id() != folder {
        e.move_to(folder).map_err(|_| "not_found")?;
        e.times.location_changed = Some(Times::now());
    }
    if is_new {
        apply_item(&mut e, item, true)?;
    } else {
        // tracking pushes the previous version into the entry's history on drop
        let mut t = e.track_changes();
        apply_item(&mut t.as_mut(), item, false)?;
    }
    trim_history(db, id);
    Ok(id.to_string())
}

#[tauri::command]
pub fn entry_save(state: tauri::State<'_, Vaults>, vault: String, item: ItemInput) -> R<(String, VaultDto)> {
    let mut saved = String::new();
    let d = mutate(&state, &vault, |db| {
        saved = save_item(db, &item)?;
        Ok(())
    })?;
    Ok((saved, d))
}

#[derive(Deserialize)]
pub struct ImportInput {
    /// folder names below the import target, created when missing (e.g. ["Work", "Mail"])
    path: Vec<String>,
    item: ItemInput,
}

/// Find or create the folder path below parent.
fn ensure_path(db: &mut Database, parent: GroupId, path: &[String]) -> R<GroupId> {
    let mut cur = parent;
    for name in path.iter().map(|n| n.trim()).filter(|n| !n.is_empty()) {
        let found = db.iter_all_groups().find(|g| g.name == name && g.parent().map(|p| p.id()) == Some(cur)).map(|g| g.id());
        cur = match found {
            Some(id) => id,
            None => {
                let mut parent = db.group_mut(cur).ok_or("not_found")?;
                let mut g = parent.add_group();
                g.name = name.to_string();
                g.id()
            }
        };
    }
    Ok(cur)
}

/// Many new entries in one go: a single write instead of one (with key derivation) per entry.
fn import_items(db: &mut Database, parent: Option<&str>, items: Vec<ImportInput>) -> R<usize> {
    let parent = match parent {
        Some(p) => GroupId::from_uuid(parse_uuid(p)?),
        None => db.root().id(),
    };
    let n = items.len();
    for ImportInput { path, mut item } in items {
        item.id = None;
        item.folder = ensure_path(db, parent, &path)?.to_string();
        save_item(db, &item)?;
    }
    Ok(n)
}

#[tauri::command]
pub fn entry_import(state: tauri::State<'_, Vaults>, vault: String, parent: Option<String>, items: Vec<ImportInput>) -> R<(usize, VaultDto)> {
    let mut n = 0;
    let d = mutate(&state, &vault, |db| {
        n = import_items(db, parent.as_deref(), items)?;
        Ok(())
    })?;
    log::info!("imported {n} entries");
    Ok((n, d))
}

/// Protected values of one entry, for edit mode or reveal.
#[tauri::command]
pub fn entry_secrets(state: tauri::State<'_, Vaults>, vault: String, id: String) -> R<HashMap<String, String>> {
    with_vault(&state, &vault, |v| {
        let e = v.db.entry(EntryId::from(parse_uuid(&id)?)).ok_or("not_found")?;
        Ok(e.fields
            .iter()
            .filter(|(_, val)| val.is_protected())
            .map(|(k, val)| (k.clone(), val.get().clone()))
            .collect())
    })
}

/// TOTP for a field. Accepts otpauth:// URIs (KeePassXC) and, for the `otp` field,
/// KeePass 2.47+ native fields (TimeOtp-Secret-Base32, TimeOtp-Period, TimeOtp-Length).
fn totp_of(e: &keepass::db::Entry, field: &str) -> R<keepass::db::TOTP> {
    let raw = match e.get(field) {
        Some(v) if !v.is_empty() => v.to_string(),
        _ if field == fields::OTP => {
            let secret = e.get("TimeOtp-Secret-Base32").ok_or("totp")?;
            format!(
                "otpauth://totp/x?secret={}&period={}&digits={}",
                secret.replace(' ', ""),
                e.get("TimeOtp-Period").unwrap_or("30"),
                e.get("TimeOtp-Length").unwrap_or("6"),
            )
        }
        _ => return Err("totp".into()),
    };
    raw.parse().or_else(|_| padded_secret(&raw).parse()).map_err(|_| "totp".into())
}

/// Authenticator apps emit unpadded base32; the crate's decoder wants '=' padding.
fn padded_secret(uri: &str) -> String {
    let Some(start) = uri.find("secret=").map(|i| i + 7) else { return uri.to_string() };
    let end = uri[start..].find('&').map_or(uri.len(), |i| start + i);
    let secret = uri[start..end].trim_end_matches('=').to_uppercase();
    let pad = (8 - secret.len() % 8) % 8;
    format!("{}{}{}{}", &uri[..start], secret, "=".repeat(pad), &uri[end..])
}

#[tauri::command]
pub fn entry_totp(state: tauri::State<'_, Vaults>, vault: String, id: String, field: String) -> R<TotpDto> {
    with_vault(&state, &vault, |v| {
        let e = v.db.entry(EntryId::from(parse_uuid(&id)?)).ok_or("not_found")?;
        let code = totp_of(&e, &field)?.value_now().map_err(|_| "totp")?;
        Ok(TotpDto { code: code.code, remaining: code.valid_for.as_secs(), period: code.period.as_secs() })
    })
}

/// Copy a field (or its current TOTP code) without the value passing through the UI.
/// Clears after `clear_after` seconds, but only if the clipboard still holds our value.
#[tauri::command]
pub fn entry_copy(
    state: tauri::State<'_, Vaults>,
    vault: String,
    id: String,
    field: String,
    as_totp: bool,
    clear_after: Option<u64>,
) -> R<()> {
    let value = with_vault(&state, &vault, |v| {
        let e = v.db.entry(EntryId::from(parse_uuid(&id)?)).ok_or("not_found")?;
        if as_totp {
            return Ok(totp_of(&e, &field)?.value_now().map_err(|_| "totp")?.code);
        }
        Ok(e.get(&field).unwrap_or_default().to_string())
    })?;
    crate::clipboard::copy_secret(value, clear_after)
}

/// Everything that makes up an entry's content, detached from its database.
pub(crate) struct EntryCopy {
    fields: HashMap<String, Value<String>>,
    tags: Vec<String>,
    custom_data: HashMap<String, keepass::db::CustomDataItem>,
    pub(crate) times: Times,
    autotype: Option<keepass::db::AutoType>,
    attachments: Vec<(String, Value<Vec<u8>>)>,
}

pub(crate) fn copy_entry(db: &Database, id: EntryId) -> R<EntryCopy> {
    let e = db.entry(id).ok_or("not_found")?;
    Ok(EntryCopy {
        fields: e.fields.clone(),
        tags: e.tags.clone(),
        custom_data: e.custom_data.clone(),
        times: e.times.clone(),
        autotype: e.autotype.clone(),
        attachments: e.attachments_named().map(|(n, a)| (n.to_string(), a.data.clone())).collect(),
    })
}

/// Replace an entry's content with a copy (KeeShare import); the previous state goes to history.
pub(crate) fn overwrite_entry(db: &mut Database, id: EntryId, c: EntryCopy) -> R<()> {
    let mut e = db.entry_mut(id).ok_or("not_found")?;
    let mut t = e.track_changes();
    let mut m = t.as_mut();
    m.fields = c.fields;
    m.tags = c.tags;
    m.custom_data = c.custom_data;
    m.autotype = c.autotype;
    let names: Vec<String> = m.as_ref().attachments_named().map(|(n, _)| n.to_string()).collect();
    for n in names {
        m.remove_attachment_by_name(&n);
    }
    for (name, data) in c.attachments {
        m.add_attachment(name, data);
    }
    drop(t);
    if let Some(mut e) = db.entry_mut(id) {
        e.times = c.times;
    }
    Ok(())
}

pub(crate) fn paste_entry(db: &mut Database, group: GroupId, id: Option<EntryId>, c: EntryCopy) -> R<EntryId> {
    // keep the UUID when possible (KeePass treats it as the entry's identity)
    let keep_id = id.filter(|i| db.entry(*i).is_none());
    let mut g = db.group_mut(group).ok_or("not_found")?;
    let mut e = match keep_id {
        Some(id) => g.add_entry_with_id(id).map_err(|_| "duplicate")?,
        None => g.add_entry(),
    };
    e.fields = c.fields;
    e.tags = c.tags;
    e.custom_data = c.custom_data;
    e.times = c.times;
    e.autotype = c.autotype;
    for (name, data) in c.attachments {
        e.add_attachment(name, data);
    }
    Ok(e.id())
}

fn group_or_root(db: &Database, folder: Option<&str>) -> R<GroupId> {
    match folder {
        Some(f) => Ok(GroupId::from_uuid(parse_uuid(f)?)),
        None => Ok(db.root().id()),
    }
}

#[tauri::command]
pub fn entry_move(state: tauri::State<'_, Vaults>, vault: String, id: String, folder: Option<String>) -> R<VaultDto> {
    mutate(&state, &vault, |db| {
        let target = group_or_root(db, folder.as_deref())?;
        let mut e = db.entry_mut(EntryId::from(parse_uuid(&id)?)).ok_or("not_found")?;
        e.move_to(target).map_err(|_| "not_found")?;
        e.times.location_changed = Some(Times::now());
        Ok(())
    })
}

/// Move an entry into another open vault. The target is written first, so a failure
/// never loses the entry. History stays behind (it belongs to the source file).
#[tauri::command]
pub fn entry_move_to_vault(
    state: tauri::State<'_, Vaults>,
    src: String,
    id: String,
    dst: String,
    folder: Option<String>,
) -> R<(VaultDto, VaultDto)> {
    let mut map = state.0.lock().map_err(|_| "lock".to_string())?;
    move_to_vault(&mut map, &src, EntryId::from(parse_uuid(&id)?), &dst, folder.as_deref())?;
    Ok((dto(&src, &map[&src]), dto(&dst, &map[&dst])))
}

fn move_to_vault(map: &mut HashMap<String, OpenVault>, src: &str, eid: EntryId, dst: &str, folder: Option<&str>) -> R<()> {
    let mut c = copy_entry(&map.get(src).ok_or("vault_closed")?.db, eid)?;
    c.times.location_changed = Some(Times::now());
    let d = map.get_mut(dst).ok_or("vault_closed")?;
    let target = group_or_root(&d.db, folder)?;
    paste_entry(&mut d.db, target, Some(eid), c)?;
    write_db(d)?;
    let s = map.get_mut(src).ok_or("vault_closed")?;
    s.db.entry_mut(eid).ok_or("not_found")?.remove();
    s.db.deleted_objects.insert(eid.uuid(), Some(Times::now()));
    write_db(s)
}

#[tauri::command]
pub fn entry_duplicate(state: tauri::State<'_, Vaults>, vault: String, id: String, suffix: String) -> R<(String, VaultDto)> {
    let mut new_id = String::new();
    let d = mutate(&state, &vault, |db| {
        new_id = duplicate_entry(db, EntryId::from(parse_uuid(&id)?), &suffix)?.to_string();
        Ok(())
    })?;
    Ok((new_id, d))
}

fn duplicate_entry(db: &mut Database, eid: EntryId, suffix: &str) -> R<EntryId> {
    let parent = db.entry(eid).ok_or("not_found")?.parent().id();
    let mut c = copy_entry(db, eid)?;
    let title = c.fields.get(fields::TITLE).map(|t| t.get().clone()).unwrap_or_default();
    c.fields.insert(fields::TITLE.into(), Value::unprotected(format!("{title}{suffix}")));
    let now = Times::now();
    c.times.creation = Some(now);
    c.times.last_modification = Some(now);
    paste_entry(db, parent, None, c)
}

#[tauri::command]
pub fn entry_trash(state: tauri::State<'_, Vaults>, vault: String, id: String) -> R<VaultDto> {
    mutate(&state, &vault, |db| {
        let bin = ensure_recycle_bin(db);
        let mut e = db.entry_mut(EntryId::from(parse_uuid(&id)?)).ok_or("not_found")?;
        e.move_to(bin).map_err(|_| "not_found")?;
        e.times.location_changed = Some(Times::now());
        Ok(())
    })
}

#[tauri::command]
pub fn entry_restore(state: tauri::State<'_, Vaults>, vault: String, id: String) -> R<VaultDto> {
    mutate(&state, &vault, |db| {
        let eid = EntryId::from(parse_uuid(&id)?);
        let root = db.root().id();
        let bin = db.recycle_bin().map(|g| g.id());
        let target = db
            .entry(eid)
            .ok_or("not_found")?
            .previous_parent()
            .map(|g| g.id())
            .filter(|g| Some(*g) != bin)
            .unwrap_or(root);
        let mut e = db.entry_mut(eid).ok_or("not_found")?;
        e.move_to(target).map_err(|_| "not_found")?;
        e.times.location_changed = Some(Times::now());
        Ok(())
    })
}

#[tauri::command]
pub fn entry_delete(state: tauri::State<'_, Vaults>, vault: String, id: String) -> R<VaultDto> {
    mutate(&state, &vault, |db| {
        let eid = EntryId::from(parse_uuid(&id)?);
        db.entry_mut(eid).ok_or("not_found")?.remove();
        db.deleted_objects.insert(eid.uuid(), Some(Times::now()));
        Ok(())
    })
}

#[tauri::command]
pub fn trash_empty(state: tauri::State<'_, Vaults>, vault: String) -> R<VaultDto> {
    mutate(&state, &vault, |db| {
        let Some(bin) = db.recycle_bin().map(|g| g.id()) else { return Ok(()) };
        let entries: Vec<EntryId> = db.group(bin).ok_or("not_found")?.entry_ids().collect();
        for id in entries {
            if let Some(e) = db.entry_mut(id) {
                e.remove();
            }
            db.deleted_objects.insert(id.uuid(), Some(Times::now()));
        }
        let groups: Vec<GroupId> = db.group(bin).ok_or("not_found")?.group_ids().collect();
        for id in groups {
            if let Some(g) = db.group_mut(id) {
                g.remove();
            }
            db.deleted_objects.insert(id.uuid(), Some(Times::now()));
        }
        Ok(())
    })
}

#[tauri::command]
pub fn entry_history_restore(
    state: tauri::State<'_, Vaults>,
    vault: String,
    id: String,
    index: usize,
) -> R<VaultDto> {
    mutate(&state, &vault, |db| {
        let eid = EntryId::from(parse_uuid(&id)?);
        let old = db
            .entry(eid)
            .ok_or("not_found")?
            .history
            .as_ref()
            .and_then(|h| h.get_entries().get(index).cloned())
            .ok_or("not_found")?;
        {
            let mut e = db.entry_mut(eid).ok_or("not_found")?;
            let mut t = e.track_changes();
            let mut e = t.as_mut();
            e.fields = old.fields.clone();
            e.tags = old.tags.clone();
            e.custom_data = old.custom_data.clone();
            e.times.last_modification = Some(Times::now());
        }
        trim_history(db, eid);
        Ok(())
    })
}

#[tauri::command]
pub fn attachment_save(
    state: tauri::State<'_, Vaults>,
    vault: String,
    id: String,
    name: String,
    dest: String,
) -> R<()> {
    with_vault(&state, &vault, |v| {
        let e = v.db.entry(EntryId::from(parse_uuid(&id)?)).ok_or("not_found")?;
        let a = e.attachment_by_name(&name).ok_or("not_found")?;
        fs::write(Path::new(&dest), a.data.get()).map_err(|e| format!("io:{e}"))
    })
}

// ---------------------------------------------------------------- commands: folders (groups)

#[tauri::command]
pub fn folder_create(state: tauri::State<'_, Vaults>, vault: String, parent: Option<String>, name: String) -> R<VaultDto> {
    mutate(&state, &vault, |db| {
        let parent = match parent {
            Some(p) => GroupId::from_uuid(parse_uuid(&p)?),
            None => db.root().id(),
        };
        db.group_mut(parent).ok_or("not_found")?.add_group().name = name;
        Ok(())
    })
}

#[tauri::command]
pub fn folder_rename(state: tauri::State<'_, Vaults>, vault: String, id: String, name: String) -> R<VaultDto> {
    mutate(&state, &vault, |db| {
        let mut g = db.group_mut(GroupId::from_uuid(parse_uuid(&id)?)).ok_or("not_found")?;
        g.name = name;
        g.times.last_modification = Some(Times::now());
        Ok(())
    })
}

/// KeePass semantics: deleting a folder moves it (with content) to the recycle bin.
#[tauri::command]
pub fn folder_trash(state: tauri::State<'_, Vaults>, vault: String, id: String) -> R<VaultDto> {
    mutate(&state, &vault, |db| {
        let bin = ensure_recycle_bin(db);
        let mut g = db.group_mut(GroupId::from_uuid(parse_uuid(&id)?)).ok_or("not_found")?;
        g.move_to(bin).map_err(|_| "not_found")?;
        Ok(())
    })
}

// ---------------------------------------------------------------- tests

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("akp-test-{}-{name}.kdbx", Uuid::new_v4()))
    }

    #[test]
    fn roundtrip_create_edit_trash_reopen() {
        let state = Vaults::default();
        let path = temp_path("rt");
        let p = path.to_string_lossy().to_string();
        let key = make_key(Some("pw"), None).unwrap();

        // create (direct, no tauri State needed)
        let mut db = Database::with_config(new_config());
        db.meta.database_name = Some("Test".into());
        ensure_recycle_bin(&mut db);
        let mut v = OpenVault { path: path.clone(), db, key: key.clone() };
        write_db(&mut v).unwrap();
        let root = v.db.root().id().to_string();
        state.0.lock().unwrap().insert(p.clone(), v);

        // add folder + entry with protected field, custom data, attachment, expiry
        let mut folder_id = String::new();
        with_vault(&state, &p, |v| {
            let id = v.db.root_mut().add_group().edit(|g| g.name = "Work".into()).id();
            folder_id = id.to_string();
            write_db(v)
        })
        .unwrap();
        let _ = root;
        let input = ItemInput {
            id: None,
            folder: folder_id.clone(),
            fields: vec![
                FieldDto { name: "Title".into(), value: Some("Mail".into()), protected: false },
                FieldDto { name: "Password".into(), value: Some("s3cret".into()), protected: true },
                FieldDto { name: "otp".into(), value: Some("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP".into()), protected: true },
            ],
            tags: vec!["pinned".into()],
            custom_data: HashMap::from([(CD_TYPE.into(), "login".into())]),
            expires: Some("2030-01-31".into()),
            keep_attachments: vec![],
            add_attachments: vec![NewAttachment { name: "a.txt".into(), base64: B64.encode(b"hello") }],
        };
        // emulate entry_save without tauri State
        let saved = save_for_test(&state, &p, input);

        // edit keeps secret when value is None, creates history
        let edit = ItemInput {
            id: Some(saved.clone()),
            folder: folder_id.clone(),
            fields: vec![
                FieldDto { name: "Title".into(), value: Some("Mail 2".into()), protected: false },
                FieldDto { name: "Password".into(), value: None, protected: true },
                FieldDto { name: "otp".into(), value: None, protected: true },
            ],
            tags: vec![],
            custom_data: HashMap::from([(CD_TYPE.into(), "login".into())]),
            expires: None,
            keep_attachments: vec!["a.txt".into()],
            add_attachments: vec![],
        };
        save_for_test(&state, &p, edit);

        // reopen from disk with the key
        let mut f = fs::File::open(&path).unwrap();
        let db = Database::open(&mut f, key.clone()).unwrap();
        let e = db.entry(EntryId::from(Uuid::parse_str(&saved).unwrap())).unwrap();
        assert_eq!(e.get_title(), Some("Mail 2"));
        assert_eq!(e.get_password(), Some("s3cret"));
        assert!(e.fields["Password"].is_protected());
        assert_eq!(e.history.as_ref().unwrap().get_entries().len(), 1);
        assert_eq!(e.attachment_by_name("a.txt").unwrap().data.get(), b"hello");
        assert!(e.get_otp().is_ok());
        assert_eq!(e.parent().name, "Work");
        assert!(matches!(
            e.custom_data.get(CD_TYPE).and_then(|c| c.value.clone()),
            Some(keepass::db::CustomDataValue::String(s)) if s == "login"
        ));

        // wrong key is rejected
        let mut f = fs::File::open(&path).unwrap();
        assert!(Database::open(&mut f, make_key(Some("nope"), None).unwrap()).is_err());

        // trash + restore + delete
        with_vault(&state, &p, |v| {
            let bin = ensure_recycle_bin(&mut v.db);
            v.db.entry_mut(EntryId::from(Uuid::parse_str(&saved).unwrap())).unwrap().move_to(bin).unwrap();
            assert!(dto(&p, v).items.iter().any(|i| i.trashed));
            Ok(())
        })
        .unwrap();

        // new vault config is Argon2id with real memory cost
        assert!(matches!(new_config().kdf_config, KdfConfig::Argon2id { memory, .. } if memory >= 64 * 1024 * 1024));
        let _ = fs::remove_file(path);
    }

    fn open_temp(state: &Vaults, name: &str) -> (String, String) {
        let path = temp_path(name);
        let p = path.to_string_lossy().to_string();
        let mut db = Database::with_config(new_config());
        ensure_recycle_bin(&mut db);
        let root = db.root().id().to_string();
        let mut v = OpenVault { path, db, key: make_key(Some("pw"), None).unwrap() };
        write_db(&mut v).unwrap();
        state.0.lock().unwrap().insert(p.clone(), v);
        (p, root)
    }

    fn login(folder: &str, title: &str) -> ItemInput {
        ItemInput {
            id: None,
            folder: folder.into(),
            fields: vec![
                FieldDto { name: "Title".into(), value: Some(title.into()), protected: false },
                FieldDto { name: "Password".into(), value: Some("pw-".to_string() + title), protected: true },
            ],
            tags: vec!["work".into()],
            custom_data: HashMap::new(),
            expires: None,
            keep_attachments: vec![],
            add_attachments: vec![NewAttachment { name: "f.txt".into(), base64: B64.encode(b"data") }],
        }
    }

    #[test]
    fn import_creates_folders_once() {
        let mut db = Database::new();
        let item = |title: &str| ItemInput {
            id: Some("ignored".into()), folder: String::new(),
            fields: vec![FieldDto { name: "Title".into(), value: Some(title.into()), protected: false }],
            tags: vec![], custom_data: HashMap::new(), expires: None, keep_attachments: vec![], add_attachments: vec![],
        };
        let items = vec![
            ImportInput { path: vec!["Work".into(), "Mail".into()], item: item("a") },
            ImportInput { path: vec!["Work".into(), "Mail".into()], item: item("b") },
            ImportInput { path: vec![], item: item("c") },
        ];
        assert_eq!(import_items(&mut db, None, items).unwrap(), 3);
        assert_eq!(db.iter_all_groups().filter(|g| g.name == "Mail").count(), 1);
        assert_eq!(db.iter_all_entries().count(), 3);
    }

    #[test]
    fn backup_pattern() {
        let vault = Path::new("C:/vaults/work.kdbx");
        assert_eq!(backup_target(vault, "{DB_FILENAME}.old.kdbx").unwrap(), Path::new("C:/vaults/work.old.kdbx"));
        let t = backup_target(vault, "backup/{DB_FILENAME}_{TIME:yyyyMMdd}.kdbx").unwrap();
        let name = t.file_name().unwrap().to_string_lossy().to_string();
        assert!(name.starts_with("work_20") && name.len() == "work_20261020.kdbx".len(), "{name}");
    }

    #[test]
    fn totp_variants() {
        let mut db = Database::new();
        let mut root = db.root_mut();
        let mut e = root.add_entry();
        // unpadded secret (Google Authenticator style): 10 chars needs padding to 16
        e.set_protected("otp", "otpauth://totp/x?secret=jbswy3dpeh&digits=6");
        e.set_protected("TimeOtp-Secret-Base32", "JBSWY3DPEHPK3PXP");
        let id = e.id();
        let e = db.entry(id).unwrap();
        assert!(totp_of(&e, "otp").is_ok());
        assert_eq!(padded_secret("otpauth://totp/x?secret=abc&p=1"), "otpauth://totp/x?secret=ABC=====&p=1");
        // KeePass 2 native fields when no otp string exists
        let mut db = Database::new();
        let mut root = db.root_mut();
        let mut e = root.add_entry();
        e.set_protected("TimeOtp-Secret-Base32", "JBSWY3DPEHPK3PXP");
        let id = e.id();
        let e = db.entry(id).unwrap();
        assert_eq!(totp_of(&e, "otp").unwrap().value_at(59).code.len(), 6);
        assert!(totp_of(&e, "Custom").is_err());
    }

    #[test]
    fn move_duplicate_and_cross_vault() {
        let state = Vaults::default();
        let (a, a_root) = open_temp(&state, "a");
        let (b, b_root) = open_temp(&state, "b");
        let id = save_for_test(&state, &a, login(&a_root, "Mail"));
        let eid = EntryId::from(Uuid::parse_str(&id).unwrap());

        // duplicate keeps secrets + attachment, new id, suffixed title
        let dup = mutate(&state, &a, |db| duplicate_entry(db, eid, " (copy)").map(|_| ())).unwrap();
        assert_eq!(dup.items.len(), 2);
        assert!(dup.items.iter().any(|i| i.fields.iter().any(|f| f.value.as_deref() == Some("Mail (copy)"))));

        // move into a folder of the same vault
        let folder = with_vault(&state, &a, |v| Ok(v.db.root_mut().add_group().edit(|g| g.name = "F".into()).id().to_string())).unwrap();
        mutate(&state, &a, |db| {
            db.entry_mut(eid).unwrap().move_to(GroupId::from_uuid(Uuid::parse_str(&folder).unwrap())).unwrap();
            Ok(())
        })
        .unwrap();

        move_to_vault(&mut state.0.lock().unwrap(), &a, eid, &b, Some(&b_root)).unwrap();
        // reopen b from disk: same UUID, secret and attachment arrived
        let pb = PathBuf::from(&b);
        let db = Database::open(&mut fs::File::open(&pb).unwrap(), make_key(Some("pw"), None).unwrap()).unwrap();
        let e = db.entry(eid).expect("moved entry keeps its UUID");
        assert_eq!(e.get_password(), Some("pw-Mail"));
        assert!(e.fields["Password"].is_protected());
        assert_eq!(e.attachment_by_name("f.txt").unwrap().data.get(), b"data");
        assert_eq!(e.tags, vec!["work".to_string()]);
        let pa = PathBuf::from(&a);
        let db = Database::open(&mut fs::File::open(&pa).unwrap(), make_key(Some("pw"), None).unwrap()).unwrap();
        assert!(db.entry(eid).is_none());
        assert_eq!(db.iter_all_entries().count(), 1); // the duplicate stays in a
        let _ = (fs::remove_file(pa), fs::remove_file(pb));
    }

    // Compatibility checks against KeePassXC (run by hand, see README):
    //   AKP_COMPAT_DIR=<dir> cargo test --lib compat -- --ignored
    fn compat_dir() -> PathBuf {
        PathBuf::from(std::env::var("AKP_COMPAT_DIR").expect("set AKP_COMPAT_DIR"))
    }

    #[test]
    #[ignore]
    fn compat_write_for_keepassxc() {
        let path = compat_dir().join("ours.kdbx");
        let p = path.to_string_lossy().to_string();
        let state = Vaults::default();
        let mut db = Database::with_config(new_config());
        db.meta.database_name = Some("Ours".into());
        ensure_recycle_bin(&mut db);
        let work = db.root_mut().add_group().edit(|g| g.name = "Work".into()).id().to_string();
        let mut v = OpenVault { path, db, key: make_key(Some("compat-pw"), None).unwrap() };
        write_db(&mut v).unwrap();
        state.0.lock().unwrap().insert(p.clone(), v);
        save_for_test(&state, &p, ItemInput {
            id: None,
            folder: work,
            fields: vec![
                FieldDto { name: "Title".into(), value: Some("Mail".into()), protected: false },
                FieldDto { name: "UserName".into(), value: Some("bob".into()), protected: false },
                FieldDto { name: "Password".into(), value: Some("s3cret-Pa55".into()), protected: true },
                FieldDto { name: "URL".into(), value: Some("https://example.org".into()), protected: false },
                FieldDto { name: "otp".into(), value: Some("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&period=30&digits=6".into()), protected: true },
                FieldDto { name: "Card number".into(), value: Some("4111".into()), protected: true },
            ],
            tags: vec!["pinned".into()],
            custom_data: HashMap::from([(CD_TYPE.into(), "login".into())]),
            expires: None,
            keep_attachments: vec![],
            add_attachments: vec![NewAttachment { name: "hello.txt".into(), base64: B64.encode(b"hello from AnotherKeepass") }],
        });
    }

    #[test]
    #[ignore]
    fn compat_edit_keepassxc_file() {
        let path = compat_dir().join("theirs.kdbx");
        let p = path.to_string_lossy().to_string();
        let key = make_key(Some("compat-pw"), None).unwrap();
        let db = Database::open(&mut fs::File::open(&path).unwrap(), key.clone()).unwrap();
        let e = db.iter_all_entries().find(|e| e.get_title() == Some("Mail")).expect("entry from KeePassXC");
        assert_eq!(e.get_username(), Some("alice"));
        let (id, folder) = (e.id().to_string(), e.parent().id().to_string());
        let state = Vaults::default();
        state.0.lock().unwrap().insert(p.clone(), OpenVault { path, db, key });
        save_for_test(&state, &p, ItemInput {
            id: Some(id),
            folder,
            fields: vec![
                FieldDto { name: "Title".into(), value: Some("Mail edited".into()), protected: false },
                FieldDto { name: "UserName".into(), value: Some("alice".into()), protected: false },
                FieldDto { name: "Password".into(), value: None, protected: true },
            ],
            tags: vec![],
            custom_data: HashMap::new(),
            expires: Some("2031-12-31".into()),
            keep_attachments: vec![],
            add_attachments: vec![],
        });
    }

    fn save_for_test(state: &Vaults, vault: &str, item: ItemInput) -> String {
        let mut out = String::new();
        mutate(state, vault, |db| {
            out = save_item(db, &item)?;
            Ok(())
        })
        .unwrap();
        out
    }
}
