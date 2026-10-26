//! KDBX vault backend. Every open .kdbx lives here; the UI only ever gets entry
//! metadata. Protected values (passwords, hidden fields, OTP secrets) leave this
//! process only on explicit reveal/edit, and copies go straight to the clipboard.

use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    sync::Mutex,
};

use base64::{Engine, engine::general_purpose::STANDARD as B64};
use chrono::{NaiveDate, NaiveDateTime};
use keepass::{
    Database, DatabaseKey,
    config::{DatabaseConfig, DatabaseVersion, InnerCipherConfig, KdfConfig},
    db::{EntryId, GroupId, Times, Value, fields},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// custom-data keys we own; KeePassXC ignores them but keeps them
mod entries;
mod open;
mod settings;
#[cfg(test)]
mod tests;
mod watch;

pub use entries::*;
pub use open::*;
pub use settings::*;
pub use watch::*;

const CD_TYPE: &str = "AnotherKeepass.Type";
const CD_KINDS: &str = "AnotherKeepass.Kinds";

pub struct OpenVault {
    path: PathBuf,
    db: Database,
    key: DatabaseKey,
    /// Vaultwarden account (in-memory database, saved by uploading changes)
    pub(crate) remote: Option<Box<crate::bitwarden::Remote>>,
}

impl OpenVault {
    pub fn path(&self) -> &Path {
        &self.path
    }
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
        Self { path, db, key: make_key(Some("pw"), None).unwrap(), remote: None }
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
    /// key derivation is weaker than today's defaults (old AES-KDF files, tiny Argon2 memory)
    weak_kdf: bool,
    /// Vaultwarden account: Some(online)
    remote: Option<bool>,
    /// .kdbx linked to this account path (two-way sync)
    sync_with: Option<String>,
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
    created: Option<String>,
    /// KeePass "last access": last copy / Auto-Type (sorts the list by last use)
    used: Option<String>,
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
            .replace("yyyy", "%Y")
            .replace("MM", "%m")
            .replace("dd", "%d")
            .replace("HH", "%H")
            .replace("mm", "%M")
            .replace("ss", "%S");
        name.replace_range(start..=end, &chrono::Local::now().format(&fmt).to_string());
    }
    let name = name.replace("{TIME}", &chrono::Local::now().format("%Y%m%d%H%M%S").to_string());
    let p = Path::new(&name);
    Some(if p.is_absolute() { p.to_path_buf() } else { vault.parent()?.join(p) })
}

/// Write via temp file + rename so a crash never leaves a half-written database.
fn write_db(v: &mut OpenVault) -> R<()> {
    // Vaultwarden: upload the changes, then show what the server has now
    if let Some(r) = v.remote.as_mut() {
        match crate::bitwarden::push(r, &v.db) {
            Ok(db) => v.db = db,
            Err(e) => {
                let title = v.db.meta.database_name.clone().unwrap_or_default();
                if let Ok(db) = crate::bitwarden::pull(r, &title) {
                    v.db = db;
                }
                return Err(e);
            }
        }
        return Ok(());
    }
    upgrade_to_kdbx4(v)?;
    let pattern = BACKUP_PATTERN.lock().ok().and_then(|p| p.clone());
    if let Some(target) = pattern.and_then(|p| backup_target(&v.path, &p)).filter(|_| v.path.is_file())
        && let Err(e) = fs::copy(&v.path, &target)
    {
        log::warn!("backup before save failed: {e}");
    }
    let mut buf = Vec::new();
    v.db.save(&mut buf, v.key.clone()).map_err(|e| format!("save:{e}"))?;
    let tmp = v.path.with_extension("kdbx.tmp");
    fs::write(&tmp, &buf).map_err(|e| format!("io:{e}"))?;
    fs::rename(&tmp, &v.path).map_err(|e| format!("io:{e}"))?;
    stamp(&v.path);
    forget_used(&v.path); // any save carries the "last access" times along
    crate::keeshare::export_all(&v.db, &v.path);
    Ok(())
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
                created: e.times.creation.as_ref().map(fmt_time),
                used: e.times.last_access.as_ref().map(fmt_time),
                expires: (e.times.expires == Some(true)).then(|| fmt_time(&e.times.expiry)),
                history: e
                    .history
                    .as_ref()
                    .map(|h| {
                        h.get_entries().iter().map(|old| old.times.last_modification.as_ref().map(fmt_time).unwrap_or_default()).collect()
                    })
                    .unwrap_or_default(),
            }
        })
        .collect();

    VaultDto {
        id: id.to_string(),
        name: db
            .meta
            .database_name
            .clone()
            .unwrap_or_else(|| v.path.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default()),
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
        weak_kdf: v.remote.is_none() && weak_kdf(&db.config.kdf_config),
        remote: v.remote.as_ref().map(|r| r.online()),
        sync_with: crate::sync::link_of(db),
    }
}

/// AES-KDF below 1 million rounds or Argon2 with less than 16 MiB counts as weak.
fn weak_kdf(k: &KdfConfig) -> bool {
    match k {
        KdfConfig::Aes { rounds } => *rounds < 1_000_000,
        KdfConfig::Argon2 { memory, .. } | KdfConfig::Argon2id { memory, .. } => *memory < 16 * 1024 * 1024,
        _ => false,
    }
}

#[derive(Serialize, Clone)]
struct UsedDto {
    vault: String,
    id: String,
    used: String,
}

/// Vault files with "last access" times not written yet (see `save_used`).
static USED_UNSAVED: Mutex<Option<std::collections::HashSet<PathBuf>>> = Mutex::new(None);

/// An entry was used (copied, typed): set its KeePass "last access" time. A copy never rewrites
/// the file; the time is saved with the next change, or on lock / close / quit (`save_used`).
pub fn mark_used<R: tauri::Runtime>(app: &tauri::AppHandle<R>, v: &mut OpenVault, vault: &str, id: EntryId) {
    let now = Times::now();
    if let Some(mut e) = v.db.entry_mut(id) {
        e.times.last_access = Some(now);
        let _ = tauri::Emitter::emit(app, "akp-entry-used", UsedDto { vault: vault.into(), id: id.to_string(), used: fmt_time(&now) });
        if v.remote.is_none()
            && let Ok(mut u) = USED_UNSAVED.lock()
        {
            u.get_or_insert_with(Default::default).insert(v.path.clone());
        }
    }
}

fn forget_used(path: &Path) -> bool {
    USED_UNSAVED.lock().ok().and_then(|mut u| u.as_mut().map(|s| s.remove(path))).unwrap_or(false)
}

/// Write pending "last access" times of a local vault file. Skipped when the file changed on
/// disk since we read it (cloud sync, KeePassXC): never overwrite someone else's change for this.
pub fn save_used(v: &mut OpenVault) {
    let pending = forget_used(&v.path);
    let unchanged = watch::STAMPS.lock().ok().and_then(|s| s.as_ref().and_then(|s| s.get(&v.path).copied())) == watch::mtime(&v.path);
    if pending && unchanged && v.remote.is_none() {
        match write_db(v) {
            Ok(()) => log::info!("saved last-use times"),
            Err(e) => log::warn!("saving last-use times failed: {e}"),
        }
    }
}

fn with_vault<T>(state: &Vaults, id: &str, f: impl FnOnce(&mut OpenVault) -> R<T>) -> R<T> {
    let mut map = state.0.lock().map_err(|_| "lock".to_string())?;
    let v = map.get_mut(id).ok_or("vault_closed")?;
    f(v)
}

/// Mutate, persist, and return the fresh listing.
/// Change one entry (no history version), persist, return the listing.
pub fn mutate_entry(state: &Vaults, vault: &str, id: &str, f: impl FnOnce(&mut keepass::db::EntryMut<'_>)) -> R<VaultDto> {
    mutate(state, vault, |db| {
        let mut e = db.entry_mut(EntryId::from(parse_uuid(id)?)).ok_or("not_found")?;
        f(&mut e);
        Ok(())
    })
}

fn mutate(state: &Vaults, id: &str, f: impl FnOnce(&mut Database) -> R<()>) -> R<VaultDto> {
    let mut map = state.0.lock().map_err(|_| "lock".to_string())?;
    let v = map.get_mut(id).ok_or("vault_closed")?;
    f(&mut v.db)?;
    write_db(v)?;
    // a linked .kdbx / Vaultwarden partner gets the change too
    crate::sync::after_change(&mut map, id);
    Ok(dto(id, map.get(id).ok_or("vault_closed")?))
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
