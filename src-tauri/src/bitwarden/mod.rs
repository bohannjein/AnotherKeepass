//! Vaultwarden account as a vault. After login the account is decrypted into an in-memory
//! KeePass database (folders → groups, ciphers → entries with the cipher id as UUID), so every
//! feature that works on .kdbx vaults works here too. Saving compares against the last sync
//! and uploads only what changed, then syncs again.
//! Vault path: "bw:<server>#<email>".

pub mod api;
pub mod crypto;
pub mod mapping;

use std::{collections::HashMap, fs, path::PathBuf};

use base64::{Engine, engine::general_purpose::STANDARD as B64};
use keepass::{
    Database,
    db::{EntryId, GroupId, Times},
};
use rsa::pkcs8::DecodePrivateKey;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

use api::{LoginError, Session, field};
use crypto::{Kdf, SymKey};
use mapping::{Meta, Plain};

pub fn parse_path(path: &str) -> Option<(String, String)> {
    let rest = path.strip_prefix("bw:")?;
    let (server, email) = rest.rsplit_once('#')?;
    Some((api::base(server), email.trim().to_string()))
}

/// Plain http only to this machine (testing); everything else must be https.
fn check_secure(server: &str) -> Result<(), String> {
    let u = url::Url::parse(server).map_err(|_| "bw:invalid_url")?;
    let local = matches!(u.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
    if u.scheme() == "https" || (u.scheme() == "http" && local) { Ok(()) } else { Err("insecure_url".into()) }
}

/// meta custom data: the account path (stable identity for the browser extension)
pub const CD_ACCOUNT: &str = "AnotherKeepass.Account";

pub fn is_remote(path: &str) -> bool {
    path.starts_with("bw:")
}

// ---------------------------------------------------------------- account file (DPAPI-protected)

#[derive(Serialize, Deserialize, Default)]
struct Account {
    device_id: String,
    /// "remember this device" token: next logins skip the second factor
    remember: Option<String>,
    kdf: Option<(u8, u32, u32, u32)>,
    /// last sync response – everything in it is encrypted with the account keys (offline use)
    sync: Option<Value>,
    /// browser extension associations (KPXC_BROWSER_*: public ids, no secrets)
    #[serde(default)]
    browser: HashMap<String, String>,
}

fn account_file(path: &str) -> Option<PathBuf> {
    use sha2::{Digest, Sha256};
    let base =
        std::env::var_os("APPDATA").map(PathBuf::from).or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))?;
    let name: String = Sha256::digest(path.as_bytes()).iter().take(12).map(|b| format!("{b:02x}")).collect();
    Some(base.join(crate::desktop::IDENTIFIER).join("vaultwarden").join(format!("{name}.json")))
}

fn load_account(path: &str) -> Account {
    let mut a: Account = account_file(path)
        .and_then(|f| fs::read(f).ok())
        .and_then(|b| crate::hardening::unprotect(&b).or(Some(b)))
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default();
    if a.device_id.is_empty() {
        a.device_id = Uuid::new_v4().to_string();
    }
    a
}

fn save_account(path: &str, a: &Account) {
    if let Some(f) = account_file(path) {
        let _ = f.parent().map(fs::create_dir_all);
        // the remember token and browser ids are secrets: only this Windows user can read the file
        let plain = serde_json::to_vec(a).unwrap_or_default();
        let data = crate::hardening::protect(&plain).unwrap_or(plain);
        if let Err(e) = fs::write(&f, data) {
            log::warn!("vaultwarden cache: {e}");
        }
    }
}

/// Forget device token and offline copy (sign out).
pub fn forget(path: &str) {
    if let Some(f) = account_file(path) {
        let _ = fs::remove_file(f);
    }
}

// ---------------------------------------------------------------- the open account

struct Snapshot {
    /// cipher id → (plain, meta, in trash, folder id)
    ciphers: HashMap<String, (Plain, Meta, bool, Option<String>)>,
    /// folder id → name
    folders: HashMap<String, String>,
    /// groups that stand for organizations (no folder)
    org_groups: HashMap<GroupId, String>,
    /// collection groups (below their organization): organization id, collection id, read-only
    collections: HashMap<GroupId, (String, String, bool)>,
    /// ciphers the account may see but not change
    read_only: std::collections::HashSet<String>,
}

pub struct Remote {
    path: String,
    session: Option<Session>,
    user_id: String,
    user: SymKey,
    private: Option<rsa::RsaPrivateKey>,
    orgs: HashMap<String, SymKey>,
    snapshot: Snapshot,
    /// entries created by the last push: (local entry uuid, server cipher id)
    created: Vec<(String, String)>,
}

impl Remote {
    pub fn online(&self) -> bool {
        self.session.is_some()
    }
    /// new entries get their id from the server: who became what in the last upload
    pub fn take_created(&mut self) -> Vec<(String, String)> {
        std::mem::take(&mut self.created)
    }
}

fn org_keys(profile: &Value, private: Option<&rsa::RsaPrivateKey>) -> HashMap<String, SymKey> {
    let mut out = HashMap::new();
    let Some(pk) = private else { return out };
    for o in field(profile, "organizations").as_array().into_iter().flatten() {
        let (Some(id), Some(k)) = (field(o, "id").as_str(), field(o, "key").as_str()) else { continue };
        match crypto::decrypt_rsa(k, pk).and_then(|b| SymKey::from_bytes(&b)) {
            Ok(key) => {
                out.insert(id.to_string(), key);
            }
            Err(e) => log::warn!("vaultwarden org key: {e}"),
        }
    }
    out
}

fn private_key(protected: Option<&str>, user: &SymKey) -> Option<rsa::RsaPrivateKey> {
    let der = crypto::decrypt(protected?, user).ok()?;
    rsa::RsaPrivateKey::from_pkcs8_der(&der).ok()
}

fn parse_time(s: Option<&str>) -> Option<chrono::NaiveDateTime> {
    chrono::DateTime::parse_from_rfc3339(s?).ok().map(|d| d.naive_utc())
}

/// Sync response → in-memory database + snapshot of what the server has.
fn build(sync: &Value, title: &str, user: &SymKey, orgs: &HashMap<String, SymKey>) -> Result<(Database, Snapshot), String> {
    let mut db = Database::new();
    // (account id and browser associations are added by with_account)
    db.config = crate::vault::new_config();
    db.meta.database_name = Some(title.to_string());
    db.root_mut().name = title.to_string();
    let root = db.root().id();
    let bin = crate::vault::ensure_recycle_bin(&mut db);
    let mut snap = Snapshot {
        ciphers: HashMap::new(),
        folders: HashMap::new(),
        org_groups: HashMap::new(),
        collections: HashMap::new(),
        read_only: Default::default(),
    };

    for f in field(sync, "folders").as_array().into_iter().flatten() {
        let Some(id) = field(f, "id").as_str() else { continue };
        let name = field(f, "name").as_str().map(|n| crypto::decrypt_str(n, user)).transpose()?.unwrap_or_default();
        let Ok(uuid) = Uuid::parse_str(id) else { continue };
        if let Some(mut r) = db.group_mut(root)
            && let Ok(mut g) = r.add_group_with_id(GroupId::from_uuid(uuid))
        {
            g.name = name.clone();
        }
        snap.folders.insert(id.to_string(), name);
    }
    let mut org_group: HashMap<String, GroupId> = HashMap::new();
    for o in field(field(sync, "profile"), "organizations").as_array().into_iter().flatten() {
        let (Some(id), name) = (field(o, "id").as_str(), field(o, "name").as_str().unwrap_or("Organization")) else { continue };
        // the organization id as group id: stays the same across syncs
        let Ok(uuid) = Uuid::parse_str(id) else { continue };
        let gid = GroupId::from_uuid(uuid);
        if let Some(mut r) = db.group_mut(root)
            && let Ok(mut g) = r.add_group_with_id(gid)
        {
            g.name = name.to_string();
        }
        org_group.insert(id.to_string(), gid);
        snap.org_groups.insert(gid, id.to_string());
    }
    // collections become groups below their organization
    for c in field(sync, "collections").as_array().into_iter().flatten() {
        let (Some(id), Some(org)) = (field(c, "id").as_str(), field(c, "organizationId").as_str()) else { continue };
        let (Some(parent), Some(key), Ok(uuid)) = (org_group.get(org).copied(), orgs.get(org), Uuid::parse_str(id)) else { continue };
        let name = field(c, "name").as_str().and_then(|n| crypto::decrypt_str(n, key).ok()).unwrap_or_default();
        let gid = GroupId::from_uuid(uuid);
        if let Some(mut p) = db.group_mut(parent)
            && let Ok(mut g) = p.add_group_with_id(gid)
        {
            g.name = name;
        }
        snap.collections.insert(gid, (org.to_string(), id.to_string(), field(c, "readOnly").as_bool() == Some(true)));
    }

    for c in field(sync, "ciphers").as_array().into_iter().flatten() {
        let Some(id) = field(c, "id").as_str().and_then(|i| Uuid::parse_str(i).ok()) else { continue };
        let decrypted = mapping::cipher_key(c, user, orgs).and_then(|k| mapping::decrypt_cipher(c, &k));
        let (plain, meta) = match decrypted {
            Ok(x) => x,
            Err(e) => {
                log::warn!("vaultwarden: skipped an item ({e})");
                continue;
            }
        };
        let deleted = !field(c, "deletedDate").is_null();
        let folder = field(c, "folderId").as_str().map(String::from);
        let parent = if deleted {
            bin
        } else if let Some(g) =
            folder.as_deref().and_then(|f| Uuid::parse_str(f).ok()).map(GroupId::from_uuid).filter(|g| db.group(*g).is_some())
        {
            g
        } else if let Some(g) = field(c, "collectionIds")
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|x| x.as_str().and_then(|x| Uuid::parse_str(x).ok()))
            .map(GroupId::from_uuid)
            .find(|g| snap.collections.contains_key(g))
        {
            g
        } else if let Some(g) = meta.org.as_deref().and_then(|o| org_group.get(o)) {
            *g
        } else {
            root
        };
        let Some(mut g) = db.group_mut(parent) else { continue };
        let Ok(mut e) = g.add_entry_with_id(EntryId::from(id)) else { continue };
        mapping::write_entry(&mut e, &plain, meta);
        e.times.last_modification = parse_time(field(c, "revisionDate").as_str()).or(Some(Times::now()));
        e.times.creation = parse_time(field(c, "creationDate").as_str()).or(e.times.last_modification);
        let eid = e.id();
        if field(c, "edit").as_bool() == Some(false) {
            snap.read_only.insert(id.to_string());
        }
        // canonical form = what reading the entry gives (so "unchanged" compares equal)
        let entry = db.entry(eid).ok_or("bw_build")?;
        let (canon, meta) = mapping::read_entry(&entry);
        snap.ciphers.insert(id.to_string(), (canon, meta, deleted, folder));
    }
    Ok((db, snap))
}

/// Log in (or open the offline copy) and decrypt the account.
/// Errors: "wrong_key", "twofactor:<ids>", "offline_no_cache", or a server message.
pub fn open(path: &str, password: &str, second: Option<(u8, String)>) -> Result<(Database, Remote), String> {
    let (server, email) = parse_path(path).ok_or("bw_path")?;
    check_secure(&server)?;
    let mut acct = load_account(path);
    let title = format!("{email} · {}", server.trim_start_matches("https://").trim_start_matches("http://"));

    let mut unreachable = String::new();
    let kdf = match api::prelogin(&server, &email) {
        Ok(k) => Some(k),
        Err(LoginError::Offline(e)) => {
            log::warn!("vaultwarden: {server} not reachable: {e}");
            unreachable = e;
            None
        }
        Err(e) => return Err(format!("bw:{e:?}")),
    };
    let Some(kdf) = kdf.or_else(|| acct.kdf.map(|(kind, iterations, memory, parallelism)| Kdf { kind, iterations, memory, parallelism }))
    else {
        return Err(format!("offline_no_cache:{unreachable}"));
    };
    if let Some((kind, iterations, memory, parallelism)) = acct.kdf
        && crypto::kdf_weaker(&kdf, &Kdf { kind, iterations, memory, parallelism })
    {
        return Err("bw:kdf_weakened".into());
    }
    let master = crypto::master_key(password, &email, &kdf)?;
    let hash = crypto::server_hash(&master, password);
    acct.kdf = Some((kdf.kind, kdf.iterations, kdf.memory, kdf.parallelism));

    let attempt = match &second {
        Some((p, code)) => api::login(&server, &email, &hash, &acct.device_id, Some((*p, code.as_str()))),
        None => match acct.remember.clone() {
            Some(token) => match api::login(&server, &email, &hash, &acct.device_id, Some((5, token.as_str()))) {
                Err(LoginError::TwoFactor(p)) => {
                    acct.remember = None;
                    Err(LoginError::TwoFactor(p))
                }
                other => other,
            },
            None => api::login(&server, &email, &hash, &acct.device_id, None),
        },
    };
    let (session, sync, user, private) = match attempt {
        Ok(token) => {
            if token.remember.is_some() {
                acct.remember = token.remember.clone();
            }
            let user = crypto::decrypt_user_key(&token.key, &master)?;
            let private = private_key(token.private_key.as_deref(), &user);
            let mut session = token.session;
            let sync = session.sync()?;
            (Some(session), sync, user, private)
        }
        Err(LoginError::TwoFactor(p)) => {
            save_account(path, &acct);
            return Err(format!("twofactor:{}", p.iter().map(|x| x.to_string()).collect::<Vec<_>>().join(",")));
        }
        Err(LoginError::WrongPassword) => return Err("wrong_key".into()),
        Err(LoginError::Offline(e)) => {
            // offline: the cached sync has the protected keys, the password still has to fit
            let sync = acct.sync.clone().ok_or_else(|| format!("offline_no_cache:{e}"))?;
            let profile = field(&sync, "profile");
            let user = crypto::decrypt_user_key(field(profile, "key").as_str().ok_or("offline_no_cache")?, &master)?;
            let private = private_key(field(profile, "privateKey").as_str(), &user);
            (None, sync, user, private)
        }
        Err(LoginError::Other(e)) => return Err(format!("bw:{e}")),
    };
    let orgs = org_keys(field(&sync, "profile"), private.as_ref());
    let (mut db, snapshot) = build(&sync, &title, &user, &orgs)?;
    with_account(&mut db, path, &acct);
    if session.is_some() {
        acct.sync = Some(sync.clone());
    }
    save_account(path, &acct);
    let user_id = field(field(&sync, "profile"), "id").as_str().unwrap_or_default().to_string();
    log::info!("vaultwarden: {} items{}", snapshot.ciphers.len(), if session.is_some() { "" } else { " (offline copy)" });
    Ok((db, Remote { path: path.to_string(), session, user_id, user, private, orgs, snapshot, created: vec![] }))
}

/// Fetch the current server state.
pub fn pull(r: &mut Remote, title: &str) -> Result<Database, String> {
    let session = r.session.as_mut().ok_or("offline")?;
    let sync = session.sync()?;
    r.orgs = org_keys(field(&sync, "profile"), r.private.as_ref());
    let (mut db, snap) = build(&sync, title, &r.user, &r.orgs)?;
    r.snapshot = snap;
    let mut acct = load_account(&r.path);
    acct.sync = Some(sync);
    save_account(&r.path, &acct);
    with_account(&mut db, &r.path, &acct);
    Ok(db)
}

fn with_account(db: &mut Database, path: &str, acct: &Account) {
    let item = |s: &str| keepass::db::CustomDataItem {
        value: Some(keepass::db::CustomDataValue::String(s.to_string())),
        last_modification_time: Some(Times::now()),
    };
    db.meta.custom_data.insert(CD_ACCOUNT.into(), item(path));
    for (k, v) in &acct.browser {
        db.meta.custom_data.insert(k.clone(), item(v));
    }
}

/// Browser associations live in the vault's meta data; for accounts they are kept locally.
fn keep_associations(path: &str, db: &Database) {
    let assoc: HashMap<String, String> = db
        .meta
        .custom_data
        .iter()
        .filter(|(k, _)| k.starts_with("KPXC_BROWSER_"))
        .filter_map(|(k, v)| match &v.value {
            Some(keepass::db::CustomDataValue::String(s)) => Some((k.clone(), s.clone())),
            _ => None,
        })
        .collect();
    let mut acct = load_account(path);
    if acct.browser != assoc {
        acct.browser = assoc;
        save_account(path, &acct);
    }
}

/// Upload what changed since the last sync, then sync again. Returns the fresh database.
pub fn push(r: &mut Remote, db: &Database) -> Result<Database, String> {
    keep_associations(&r.path, db);
    if r.session.is_none() {
        return Err("offline".into());
    }
    let title = db.meta.database_name.clone().unwrap_or_default();
    let root = db.root().id();
    let bin = db.recycle_bin().map(|b| b.id());
    let in_bin = |mut g: Option<GroupId>| {
        while let Some(id) = g {
            if Some(id) == bin {
                return true;
            }
            g = db.group(id).and_then(|x| x.parent().map(|p| p.id()));
        }
        false
    };
    // organization (and collection) a group belongs to
    let place = |mut g: Option<GroupId>| -> Option<(String, Option<(String, bool)>)> {
        while let Some(id) = g {
            if let Some((org, coll, ro)) = r.snapshot.collections.get(&id) {
                return Some((org.clone(), Some((coll.clone(), *ro))));
            }
            if let Some(org) = r.snapshot.org_groups.get(&id) {
                return Some((org.clone(), None));
            }
            g = db.group(id).and_then(|x| x.parent().map(|p| p.id()));
        }
        None
    };
    // refuse before anything is uploaded, so a rejected change never leaves half a push behind
    let changed = |id: &str, plain: &Plain, trashed: bool| match r.snapshot.ciphers.get(id) {
        None => true,
        Some((old, _, was_trashed, _)) => old != plain || *was_trashed != trashed,
    };
    let present: std::collections::HashSet<String> = db.iter_all_entries().map(|e| e.id().to_string()).collect();
    for e in db.iter_all_entries() {
        let id = e.id().to_string();
        let trashed = in_bin(Some(e.parent().id()));
        let here = if trashed { None } else { place(Some(e.parent().id())) };
        let known = r.snapshot.ciphers.get(&id);
        if known.is_some() && r.snapshot.read_only.contains(&id) && changed(&id, &mapping::read_entry(&e).0, trashed) {
            return Err("bw_readonly".into());
        }
        match (known, &here) {
            (None, Some((_, None))) if !trashed => return Err("bw_org_collection".into()),
            (None, Some((_, Some((_, true))))) => return Err("bw_readonly".into()),
            (Some((_, meta, _, _)), _) if !trashed && meta.org != here.as_ref().map(|h| h.0.clone()) => return Err("bw_org_move".into()),
            _ => {}
        }
    }
    if r.snapshot.read_only.iter().any(|id| !present.contains(id)) {
        return Err("bw_readonly".into());
    }
    let session = r.session.as_mut().expect("checked above");

    // folders: every group except root, bin and organizations; nested groups become "A/B"
    let mut folder_of: HashMap<GroupId, Option<String>> = HashMap::from([(root, None)]);
    let mut seen_folders = Vec::new();
    for g in db.iter_all_groups() {
        let gid = g.id();
        if gid == root || in_bin(Some(gid)) || place(Some(gid)).is_some() {
            folder_of.insert(gid, None);
            continue;
        }
        let mut names = vec![g.name.clone()];
        let mut p = g.parent().map(|x| x.id());
        while let Some(pid) = p.filter(|x| *x != root) {
            let pg = db.group(pid).ok_or("bw_group")?;
            names.push(pg.name.clone());
            p = pg.parent().map(|x| x.id());
        }
        names.reverse();
        let name = names.join("/");
        let id = gid.to_string();
        let folder_id = match r.snapshot.folders.get(&id) {
            Some(old) => {
                if *old != name {
                    session.rename_folder(&id, &crypto::encrypt(name.as_bytes(), &r.user))?;
                }
                id
            }
            None => session.create_folder(&crypto::encrypt(name.as_bytes(), &r.user))?,
        };
        seen_folders.push(gid.to_string());
        folder_of.insert(gid, Some(folder_id));
    }

    // ciphers
    let mut seen = Vec::new();
    for e in db.iter_all_entries() {
        let id = e.id().to_string();
        let trashed = in_bin(Some(e.parent().id()));
        let (plain, mut meta) = mapping::read_entry(&e);
        let folder = if trashed { None } else { folder_of.get(&e.parent().id()).cloned().flatten() };
        let key = mapping::cipher_key(&json!({ "organizationId": meta.org, "key": meta.key }), &r.user, &r.orgs)?;
        match r.snapshot.ciphers.get(&id) {
            None => {
                seen.push(id.clone());
                if !trashed {
                    meta.revision = None;
                    let res = match place(Some(e.parent().id())) {
                        Some((org, Some((coll, _)))) => {
                            meta.org = Some(org);
                            meta.key = None;
                            let key = mapping::cipher_key(&json!({ "organizationId": meta.org, "key": null }), &r.user, &r.orgs)?;
                            session.create_org_cipher(&mapping::cipher_body(&plain, &meta, None, &key, &r.user_id), &[coll])?
                        }
                        _ => session.create_cipher(&mapping::cipher_body(&plain, &meta, folder.as_deref(), &key, &r.user_id))?,
                    };
                    if let Some(sid) = field(&res, "id").as_str() {
                        r.created.push((id, sid.to_string()));
                    }
                }
            }
            Some((old, _, was_trashed, old_folder)) => {
                seen.push(id.clone());
                if trashed && !was_trashed {
                    session.trash_cipher(&id)?;
                    continue;
                }
                if !trashed && *was_trashed {
                    session.restore_cipher(&id)?;
                }
                if !trashed && (*old != plain || *old_folder != folder) {
                    session.update_cipher(&id, &mapping::cipher_body(&plain, &meta, folder.as_deref(), &key, &r.user_id))?;
                }
            }
        }
    }
    // gone locally: to the server's trash; permanently only what already was in the trash
    let gone: Vec<(String, bool)> =
        r.snapshot.ciphers.iter().filter(|(id, _)| !seen.contains(id)).map(|(id, c)| (id.clone(), c.2)).collect();
    for (id, was_trashed) in gone {
        if was_trashed { session.delete_cipher(&id)? } else { session.trash_cipher(&id)? }
    }
    let gone: Vec<String> = r.snapshot.folders.keys().filter(|id| !seen_folders.contains(id)).cloned().collect();
    for id in gone {
        session.delete_folder(&id)?;
    }
    pull(r, &title)
}

/// Email 2FA: ask the server to send the code.
pub fn send_email_code(path: &str, password: &str) -> Result<(), String> {
    let (server, email) = parse_path(path).ok_or("bw_path")?;
    let kdf = api::prelogin(&server, &email).map_err(|e| format!("bw:{e:?}"))?;
    let master = crypto::master_key(password, &email, &kdf)?;
    let acct = load_account(path);
    save_account(path, &acct);
    api::send_email_code(&server, &email, &crypto::server_hash(&master, password), &acct.device_id)
}

/// for tests and diagnostics: key fingerprint without exposing the key
#[allow(dead_code)]
pub fn key_id(k: &SymKey) -> String {
    use sha2::{Digest, Sha256};
    B64.encode(&Sha256::digest(k.enc.as_ref())[..6])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::encrypt;
    use rand_core::{OsRng, RngCore};

    #[test]
    fn path_parsing() {
        assert_eq!(parse_path("bw:https://vault.example.com/#me@x.de"), Some(("https://vault.example.com".into(), "me@x.de".into())));
        assert!(parse_path("C:/a.kdbx").is_none());
    }

    #[test]
    fn build_from_sync() {
        let mut b = [0u8; 64];
        OsRng.fill_bytes(&mut b);
        let user = SymKey::from_bytes(&b).unwrap();
        let e = |s: &str| json!(encrypt(s.as_bytes(), &user));
        let folder = "aaaaaaaa-0000-0000-0000-000000000001";
        let sync = json!({
            "profile": { "id": "u1", "organizations": [] },
            "folders": [{ "id": folder, "name": e("Work") }],
            "ciphers": [
                { "id": "bbbbbbbb-0000-0000-0000-000000000001", "type": 1, "name": e("Mail"), "folderId": folder, "login": { "username": e("me"), "password": e("pw"), "uris": [] } },
                { "id": "bbbbbbbb-0000-0000-0000-000000000002", "type": 2, "name": e("Old"), "deletedDate": "2026-10-01T00:00:00Z", "secureNote": { "type": 0 } },
            ],
        });
        let (db, snap) = build(&sync, "test", &user, &HashMap::new()).unwrap();
        let mail = db.entry(EntryId::from(Uuid::parse_str("bbbbbbbb-0000-0000-0000-000000000001").unwrap())).unwrap();
        assert_eq!(mail.get("Password"), Some("pw"));
        assert_eq!(mail.parent().name, "Work");
        let old = db.entry(EntryId::from(Uuid::parse_str("bbbbbbbb-0000-0000-0000-000000000002").unwrap())).unwrap();
        assert_eq!(Some(old.parent().id()), db.recycle_bin().map(|b| b.id()));
        assert_eq!(snap.ciphers.len(), 2);
        assert!(snap.ciphers.values().any(|c| c.2), "trashed item marked");
    }

    /// Minimal Vaultwarden stand-in on 127.0.0.1: prelogin, token with 2FA, sync, cipher writes.
    struct Mock {
        url: String,
        log: std::sync::Arc<std::sync::Mutex<Vec<(String, String, String)>>>,
    }

    /// `org`: organizations, collections and the protected private key for the sync profile
    fn mock(user: SymKey, protected_user_key: String, ciphers: Vec<Value>, org: Value) -> Mock {
        use std::io::{BufRead, BufReader, Read, Write};
        use std::sync::{Arc, Mutex};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let log = Arc::new(Mutex::new(Vec::<(String, String, String)>::new()));
        let state = Arc::new(Mutex::new(ciphers));
        let (log2, _) = (log.clone(), &user);
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                if reader.read_line(&mut line).is_err() {
                    continue;
                }
                let mut parts = line.split_whitespace();
                let (method, path) = (parts.next().unwrap_or("").to_string(), parts.next().unwrap_or("").to_string());
                let mut len = 0;
                loop {
                    let mut h = String::new();
                    reader.read_line(&mut h).unwrap();
                    if h.trim().is_empty() {
                        break;
                    }
                    if let Some(v) = h.to_lowercase().strip_prefix("content-length:") {
                        len = v.trim().parse().unwrap_or(0);
                    }
                }
                let mut body = vec![0; len];
                reader.read_exact(&mut body).unwrap();
                let body = String::from_utf8_lossy(&body).to_string();
                log2.lock().unwrap().push((method.clone(), path.clone(), body.clone()));
                let (code, reply) = match (method.as_str(), path.split('?').next().unwrap()) {
                    ("POST", "/identity/accounts/prelogin") => (200, json!({ "kdf": 0, "kdfIterations": 5000 })),
                    ("POST", "/identity/connect/token")
                        if body.contains("twoFactorToken=123456") || body.contains("twoFactorToken=remember-me") =>
                    {
                        (
                            200,
                            json!({ "access_token": "acc", "refresh_token": "ref", "Key": protected_user_key, "PrivateKey": org["privateKey"], "TwoFactorToken": "remember-me" }),
                        )
                    }
                    ("POST", "/identity/connect/token") => {
                        (400, json!({ "error": "invalid_grant", "error_description": "Two factor required.", "TwoFactorProviders": ["0"] }))
                    }
                    ("GET", "/api/sync") => (
                        200,
                        json!({
                            "profile": { "id": "user-1", "organizations": org.get("organizations").cloned().unwrap_or(json!([])), "privateKey": org["privateKey"] },
                            "collections": org.get("collections").cloned().unwrap_or(json!([])),
                            "folders": [], "ciphers": *state.lock().unwrap(),
                        }),
                    ),
                    ("PUT", p) if p.starts_with("/api/ciphers/") => {
                        let id = p.trim_start_matches("/api/ciphers/").to_string();
                        let mut c: Value = serde_json::from_str(&body).unwrap();
                        c["id"] = json!(id);
                        let mut list = state.lock().unwrap();
                        list.retain(|x| x["id"] != json!(id));
                        list.push(c.clone());
                        (200, c)
                    }
                    ("POST", "/api/ciphers/create") => {
                        let b: Value = serde_json::from_str(&body).unwrap();
                        let mut c = b["cipher"].clone();
                        c["id"] = json!(Uuid::new_v4().to_string());
                        c["collectionIds"] = b["collectionIds"].clone();
                        state.lock().unwrap().push(c.clone());
                        (200, c)
                    }
                    ("POST", "/api/ciphers") => {
                        let mut c: Value = serde_json::from_str(&body).unwrap();
                        c["id"] = json!(Uuid::new_v4().to_string());
                        state.lock().unwrap().push(c.clone());
                        (200, c)
                    }
                    _ => (404, json!({ "message": "not found" })),
                };
                let text = reply.to_string();
                let mut s = stream;
                let _ = write!(
                    s,
                    "HTTP/1.1 {code} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{text}",
                    text.len()
                );
                let _ = s.flush();
            }
        });
        Mock { url, log }
    }

    #[test]
    fn login_2fa_sync_and_upload_against_mock_server() {
        let password = "correct horse";
        let email = format!("t{}@example.com", Uuid::new_v4().simple());
        let kdf = Kdf { kind: 0, iterations: 5000, memory: 0, parallelism: 0 };
        let master = crypto::master_key(password, &email, &kdf).unwrap();
        let mut ub = [0u8; 64];
        OsRng.fill_bytes(&mut ub);
        let user = SymKey::from_bytes(&ub).unwrap();
        let protected = encrypt(&ub, &crypto::stretch(&master));
        let e = |s: &str| json!(encrypt(s.as_bytes(), &user));
        let id1 = "cccccccc-0000-0000-0000-000000000001";
        let m = mock(
            user.clone(),
            protected,
            vec![
                json!({ "id": id1, "type": 1, "name": e("Mail"), "revisionDate": "2026-10-21T10:00:00Z", "login": { "username": e("me"), "password": e("old"), "uris": [] } }),
                json!({ "id": "cccccccc-0000-0000-0000-000000000002", "type": 2, "name": e("Note"), "secureNote": { "type": 0 } }),
            ],
            json!({}),
        );
        let path = format!("bw:{}#{}", m.url, email);

        // 1. second factor needed, 2. with the code it works, 3. remembered device skips it
        assert_eq!(open(&path, password, None).err().as_deref(), Some("twofactor:0"));
        assert_eq!(open(&path, "wrong", Some((0, "123456".into()))).err().as_deref(), Some("wrong_key"));
        let (mut db, mut remote) = open(&path, password, Some((0, "123456".into()))).unwrap();
        assert!(open(&path, password, None).is_ok(), "remember token used");
        assert_eq!(db.iter_all_entries().count(), 2);

        // nothing changed → no upload
        let before = m.log.lock().unwrap().len();
        db = push(&mut remote, &db).unwrap();
        assert!(m.log.lock().unwrap()[before..].iter().all(|(meth, _, _)| meth == "GET"), "only a sync, no writes");

        // change one password and add a new login → one PUT, one POST, encrypted correctly
        let eid = EntryId::from(Uuid::parse_str(id1).unwrap());
        db.entry_mut(eid).unwrap().set_protected("Password", "new secret");
        {
            let root = db.root().id();
            let mut g = db.group_mut(root).unwrap();
            let mut n = g.add_entry();
            n.set_unprotected("Title", "Shop");
            n.set_unprotected("UserName", "buyer");
        }
        let before = m.log.lock().unwrap().len();
        db = push(&mut remote, &db).unwrap();
        let log = m.log.lock().unwrap()[before..].to_vec();
        let put = log.iter().find(|(meth, p, _)| meth == "PUT" && p.ends_with(id1)).expect("PUT for the changed entry");
        let body: Value = serde_json::from_str(&put.2).unwrap();
        assert_eq!(crypto::decrypt_str(body["login"]["password"].as_str().unwrap(), &user).unwrap(), "new secret");
        assert_eq!(body["encryptedFor"], "user-1");
        assert_eq!(body["lastKnownRevisionDate"], "2026-10-21T10:00:00Z");
        assert_eq!(log.iter().filter(|(meth, p, _)| meth == "POST" && p == "/api/ciphers").count(), 1);
        assert_eq!(log.iter().filter(|(meth, _, _)| meth == "PUT").count(), 1, "the untouched note is not uploaded");
        // after the push the vault shows the server state (3 items, new password)
        assert_eq!(db.iter_all_entries().count(), 3);
        assert_eq!(db.entry(eid).unwrap().get("Password"), Some("new secret"));
        forget(&path);
    }

    #[test]
    fn kdbx_sync_survives_server_ids() {
        let password = "pw pw";
        let email = format!("s{}@example.com", Uuid::new_v4().simple());
        let kdf = Kdf { kind: 0, iterations: 5000, memory: 0, parallelism: 0 };
        let master = crypto::master_key(password, &email, &kdf).unwrap();
        let mut ub = [0u8; 64];
        OsRng.fill_bytes(&mut ub);
        let user = SymKey::from_bytes(&ub).unwrap();
        let m = mock(user.clone(), encrypt(&ub, &crypto::stretch(&master)), vec![], json!({}));
        let path = format!("bw:{}#{}", m.url, email);
        let (mut b, mut remote) = open(&path, password, Some((0, "123456".into()))).unwrap();

        // the .kdbx has one entry; sync copies it to the account (local id) …
        let mut a = Database::new();
        a.root_mut().add_entry().set_unprotected("Title", "Only in file");
        let (_, cb) = crate::sync::sync(&mut a, &mut b);
        assert!(cb);
        // … the upload gives it a server id …
        b = push(&mut remote, &b).unwrap();
        let renamed = remote.take_created();
        assert_eq!(renamed.len(), 1);
        crate::sync::remap(&mut a, &renamed);
        // … and the next sync sees nothing to do (no delete, no duplicate)
        assert_eq!(crate::sync::sync(&mut a, &mut b), (false, false));
        assert_eq!(b.iter_all_entries().filter(|e| e.get_title() == Some("Only in file")).count(), 1);
        assert_eq!(a.iter_all_entries().filter(|e| e.get_title() == Some("Only in file")).count(), 1);
        forget(&path);
    }

    #[test]
    fn organization_items_are_writable_unless_read_only() {
        use rsa::pkcs8::EncodePrivateKey;
        let password = "org pw";
        let email = format!("o{}@example.com", Uuid::new_v4().simple());
        let kdf = Kdf { kind: 0, iterations: 5000, memory: 0, parallelism: 0 };
        let master = crypto::master_key(password, &email, &kdf).unwrap();
        let mut ub = [0u8; 64];
        OsRng.fill_bytes(&mut ub);
        let user = SymKey::from_bytes(&ub).unwrap();
        // account key pair; the organization key reaches the account RSA-encrypted (type 4)
        let private = rsa::RsaPrivateKey::new(&mut OsRng, 1024).unwrap();
        let mut ob = [0u8; 64];
        OsRng.fill_bytes(&mut ob);
        let org_key = SymKey::from_bytes(&ob).unwrap();
        let wrapped = private.to_public_key().encrypt(&mut OsRng, rsa::Oaep::new::<sha1::Sha1>(), &ob).unwrap();
        let (org, shared, locked) =
            ("aaaaaaaa-0000-0000-0000-00000000000a", "bbbbbbbb-0000-0000-0000-00000000000b", "bbbbbbbb-0000-0000-0000-00000000000c");
        let o = |s: &str| json!(encrypt(s.as_bytes(), &org_key));
        let (team, ro) = ("dddddddd-0000-0000-0000-000000000001", "dddddddd-0000-0000-0000-000000000002");
        let m = mock(
            user.clone(),
            encrypt(&ub, &crypto::stretch(&master)),
            vec![
                json!({ "id": team, "type": 1, "organizationId": org, "collectionIds": [shared], "edit": true, "name": o("Team mail"),
                    "revisionDate": "2026-10-21T10:00:00Z", "login": { "username": o("team"), "password": o("old"), "uris": [] } }),
                json!({ "id": ro, "type": 1, "organizationId": org, "collectionIds": [locked], "edit": false, "name": o("Server root"),
                    "login": { "username": o("root"), "password": o("pw"), "uris": [] } }),
            ],
            json!({
                "privateKey": encrypt(private.to_pkcs8_der().unwrap().as_bytes(), &user),
                "organizations": [{ "id": org, "name": "Team", "key": format!("4.{}", B64.encode(wrapped)) }],
                "collections": [
                    { "id": shared, "organizationId": org, "name": o("Shared"), "readOnly": false },
                    { "id": locked, "organizationId": org, "name": o("Locked"), "readOnly": true },
                ],
            }),
        );
        let path = format!("bw:{}#{}", m.url, email);
        let (mut db, mut remote) = open(&path, password, Some((0, "123456".into()))).unwrap();
        let title = db.meta.database_name.clone().unwrap_or_default();
        let shared_g = GroupId::from_uuid(Uuid::parse_str(shared).unwrap());
        let org_g = GroupId::from_uuid(Uuid::parse_str(org).unwrap());
        let team_id = EntryId::from(Uuid::parse_str(team).unwrap());
        assert_eq!(db.group(shared_g).unwrap().name, "Shared", "collections are groups below the organization");
        assert_eq!(db.entry(team_id).unwrap().parent().id(), shared_g);
        let writes = |m: &Mock, from: usize| m.log.lock().unwrap()[from..].iter().filter(|(meth, _, _)| meth != "GET").count();

        // editable item: uploaded encrypted with the organization key
        db.entry_mut(team_id).unwrap().set_protected("Password", "rotated");
        let before = m.log.lock().unwrap().len();
        db = push(&mut remote, &db).unwrap();
        let put = m.log.lock().unwrap()[before..].iter().find(|(meth, p, _)| meth == "PUT" && p.ends_with(team)).cloned().expect("PUT");
        let body: Value = serde_json::from_str(&put.2).unwrap();
        assert_eq!(body["organizationId"], org);
        assert_eq!(crypto::decrypt_str(body["login"]["password"].as_str().unwrap(), &org_key).unwrap(), "rotated");

        // new entry inside a collection: created as organization item in that collection
        db.group_mut(shared_g).unwrap().add_entry().set_unprotected("Title", "Team wiki");
        let before = m.log.lock().unwrap().len();
        db = push(&mut remote, &db).unwrap();
        let post = m.log.lock().unwrap()[before..]
            .iter()
            .find(|(meth, p, _)| meth == "POST" && p == "/api/ciphers/create")
            .cloned()
            .expect("POST");
        let body: Value = serde_json::from_str(&post.2).unwrap();
        assert_eq!(body["collectionIds"], json!([shared]));
        assert_eq!(body["cipher"]["organizationId"], org);
        assert_eq!(db.iter_all_entries().filter(|e| e.get_title() == Some("Team wiki") && e.parent().id() == shared_g).count(), 1);

        // read-only item: refused before anything is uploaded
        let ro_id = EntryId::from(Uuid::parse_str(ro).unwrap());
        db.entry_mut(ro_id).unwrap().set_protected("Password", "nope");
        let before = m.log.lock().unwrap().len();
        assert_eq!(push(&mut remote, &db).err().as_deref(), Some("bw_readonly"));
        assert_eq!(writes(&m, before), 0);

        // directly in the organization (no collection) or moved out of it: refused as well
        let mut db = pull(&mut remote, &title).unwrap();
        db.group_mut(org_g).unwrap().add_entry().set_unprotected("Title", "Loose");
        assert_eq!(push(&mut remote, &db).err().as_deref(), Some("bw_org_collection"));
        let mut db = pull(&mut remote, &title).unwrap();
        let root = db.root().id();
        db.entry_mut(team_id).unwrap().move_to(root).unwrap();
        assert_eq!(push(&mut remote, &db).err().as_deref(), Some("bw_org_move"));
        forget(&path);
    }
}
