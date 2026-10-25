//! KeePassXC-Browser protocol, so the existing browser extension works with AnotherKeepass.
//!
//! Extension ⇄ native-messaging proxy (keepassxc-proxy, or our own exe in proxy mode)
//! ⇄ local socket ⇄ this server. Messages are JSON; payloads are NaCl `crypto_box`
//! encrypted with per-session keys. Associations and per-entry permissions are stored
//! exactly where KeePassXC stores them, so the same .kdbx works with both apps.

use std::collections::HashMap;

use base64::{Engine, engine::general_purpose::STANDARD as B64};
use crypto_box::{
    PublicKey, SalsaBox, SecretKey,
    aead::{Aead, OsRng, rand_core::RngCore},
};
use keepass::Database;
use keepass::db::{CustomDataItem, CustomDataValue, Entry, EntryId, GroupId, Times, fields};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::passkeys;
use crate::vault::{OpenVault, VaultDto, Vaults};

/// Reported to the extension; it enables features by version (2.7.x = current protocol).
pub const PROTOCOL_VERSION: &str = "2.7.10";
const ASSOC_PREFIX: &str = "KPXC_BROWSER_";
const ENTRY_SETTINGS: &str = "KeePassXC-Browser Settings";
const DEFAULT_GROUP: &str = "KeePassXC-Browser Passwords";
const ADDITIONAL_URL: &str = "KP2A_URL";

// error codes of the KeePassXC protocol
const E_DB_NOT_OPENED: u32 = 1;
const E_HASH_NOT_RECEIVED: u32 = 2;
const E_CLIENT_KEY_NOT_RECEIVED: u32 = 3;
const E_CANNOT_DECRYPT: u32 = 4;
const E_CANCELLED_OR_DENIED: u32 = 6;
const E_ASSOCIATION_FAILED: u32 = 8;
const E_INCORRECT_ACTION: u32 = 12;
const E_NO_URL: u32 = 14;
const E_NO_LOGINS: u32 = 15;
const E_NO_GROUPS: u32 = 16;
const E_CANNOT_CREATE_GROUP: u32 = 17;
const E_NO_VALID_UUID: u32 = 18;
const E_ALL_DENIED: u32 = 19;

fn error_text(code: u32) -> &'static str {
    match code {
        E_DB_NOT_OPENED => "Database not opened",
        E_HASH_NOT_RECEIVED => "Database hash not available",
        E_CLIENT_KEY_NOT_RECEIVED => "Client public key not received",
        E_CANNOT_DECRYPT => "Cannot decrypt message",
        E_CANCELLED_OR_DENIED => "Action cancelled or denied",
        E_ASSOCIATION_FAILED => "Association failed",
        E_INCORRECT_ACTION => "Incorrect action",
        E_NO_URL => "No URL provided",
        E_NO_LOGINS => "No logins found",
        E_NO_GROUPS => "No groups found",
        E_CANNOT_CREATE_GROUP => "Cannot create new group",
        E_NO_VALID_UUID => "No valid UUID provided",
        E_ALL_DENIED => "Access to all entries is denied",
        _ => "Unknown error",
    }
}

/// Browser-related options (mirrored from the settings page via desktop.json).
#[derive(Clone, Debug, Default)]
pub struct BrowserPrefs {
    pub enabled: bool,
    pub unlock: bool,
    pub match_scheme: bool,
    pub best_match: bool,
    pub allow_expired: bool,
    pub search_all: bool,
    pub no_access_confirm: bool,
    pub update_no_confirm: bool,
    pub kph: bool,
    /// HTTP Basic Auth requests (httpAuth: true) don't ask for access
    pub skip_basic_auth: bool,
    /// passkeys also for http://localhost (development)
    pub localhost_passkeys: bool,
}

/// Questions for the user. Answers come back as JSON (None = denied / timed out).
pub enum Ask {
    Associate,
    Access {
        host: String,
        entries: Vec<Value>,
    },
    Update {
        title: String,
        username: String,
    },
    /// the extension wants to delete an entry
    Delete {
        title: String,
        username: String,
    },
    /// new passkey; `existing` = entries of the same account that could take it instead
    PasskeyRegister {
        rp_id: String,
        username: String,
        existing: Vec<Value>,
    },
    /// sign in with one of these passkeys
    PasskeyGet {
        rp_id: String,
        entries: Vec<Value>,
    },
}

/// What the protocol needs from the app (implemented by the Tauri app and by tests).
pub trait Host: Send + Sync + 'static {
    fn vaults(&self) -> &Vaults;
    fn prefs(&self) -> BrowserPrefs;
    /// vault the extension talks to (its hash identifies the "database")
    fn active_vault(&self) -> Option<String>;
    fn ask(&self, ask: Ask) -> Option<Value>;
    fn vault_changed(&self, dto: VaultDto);
    fn lock_all(&self);
    fn show_window(&self);
    fn autotype_search(&self, search: &str);
}

// ---------------------------------------------------------------- session crypto

pub struct Session {
    secret: SecretKey,
    client: Option<PublicKey>,
    client_b64: String,
    associated: bool,
    /// vaults this client proved an association for (associate / test-associate)
    vaults: std::collections::HashSet<String>,
}

impl Default for Session {
    fn default() -> Self {
        Self {
            secret: SecretKey::generate(&mut OsRng),
            client: None,
            client_b64: String::new(),
            associated: false,
            vaults: Default::default(),
        }
    }
}

/// libsodium's sodium_increment: little-endian +1 over the whole nonce.
pub fn increment(nonce: &[u8]) -> Vec<u8> {
    let mut n = nonce.to_vec();
    for b in n.iter_mut() {
        let (v, carry) = b.overflowing_add(1);
        *b = v;
        if !carry {
            break;
        }
    }
    n
}

fn nonce_of(v: &Value) -> Option<[u8; 24]> {
    B64.decode(v["nonce"].as_str()?).ok()?.try_into().ok()
}

fn error_reply(action: &str, code: u32) -> Value {
    json!({ "action": action, "errorCode": code.to_string(), "error": error_text(code) })
}

/// Database identity for the extension: SHA-256 (hex) of the root group UUID as 32 hex chars.
pub fn db_hash(db: &Database) -> String {
    // server accounts are rebuilt on every sync: hash their stable account id instead of the root uuid
    if let Some(account) = cd_string(db.meta.custom_data.get(crate::bitwarden::CD_ACCOUNT)) {
        return hex(&Sha256::digest(account.as_bytes()));
    }
    hex(&Sha256::digest(db.root().id().uuid().simple().to_string().as_bytes()))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn uuid_hex(id: Uuid) -> String {
    id.simple().to_string()
}

fn parse_uuid_hex(s: &str) -> Option<Uuid> {
    Uuid::parse_str(s).ok()
}

/// One incoming message → one reply. May block on user confirmation (`Host::ask`).
pub fn handle(host: &dyn Host, s: &mut Session, req: &Value) -> Value {
    let action = req["action"].as_str().unwrap_or_default().to_string();

    if action == "change-public-keys" {
        let (Some(key), Some(nonce)) = (req["publicKey"].as_str(), nonce_of(req)) else {
            return error_reply(&action, E_CLIENT_KEY_NOT_RECEIVED);
        };
        let Some(pk) = B64.decode(key).ok().and_then(|b| PublicKey::from_slice(&b).ok()) else {
            return error_reply(&action, E_CLIENT_KEY_NOT_RECEIVED);
        };
        *s = Session { client: Some(pk), client_b64: key.to_string(), ..Session::default() };
        return json!({
            "action": action,
            "version": PROTOCOL_VERSION,
            "publicKey": B64.encode(s.secret.public_key().as_bytes()),
            "nonce": B64.encode(increment(&nonce)),
            "success": "true",
        });
    }

    let Some(client) = s.client.clone() else { return error_reply(&action, E_CLIENT_KEY_NOT_RECEIVED) };
    let Some(nonce) = nonce_of(req) else { return error_reply(&action, E_CANNOT_DECRYPT) };
    let cbox = SalsaBox::new(&client, &s.secret);
    let payload: Value = match req["message"].as_str() {
        Some(m) => match B64.decode(m).ok().and_then(|ct| cbox.decrypt(&nonce.into(), ct.as_slice()).ok()) {
            Some(plain) => serde_json::from_slice(&plain).unwrap_or(Value::Null),
            None => return error_reply(&action, E_CANNOT_DECRYPT),
        },
        // only the key exchange travels unencrypted; anything else is refused
        None => return error_reply(&action, E_CANNOT_DECRYPT),
    };
    let p = &payload;

    let open = host.vaults().0.lock().map(|m| !m.is_empty()).unwrap_or(false);
    if !open {
        if p["triggerUnlock"].as_str() == Some("true") && host.prefs().unlock {
            host.show_window();
        }
        return error_reply(&action, E_DB_NOT_OPENED);
    }

    let result = match action.as_str() {
        "get-databasehash" => active_hash(host).map(|h| params(&[("hash", json!(h))])).ok_or(E_HASH_NOT_RECEIVED),
        "associate" => associate(host, s, p),
        "test-associate" => test_associate(host, s, p),
        "get-logins" => get_logins(host, s, p),
        "generate-password" => Ok(generate_password()),
        "set-login" => set_login(host, s, p),
        "lock-database" if s.associated => {
            host.lock_all();
            Ok(Map::new())
        }
        "lock-database" => Err(E_ASSOCIATION_FAILED),
        "get-totp" => get_totp(host, s, p),
        "get-database-groups" => database_groups(host, s),
        "create-new-group" => create_group(host, s, p),
        // always with the entry picker: a page must not make us type into a window it chose
        "request-autotype" if s.associated => {
            host.autotype_search(p["search"].as_str().unwrap_or_default());
            Ok(Map::new())
        }
        "request-autotype" => Err(E_ASSOCIATION_FAILED),
        "delete-entry" => delete_entry(host, s, p),
        "passkeys-register" => passkeys_register(host, s, p),
        "passkeys-get" => passkeys_get(host, s, p),
        _ => Err(E_INCORRECT_ACTION),
    };

    match result {
        Ok(mut m) => {
            let next = increment(&nonce);
            m.insert("version".into(), json!(PROTOCOL_VERSION));
            m.insert("success".into(), json!("true"));
            m.insert("nonce".into(), json!(B64.encode(&next)));
            let plain = serde_json::to_vec(&Value::Object(m)).unwrap_or_default();
            match cbox.encrypt(next.as_slice().into(), plain.as_slice()) {
                Ok(ct) => json!({ "action": action, "message": B64.encode(ct), "nonce": B64.encode(&next) }),
                Err(_) => error_reply(&action, 7),
            }
        }
        Err(code) => error_reply(&action, code),
    }
}

fn params(kv: &[(&str, Value)]) -> Map<String, Value> {
    kv.iter().map(|(k, v)| (k.to_string(), v.clone())).collect()
}

type ActionResult = Result<Map<String, Value>, u32>;

// ---------------------------------------------------------------- vault access helpers

fn active_id(host: &dyn Host) -> Option<String> {
    let map = host.vaults().0.lock().ok()?;
    host.active_vault().filter(|id| map.contains_key(id)).or_else(|| map.keys().next().cloned())
}

fn active_hash(host: &dyn Host) -> Option<String> {
    let id = active_id(host)?;
    let map = host.vaults().0.lock().ok()?;
    Some(db_hash(map.get(&id)?.db()))
}

fn cd_string(item: Option<&CustomDataItem>) -> Option<String> {
    match item?.value.as_ref()? {
        CustomDataValue::String(s) => Some(s.clone()),
        _ => None,
    }
}

fn cd_item(s: String) -> CustomDataItem {
    CustomDataItem { value: Some(CustomDataValue::String(s)), last_modification_time: Some(Times::now()) }
}

/// Persist a vault after a browser change and refresh the UI.
fn save_and_notify(host: &dyn Host, id: &str, v: &mut OpenVault) -> Result<(), u32> {
    v.persist().map_err(|_| E_CANCELLED_OR_DENIED)?;
    host.vault_changed(v.listing(id));
    Ok(())
}

/// Vaults whose stored association matches one of the extension's keys.
fn associated_vaults(host: &dyn Host, keys: &[(String, String)]) -> Vec<String> {
    let Ok(map) = host.vaults().0.lock() else { return vec![] };
    map.iter()
        .filter(|(_, v)| {
            keys.iter().any(|(id, key)| cd_string(v.db().meta.custom_data.get(&format!("{ASSOC_PREFIX}{id}"))).as_deref() == Some(key))
        })
        .map(|(id, _)| id.clone())
        .collect()
}

/// Vaults a client may touch by entry UUID: the ones it proved an association for.
fn allowed_vaults(host: &dyn Host, s: &Session, p: &Value) -> std::collections::HashSet<String> {
    let mut v = s.vaults.clone();
    v.extend(associated_vaults(host, &keys_of(p)));
    v
}

fn keys_of(p: &Value) -> Vec<(String, String)> {
    p["keys"]
        .as_array()
        .map(|a| a.iter().filter_map(|k| Some((k["id"].as_str()?.to_string(), k["key"].as_str()?.to_string()))).collect())
        .unwrap_or_default()
}

// ---------------------------------------------------------------- actions

fn associate(host: &dyn Host, s: &mut Session, p: &Value) -> ActionResult {
    // the payload key must be the session key the extension negotiated
    if p["key"].as_str() != Some(s.client_b64.as_str()) {
        return Err(E_ASSOCIATION_FAILED);
    }
    let id_key = p["idKey"].as_str().filter(|k| !k.is_empty()).or(p["key"].as_str()).ok_or(E_ASSOCIATION_FAILED)?.to_string();
    let answer = host.ask(Ask::Associate).ok_or(E_CANCELLED_OR_DENIED)?;
    let name = answer["name"].as_str().map(str::trim).filter(|n| !n.is_empty()).ok_or(E_CANCELLED_OR_DENIED)?.to_string();
    let vid = active_id(host).ok_or(E_DB_NOT_OPENED)?;
    let mut map = host.vaults().0.lock().map_err(|_| E_ASSOCIATION_FAILED)?;
    let v = map.get_mut(&vid).ok_or(E_DB_NOT_OPENED)?;
    v.db_mut().meta.custom_data.insert(format!("{ASSOC_PREFIX}{name}"), cd_item(id_key));
    save_and_notify(host, &vid, v)?;
    s.associated = true;
    s.vaults.insert(vid.clone());
    Ok(params(&[("hash", json!(db_hash(v.db()))), ("id", json!(name))]))
}

fn test_associate(host: &dyn Host, s: &mut Session, p: &Value) -> ActionResult {
    let (Some(id), Some(key)) = (p["id"].as_str(), p["key"].as_str()) else { return Err(E_ASSOCIATION_FAILED) };
    let vid = active_id(host).ok_or(E_DB_NOT_OPENED)?;
    let map = host.vaults().0.lock().map_err(|_| E_ASSOCIATION_FAILED)?;
    let v = map.get(&vid).ok_or(E_DB_NOT_OPENED)?;
    if cd_string(v.db().meta.custom_data.get(&format!("{ASSOC_PREFIX}{id}"))).as_deref() != Some(key) {
        return Err(E_ASSOCIATION_FAILED);
    }
    s.associated = true;
    s.vaults.insert(vid.clone());
    Ok(params(&[("hash", json!(db_hash(v.db()))), ("id", json!(id))]))
}

// ---- URL matching (rules after KeePassXC: scheme, port, host, subdomains, www, KP2A_URL)

struct Site {
    scheme: String,
    host: String,
    port: Option<u16>,
    full: String,
    no_query: String,
}

fn site(raw: &str) -> Option<Site> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    let with_scheme = if raw.contains("://") { raw.to_string() } else { format!("https://{raw}") };
    let u = url::Url::parse(&with_scheme).ok()?;
    let host = u.host_str()?.trim_start_matches("www.").to_lowercase();
    // compare without scheme (checked separately) and without www.
    let port = u.port().map(|p| format!(":{p}")).unwrap_or_default();
    let no_query = format!("{host}{port}{}", u.path().trim_end_matches('/'));
    let full = match u.query() {
        Some(q) => format!("{no_query}?{q}"),
        None => no_query.clone(),
    };
    Some(Site { scheme: u.scheme().into(), host, port: u.port(), full, no_query })
}

/// Match score of one stored URL against the page (0 = no match), after KeePassXC's priorities.
fn score(entry_url: &str, page: &Site, form: Option<&Site>, match_scheme: bool) -> u32 {
    let Some(e) = site(entry_url) else { return 0 };
    if e.port.is_some() && e.port != page.port {
        return 0;
    }
    if match_scheme && entry_url.contains("://") && e.scheme != page.scheme {
        return 0;
    }
    if e.full == page.full || form.is_some_and(|f| e.full == f.full) {
        100
    } else if e.no_query == page.no_query {
        90
    } else if e.host == page.host {
        80
    } else if form.is_some_and(|f| e.host == f.host) {
        70
    } else if page.host.ends_with(&format!(".{}", e.host)) {
        60
    } else if form.is_some_and(|f| f.host.ends_with(&format!(".{}", e.host))) {
        50
    } else {
        0
    }
}

fn entry_score(e: &Entry, page: &Site, form: Option<&Site>, match_scheme: bool) -> u32 {
    let mut urls: Vec<&str> = e.get_url().into_iter().collect();
    urls.extend(e.fields.iter().filter(|(k, _)| k.starts_with(ADDITIONAL_URL)).map(|(_, v)| v.get().as_str()));
    urls.into_iter().map(|u| score(u, page, form, match_scheme)).max().unwrap_or(0)
}

/// Per-entry browser permissions, stored like KeePassXC: {"Allow":[hosts],"Deny":[hosts],"Realm":""}
fn entry_settings(e: &Entry) -> Value {
    cd_string(e.custom_data.get(ENTRY_SETTINGS)).and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_else(|| json!({}))
}

fn host_in(settings: &Value, list: &str, host: &str) -> bool {
    settings[list].as_array().is_some_and(|a| a.iter().any(|h| h.as_str() == Some(host)))
}

fn set_permission(e: &mut Entry, host: &str, allow: bool) {
    let mut s = entry_settings(e);
    let (add, remove) = if allow { ("Allow", "Deny") } else { ("Deny", "Allow") };
    let mut list: Vec<String> =
        s[add].as_array().map(|a| a.iter().filter_map(|h| h.as_str().map(String::from)).collect()).unwrap_or_default();
    if !list.iter().any(|h| h == host) {
        list.push(host.to_string());
    }
    s[add] = json!(list);
    if let Some(a) = s[remove].as_array_mut() {
        a.retain(|h| h.as_str() != Some(host));
    }
    if s.get("Realm").is_none() {
        s["Realm"] = json!("");
    }
    e.custom_data.insert(ENTRY_SETTINGS.into(), cd_item(s.to_string()));
}

fn entry_json(e: &Entry, group: &str, kph: bool, expired: bool) -> Value {
    let mut o = json!({
        "login": e.get_username().unwrap_or_default(),
        "name": e.get_title().unwrap_or_default(),
        "password": e.get_password().unwrap_or_default(),
        "uuid": uuid_hex(e.id().uuid()),
        "group": group,
        "skipAutoSubmit": if cd_string(e.custom_data.get("BrowserSkipAutoSubmit")).as_deref() == Some("true") { "true" } else { "false" },
    });
    if let Ok(code) = crate::vault::totp_code(e, fields::OTP) {
        o["totp"] = json!(code);
    }
    if expired {
        o["expired"] = json!("true");
    }
    if kph {
        let sf: Vec<Value> = e.fields.iter().filter(|(k, _)| k.starts_with("KPH: ")).map(|(k, v)| json!({ k.clone(): v.get() })).collect();
        o["stringFields"] = json!(sf);
    }
    o
}

fn get_logins(host: &dyn Host, s: &mut Session, p: &Value) -> ActionResult {
    if !s.associated {
        return Err(E_ASSOCIATION_FAILED);
    }
    let page = p["url"].as_str().and_then(site).ok_or(E_NO_URL)?;
    let form = p["submitUrl"].as_str().and_then(site);
    let prefs = host.prefs();
    let basic_auth_ok = prefs.skip_basic_auth && p["httpAuth"].as_bool().unwrap_or(false);
    let keys = keys_of(p);
    let mut vault_ids = associated_vaults(host, &keys);
    if !prefs.search_all {
        let active = active_id(host);
        vault_ids.retain(|v| Some(v) == active.as_ref());
    }
    if vault_ids.is_empty() {
        return Err(E_ASSOCIATION_FAILED);
    }

    let now = Times::now();
    // (vault, entry, score, permission: Some(true)=allowed Some(false)=denied None=ask)
    let mut found: Vec<(String, EntryId, u32, Option<bool>)> = Vec::new();
    {
        let map = host.vaults().0.lock().map_err(|_| E_NO_LOGINS)?;
        for vid in &vault_ids {
            let Some(v) = map.get(vid) else { continue };
            let db = v.db();
            let bin = db.recycle_bin().map(|g| g.id());
            for e in db.iter_all_entries() {
                // anything below the recycle bin counts as deleted
                let mut g = Some(e.parent().id());
                let mut trashed = false;
                while let Some(gid) = g {
                    if Some(gid) == bin {
                        trashed = true;
                        break;
                    }
                    g = db.group(gid).and_then(|x| x.parent().map(|p| p.id()));
                }
                let expired = e.times.expires == Some(true) && e.times.expiry < now;
                if trashed
                    || (expired && !prefs.allow_expired)
                    || cd_string(e.custom_data.get("BrowserHideEntry")).as_deref() == Some("true")
                {
                    continue;
                }
                let sc = entry_score(&e, &page, form.as_ref(), prefs.match_scheme);
                if sc == 0 {
                    continue;
                }
                let st = entry_settings(&e);
                let perm = if host_in(&st, "Deny", &page.host) {
                    Some(false)
                } else if host_in(&st, "Allow", &page.host) || prefs.no_access_confirm || basic_auth_ok {
                    Some(true)
                } else {
                    None
                };
                found.push((vid.clone(), e.id(), sc, perm));
            }
        }
    }
    if found.is_empty() {
        return Err(E_NO_LOGINS);
    }

    // ask once for all entries the user hasn't decided on for this host
    let unknown: Vec<Value> = {
        let map = host.vaults().0.lock().map_err(|_| E_NO_LOGINS)?;
        found.iter().filter(|f| f.3.is_none()).filter_map(|(vid, id, _, _)| {
            let e = map.get(vid)?.db().entry(*id)?;
            Some(json!({ "vault": vid, "uuid": uuid_hex(id.uuid()), "title": e.get_title().unwrap_or_default(), "username": e.get_username().unwrap_or_default() }))
        }).collect()
    };
    if !unknown.is_empty() {
        let answer = host.ask(Ask::Access { host: page.host.clone(), entries: unknown.clone() });
        let allowed: Vec<String> = answer
            .as_ref()
            .and_then(|a| a["allow"].as_array())
            .map(|a| a.iter().filter_map(|u| u.as_str().map(String::from)).collect())
            .unwrap_or_default();
        let remember = answer.as_ref().and_then(|a| a["remember"].as_bool()).unwrap_or(false);
        for f in found.iter_mut().filter(|f| f.3.is_none()) {
            f.3 = Some(allowed.contains(&uuid_hex(f.1.uuid())));
        }
        if remember {
            let mut map = host.vaults().0.lock().map_err(|_| E_NO_LOGINS)?;
            let mut touched: Vec<String> = Vec::new();
            for u in &unknown {
                let vid = u["vault"].as_str().unwrap_or_default().to_string();
                let Some(uuid) = u["uuid"].as_str().and_then(parse_uuid_hex) else { continue };
                if let Some(mut e) = map.get_mut(&vid).and_then(|v| v.db_mut().entry_mut(EntryId::from(uuid))) {
                    set_permission(&mut e, &page.host, allowed.contains(&uuid_hex(uuid)));
                    if !touched.contains(&vid) {
                        touched.push(vid);
                    }
                }
            }
            for vid in touched {
                if let Some(v) = map.get_mut(&vid) {
                    let _ = save_and_notify(host, &vid, v);
                }
            }
        }
    }

    found.retain(|f| f.3 == Some(true));
    if found.is_empty() {
        return Err(E_ALL_DENIED);
    }
    found.sort_by_key(|f| std::cmp::Reverse(f.2));
    if prefs.best_match {
        let top = found[0].2;
        found.retain(|f| f.2 == top);
    }
    let map = host.vaults().0.lock().map_err(|_| E_NO_LOGINS)?;
    let entries: Vec<Value> = found
        .iter()
        .filter_map(|(vid, id, _, _)| {
            let db = map.get(vid)?.db();
            let e = db.entry(*id)?;
            let expired = e.times.expires == Some(true) && e.times.expiry < now;
            Some(entry_json(&e, &e.parent().name, prefs.kph, expired))
        })
        .collect();
    let hash = active_hash_locked(&map, host);
    Ok(params(&[("count", json!(entries.len())), ("entries", json!(entries)), ("hash", json!(hash)), ("id", p["id"].clone())]))
}

fn active_hash_locked(map: &HashMap<String, OpenVault>, host: &dyn Host) -> String {
    host.active_vault().and_then(|id| map.get(&id)).or_else(|| map.values().next()).map(|v| db_hash(v.db())).unwrap_or_default()
}

fn generate_password() -> Map<String, Value> {
    // 20 chars from the same alphabet as the UI generator, unbiased
    const SET: &[u8] = b"abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!#$%&*+-=?@_.";
    let limit = 256 - (256 % SET.len());
    let mut pw = String::with_capacity(20);
    while pw.len() < 20 {
        let mut b = [0u8; 1];
        OsRng.fill_bytes(&mut b);
        if (b[0] as usize) < limit {
            pw.push(SET[b[0] as usize % SET.len()] as char);
        }
    }
    // 2.7 reads "password"; older extensions read entries[0].password
    params(&[("password", json!(pw.clone())), ("entries", json!([{ "login": 20 * 6, "password": pw }]))])
}

fn default_group(db: &mut Database) -> GroupId {
    let bin = db.recycle_bin().map(|g| g.id());
    if let Some(g) = db.iter_all_groups().find(|g| g.name == DEFAULT_GROUP && Some(g.id()) != bin) {
        return g.id();
    }
    let mut root = db.root_mut();
    let mut g = root.add_group();
    g.name = DEFAULT_GROUP.into();
    g.set_icon_builtin(1);
    g.id()
}

fn set_login(host: &dyn Host, s: &mut Session, p: &Value) -> ActionResult {
    if !s.associated {
        return Err(E_ASSOCIATION_FAILED);
    }
    let url = p["url"].as_str().filter(|u| !u.is_empty()).ok_or(E_NO_URL)?.to_string();
    let login = p["login"].as_str().unwrap_or_default().to_string();
    let password = p["password"].as_str().unwrap_or_default().to_string();
    let vid = active_id(host).ok_or(E_DB_NOT_OPENED)?;
    let existing = p["uuid"].as_str().filter(|u| !u.is_empty());

    if let Some(u) = existing {
        let uuid = parse_uuid_hex(u).ok_or(E_NO_VALID_UUID)?;
        if !host.prefs().update_no_confirm {
            let allowed = allowed_vaults(host, s, p);
            let (title, username) = {
                let map = host.vaults().0.lock().map_err(|_| E_CANCELLED_OR_DENIED)?;
                let e = map
                    .iter()
                    .filter(|(k, _)| allowed.contains(*k))
                    .find_map(|(_, v)| v.db().entry(EntryId::from(uuid)))
                    .ok_or(E_NO_VALID_UUID)?;
                (e.get_title().unwrap_or_default().to_string(), e.get_username().unwrap_or_default().to_string())
            };
            host.ask(Ask::Update { title, username }).filter(|a| a["ok"].as_bool() == Some(true)).ok_or(E_CANCELLED_OR_DENIED)?;
        }
        let allowed = allowed_vaults(host, s, p);
        let mut map = host.vaults().0.lock().map_err(|_| E_CANCELLED_OR_DENIED)?;
        let target = map
            .iter()
            .filter(|(k, _)| allowed.contains(*k))
            .find(|(_, v)| v.db().entry(EntryId::from(uuid)).is_some())
            .map(|(k, _)| k.clone())
            .ok_or(E_NO_VALID_UUID)?;
        let v = map.get_mut(&target).ok_or(E_NO_VALID_UUID)?;
        {
            let mut e = v.db_mut().entry_mut(EntryId::from(uuid)).ok_or(E_NO_VALID_UUID)?;
            let mut t = e.track_changes();
            let mut e = t.as_mut();
            e.set_unprotected(fields::USERNAME, login);
            e.set_protected(fields::PASSWORD, password);
            e.times.last_modification = Some(Times::now());
        }
        save_and_notify(host, &target, v)?;
    } else {
        let mut map = host.vaults().0.lock().map_err(|_| E_CANCELLED_OR_DENIED)?;
        let v = map.get_mut(&vid).ok_or(E_DB_NOT_OPENED)?;
        let db = v.db_mut();
        let group = p["groupUuid"]
            .as_str()
            .and_then(parse_uuid_hex)
            .map(GroupId::from_uuid)
            .filter(|g| db.group(*g).is_some())
            .unwrap_or_else(|| default_group(db));
        let title = site(&url).map(|s| s.host).unwrap_or_else(|| url.clone());
        {
            let mut g = db.group_mut(group).ok_or(E_CANCELLED_OR_DENIED)?;
            let mut e = g.add_entry();
            e.set_unprotected(fields::TITLE, title);
            e.set_unprotected(fields::USERNAME, login);
            e.set_protected(fields::PASSWORD, password);
            e.set_unprotected(fields::URL, url);
            let now = Times::now();
            e.times.creation = Some(now);
            e.times.last_modification = Some(now);
            e.custom_data.insert("AnotherKeepass.Type".into(), cd_item("login".into()));
        }
        save_and_notify(host, &vid, v)?;
    }
    let hash = active_hash(host).unwrap_or_default();
    Ok(params(&[("count", Value::Null), ("entries", Value::Null), ("error", json!("success")), ("hash", json!(hash))]))
}

fn get_totp(host: &dyn Host, s: &mut Session, p: &Value) -> ActionResult {
    if !s.associated {
        return Err(E_ASSOCIATION_FAILED);
    }
    let uuid = p["uuid"].as_str().and_then(parse_uuid_hex).ok_or(E_NO_VALID_UUID)?;
    let allowed = allowed_vaults(host, s, p);
    let map = host.vaults().0.lock().map_err(|_| E_NO_VALID_UUID)?;
    let e = map.iter().filter(|(k, _)| allowed.contains(*k)).find_map(|(_, v)| v.db().entry(EntryId::from(uuid))).ok_or(E_NO_VALID_UUID)?;
    Ok(params(&[("totp", json!(crate::vault::totp_code(&e, fields::OTP).unwrap_or_default()))]))
}

fn group_tree(db: &Database, id: GroupId, bin: Option<GroupId>) -> Value {
    let g = db.group(id).expect("group exists");
    let children: Vec<Value> = g.group_ids().filter(|c| Some(*c) != bin).map(|c| group_tree(db, c, bin)).collect();
    json!({ "name": g.name, "uuid": uuid_hex(id.uuid()), "children": children })
}

fn database_groups(host: &dyn Host, s: &mut Session) -> ActionResult {
    if !s.associated {
        return Err(E_ASSOCIATION_FAILED);
    }
    let vid = active_id(host).ok_or(E_DB_NOT_OPENED)?;
    let map = host.vaults().0.lock().map_err(|_| E_NO_GROUPS)?;
    let db = map.get(&vid).ok_or(E_NO_GROUPS)?.db();
    let tree = group_tree(db, db.root().id(), db.recycle_bin().map(|g| g.id()));
    Ok(params(&[("defaultGroup", json!("")), ("defaultGroupAlwaysAllow", json!(false)), ("groups", json!({ "groups": [tree] }))]))
}

fn create_group(host: &dyn Host, s: &mut Session, p: &Value) -> ActionResult {
    if !s.associated {
        return Err(E_ASSOCIATION_FAILED);
    }
    let path = p["groupName"].as_str().map(str::trim).filter(|n| !n.is_empty()).ok_or(E_CANNOT_CREATE_GROUP)?;
    let vid = active_id(host).ok_or(E_DB_NOT_OPENED)?;
    let mut map = host.vaults().0.lock().map_err(|_| E_CANNOT_CREATE_GROUP)?;
    let v = map.get_mut(&vid).ok_or(E_CANNOT_CREATE_GROUP)?;
    let db = v.db_mut();
    // "A/B/C": reuse existing levels, create the missing ones
    let mut cur = db.root().id();
    let mut last = String::new();
    for name in path.split('/').filter(|n| !n.is_empty()) {
        let found = db.group(cur).and_then(|g| g.groups().find(|c| c.name == name).map(|c| c.id()));
        cur = match found {
            Some(id) => id,
            None => {
                let mut g = db.group_mut(cur).ok_or(E_CANNOT_CREATE_GROUP)?;
                let mut n = g.add_group();
                n.name = name.into();
                n.id()
            }
        };
        last = name.into();
    }
    save_and_notify(host, &vid, v)?;
    Ok(params(&[("name", json!(last)), ("uuid", json!(uuid_hex(cur.uuid())))]))
}

fn delete_entry(host: &dyn Host, s: &mut Session, p: &Value) -> ActionResult {
    if !s.associated {
        return Err(E_ASSOCIATION_FAILED);
    }
    let uuid = p["uuid"].as_str().and_then(parse_uuid_hex).ok_or(E_NO_VALID_UUID)?;
    let allowed = allowed_vaults(host, s, p);
    let (title, username) = {
        let map = host.vaults().0.lock().map_err(|_| E_NO_VALID_UUID)?;
        let e =
            map.iter().filter(|(k, _)| allowed.contains(*k)).find_map(|(_, v)| v.db().entry(EntryId::from(uuid))).ok_or(E_NO_VALID_UUID)?;
        (e.get_title().unwrap_or_default().to_string(), e.get_username().unwrap_or_default().to_string())
    };
    // deleting from a web page always needs a yes
    host.ask(Ask::Delete { title, username }).filter(|a| a["ok"].as_bool() == Some(true)).ok_or(E_CANCELLED_OR_DENIED)?;
    let mut map = host.vaults().0.lock().map_err(|_| E_NO_VALID_UUID)?;
    let vid = map
        .iter()
        .filter(|(k, _)| allowed.contains(*k))
        .find(|(_, v)| v.db().entry(EntryId::from(uuid)).is_some())
        .map(|(k, _)| k.clone())
        .ok_or(E_NO_VALID_UUID)?;
    let v = map.get_mut(&vid).ok_or(E_NO_VALID_UUID)?;
    v.trash_entry(EntryId::from(uuid)).map_err(|_| E_NO_VALID_UUID)?;
    save_and_notify(host, &vid, v)?;
    Ok(params(&[("success", json!("true"))]))
}

// ---------------------------------------------------------------- passkeys

/// Vaults the extension may use (associated; only the active one unless "search all").
fn usable_vaults(host: &dyn Host, p: &Value) -> Vec<String> {
    let mut ids = associated_vaults(host, &keys_of(p));
    if !host.prefs().search_all {
        let active = active_id(host);
        ids.retain(|v| Some(v) == active.as_ref());
    }
    ids
}

fn field(e: &Entry, name: &str) -> String {
    e.get(name).unwrap_or_default().to_string()
}

/// Passkey entries for an RP: (vault, entry, credential id).
fn passkey_entries(host: &dyn Host, vaults: &[String], rp: &str) -> Vec<(String, EntryId, String)> {
    let Ok(map) = host.vaults().0.lock() else { return vec![] };
    let mut out = Vec::new();
    for vid in vaults {
        let Some(v) = map.get(vid) else { continue };
        let db = v.db();
        let bin = db.recycle_bin().map(|g| g.id());
        for e in db.iter_all_entries() {
            if field(&e, passkeys::PRIVATE_KEY).is_empty() || field(&e, passkeys::RELYING_PARTY) != rp {
                continue;
            }
            let mut g = Some(e.parent().id());
            let mut trashed = false;
            while let Some(gid) = g {
                if Some(gid) == bin {
                    trashed = true;
                    break;
                }
                g = db.group(gid).and_then(|x| x.parent().map(|p| p.id()));
            }
            if trashed {
                continue;
            }
            let cred = e.get(passkeys::GENERATED_USER_ID).map(String::from).unwrap_or_else(|| field(&e, passkeys::CREDENTIAL_ID));
            out.push((vid.clone(), e.id(), cred));
        }
    }
    out
}

fn entry_brief(map: &HashMap<String, OpenVault>, vid: &str, id: EntryId) -> Option<Value> {
    let e = map.get(vid)?.db().entry(id)?;
    let user = e.get(passkeys::USERNAME).filter(|u| !u.is_empty()).or_else(|| e.get_username()).unwrap_or_default();
    Some(json!({ "vault": vid, "uuid": uuid_hex(id.uuid()), "title": e.get_title().unwrap_or_default(), "username": user }))
}

fn write_passkey(e: &mut keepass::db::EntryMut<'_>, reg: &passkeys::Registration, cred_id: &str, pem: &str) {
    e.set_unprotected(passkeys::USERNAME, reg.username.clone());
    e.set_protected(passkeys::CREDENTIAL_ID, cred_id.to_string());
    e.set_protected(passkeys::PRIVATE_KEY, pem.to_string());
    e.set_unprotected(passkeys::RELYING_PARTY, reg.rp_id.clone());
    e.set_protected(passkeys::USER_HANDLE, reg.user_handle.clone());
    e.set_unprotected(passkeys::FLAG_BE, "1");
    e.set_unprotected(passkeys::FLAG_BS, "1");
    if !e.tags.iter().any(|t| t == "Passkey") {
        e.tags.push("Passkey".into());
    }
}

fn passkey_reply(v: Value) -> ActionResult {
    Ok(params(&[("response", v)]))
}

fn passkeys_register(host: &dyn Host, s: &mut Session, p: &Value) -> ActionResult {
    if !s.associated {
        return Err(E_ASSOCIATION_FAILED);
    }
    let pk = &p["publicKey"];
    if !pk.is_object() || pk.as_object().is_some_and(|o| o.is_empty()) {
        return Err(passkeys::E_EMPTY_PUBLIC_KEY);
    }
    let origin = p["origin"].as_str().unwrap_or_default();
    if !passkeys::origin_allowed(origin, host.prefs().localhost_passkeys) {
        return Err(passkeys::E_INVALID_URL);
    }
    let reg = match passkeys::check_create(pk, origin) {
        Ok(r) => r,
        Err(code) => return passkey_reply(passkeys::error(code)),
    };
    let vaults = usable_vaults(host, p);
    let vid = active_id(host).filter(|a| vaults.contains(a)).or_else(|| vaults.first().cloned()).ok_or(E_ASSOCIATION_FAILED)?;
    let known = passkey_entries(host, &vaults, &reg.rp_id);
    if known.iter().any(|(_, _, c)| reg.exclude.contains(c)) {
        return passkey_reply(passkeys::error(passkeys::E_EXCLUDED));
    }
    // same account already has a passkey here → offer to replace it
    let existing: Vec<Value> = {
        let map = host.vaults().0.lock().map_err(|_| E_CANCELLED_OR_DENIED)?;
        known
            .iter()
            .filter(|(v, id, _)| {
                map.get(v).and_then(|x| x.db().entry(*id)).is_some_and(|e| field(&e, passkeys::USER_HANDLE) == reg.user_handle)
            })
            .filter_map(|(v, id, _)| entry_brief(&map, v, *id))
            .collect()
    };
    let Some(answer) = host
        .ask(Ask::PasskeyRegister { rp_id: reg.rp_id.clone(), username: reg.username.clone(), existing })
        .filter(|a| a["ok"].as_bool() == Some(true))
    else {
        return passkey_reply(passkeys::error(passkeys::E_CANCELED));
    };
    let attachment = pk["authenticatorSelection"]["authenticatorAttachment"].as_str();
    let (credential, cred_id, pem) = match passkeys::create(&reg, attachment) {
        Ok(x) => x,
        Err(code) => return passkey_reply(passkeys::error(code)),
    };

    let mut map = host.vaults().0.lock().map_err(|_| E_CANCELLED_OR_DENIED)?;
    let target = answer["uuid"].as_str().and_then(parse_uuid_hex).map(EntryId::from);
    let target_vault = target.and_then(|t| map.iter().find(|(_, v)| v.db().entry(t).is_some()).map(|(k, _)| k.clone())).unwrap_or(vid);
    let v = map.get_mut(&target_vault).ok_or(E_DB_NOT_OPENED)?;
    match target {
        Some(id) if v.db().entry(id).is_some() => {
            let mut e = v.db_mut().entry_mut(id).ok_or(E_NO_VALID_UUID)?;
            let mut t = e.track_changes();
            let mut e = t.as_mut();
            write_passkey(&mut e, &reg, &cred_id, &pem);
        }
        _ => {
            let db = v.db_mut();
            let group_name = p["groupName"].as_str().filter(|g| !g.is_empty()).unwrap_or(passkeys::DEFAULT_GROUP).to_string();
            let bin = db.recycle_bin().map(|g| g.id());
            let root = db.root().id();
            let found = db.iter_all_groups().find(|g| g.name == group_name && Some(g.id()) != bin).map(|g| g.id());
            let group = match found {
                Some(g) => g,
                None => {
                    let mut r = db.group_mut(root).ok_or(E_CANNOT_CREATE_GROUP)?;
                    let mut g = r.add_group();
                    g.name = group_name;
                    g.id()
                }
            };
            let mut g = db.group_mut(group).ok_or(E_CANNOT_CREATE_GROUP)?;
            let mut e = g.add_entry();
            e.set_unprotected(fields::TITLE, format!("{} (Passkey)", reg.rp_name));
            e.set_unprotected(fields::USERNAME, reg.username.clone());
            e.set_unprotected(fields::URL, origin.to_string());
            let now = Times::now();
            e.times.creation = Some(now);
            e.times.last_modification = Some(now);
            e.custom_data.insert("AnotherKeepass.Type".into(), cd_item("login".into()));
            write_passkey(&mut e, &reg, &cred_id, &pem);
        }
    }
    save_and_notify(host, &target_vault, v)?;
    passkey_reply(credential)
}

fn passkeys_get(host: &dyn Host, s: &mut Session, p: &Value) -> ActionResult {
    if !s.associated {
        return Err(E_ASSOCIATION_FAILED);
    }
    let pk = &p["publicKey"];
    if !pk.is_object() || pk.as_object().is_some_and(|o| o.is_empty()) {
        return Err(passkeys::E_EMPTY_PUBLIC_KEY);
    }
    let origin = p["origin"].as_str().unwrap_or_default();
    if !passkeys::origin_allowed(origin, host.prefs().localhost_passkeys) {
        return Err(passkeys::E_INVALID_URL);
    }
    let (rp, allowed) = match passkeys::check_get(pk, origin) {
        Ok(x) => x,
        Err(code) => return passkey_reply(passkeys::error(code)),
    };
    if pk["allowCredentials"].as_array().is_some_and(|a| !a.is_empty()) && allowed.is_empty() {
        return passkey_reply(passkeys::error(E_NO_LOGINS));
    }
    let vaults = usable_vaults(host, p);
    let all = passkey_entries(host, &vaults, &rp); // locks the vaults itself: call before taking the lock below
    let candidates: Vec<(String, EntryId, String)> = {
        let map = host.vaults().0.lock().map_err(|_| E_CANCELLED_OR_DENIED)?;
        all.into_iter()
            .filter(|(v, id, cred)| {
                allowed.contains(cred)
                    || (allowed.is_empty()
                        && map.get(v).and_then(|x| x.db().entry(*id)).is_some_and(|e| !field(&e, passkeys::USER_HANDLE).is_empty()))
            })
            .collect()
    };
    if candidates.is_empty() {
        return passkey_reply(passkeys::error(E_NO_LOGINS));
    }
    let briefs: Vec<Value> = {
        let map = host.vaults().0.lock().map_err(|_| E_CANCELLED_OR_DENIED)?;
        candidates.iter().filter_map(|(v, id, _)| entry_brief(&map, v, *id)).collect()
    };
    let Some(choice) =
        host.ask(Ask::PasskeyGet { rp_id: rp.clone(), entries: briefs }).and_then(|a| a["uuid"].as_str().and_then(parse_uuid_hex))
    else {
        return passkey_reply(passkeys::error(passkeys::E_CANCELED));
    };
    let (vid, id, cred) = candidates.into_iter().find(|(_, id, _)| id.uuid() == choice).ok_or(E_NO_VALID_UUID)?;
    let map = host.vaults().0.lock().map_err(|_| E_CANCELLED_OR_DENIED)?;
    let e = map.get(&vid).and_then(|v| v.db().entry(id)).ok_or(E_NO_VALID_UUID)?;
    let flag = |k: &str| e.get(k).map(|v| v == "1" || v.eq_ignore_ascii_case("true")).unwrap_or(true);
    let reply = passkeys::assert(
        pk,
        origin,
        &rp,
        &cred,
        &field(&e, passkeys::USER_HANDLE),
        &field(&e, passkeys::PRIVATE_KEY),
        flag(passkeys::FLAG_BE),
        flag(passkeys::FLAG_BS),
    );
    passkey_reply(reply.unwrap_or_else(passkeys::error))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crypto_box::aead::AeadCore;

    pub(crate) struct TestHost {
        pub(crate) vaults: Vaults,
        pub(crate) prefs: BrowserPrefs,
        pub(crate) answer_access: bool,
    }

    impl Host for TestHost {
        fn vaults(&self) -> &Vaults {
            &self.vaults
        }
        fn prefs(&self) -> BrowserPrefs {
            self.prefs.clone()
        }
        fn active_vault(&self) -> Option<String> {
            None
        }
        fn ask(&self, ask: Ask) -> Option<Value> {
            match ask {
                Ask::Associate => Some(json!({ "name": "test-browser" })),
                Ask::Access { entries, .. } => self.answer_access.then(|| {
                    json!({
                    "allow": entries.iter().map(|e| e["uuid"].clone()).collect::<Vec<_>>(), "remember": true })
                }),
                Ask::Update { .. } | Ask::Delete { .. } => Some(json!({ "ok": true })),
                Ask::PasskeyRegister { .. } => Some(json!({ "ok": true })),
                Ask::PasskeyGet { entries, .. } => entries.first().map(|e| json!({ "uuid": e["uuid"] })),
            }
        }
        fn vault_changed(&self, _dto: VaultDto) {}
        fn lock_all(&self) {
            self.vaults.0.lock().unwrap().clear();
        }
        fn show_window(&self) {}
        fn autotype_search(&self, _search: &str) {}
    }

    /// Client side of the protocol, like keepassxc-browser does it with tweetnacl.
    struct Client {
        secret: SecretKey,
        host_pk: Option<PublicKey>,
    }

    impl Client {
        fn call(&mut self, host: &dyn Host, s: &mut Session, action: &str, payload: Value) -> Value {
            let nonce = SalsaBox::generate_nonce(&mut OsRng);
            let cbox = SalsaBox::new(self.host_pk.as_ref().unwrap(), &self.secret);
            let ct = cbox.encrypt(&nonce, serde_json::to_vec(&payload).unwrap().as_slice()).unwrap();
            let req = json!({ "action": action, "message": B64.encode(ct), "nonce": B64.encode(nonce), "clientID": "c" });
            let resp = handle(host, s, &req);
            if let Some(m) = resp["message"].as_str() {
                let n = B64.decode(resp["nonce"].as_str().unwrap()).unwrap();
                assert_eq!(n, increment(&nonce), "response nonce = request nonce + 1");
                let plain = cbox.decrypt(n.as_slice().into(), B64.decode(m).unwrap().as_slice()).unwrap();
                serde_json::from_slice(&plain).unwrap()
            } else {
                resp
            }
        }
    }

    pub(crate) fn test_vault() -> (Vaults, String) {
        let mut db = Database::new();
        {
            let mut root = db.root_mut();
            let mut e = root.add_entry();
            e.set_unprotected(fields::TITLE, "GitHub");
            e.set_unprotected(fields::USERNAME, "octo");
            e.set_protected(fields::PASSWORD, "s3cret");
            e.set_unprotected(fields::URL, "https://github.com/login");
        }
        {
            let mut root = db.root_mut();
            let mut e2 = root.add_entry();
            e2.set_unprotected(fields::TITLE, "Other");
            e2.set_unprotected(fields::URL, "https://example.org");
        }
        let path = std::env::temp_dir().join(format!("akp-browser-{}.kdbx", Uuid::new_v4()));
        let id = path.to_string_lossy().to_string();
        let v = OpenVault::new_for_test(path, db);
        let vaults = Vaults::default();
        vaults.0.lock().unwrap().insert(id.clone(), v);
        (vaults, id)
    }

    #[test]
    fn nonce_increment_matches_libsodium() {
        assert_eq!(increment(&[0, 0, 0]), vec![1, 0, 0]);
        assert_eq!(increment(&[255, 0, 1]), vec![0, 1, 1]);
        assert_eq!(increment(&[255, 255]), vec![0, 0]);
    }

    #[test]
    fn url_scores() {
        let page = site("https://www.github.com/login?x=1").unwrap();
        assert_eq!(score("https://github.com/login?x=1", &page, None, true), 100);
        assert_eq!(score("https://github.com/login", &page, None, true), 90);
        assert_eq!(score("github.com", &page, None, true), 80);
        assert_eq!(score("http://github.com", &page, None, true), 0); // scheme must match
        assert_eq!(score("http://github.com", &page, None, false), 80);
        assert_eq!(score("https://github.com:8443", &page, None, true), 0);
        let sub = site("https://gist.github.com").unwrap();
        assert_eq!(score("https://github.com", &sub, None, true), 60);
        assert_eq!(score("https://evilgithub.com", &page, None, true), 0);
    }

    #[test]
    fn full_protocol_flow() {
        let (vaults, vid) = test_vault();
        let host = TestHost {
            vaults,
            prefs: BrowserPrefs { enabled: true, unlock: true, match_scheme: true, ..Default::default() },
            answer_access: true,
        };
        let mut s = Session::default();
        let mut c = Client { secret: SecretKey::generate(&mut OsRng), host_pk: None };

        // key exchange (plain)
        let n = SalsaBox::generate_nonce(&mut OsRng);
        let r = handle(
            &host,
            &mut s,
            &json!({ "action": "change-public-keys", "publicKey": B64.encode(c.secret.public_key().as_bytes()), "nonce": B64.encode(n), "clientID": "c" }),
        );
        assert_eq!(r["success"], "true");
        c.host_pk = Some(PublicKey::from_slice(&B64.decode(r["publicKey"].as_str().unwrap()).unwrap()).unwrap());

        let hash = c.call(&host, &mut s, "get-databasehash", json!({ "action": "get-databasehash" }));
        assert_eq!(hash["hash"].as_str().unwrap().len(), 64);

        // anything but the key exchange must be encrypted, and auto-type needs an association
        let plain = handle(
            &host,
            &mut s,
            &json!({ "action": "request-autotype", "search": "github.com", "nonce": B64.encode(SalsaBox::generate_nonce(&mut OsRng)) }),
        );
        assert_eq!(plain["errorCode"], "4");
        assert_eq!(
            c.call(&host, &mut s, "request-autotype", json!({ "action": "request-autotype", "search": "github.com" }))["errorCode"],
            "8"
        );
        assert_eq!(c.call(&host, &mut s, "lock-database", json!({ "action": "lock-database" }))["errorCode"], "8");

        // logins need an association first
        let denied = c.call(&host, &mut s, "get-logins", json!({ "action": "get-logins", "url": "https://github.com" }));
        assert_eq!(denied["errorCode"], "8");

        let id_key = B64.encode(SecretKey::generate(&mut OsRng).public_key().as_bytes());
        let client_pk = B64.encode(c.secret.public_key().as_bytes());
        let assoc = c.call(&host, &mut s, "associate", json!({ "action": "associate", "key": client_pk, "idKey": id_key }));
        assert_eq!(assoc["id"], "test-browser");
        assert_eq!(assoc["hash"], hash["hash"]);
        let stored = cd_string(host.vaults.0.lock().unwrap()[&vid].db().meta.custom_data.get("KPXC_BROWSER_test-browser"));
        assert_eq!(stored.as_deref(), Some(id_key.as_str()));

        // new session: test-associate restores the association
        let mut s2 = Session::default();
        let n = SalsaBox::generate_nonce(&mut OsRng);
        let r = handle(&host, &mut s2, &json!({ "action": "change-public-keys", "publicKey": client_pk, "nonce": B64.encode(n) }));
        c.host_pk = Some(PublicKey::from_slice(&B64.decode(r["publicKey"].as_str().unwrap()).unwrap()).unwrap());
        assert_eq!(
            c.call(&host, &mut s2, "test-associate", json!({ "action": "test-associate", "id": "test-browser", "key": "wrong" }))["errorCode"],
            "8"
        );
        assert_eq!(
            c.call(&host, &mut s2, "test-associate", json!({ "action": "test-associate", "id": "test-browser", "key": id_key }))["success"],
            "true"
        );

        let keys = json!([{ "id": "test-browser", "key": id_key }]);
        let logins =
            c.call(&host, &mut s2, "get-logins", json!({ "action": "get-logins", "url": "https://github.com/session", "keys": keys }));
        assert_eq!(logins["count"], 1);
        assert_eq!(logins["entries"][0]["login"], "octo");
        assert_eq!(logins["entries"][0]["password"], "s3cret");
        // "remember" stored the permission KeePassXC-style
        let allow = host.vaults.0.lock().unwrap()[&vid]
            .db()
            .iter_all_entries()
            .find(|e| e.get_title() == Some("GitHub"))
            .and_then(|e| cd_string(e.custom_data.get(ENTRY_SETTINGS)))
            .unwrap();
        assert!(allow.contains("\"Allow\":[\"github.com\"]"), "{allow}");

        assert_eq!(
            c.call(&host, &mut s2, "get-logins", json!({ "action": "get-logins", "url": "https://nothing.test", "keys": keys }))["errorCode"],
            "15"
        );

        // save a new login from the browser, then find it
        let set = c.call(
            &host,
            &mut s2,
            "set-login",
            json!({ "action": "set-login", "url": "https://shop.test/login", "login": "me", "password": "pw1", "id": "test-browser" }),
        );
        assert_eq!(set["error"], "success");
        let found = c.call(&host, &mut s2, "get-logins", json!({ "action": "get-logins", "url": "https://shop.test", "keys": keys }));
        assert_eq!(found["entries"][0]["login"], "me");
        assert_eq!(found["entries"][0]["group"], DEFAULT_GROUP);

        let pw = c.call(&host, &mut s2, "generate-password", json!({ "action": "generate-password" }));
        assert_eq!(pw["password"].as_str().unwrap().len(), 20);

        let groups = c.call(&host, &mut s2, "create-new-group", json!({ "action": "create-new-group", "groupName": "Web/Shops" }));
        assert_eq!(groups["name"], "Shops");
        let tree = c.call(&host, &mut s2, "get-database-groups", json!({ "action": "get-database-groups" }));
        assert!(tree["groups"]["groups"][0]["children"].as_array().unwrap().iter().any(|g| g["name"] == "Web"));

        assert_eq!(c.call(&host, &mut s2, "passkeys-get", json!({ "action": "passkeys-get" }))["errorCode"], "24");

        // passkeys: register, then sign in with it
        let create = json!({ "challenge": "AAAAAAAAAAAAAAAAAAAAAAAAAAAA", "rp": { "id": "shop.test", "name": "Shop" },
            "user": { "id": "dXNlcjE", "name": "alice" }, "pubKeyCredParams": [{ "type": "public-key", "alg": -7 }] });
        let reg = c.call(
            &host,
            &mut s2,
            "passkeys-register",
            json!({ "action": "passkeys-register", "publicKey": create, "origin": "https://shop.test", "keys": keys }),
        );
        let cred_id = reg["response"]["id"].as_str().expect("credential").to_string();
        let get = json!({ "challenge": "BBBBBBBBBBBBBBBBBBBBBBBBBBBB", "rpId": "shop.test", "allowCredentials": [{ "type": "public-key", "id": cred_id }] });
        let login = c.call(
            &host,
            &mut s2,
            "passkeys-get",
            json!({ "action": "passkeys-get", "publicKey": get, "origin": "https://shop.test", "keys": keys }),
        );
        assert_eq!(login["response"]["id"], cred_id.as_str());
        assert!(login["response"]["response"]["signature"].as_str().is_some_and(|s| !s.is_empty()));
        let mut excluded = create.clone();
        excluded["excludeCredentials"] = json!([{ "type": "public-key", "id": cred_id }]);
        let again = c.call(
            &host,
            &mut s2,
            "passkeys-register",
            json!({ "action": "passkeys-register", "publicKey": excluded, "origin": "https://shop.test", "keys": keys }),
        );
        assert_eq!(again["response"]["errorCode"], 21);
        assert_eq!(
            c.call(
                &host,
                &mut s2,
                "passkeys-get",
                json!({ "action": "passkeys-get", "publicKey": get, "origin": "http://shop.test", "keys": keys })
            )["errorCode"],
            "25"
        );

        // lock: further requests report "database not opened"
        c.call(&host, &mut s2, "lock-database", json!({ "action": "lock-database" }));
        assert_eq!(c.call(&host, &mut s2, "get-databasehash", json!({ "action": "get-databasehash" }))["errorCode"], "1");
        let _ = std::fs::remove_file(vid);
    }

    #[test]
    fn hash_matches_keepassxc_formula() {
        // SHA-256 over the root UUID rendered as 32 lowercase hex chars (Qt toRfc4122().toHex())
        let db = Database::new();
        let expected = hex(&Sha256::digest(db.root().id().uuid().as_simple().to_string().as_bytes()));
        assert_eq!(db_hash(&db), expected);
        assert_eq!(db.root().id().uuid().simple().to_string().len(), 32);
    }
}
