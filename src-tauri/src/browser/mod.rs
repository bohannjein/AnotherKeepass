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

mod actions;
#[cfg(test)]
pub(crate) mod tests;
mod webauthn;

use actions::*;
use webauthn::*;

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
    /// entries handed to the extension count as used (KeePass "last access", desktop list)
    fn entry_used(&self, _v: &mut OpenVault, _vault: &str, _id: EntryId) {}
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
