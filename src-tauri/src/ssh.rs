//! SSH agent integration, compatible with KeeAgent / KeePassXC: an entry carries the private
//! key as attachment plus a "KeeAgent.settings" attachment saying what to do with it.
//! We are a client of the system agent (Windows OpenSSH agent pipe, SSH_AUTH_SOCK on Unix):
//! keys are added on unlock and removed on lock, as configured per entry.

use std::{
    collections::HashMap,
    io::{Read, Write},
    sync::Mutex,
};

use keepass::db::{EntryId, EntryRef, Value};
use serde::{Deserialize, Serialize};
use ssh_encoding::Encode;
use ssh_key::private::PrivateKey;
use uuid::Uuid;

use crate::vault::{OpenVault, Vaults};

pub const SETTINGS_ATTACHMENT: &str = "KeeAgent.settings";

/// Set from the settings: None = integration off, Some(path) = agent socket/pipe ("" = default).
pub static AGENT: Mutex<Option<String>> = Mutex::new(None);
/// Public key blobs we added, per vault, so lock removes exactly those.
static ADDED: Mutex<Option<HashMap<String, Vec<Vec<u8>>>>> = Mutex::new(None);

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct KeeAgent {
    pub allow: bool,
    pub add_at_open: bool,
    pub remove_at_close: bool,
    pub confirm: bool,
    /// seconds, 0 = no lifetime constraint
    pub lifetime: u32,
    pub attachment: String,
}

impl Default for KeeAgent {
    fn default() -> Self {
        Self { allow: true, add_at_open: true, remove_at_close: true, confirm: false, lifetime: 0, attachment: String::new() }
    }
}

// ---------------------------------------------------------------- KeeAgent.settings (XML, UTF-16 from KeePassXC)

fn decode_text(bytes: &[u8]) -> String {
    if bytes.starts_with(&[0xFF, 0xFE]) || (bytes.len() > 1 && bytes[1] == 0) {
        let start = if bytes.starts_with(&[0xFF, 0xFE]) { 2 } else { 0 };
        let units: Vec<u16> = bytes[start..].chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        String::from_utf16_lossy(&units)
    } else {
        String::from_utf8_lossy(bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(bytes)).into_owned()
    }
}

fn tag<'a>(xml: &'a str, name: &str) -> Option<&'a str> {
    let open = format!("<{name}>");
    let start = xml.find(&open)? + open.len();
    let end = start + xml[start..].find(&format!("</{name}>"))?;
    Some(xml[start..end].trim())
}

pub fn parse_settings(bytes: &[u8]) -> KeeAgent {
    let xml = decode_text(bytes);
    let flag = |n: &str, d: bool| tag(&xml, n).map(|v| v.eq_ignore_ascii_case("true")).unwrap_or(d);
    let d = KeeAgent::default();
    KeeAgent {
        allow: flag("AllowUseOfSshKey", d.allow),
        add_at_open: flag("AddAtDatabaseOpen", d.add_at_open),
        remove_at_close: flag("RemoveAtDatabaseClose", d.remove_at_close),
        confirm: flag("UseConfirmConstraintWhenAdding", false),
        lifetime: if flag("UseLifetimeConstraintWhenAdding", false) {
            tag(&xml, "LifetimeConstraintDuration").and_then(|v| v.parse().ok()).unwrap_or(600)
        } else {
            0
        },
        attachment: tag(&xml, "AttachmentName").unwrap_or_default().to_string(),
    }
}

/// Same layout and encoding (UTF-16 LE with BOM) as KeePassXC writes.
pub fn write_settings(s: &KeeAgent) -> Vec<u8> {
    let b = |v: bool| if v { "true" } else { "false" };
    let esc = |v: &str| v.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;");
    let xml = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-16\"?>\n<EntrySettings xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">\n  <AllowUseOfSshKey>{}</AllowUseOfSshKey>\n  <AddAtDatabaseOpen>{}</AddAtDatabaseOpen>\n  <RemoveAtDatabaseClose>{}</RemoveAtDatabaseClose>\n  <UseConfirmConstraintWhenAdding>{}</UseConfirmConstraintWhenAdding>\n  <UseLifetimeConstraintWhenAdding>{}</UseLifetimeConstraintWhenAdding>\n  <LifetimeConstraintDuration>{}</LifetimeConstraintDuration>\n  <Location>\n    <SelectedType>attachment</SelectedType>\n    <AttachmentName>{}</AttachmentName>\n    <SaveAttachmentToTempFile>false</SaveAttachmentToTempFile>\n    <FileName />\n  </Location>\n</EntrySettings>\n",
        b(s.allow),
        b(s.add_at_open),
        b(s.remove_at_close),
        b(s.confirm),
        b(s.lifetime > 0),
        if s.lifetime > 0 { s.lifetime } else { 600 },
        esc(&s.attachment)
    );
    let mut out = vec![0xFF, 0xFE];
    out.extend(xml.encode_utf16().flat_map(|u| u.to_le_bytes()));
    out
}

pub fn entry_settings(e: &EntryRef<'_>) -> Option<KeeAgent> {
    e.attachments_named().find(|(n, _)| *n == SETTINGS_ATTACHMENT).map(|(_, a)| parse_settings(a.data.get()))
}

/// The entry's private key, decrypted with the entry password when it is protected.
fn private_key(e: &EntryRef<'_>, s: &KeeAgent) -> Result<PrivateKey, String> {
    let (_, a) = e.attachments_named().find(|(n, _)| *n == s.attachment).ok_or("ssh_no_key")?;
    let key = PrivateKey::from_openssh(a.data.get()).map_err(|e| format!("ssh_key:{e}"))?;
    if key.is_encrypted() { key.decrypt(e.get("Password").unwrap_or_default()).map_err(|_| "ssh_passphrase".to_string()) } else { Ok(key) }
}

// ---------------------------------------------------------------- agent protocol

const ADD_IDENTITY: u8 = 17;
const REMOVE_IDENTITY: u8 = 18;
const ADD_ID_CONSTRAINED: u8 = 25;
const SUCCESS: u8 = 6;

fn put_string(buf: &mut Vec<u8>, s: &[u8]) {
    buf.extend((s.len() as u32).to_be_bytes());
    buf.extend(s);
}

fn add_message(key: &PrivateKey, s: &KeeAgent) -> Result<Vec<u8>, String> {
    let mut body = Vec::new();
    key.key_data().encode(&mut body).map_err(|e| e.to_string())?;
    put_string(&mut body, key.comment().as_bytes());
    let constrained = s.confirm || s.lifetime > 0;
    if s.lifetime > 0 {
        body.push(1);
        body.extend(s.lifetime.to_be_bytes());
    }
    if s.confirm {
        body.push(2);
    }
    let mut msg = vec![if constrained { ADD_ID_CONSTRAINED } else { ADD_IDENTITY }];
    msg.extend(body);
    Ok(msg)
}

fn remove_message(public_blob: &[u8]) -> Vec<u8> {
    let mut msg = vec![REMOVE_IDENTITY];
    put_string(&mut msg, public_blob);
    msg
}

fn public_blob(key: &PrivateKey) -> Result<Vec<u8>, String> {
    let mut blob = Vec::new();
    key.public_key().key_data().encode(&mut blob).map_err(|e| e.to_string())?;
    Ok(blob)
}

fn agent_path(configured: &str) -> String {
    if !configured.trim().is_empty() {
        return configured.trim().to_string();
    }
    #[cfg(windows)]
    return r"\\.\pipe\openssh-ssh-agent".into();
    #[cfg(not(windows))]
    return std::env::var("SSH_AUTH_SOCK").unwrap_or_default();
}

/// One request/response round trip with the agent.
fn request(msg: &[u8]) -> Result<(), String> {
    let configured = AGENT.lock().ok().and_then(|a| a.clone()).ok_or("ssh_off")?;
    let path = agent_path(&configured);
    #[cfg(windows)]
    let mut conn = {
        use std::os::windows::fs::OpenOptionsExt;
        use std::os::windows::io::AsRawHandle;
        // GENERIC_READ | GENERIC_WRITE | READ_CONTROL (to check who owns the pipe)
        let f = std::fs::OpenOptions::new()
            .access_mode(0x8000_0000 | 0x4000_0000 | 0x0002_0000)
            .open(&path)
            .map_err(|e| format!("ssh_agent:{e}"))?;
        if !crate::hardening::pipe_owner_trusted(f.as_raw_handle() as _) {
            return Err("ssh_agent:untrusted agent pipe (owned by another user)".into());
        }
        f
    };
    #[cfg(unix)]
    let mut conn = std::os::unix::net::UnixStream::connect(&path).map_err(|e| format!("ssh_agent:{e}"))?;
    let mut framed = (msg.len() as u32).to_be_bytes().to_vec();
    framed.extend(msg);
    conn.write_all(&framed).map_err(|e| format!("ssh_agent:{e}"))?;
    let mut len = [0u8; 4];
    conn.read_exact(&mut len).map_err(|e| format!("ssh_agent:{e}"))?;
    let mut reply = vec![0u8; u32::from_be_bytes(len).min(1 << 20) as usize];
    conn.read_exact(&mut reply).map_err(|e| format!("ssh_agent:{e}"))?;
    if reply.first() == Some(&SUCCESS) { Ok(()) } else { Err("ssh_refused".into()) }
}

fn remember(vault: &str, blob: Vec<u8>) {
    if let Ok(mut a) = ADDED.lock() {
        let list = a.get_or_insert_with(HashMap::new).entry(vault.to_string()).or_default();
        if !list.contains(&blob) {
            list.push(blob);
        }
    }
}

fn add_entry(vault: &str, e: &EntryRef<'_>, s: &KeeAgent) -> Result<(), String> {
    let key = private_key(e, s)?;
    request(&add_message(&key, s)?)?;
    if s.remove_at_close {
        remember(vault, public_blob(&key)?);
    }
    Ok(())
}

// ---------------------------------------------------------------- hooks + commands

/// After unlock: add every key marked "add at database open".
pub fn on_unlock(vault: &str, v: &OpenVault) {
    if AGENT.lock().map(|a| a.is_none()).unwrap_or(true) {
        return;
    }
    let mut n = 0;
    for e in v.db().iter_all_entries() {
        let Some(s) = entry_settings(&e).filter(|s| s.allow && s.add_at_open) else { continue };
        match add_entry(vault, &e, &s) {
            Ok(()) => n += 1,
            Err(err) => log::warn!("ssh agent: {err}"),
        }
    }
    if n > 0 {
        log::info!("ssh agent: added {n} key(s)");
    }
}

/// Before lock/close: remove the keys we added for this vault.
pub fn on_lock(vault: &str) {
    let blobs = ADDED.lock().ok().and_then(|mut a| a.as_mut()?.remove(vault)).unwrap_or_default();
    for b in blobs {
        if let Err(e) = request(&remove_message(&b)) {
            log::warn!("ssh agent remove: {e}");
        }
    }
}

fn with_entry<T>(state: &Vaults, vault: &str, id: &str, f: impl FnOnce(&EntryRef<'_>) -> Result<T, String>) -> Result<T, String> {
    let map = state.0.lock().map_err(|_| "lock")?;
    let v = map.get(vault).ok_or("vault_closed")?;
    let e = v.db().entry(EntryId::from(Uuid::parse_str(id).map_err(|_| "not_found")?)).ok_or("not_found")?;
    f(&e)
}

#[derive(Serialize)]
pub struct AgentStatus {
    path: String,
    reachable: bool,
}

/// Settings page: which socket/pipe we would use and whether something answers there.
#[tauri::command]
pub fn ssh_status(configured: String) -> AgentStatus {
    let path = agent_path(&configured);
    #[cfg(windows)]
    let reachable = std::fs::OpenOptions::new().read(true).write(true).open(&path).is_ok();
    #[cfg(unix)]
    let reachable = std::os::unix::net::UnixStream::connect(&path).is_ok();
    AgentStatus { path, reachable }
}

#[tauri::command]
pub fn ssh_settings(state: tauri::State<'_, Vaults>, vault: String, id: String) -> Result<Option<KeeAgent>, String> {
    with_entry(&state, &vault, &id, |e| Ok(entry_settings(e)))
}

/// Store (or with None remove) the KeeAgent settings attachment.
#[tauri::command]
pub fn ssh_settings_set(
    state: tauri::State<'_, Vaults>,
    vault: String,
    id: String,
    settings: Option<KeeAgent>,
) -> Result<crate::vault::VaultDto, String> {
    crate::vault::mutate_entry(&state, &vault, &id, |e| {
        e.remove_attachment_by_name(SETTINGS_ATTACHMENT);
        if let Some(s) = settings {
            e.add_attachment(SETTINGS_ATTACHMENT.to_string(), Value::unprotected(write_settings(&s)));
        }
    })
}

/// "Add to agent now" / "Remove from agent" buttons.
#[tauri::command]
pub fn ssh_agent_add(state: tauri::State<'_, Vaults>, vault: String, id: String) -> Result<(), String> {
    with_entry(&state, &vault, &id, |e| {
        let s = entry_settings(e).ok_or("ssh_no_settings")?;
        add_entry(&vault, e, &s)
    })
}

#[tauri::command]
pub fn ssh_agent_remove(state: tauri::State<'_, Vaults>, vault: String, id: String) -> Result<(), String> {
    with_entry(&state, &vault, &id, |e| {
        let s = entry_settings(e).ok_or("ssh_no_settings")?;
        request(&remove_message(&public_blob(&private_key(e, &s)?)?))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const ED25519: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDklsU0iTBQ+UpbZnG5taWEqkzd9BDnmNUqt15BviOyfAAAAJAXh6eCF4en
ggAAAAtzc2gtZWQyNTUxOQAAACDklsU0iTBQ+UpbZnG5taWEqkzd9BDnmNUqt15BviOyfA
AAAEBJF9hGPahsj/w+d+6Hox6Qf7d8f5Wk3hgtWgiC7pqmguSWxTSJMFD5Sltmcbm1pYSq
TN30EOeY1Sq3XkG+I7J8AAAACnRlc3RAbG9jYWwBAgM=
-----END OPENSSH PRIVATE KEY-----
";
    /// passphrase "secret"
    const ED25519_ENC: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABAF5HnQnT
iL4lbnqCdE2TR9AAAAGAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAILk7jLmPrOXO0ppB
Qo9DQ5Rerdf5KGBKtxXCdNA4xjIuAAAAkPXb0iyCh4vkgouIsqKc9l28xJE2ElImS0/x9B
c8EmNfJvjfjJnUy20GhV/FcWeYe4qdT0HALyKeQNNW2IvO+yvsvQr0LOIkKRTWymPaKOcx
HAiogBuIf4OvY1Oz0ZI9y0nsA+/atQw4ZNT+P/0YCyNfOhs5VACl5YGC5pAnwSWaSXwqDl
8B4xJeIzjxn3ghnQ==
-----END OPENSSH PRIVATE KEY-----
";

    #[test]
    fn settings_roundtrip() {
        let s = KeeAgent { confirm: true, lifetime: 300, attachment: "id_ed25519".into(), ..Default::default() };
        let bytes = write_settings(&s);
        assert!(bytes.starts_with(&[0xFF, 0xFE]));
        assert_eq!(parse_settings(&bytes), s);
        // KeePassXC-style UTF-8 file without lifetime
        let p = parse_settings(b"<EntrySettings><AllowUseOfSshKey>true</AllowUseOfSshKey><AddAtDatabaseOpen>false</AddAtDatabaseOpen><Location><AttachmentName>k</AttachmentName></Location></EntrySettings>");
        assert!(p.allow && !p.add_at_open && p.lifetime == 0 && p.attachment == "k");
    }

    #[test]
    fn agent_messages() {
        let key = PrivateKey::from_openssh(ED25519).unwrap();
        let msg = add_message(&key, &KeeAgent::default()).unwrap();
        assert_eq!(msg[0], ADD_IDENTITY);
        // string "ssh-ed25519" right after the type byte
        assert_eq!(&msg[1..5], &11u32.to_be_bytes());
        assert_eq!(&msg[5..16], b"ssh-ed25519");
        assert!(msg.ends_with(b"test@local"));
        let c = add_message(&key, &KeeAgent { confirm: true, ..Default::default() }).unwrap();
        assert_eq!((c[0], *c.last().unwrap()), (ADD_ID_CONSTRAINED, 2));
        let r = remove_message(&public_blob(&key).unwrap());
        let enc = PrivateKey::from_openssh(ED25519_ENC).unwrap();
        assert!(enc.is_encrypted() && enc.decrypt("secret").is_ok());
        assert_eq!(r[0], REMOVE_IDENTITY);
    }
}
