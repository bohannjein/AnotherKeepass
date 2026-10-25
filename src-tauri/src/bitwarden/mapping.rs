//! Cipher (Bitwarden item) ↔ KeePass entry. Everything the UI can't show (field order,
//! linked fields, cipher key, password history, revision) rides along in custom data, so
//! an unchanged entry maps back to exactly the same plain cipher and isn't re-uploaded.

use std::collections::HashMap;

use keepass::db::{CustomDataItem, CustomDataValue, Entry, EntryMut, Times};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::api::field;
use super::crypto::{SymKey, decrypt, decrypt_str, encrypt};

pub const CD_BW: &str = "Bitwarden.Meta";
const CD_TYPE: &str = "AnotherKeepass.Type";
const CD_KINDS: &str = "AnotherKeepass.Kinds";

/// Decrypted cipher in a canonical form (compared to detect changes).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub struct Plain {
    pub kind: u8,
    pub name: String,
    pub notes: String,
    pub favorite: bool,
    /// strings by Bitwarden property name, e.g. "login.username", "card.number", "identity.city"
    pub props: Vec<(String, String)>,
    pub uris: Vec<String>,
    /// custom fields: (name, value, type 0 text / 1 hidden / 2 boolean / 3 linked, linkedId)
    pub fields: Vec<(String, String, u8, Option<u64>)>,
}

/// What we keep per entry that has no place in KeePass fields.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct Meta {
    pub id: String,
    pub kind: u8,
    pub org: Option<String>,
    pub key: Option<String>,
    pub revision: Option<String>,
    pub reprompt: u8,
    pub history: Value,
    /// custom fields in Bitwarden order: (entry string name or None for linked fields, original name, type, linkedId)
    pub field_names: Vec<(Option<String>, String, u8, Option<u64>)>,
}

// Bitwarden property → KeePass string name (and protected?)
const LOGIN: &[(&str, &str, bool)] =
    &[("login.username", "UserName", false), ("login.password", "Password", true), ("login.totp", "otp", true)];
const CARD: &[(&str, &str, bool)] = &[
    ("card.cardholderName", "Cardholder", false),
    ("card.number", "Card number", true),
    ("card.code", "CVC", true),
    ("card.brand", "Brand", false),
];
const IDENTITY: &[(&str, &str, bool)] = &[
    ("identity.title", "Title (name)", false),
    ("identity.firstName", "First name", false),
    ("identity.middleName", "Middle name", false),
    ("identity.lastName", "Last name", false),
    ("identity.email", "Email", false),
    ("identity.phone", "Phone", false),
    ("identity.company", "Company", false),
    ("identity.username", "Username", false),
    ("identity.address1", "Address", false),
    ("identity.address2", "Address 2", false),
    ("identity.address3", "Address 3", false),
    ("identity.city", "City", false),
    ("identity.state", "State", false),
    ("identity.postalCode", "Postal code", false),
    ("identity.country", "Country", false),
    ("identity.ssn", "SSN", true),
    ("identity.passportNumber", "Passport number", true),
    ("identity.licenseNumber", "License number", true),
];
const SSH: &[(&str, &str, bool)] = &[
    ("sshKey.privateKey", "Private key", true),
    ("sshKey.publicKey", "Public key", false),
    ("sshKey.keyFingerprint", "Fingerprint", false),
];

fn props_for(kind: u8) -> &'static [(&'static str, &'static str, bool)] {
    match kind {
        1 => LOGIN,
        3 => CARD,
        4 => IDENTITY,
        5 => SSH,
        _ => &[],
    }
}
const SECTION: [&str; 6] = ["", "login", "secureNote", "card", "identity", "sshKey"];

fn dec(v: &Value, key: &SymKey) -> Result<String, String> {
    match v.as_str() {
        Some(s) if !s.is_empty() => decrypt_str(s, key),
        _ => Ok(String::new()),
    }
}

/// Key for a cipher: its own item key if it has one, else the user / organization key.
pub fn cipher_key(c: &Value, user: &SymKey, orgs: &HashMap<String, SymKey>) -> Result<SymKey, String> {
    let base = match field(c, "organizationId").as_str() {
        Some(org) => orgs.get(org).ok_or("bw_org_key")?,
        None => user,
    };
    match field(c, "key").as_str() {
        Some(k) if !k.is_empty() => SymKey::from_bytes(&decrypt(k, base)?),
        _ => Ok(base.clone()),
    }
}

pub fn decrypt_cipher(c: &Value, key: &SymKey) -> Result<(Plain, Meta), String> {
    let kind = field(c, "type").as_u64().unwrap_or(2) as u8;
    let mut p = Plain {
        kind,
        name: dec(field(c, "name"), key)?,
        notes: dec(field(c, "notes"), key)?,
        favorite: field(c, "favorite").as_bool().unwrap_or(false),
        ..Default::default()
    };
    if let Some(section) = SECTION.get(kind as usize).map(|s| field(c, s)).filter(|s| s.is_object()) {
        for (prop, _, _) in props_for(kind) {
            let name = prop.split_once('.').map(|x| x.1).unwrap_or(prop);
            let v = dec(field(section, name), key)?;
            if !v.is_empty() {
                p.props.push((prop.to_string(), v));
            }
        }
        if kind == 3 {
            let (m, y) = (dec(field(section, "expMonth"), key)?, dec(field(section, "expYear"), key)?);
            if !m.is_empty() || !y.is_empty() {
                p.props.push(("card.exp".into(), format!("{m}/{y}")));
            }
        }
        if kind == 1 {
            for u in field(section, "uris").as_array().into_iter().flatten() {
                p.uris.push(dec(field(u, "uri"), key)?);
            }
        }
    }
    for f in field(c, "fields").as_array().into_iter().flatten() {
        let t = field(f, "type").as_u64().unwrap_or(0) as u8;
        p.fields.push((dec(field(f, "name"), key)?, dec(field(f, "value"), key)?, t, field(f, "linkedId").as_u64()));
    }
    let meta = Meta {
        id: field(c, "id").as_str().unwrap_or_default().to_string(),
        kind,
        org: field(c, "organizationId").as_str().map(String::from),
        key: field(c, "key").as_str().filter(|k| !k.is_empty()).map(String::from),
        revision: field(c, "revisionDate").as_str().map(String::from),
        reprompt: field(c, "reprompt").as_u64().unwrap_or(0) as u8,
        history: field(c, "passwordHistory").clone(),
        field_names: vec![],
    };
    Ok((p, meta))
}

fn kp_type(kind: u8) -> &'static str {
    match kind {
        1 => "login",
        3 => "card",
        4 => "identity",
        5 => "other",
        _ => "note",
    }
}

fn cd(s: String) -> CustomDataItem {
    CustomDataItem { value: Some(CustomDataValue::String(s)), last_modification_time: Some(Times::now()) }
}

/// Fill a (new, empty) entry from a plain cipher.
pub fn write_entry(e: &mut EntryMut<'_>, p: &Plain, mut meta: Meta) {
    e.set_unprotected("Title", p.name.clone());
    e.set_unprotected("Notes", p.notes.clone());
    let mut kinds = serde_json::Map::new();
    for (prop, value) in &p.props {
        if prop == "card.exp" {
            e.set_unprotected("Card expiry", value.clone());
            continue;
        }
        if let Some((_, name, protected)) = props_for(p.kind).iter().find(|(pr, _, _)| pr == prop) {
            if *protected { e.set_protected(*name, value.clone()) } else { e.set_unprotected(*name, value.clone()) }
        }
    }
    for (i, uri) in p.uris.iter().enumerate() {
        match i {
            0 => e.set_unprotected("URL", uri.clone()),
            1 => e.set_unprotected("KP2A_URL", uri.clone()),
            n => e.set_unprotected(format!("KP2A_URL_{}", n - 1), uri.clone()),
        }
        if i > 0 {
            kinds.insert(if i == 1 { "KP2A_URL".into() } else { format!("KP2A_URL_{}", i - 1) }, json!("url"));
        }
    }
    // custom fields: unique names (KeePass strings are a map), original names kept in meta
    meta.field_names.clear();
    for (name, value, t, linked) in &p.fields {
        if *t == 3 {
            meta.field_names.push((None, name.clone(), 3, *linked));
            continue;
        }
        let mut n = if name.is_empty() { "Field".to_string() } else { name.clone() };
        let base = n.clone();
        let mut i = 2;
        while e.fields.contains_key(&n) || ["Title", "Notes", "URL"].contains(&n.as_str()) {
            n = format!("{base} ({i})");
            i += 1;
        }
        if *t == 1 {
            e.set_protected(n.clone(), value.clone())
        } else {
            e.set_unprotected(n.clone(), value.clone())
        }
        if *t == 1 {
            kinds.insert(n.clone(), json!("hidden"));
        }
        meta.field_names.push((Some(n), name.clone(), *t, None));
    }
    if p.favorite {
        e.tags.push("pinned".into());
    }
    e.custom_data.insert(CD_TYPE.into(), cd(kp_type(p.kind).into()));
    if !kinds.is_empty() {
        e.custom_data.insert(CD_KINDS.into(), cd(Value::Object(kinds).to_string()));
    }
    e.custom_data.insert(CD_BW.into(), cd(serde_json::to_string(&meta).unwrap_or_default()));
}

pub fn meta_of(e: &Entry) -> Option<Meta> {
    match &e.custom_data.get(CD_BW)?.value {
        Some(CustomDataValue::String(s)) => serde_json::from_str(s).ok(),
        _ => None,
    }
}

/// Entry → plain cipher (inverse of `write_entry`; also handles entries created in the UI).
pub fn read_entry(e: &Entry) -> (Plain, Meta) {
    let meta = meta_of(e).unwrap_or_default();
    let get = |k: &str| e.get(k).unwrap_or_default().to_string();
    let ui_type = match &e.custom_data.get(CD_TYPE).and_then(|c| c.value.clone()) {
        Some(CustomDataValue::String(s)) => s.clone(),
        _ => String::new(),
    };
    let kind = if meta.kind != 0 {
        meta.kind
    } else {
        match ui_type.as_str() {
            "login" => 1,
            "card" => 3,
            "identity" => 4,
            _ if !get("UserName").is_empty() || !get("Password").is_empty() || !get("URL").is_empty() => 1,
            _ => 2,
        }
    };
    let mut p =
        Plain { kind, name: get("Title"), notes: get("Notes"), favorite: e.tags.iter().any(|t| t == "pinned"), ..Default::default() };
    let mut used: Vec<String> = vec!["Title".into(), "Notes".into()];
    for (prop, name, _) in props_for(kind) {
        let v = get(name);
        used.push(name.to_string());
        if !v.is_empty() {
            p.props.push((prop.to_string(), v));
        }
    }
    if kind == 3 {
        used.push("Card expiry".into());
        let v = get("Card expiry");
        if !v.is_empty() {
            p.props.push(("card.exp".into(), if v.contains('/') { v } else { format!("{v}/") }));
        }
    }
    if kind == 4 {
        // identities typed in our UI use "Full name" / "Address" / "Date of birth"
        let full = get("Full name");
        if !full.is_empty() && !p.props.iter().any(|(k, _)| k == "identity.firstName" || k == "identity.lastName") {
            let (first, last) = full.rsplit_once(' ').unwrap_or((full.as_str(), ""));
            p.props.push(("identity.firstName".into(), first.to_string()));
            if !last.is_empty() {
                p.props.push(("identity.lastName".into(), last.to_string()));
            }
            used.push("Full name".into());
        }
    }
    if kind == 1 {
        used.extend(["URL".to_string()]);
        let mut extra: Vec<(String, String)> = e.fields.keys().filter(|k| k.starts_with("KP2A_URL")).map(|k| (k.clone(), get(k))).collect();
        extra.sort_by_key(|(k, _)| if k == "KP2A_URL" { 0 } else { k.trim_start_matches("KP2A_URL_").parse::<u32>().unwrap_or(999) });
        let url = get("URL");
        if !url.is_empty() || !extra.is_empty() {
            p.uris.push(url);
        }
        for (k, v) in extra {
            used.push(k);
            p.uris.push(v);
        }
    }
    // custom fields: known ones in their original order and name, then new ones
    let hidden = |n: &str| e.fields.get(n).is_some_and(|v| v.is_protected());
    for (entry_name, original, orig_type, linked) in &meta.field_names {
        match entry_name {
            None => p.fields.push((original.clone(), String::new(), 3, *linked)),
            Some(n) if e.fields.contains_key(n) => {
                used.push(n.clone());
                let v = get(n);
                // booleans stay booleans; otherwise the protection flag decides text vs hidden
                let t = if *orig_type == 2 {
                    2
                } else if hidden(n) {
                    1
                } else {
                    0
                };
                p.fields.push((original.clone(), v, t, None));
            }
            _ => {}
        }
    }
    let mut rest: Vec<&String> =
        e.fields.keys().filter(|k| !used.contains(k) && !k.starts_with("KPEX_") && !k.starts_with("KP2A_URL")).collect();
    rest.sort();
    for n in rest {
        p.fields.push((n.clone(), get(n), if hidden(n) { 1 } else { 0 }, None));
    }
    (p, meta)
}

fn enc_opt(v: &str, key: &SymKey) -> Value {
    if v.is_empty() { Value::Null } else { json!(encrypt(v.as_bytes(), key)) }
}

/// Plain cipher → request body for POST/PUT /api/ciphers.
pub fn cipher_body(p: &Plain, meta: &Meta, folder: Option<&str>, key: &SymKey, user_id: &str) -> Value {
    let prop = |name: &str| p.props.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str()).unwrap_or("");
    let mut body = json!({
        "type": p.kind,
        "name": encrypt(p.name.as_bytes(), key),
        "notes": enc_opt(&p.notes, key),
        "favorite": p.favorite,
        "folderId": folder,
        "organizationId": meta.org,
        "key": meta.key,
        "reprompt": meta.reprompt,
        "encryptedFor": user_id,
        "lastKnownRevisionDate": meta.revision,
        "passwordHistory": if meta.history.is_null() { json!([]) } else { meta.history.clone() },
        "fields": p.fields.iter().map(|(n, v, t, linked)| json!({
            "name": enc_opt(n, key), "value": if *t == 3 { Value::Null } else { enc_opt(v, key) }, "type": t, "linkedId": linked,
        })).collect::<Vec<_>>(),
    });
    let section = SECTION.get(p.kind as usize).copied().unwrap_or("secureNote");
    let mut obj = serde_json::Map::new();
    for (pr, _, _) in props_for(p.kind) {
        let name = pr.split_once('.').map(|x| x.1).unwrap_or(pr);
        obj.insert(name.into(), enc_opt(prop(pr), key));
    }
    match p.kind {
        1 => {
            obj.insert(
                "uris".into(),
                json!(
                    p.uris
                        .iter()
                        .filter(|u| !u.is_empty())
                        .map(|u| json!({ "uri": encrypt(u.as_bytes(), key), "match": Value::Null }))
                        .collect::<Vec<_>>()
                ),
            );
        }
        2 => {
            obj.insert("type".into(), json!(0));
        }
        3 => {
            let (m, y) = prop("card.exp").split_once('/').unwrap_or((prop("card.exp"), ""));
            obj.insert("expMonth".into(), enc_opt(m, key));
            obj.insert("expYear".into(), enc_opt(y, key));
        }
        _ => {}
    }
    body[section] = Value::Object(obj);
    body
}

#[cfg(test)]
mod tests {
    use super::*;
    use keepass::Database;
    use rand_core::{OsRng, RngCore};

    fn key() -> SymKey {
        let mut b = [0u8; 64];
        OsRng.fill_bytes(&mut b);
        SymKey::from_bytes(&b).unwrap()
    }

    /// A cipher as the server sends it, encrypted with `k`.
    fn server_cipher(k: &SymKey) -> Value {
        let e = |s: &str| json!(encrypt(s.as_bytes(), k));
        json!({
            "id": "11111111-2222-3333-4444-555555555555", "type": 1, "name": e("GitHub"), "notes": e("note"), "favorite": true,
            "revisionDate": "2026-10-21T10:00:00Z", "reprompt": 0, "passwordHistory": null, "key": null, "organizationId": null,
            "login": { "username": e("octo"), "password": e("pw"), "totp": e("JBSWY3DPEHPK3PXP"),
                       "uris": [{ "uri": e("https://github.com/login"), "match": null }, { "uri": e("https://gist.github.com"), "match": null }] },
            "fields": [{ "name": e("Recovery"), "value": e("abc"), "type": 1 }, { "name": e("Active"), "value": e("true"), "type": 2 }, { "name": e("Password"), "value": e("dup name"), "type": 0 },
                       { "name": e("Linked"), "value": null, "type": 3, "linkedId": 100 }],
        })
    }

    #[test]
    fn roundtrip_is_stable() {
        let k = key();
        let (p, meta) = decrypt_cipher(&server_cipher(&k), &k).unwrap();
        assert_eq!(p.uris.len(), 2);
        let mut db = Database::new();
        let id = {
            let mut root = db.root_mut();
            let mut e = root.add_entry();
            write_entry(&mut e, &p, meta.clone());
            e.id()
        };
        let e = db.entry(id).unwrap();
        assert_eq!(e.get("UserName"), Some("octo"));
        assert_eq!(e.get("KP2A_URL"), Some("https://gist.github.com"));
        assert!(e.fields.get("Password (2)").is_some(), "custom field named like a built-in gets a unique name");
        // reading the untouched entry gives the identical plain cipher → no upload
        let (back, meta2) = read_entry(&e);
        assert_eq!(back, p);
        assert_eq!(meta2.id, meta.id);
        // body decrypts back to the same values
        let body = cipher_body(&back, &meta2, None, &k, "user");
        let (again, _) = decrypt_cipher(
            &json!({ "type": 1, "favorite": true, "id": meta.id, "name": body["name"], "notes": body["notes"],
            "login": body["login"], "fields": body["fields"] }),
            &k,
        )
        .unwrap();
        assert_eq!(again, p);
        assert_eq!(body["encryptedFor"], "user");
    }

    #[test]
    fn new_ui_entry_becomes_login() {
        let mut db = Database::new();
        let id = {
            let mut root = db.root_mut();
            let mut e = root.add_entry();
            e.set_unprotected("Title", "Shop");
            e.set_unprotected("UserName", "me");
            e.set_protected("Password", "secret");
            e.set_unprotected("Shoe size", "44");
            e.id()
        };
        let (p, meta) = read_entry(&db.entry(id).unwrap());
        assert_eq!((p.kind, meta.id.as_str()), (1, ""));
        assert!(p.props.contains(&("login.password".into(), "secret".into())));
        assert_eq!(p.fields, vec![("Shoe size".into(), "44".into(), 0, None)]);
    }
}
