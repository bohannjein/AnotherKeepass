//! Two-way sync between a .kdbx vault and a Vaultwarden account vault. The account is an
//! in-memory KeePass database too, so this compares two databases entry by entry.
//! The link and the state of the last sync (which entry pairs with which, and a fingerprint of
//! their content) live in the .kdbx meta data. Per pair: only one side changed → copy it over;
//! both changed → the newer one wins; one side deleted and the other unchanged → delete there.
//! Entries without a pair are matched by title/username/URL first, else created on the other side.

use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;

use keepass::db::{CustomDataItem, CustomDataValue, EntryId, EntryRef, GroupId, Times};
use keepass::Database;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tauri::{AppHandle, Emitter};

use crate::vault::{ensure_recycle_bin, OpenVault};

pub const CD_LINK: &str = "AnotherKeepass.SyncWith";
const CD_STATE: &str = "AnotherKeepass.SyncState";

/// set at startup, to tell the UI about vaults changed by a sync
pub static APP: OnceLock<AppHandle> = OnceLock::new();

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
struct Pair {
    a: String,
    b: String,
    /// fingerprint of both sides after the last sync
    h: String,
}

fn cd(db: &Database, key: &str) -> Option<String> {
    match &db.meta.custom_data.get(key)?.value {
        Some(CustomDataValue::String(s)) => Some(s.clone()),
        _ => None,
    }
}

fn set_cd(db: &mut Database, key: &str, value: Option<String>) {
    match value {
        Some(v) => { db.meta.custom_data.insert(key.into(), CustomDataItem { value: Some(CustomDataValue::String(v)), last_modification_time: Some(Times::now()) }); }
        None => { db.meta.custom_data.remove(key); }
    }
}

pub fn link_of(db: &Database) -> Option<String> {
    cd(db, CD_LINK)
}

/// Link a .kdbx to an account (None = unlink). A new link starts with a fresh state.
pub fn set_link(db: &mut Database, remote: Option<&str>) {
    if link_of(db).as_deref() != remote {
        set_cd(db, CD_STATE, None);
    }
    set_cd(db, CD_LINK, remote.map(String::from));
}

fn in_bin(db: &Database, mut g: Option<GroupId>) -> bool {
    let bin = db.recycle_bin().map(|b| b.id());
    while let Some(id) = g {
        if Some(id) == bin {
            return true;
        }
        g = db.group(id).and_then(|x| x.parent().map(|p| p.id()));
    }
    false
}

/// Folder names from the root down (root itself not included).
fn folder_path(db: &Database, e: &EntryRef<'_>) -> Vec<String> {
    let root = db.root().id();
    let mut names = Vec::new();
    let mut g = Some(e.parent().id());
    while let Some(id) = g.filter(|x| *x != root) {
        let Some(grp) = db.group(id) else { break };
        names.push(grp.name.clone());
        g = grp.parent().map(|p| p.id());
    }
    names.reverse();
    names
}

fn ensure_path(db: &mut Database, names: &[String]) -> GroupId {
    let mut cur = db.root().id();
    for n in names {
        let found = db.group(cur).and_then(|g| g.groups().find(|c| &c.name == n).map(|c| c.id()));
        cur = match found {
            Some(id) => id,
            None => match db.group_mut(cur) {
                Some(mut g) => { let mut c = g.add_group(); c.name = n.clone(); c.id() }
                None => cur,
            },
        };
    }
    cur
}

/// Content that matters for sync: folder, strings (non-empty), tags. Passkey strings,
/// attachments and Bitwarden bookkeeping are not compared.
fn fingerprint(db: &Database, e: &EntryRef<'_>) -> String {
    let mut fields: Vec<(&String, String)> = e.fields.iter()
        .filter(|(k, v)| !v.get().is_empty() && !k.starts_with("KPEX_PASSKEY") && !k.starts_with("KPXC_PASSKEY"))
        .map(|(k, v)| (k, v.get().clone()))
        .collect();
    fields.sort();
    let mut tags = e.tags.clone();
    tags.sort();
    let doc = serde_json::json!({ "path": folder_path(db, e), "fields": fields, "tags": tags });
    Sha256::digest(doc.to_string().as_bytes()).iter().take(12).map(|b| format!("{b:02x}")).collect()
}

fn key_of(e: &EntryRef<'_>) -> (String, String, String) {
    let g = |k: &str| e.get(k).unwrap_or_default().trim().to_lowercase();
    (g("Title"), g("UserName"), g("URL"))
}

fn modified(e: &EntryRef<'_>) -> chrono::NaiveDateTime {
    e.times.last_modification.unwrap_or_default()
}

/// Copy content from src into dst (existing entry or a new one). Keeps the target's own
/// bookkeeping (Bitwarden meta, attachments) and pushes the old version into its history.
fn copy_over(src_db: &Database, src: EntryId, dst_db: &mut Database, dst: Option<EntryId>) -> Option<EntryId> {
    let s = src_db.entry(src)?;
    let path = folder_path(src_db, &s);
    let (fields, tags, times) = (s.fields.clone(), s.tags.clone(), s.times.clone());
    let ours: Vec<(String, CustomDataItem)> = s.custom_data.iter().filter(|(k, _)| k.starts_with("AnotherKeepass.")).map(|(k, v)| (k.clone(), v.clone())).collect();
    let folder = ensure_path(dst_db, &path);
    let id = match dst.filter(|d| dst_db.entry(*d).is_some()) {
        Some(d) => {
            let mut e = dst_db.entry_mut(d)?;
            if e.as_ref().parent().id() != folder {
                let _ = e.move_to(folder);
            }
            let mut t = e.track_changes();
            let mut m = t.as_mut();
            // passkeys and other strings the source doesn't know stay on the target
            let keep: Vec<(String, keepass::db::Value<String>)> = m.fields.iter().filter(|(k, _)| k.starts_with("KPEX_")).map(|(k, v)| (k.clone(), v.clone())).collect();
            m.fields = fields;
            for (k, v) in keep {
                m.fields.entry(k).or_insert(v);
            }
            m.tags = tags;
            m.custom_data.retain(|k, _| !k.starts_with("AnotherKeepass."));
            m.custom_data.extend(ours);
            d
        }
        None => {
            let mut g = dst_db.group_mut(folder)?;
            let mut e = g.add_entry();
            e.fields = fields;
            e.tags = tags;
            e.custom_data.extend(ours);
            e.id()
        }
    };
    if let Some(mut e) = dst_db.entry_mut(id) {
        e.times.last_modification = times.last_modification;
        e.times.creation = e.times.creation.or(times.creation);
    }
    Some(id)
}

fn trash(db: &mut Database, id: EntryId) {
    let bin = ensure_recycle_bin(db);
    if let Some(mut e) = db.entry_mut(id) {
        let _ = e.move_to(bin);
        e.times.location_changed = Some(Times::now());
    }
}

fn live(db: &Database, id: &str) -> Option<EntryId> {
    let eid = EntryId::from(uuid::Uuid::parse_str(id).ok()?);
    let e = db.entry(eid)?;
    (!in_bin(db, Some(e.parent().id()))).then_some(eid)
}

/// Sync a (the .kdbx) with b (the account). Returns (a changed, b changed).
pub fn sync(a: &mut Database, b: &mut Database) -> (bool, bool) {
    let state: Vec<Pair> = cd(a, CD_STATE).and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default();
    let (mut ca, mut cb) = (false, false);
    let mut next = Vec::new();
    let (mut used_a, mut used_b) = (HashSet::new(), HashSet::new());

    for p in &state {
        let (ea, eb) = (live(a, &p.a), live(b, &p.b));
        used_a.insert(p.a.clone());
        used_b.insert(p.b.clone());
        match (ea, eb) {
            (Some(ia), Some(ib)) => {
                let fa = fingerprint(a, &a.entry(ia).expect("live"));
                let fb = fingerprint(b, &b.entry(ib).expect("live"));
                if fa != fb {
                    let a_newer = modified(&a.entry(ia).expect("live")) >= modified(&b.entry(ib).expect("live"));
                    if (fa != p.h && fb == p.h) || (fa != p.h && fb != p.h && a_newer) {
                        copy_over(a, ia, b, Some(ib));
                        cb = true;
                    } else {
                        copy_over(b, ib, a, Some(ia));
                        ca = true;
                    }
                }
                let h = fingerprint(a, &a.entry(ia).expect("live"));
                next.push(Pair { a: p.a.clone(), b: p.b.clone(), h });
            }
            (Some(ia), None) => {
                if fingerprint(a, &a.entry(ia).expect("live")) == p.h {
                    trash(a, ia); // deleted in the account → delete here
                    ca = true;
                } else if let Some(nb) = copy_over(a, ia, b, None) {
                    // changed here after it was deleted there → bring it back
                    cb = true;
                    let h = fingerprint(a, &a.entry(ia).expect("live"));
                    next.push(Pair { a: p.a.clone(), b: nb.to_string(), h });
                }
            }
            (None, Some(ib)) => {
                if fingerprint(b, &b.entry(ib).expect("live")) == p.h {
                    trash(b, ib);
                    cb = true;
                } else if let Some(na) = copy_over(b, ib, a, None) {
                    ca = true;
                    let h = fingerprint(a, &a.entry(na).expect("new"));
                    next.push(Pair { a: na.to_string(), b: p.b.clone(), h });
                }
            }
            (None, None) => {}
        }
    }

    // not paired yet: match by title/username/URL (first sync, imports), else create
    let mut free_b: HashMap<(String, String, String), Vec<EntryId>> = HashMap::new();
    for e in b.iter_all_entries() {
        let id = e.id().to_string();
        if !used_b.contains(&id) && !in_bin(b, Some(e.parent().id())) {
            free_b.entry(key_of(&e)).or_default().push(e.id());
        }
    }
    let new_a: Vec<EntryId> = a.iter_all_entries()
        .filter(|e| !used_a.contains(&e.id().to_string()) && !in_bin(a, Some(e.parent().id())))
        .map(|e| e.id())
        .collect();
    for ia in new_a {
        let k = key_of(&a.entry(ia).expect("listed"));
        let matched = free_b.get_mut(&k).and_then(|v| v.pop());
        let ib = match matched {
            Some(ib) => {
                let (fa, fb) = (fingerprint(a, &a.entry(ia).expect("listed")), fingerprint(b, &b.entry(ib).expect("listed")));
                if fa != fb {
                    if modified(&a.entry(ia).expect("listed")) >= modified(&b.entry(ib).expect("listed")) {
                        copy_over(a, ia, b, Some(ib));
                        cb = true;
                    } else {
                        copy_over(b, ib, a, Some(ia));
                        ca = true;
                    }
                }
                ib
            }
            None => match copy_over(a, ia, b, None) {
                Some(n) => { cb = true; n }
                None => continue,
            },
        };
        used_b.insert(ib.to_string());
        let h = fingerprint(a, &a.entry(ia).expect("listed"));
        next.push(Pair { a: ia.to_string(), b: ib.to_string(), h });
    }
    let new_b: Vec<EntryId> = free_b.into_values().flatten().collect();
    for ib in new_b {
        if let Some(na) = copy_over(b, ib, a, None) {
            ca = true;
            let h = fingerprint(a, &a.entry(na).expect("new"));
            next.push(Pair { a: na.to_string(), b: ib.to_string(), h });
        }
    }

    if next != state {
        set_cd(a, CD_STATE, Some(serde_json::to_string(&next).unwrap_or_default()));
        ca = true;
    }
    (ca, cb)
}

/// The account renamed new entries to their server ids: follow that in the pair list.
pub(crate) fn remap(a: &mut Database, renamed: &[(String, String)]) -> bool {
    if renamed.is_empty() {
        return false;
    }
    let mut state: Vec<Pair> = cd(a, CD_STATE).and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default();
    for p in &mut state {
        if let Some((_, new)) = renamed.iter().find(|(old, _)| *old == p.b) {
            p.b = new.clone();
        }
    }
    set_cd(a, CD_STATE, Some(serde_json::to_string(&state).unwrap_or_default()));
    true
}

/// After a vault changed or was unlocked: sync it with its partner if both are open.
pub fn after_change(map: &mut HashMap<String, OpenVault>, id: &str) {
    let pairs: Vec<(String, String)> = match map.get(id) {
        Some(v) if v.remote.is_some() => map.iter()
            .filter(|(_, x)| x.remote.is_none() && link_of(x.db()).as_deref() == Some(id))
            .map(|(k, _)| (k.clone(), id.to_string()))
            .collect(),
        Some(v) => link_of(v.db()).filter(|l| map.contains_key(l)).map(|l| vec![(id.to_string(), l)]).unwrap_or_default(),
        None => vec![],
    };
    for (aid, bid) in pairs {
        let (Some(mut a), Some(mut b)) = (map.remove(&aid), map.remove(&bid)) else { continue };
        let (mut ca, cb) = sync(a.db_mut(), b.db_mut());
        let mut problem = None;
        if cb {
            match b.persist() {
                Ok(()) => {
                    let renamed = b.remote.as_mut().map(|r| r.take_created()).unwrap_or_default();
                    ca |= remap(a.db_mut(), &renamed);
                }
                Err(e) => problem = Some(e),
            }
        }
        if ca {
            if let Err(e) = a.persist() {
                problem = Some(e);
            }
        }
        if let Some(app) = APP.get() {
            let _ = app.emit("akp-vault-updated", a.listing(&aid));
            let _ = app.emit("akp-vault-updated", b.listing(&bid));
            if let Some(e) = &problem {
                let _ = app.emit("akp-sync-problem", e.clone());
            }
        }
        if let Some(e) = problem {
            log::warn!("kdbx/vaultwarden sync: {e}");
        } else if ca || cb {
            log::info!("kdbx/vaultwarden sync done");
        }
        map.insert(aid, a);
        map.insert(bid, b);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn add(db: &mut Database, folder: &[&str], title: &str, user: &str, pw: &str) -> EntryId {
        let names: Vec<String> = folder.iter().map(|s| s.to_string()).collect();
        let g = ensure_path(db, &names);
        let mut grp = db.group_mut(g).unwrap();
        let mut e = grp.add_entry();
        e.set_unprotected("Title", title);
        e.set_unprotected("UserName", user);
        e.set_protected("Password", pw);
        e.times.last_modification = Some(Times::now());
        e.id()
    }
    fn titles(db: &Database) -> Vec<String> {
        let mut t: Vec<String> = db.iter_all_entries().filter(|e| !in_bin(db, Some(e.parent().id()))).map(|e| e.get_title().unwrap_or_default().to_string()).collect();
        t.sort();
        t
    }
    fn pw(db: &Database, title: &str) -> String {
        db.iter_all_entries().find(|e| e.get_title() == Some(title) && !in_bin(db, Some(e.parent().id()))).and_then(|e| e.get("Password").map(String::from)).unwrap_or_default()
    }

    #[test]
    fn two_way() {
        let (mut a, mut b) = (Database::new(), Database::new());
        add(&mut a, &["Work"], "Mail", "me", "1");
        add(&mut b, &[], "Bank", "me", "2");
        add(&mut a, &[], "Shared", "x", "old");
        add(&mut b, &[], "Shared", "x", "old");
        // first sync: both sides get everything, the common entry is paired, not duplicated
        sync(&mut a, &mut b);
        assert_eq!(titles(&a), ["Bank", "Mail", "Shared"]);
        assert_eq!(titles(&b), ["Bank", "Mail", "Shared"]);
        assert_eq!(sync(&mut a, &mut b), (false, false), "second sync is a no-op");
        assert!(b.iter_all_entries().any(|e| e.get_title() == Some("Mail") && e.parent().name == "Work"), "folder carried over");

        // change on one side travels
        let id = b.iter_all_entries().find(|e| e.get_title() == Some("Shared")).unwrap().id();
        b.entry_mut(id).unwrap().set_protected("Password", "new");
        assert_eq!(sync(&mut a, &mut b), (true, false));
        assert_eq!(pw(&a, "Shared"), "new");

        // delete on one side travels
        let id = a.iter_all_entries().find(|e| e.get_title() == Some("Bank")).unwrap().id();
        trash(&mut a, id);
        sync(&mut a, &mut b);
        assert_eq!(titles(&b), ["Mail", "Shared"]);
    }
}
