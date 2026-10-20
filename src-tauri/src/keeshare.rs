//! KeeShare (KeePassXC compatible): a folder is mirrored into its own .kdbx "container"
//! file that others open with a share password — via a shared drive, Nextcloud, …
//! Export: the folder is written to the container after every save.
//! Import: the container's content replaces the folder (on unlock and when the file changes).
//! Synchronize: both; newer entries win, nothing is deleted.
//! The setting lives in the group's custom data "KeeShare/Reference" (base64 XML), exactly
//! where KeePassXC keeps it. Signed .kshare containers are not supported.

use std::{
    collections::{HashMap, HashSet},
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
};

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use keepass::{
    db::{CustomDataItem, CustomDataValue, EntryId, GroupId, Times},
    Database, DatabaseKey,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::vault::{copy_entry, new_config, paste_entry};

const KEY: &str = "KeeShare/Reference";
pub static IMPORT_ON: AtomicBool = AtomicBool::new(true);
pub static EXPORT_ON: AtomicBool = AtomicBool::new(true);

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Share {
    /// "import" | "export" | "sync"
    pub kind: String,
    pub path: String,
    pub password: String,
}

impl Share {
    fn imports(&self) -> bool {
        self.kind != "export"
    }
    fn exports(&self) -> bool {
        self.kind != "import"
    }
}

// ---------------------------------------------------------------- reference format

fn tag<'a>(xml: &'a str, name: &str) -> Option<&'a str> {
    let open = format!("<{name}>");
    let start = xml.find(&open)? + open.len();
    let end = start + xml[start..].find(&format!("</{name}>"))?;
    Some(xml[start..end].trim())
}

fn b64_text(v: Option<&str>) -> String {
    v.and_then(|s| B64.decode(s).ok()).map(|b| String::from_utf8_lossy(&b).into_owned()).unwrap_or_default()
}

pub fn parse(value: &str) -> Option<Share> {
    // KeePassXC stores the XML base64-encoded; accept plain XML too
    let xml = B64.decode(value.trim()).ok().map(|b| String::from_utf8_lossy(&b).into_owned()).filter(|x| x.contains("<KeeShare"))
        .unwrap_or_else(|| value.to_string());
    let types = tag(&xml, "Type").unwrap_or_default();
    let (import, export) = (types.contains("<Import"), types.contains("<Export"));
    let kind = match (import, export) {
        (true, true) => "sync",
        (true, false) => "import",
        (false, true) => "export",
        _ => return None,
    };
    Some(Share { kind: kind.into(), path: b64_text(tag(&xml, "Path")), password: b64_text(tag(&xml, "Password")) })
}

pub fn serialize(s: &Share, group: GroupId) -> String {
    let mut types = String::new();
    if s.imports() { types.push_str("<Import/>"); }
    if s.exports() { types.push_str("<Export/>"); }
    let xml = format!(
        "<?xml version=\"1.0\"?>\n<KeeShare><Type>{types}</Type><Group>{}</Group><Path>{}</Path><Password>{}</Password><KeepGroups>True</KeepGroups></KeeShare>\n",
        B64.encode(group.uuid().as_bytes()),
        B64.encode(s.path.as_bytes()),
        B64.encode(s.password.as_bytes()),
    );
    B64.encode(xml)
}

pub fn group_share(db: &Database, g: GroupId) -> Option<Share> {
    match &db.group(g)?.custom_data.get(KEY)?.value {
        Some(CustomDataValue::String(v)) => parse(v),
        _ => None,
    }
}

pub fn set_group_share(db: &mut Database, g: GroupId, s: Option<&Share>) -> Result<(), String> {
    let mut grp = db.group_mut(g).ok_or("not_found")?;
    match s {
        Some(s) => {
            grp.custom_data.insert(KEY.into(), CustomDataItem { value: Some(CustomDataValue::String(serialize(s, g))), last_modification_time: Some(Times::now()) });
        }
        None => {
            grp.custom_data.remove(KEY);
        }
    }
    Ok(())
}

fn shares(db: &Database) -> Vec<(GroupId, Share)> {
    db.iter_all_groups().filter_map(|g| group_share(db, g.id()).map(|s| (g.id(), s))).collect()
}

/// Relative paths are relative to the vault file, like in KeePassXC.
pub fn container_path(vault: &Path, share: &Share) -> PathBuf {
    let p = Path::new(&share.path);
    if p.is_absolute() { p.to_path_buf() } else { vault.parent().unwrap_or(Path::new(".")).join(p) }
}

fn key(share: &Share) -> DatabaseKey {
    DatabaseKey::new().with_password(&share.password)
}

// ---------------------------------------------------------------- tree copy

/// Entries and subfolders below `g` (recursively), with their path of group ids.
fn subtree(db: &Database, g: GroupId) -> (Vec<GroupId>, Vec<EntryId>) {
    let (mut groups, mut entries) = (Vec::new(), Vec::new());
    let mut stack = vec![g];
    while let Some(cur) = stack.pop() {
        let Some(grp) = db.group(cur) else { continue };
        entries.extend(grp.entries().map(|e| e.id()));
        for sub in grp.groups() {
            groups.push(sub.id());
            stack.push(sub.id());
        }
    }
    (groups, entries)
}

/// Copy everything below `from` in `src` into `to` in `dst`, keeping UUIDs.
/// Existing entries are overwritten when the source is newer (`newer_only`) or always.
fn copy_tree(src: &Database, from: GroupId, dst: &mut Database, to: GroupId, newer_only: bool) -> Result<bool, String> {
    let mut changed = false;
    let mut map = HashMap::from([(from, to)]);
    let mut queue = vec![from];
    while let Some(cur) = queue.pop() {
        let target = map[&cur];
        let Some(grp) = src.group(cur) else { continue };
        let subs: Vec<(GroupId, String)> = grp.groups().map(|s| (s.id(), s.name.clone())).collect();
        let entries: Vec<EntryId> = grp.entries().map(|e| e.id()).collect();
        for (sid, name) in subs {
            if dst.group(sid).is_none() {
                let mut parent = dst.group_mut(target).ok_or("not_found")?;
                parent.add_group_with_id(sid).map_err(|_| "duplicate")?.name = name;
                changed = true;
            } else if dst.group(sid).is_some_and(|g| g.name != name) {
                dst.group_mut(sid).ok_or("not_found")?.name = name;
                changed = true;
            }
            map.insert(sid, sid);
            queue.push(sid);
        }
        for eid in entries {
            let incoming = copy_entry(src, eid)?;
            match dst.entry(eid).map(|e| e.times.last_modification) {
                None => {
                    paste_entry(dst, target, Some(eid), incoming)?;
                    changed = true;
                }
                Some(local) if !newer_only || incoming.times.last_modification > local => {
                    if dst.entry(eid).is_some_and(|e| e.parent().id() != target) {
                        dst.entry_mut(eid).ok_or("not_found")?.move_to(target).map_err(|_| "not_found")?;
                    }
                    crate::vault::overwrite_entry(dst, eid, incoming)?;
                    changed = true;
                }
                Some(_) => {}
            }
        }
    }
    Ok(changed)
}

// ---------------------------------------------------------------- export / import

fn export_one(db: &Database, g: GroupId, vault: &Path, share: &Share) -> Result<(), String> {
    let mut out = Database::new();
    out.config = new_config();
    out.meta.database_name = db.group(g).map(|x| x.name.clone());
    let root = out.root().id();
    out.root_mut().name = db.group(g).map(|x| x.name.clone()).unwrap_or_default();
    copy_tree(db, g, &mut out, root, false)?;
    // the share setting itself is not part of the share
    let mut buf = Vec::new();
    out.save(&mut buf, key(share)).map_err(|e| format!("save:{e}"))?;
    let path = container_path(vault, share);
    let tmp = path.with_extension("kdbx.tmp");
    fs::write(&tmp, &buf).map_err(|e| format!("io:{e}"))?;
    fs::rename(&tmp, &path).map_err(|e| format!("io:{e}"))?;
    crate::vault::stamp(&path);
    Ok(())
}

/// After a save: write every export/sync share. Runs on a copy in the background
/// (each container costs a key derivation).
pub fn export_all(db: &Database, vault: &Path) {
    if !EXPORT_ON.load(Ordering::Relaxed) {
        return;
    }
    let list: Vec<_> = shares(db).into_iter().filter(|(_, s)| s.exports()).collect();
    if list.is_empty() {
        return;
    }
    let (db, vault) = (db.clone(), vault.to_path_buf());
    std::thread::spawn(move || {
        for (g, s) in list {
            if let Err(e) = export_one(&db, g, &vault, &s) {
                log::warn!("keeshare export: {e}");
            }
        }
    });
}

pub fn import_one(db: &mut Database, g: GroupId, vault: &Path, share: &Share) -> Result<bool, String> {
    let path = container_path(vault, share);
    let mut f = fs::File::open(&path).map_err(|e| format!("io:{e}"))?;
    let src = Database::open(&mut f, key(share)).map_err(|e| format!("open:{e}"))?;
    let root = src.root().id();
    let mut changed = copy_tree(&src, root, db, g, share.kind == "sync")?;
    if share.kind == "import" {
        // mirror: what is gone from the container is gone here too
        let (src_groups, src_entries) = subtree(&src, root);
        let (keep_g, keep_e): (HashSet<_>, HashSet<_>) = (src_groups.into_iter().collect(), src_entries.into_iter().collect());
        let (groups, entries) = subtree(db, g);
        for e in entries.into_iter().filter(|e| !keep_e.contains(e)) {
            if let Some(m) = db.entry_mut(e) {
                m.remove();
                changed = true;
            }
        }
        for sg in groups.into_iter().rev().filter(|x| !keep_g.contains(x)) {
            if let Some(m) = db.group_mut(sg) {
                let _ = m.remove();
                changed = true;
            }
        }
    }
    Ok(changed)
}

/// On unlock / file change: pull every import/sync share. Returns whether the vault changed.
pub fn import_all(db: &mut Database, vault: &Path) -> bool {
    if !IMPORT_ON.load(Ordering::Relaxed) {
        return false;
    }
    let mut changed = false;
    for (g, s) in shares(db).into_iter().filter(|(_, s)| s.imports()) {
        match import_one(db, g, vault, &s) {
            Ok(c) => changed |= c,
            Err(e) => log::warn!("keeshare import: {e}"),
        }
    }
    changed
}

/// Container files to watch for changes (import/sync shares of a vault).
pub fn watched(db: &Database, vault: &Path) -> Vec<PathBuf> {
    shares(db).into_iter().filter(|(_, s)| s.imports()).map(|(_, s)| container_path(vault, &s)).collect()
}

pub fn parse_group(id: &str) -> Result<GroupId, String> {
    Ok(GroupId::from_uuid(Uuid::parse_str(id).map_err(|_| "not_found")?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reference_roundtrip() {
        let s = Share { kind: "sync".into(), path: "team.kdbx".into(), password: "pw".into() };
        let g = GroupId::from_uuid(Uuid::new_v4());
        assert_eq!(parse(&serialize(&s, g)), Some(s));
        assert_eq!(parse("<KeeShare><Type><Import/></Type><Path>YS5rZGJ4</Path><Password></Password></KeeShare>").unwrap().path, "a.kdbx");
    }

    #[test]
    fn export_then_import_mirrors() {
        let dir = std::env::temp_dir().join(format!("akp-ks-{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let vault = dir.join("v.kdbx");
        // source vault with a shared folder (2 entries, 1 subfolder)
        let mut a = Database::new();
        let shared = { let mut r = a.root_mut(); let mut g = r.add_group(); g.name = "Team".into(); g.id() };
        let e1 = { let mut g = a.group_mut(shared).unwrap(); let mut e = g.add_entry(); e.set_unprotected("Title", "one"); e.id() };
        let sub = { let mut g = a.group_mut(shared).unwrap(); let mut s = g.add_group(); s.name = "Sub".into(); s.id() };
        { let mut g = a.group_mut(sub).unwrap(); g.add_entry().set_unprotected("Title", "two"); }
        let share = Share { kind: "export".into(), path: "team.kdbx".into(), password: "pw".into() };
        // fast KDF for the test
        let mut out = Database::new();
        out.config = new_config();
        export_one(&a, shared, &vault, &share).unwrap();
        // other vault imports it
        let mut b = Database::new();
        let target = { let mut r = b.root_mut(); let mut g = r.add_group(); g.name = "From team".into(); g.id() };
        let imp = Share { kind: "import".into(), ..share.clone() };
        assert!(import_one(&mut b, target, &vault, &imp).unwrap());
        assert_eq!(b.entry(e1).unwrap().parent().id(), target);
        assert!(b.group(sub).is_some());
        // second import: nothing new; local extra entry gets removed (mirror)
        { let mut g = b.group_mut(target).unwrap(); g.add_entry().set_unprotected("Title", "local"); }
        assert!(import_one(&mut b, target, &vault, &imp).unwrap());
        assert_eq!(subtree(&b, target).1.len(), 2);
        let _ = fs::remove_dir_all(dir);
    }
}
