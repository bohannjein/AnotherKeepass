//! Getting data out and in: CSV export (KeePassXC's column layout), encrypted copy,
//! merging another .kdbx (e.g. a KeePassXC copy of the same file), attachment preview.

use std::{fs, path::Path};

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use keepass::{
    db::{merge::MergeEventType, Database, EntryId, GroupId},
    DatabaseKey,
};
use serde::Serialize;

use crate::vault::{VaultDto, Vaults};

fn csv_cell(s: &str) -> String {
    format!("\"{}\"", s.replace('"', "\"\""))
}

/// "Root/Work/Mail" like KeePassXC writes it; None for anything in the recycle bin.
fn group_path(db: &Database, g: GroupId) -> Option<String> {
    let bin = db.recycle_bin().map(|b| b.id());
    let mut names = Vec::new();
    let mut cur = Some(g);
    while let Some(id) = cur {
        if Some(id) == bin {
            return None;
        }
        let grp = db.group(id)?;
        cur = grp.parent().map(|p| p.id());
        // an unnamed root is written as "Root" (what KeePassXC and our importer expect)
        names.push(if cur.is_none() && grp.name.is_empty() { "Root".into() } else { grp.name.clone() });
    }
    names.reverse();
    Some(names.join("/"))
}

pub fn to_csv(db: &Database) -> String {
    let mut out = String::from("\"Group\",\"Title\",\"Username\",\"Password\",\"URL\",\"Notes\",\"TOTP\",\"Icon\",\"Last Modified\",\"Created\"\n");
    for e in db.iter_all_entries() {
        let Some(path) = group_path(db, e.parent().id()) else { continue };
        let f = |k: &str| e.get(k).unwrap_or_default().to_string();
        let time = |t: Option<&chrono::NaiveDateTime>| t.map(|t| t.format("%Y-%m-%dT%H:%M:%SZ").to_string()).unwrap_or_default();
        let row = [
            path, f("Title"), f("UserName"), f("Password"), f("URL"), f("Notes"), f("otp"), "0".into(),
            time(e.times.last_modification.as_ref()), time(e.times.creation.as_ref()),
        ];
        out.push_str(&row.iter().map(|c| csv_cell(c)).collect::<Vec<_>>().join(","));
        out.push('\n');
    }
    out
}

#[tauri::command]
pub fn vault_export_csv(state: tauri::State<'_, Vaults>, vault: String, dest: String) -> Result<usize, String> {
    let map = state.0.lock().map_err(|_| "lock")?;
    let v = map.get(&vault).ok_or("vault_closed")?;
    let csv = to_csv(v.db());
    fs::write(Path::new(&dest), csv.as_bytes()).map_err(|e| format!("io:{e}"))?;
    log::info!("exported CSV");
    Ok(csv.lines().count().saturating_sub(1))
}

/// Encrypted copy with the same master key (a manual backup).
#[tauri::command]
pub fn vault_save_copy(state: tauri::State<'_, Vaults>, vault: String, dest: String) -> Result<(), String> {
    let map = state.0.lock().map_err(|_| "lock")?;
    let v = map.get(&vault).ok_or("vault_closed")?;
    fs::copy(v.path(), Path::new(&dest)).map(|_| ()).map_err(|e| format!("io:{e}"))
}

#[derive(Serialize, Default, Debug, PartialEq)]
pub struct MergeSummary {
    created: usize,
    updated: usize,
    moved: usize,
    deleted: usize,
}

pub fn merge_into(db: &mut Database, other: &Database) -> Result<MergeSummary, String> {
    let log = db.merge(other).map_err(|e| format!("merge:{e}"))?;
    let mut s = MergeSummary::default();
    for ev in log.events {
        match ev.event_type {
            MergeEventType::Created => s.created += 1,
            MergeEventType::Updated => s.updated += 1,
            MergeEventType::LocationUpdated => s.moved += 1,
            MergeEventType::Deleted => s.deleted += 1,
            _ => {}
        }
    }
    Ok(s)
}

/// Merge another .kdbx into an open vault (same UUIDs = same entries; newer wins, like KeePassXC).
#[tauri::command]
pub async fn vault_merge(
    state: tauri::State<'_, Vaults>,
    vault: String,
    path: String,
    password: Option<String>,
    keyfile: Option<String>,
) -> Result<(MergeSummary, VaultDto), String> {
    let mut key = DatabaseKey::new();
    if let Some(p) = password.filter(|p| !p.is_empty()) {
        key = key.with_password(&p);
    }
    if let Some(k) = keyfile.filter(|k| !k.is_empty()) {
        let mut f = fs::File::open(k).map_err(|e| format!("keyfile:{e}"))?;
        key = key.with_keyfile(&mut f).map_err(|e| format!("keyfile:{e}"))?;
    }
    let other = tauri::async_runtime::spawn_blocking(move || -> Result<Database, String> {
        let mut f = fs::File::open(&path).map_err(|e| format!("io:{e}"))?;
        Database::open(&mut f, key).map_err(|e| match e {
            keepass::db::DatabaseOpenError::Key(_) => "wrong_key".to_string(),
            other => format!("open:{other}"),
        })
    })
    .await
    .map_err(|e| e.to_string())??;
    let mut map = state.0.lock().map_err(|_| "lock")?;
    let v = map.get_mut(&vault).ok_or("vault_closed")?;
    let summary = merge_into(v.db_mut(), &other)?;
    v.persist()?;
    log::info!("merged: {summary:?}");
    Ok((summary, v.listing(&vault)))
}

/// Attachment bytes for the in-app preview (images, text); large files are refused.
#[tauri::command]
pub fn attachment_get(state: tauri::State<'_, Vaults>, vault: String, id: String, name: String) -> Result<String, String> {
    let map = state.0.lock().map_err(|_| "lock")?;
    let v = map.get(&vault).ok_or("vault_closed")?;
    let e = v.db().entry(EntryId::from(uuid::Uuid::parse_str(&id).map_err(|_| "not_found")?)).ok_or("not_found")?;
    let a = e.attachment_by_name(&name).ok_or("not_found")?;
    let data = a.data.get();
    if data.len() > 10 * 1024 * 1024 {
        return Err("too_large".into());
    }
    Ok(B64.encode(data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_layout_and_merge() {
        let mut db = Database::new();
        {
            let mut root = db.root_mut();
            let mut g = root.add_group();
            g.name = "Work".into();
            let mut e = g.add_entry();
            e.set_unprotected("Title", "Mail \"main\"");
            e.set_protected("Password", "p,w");
        }
        let csv = to_csv(&db);
        assert!(csv.lines().nth(1).unwrap().starts_with("\"Root/Work\",\"Mail \"\"main\"\"\",\"\",\"p,w\""), "{csv}");

        // a copy gets a new entry; merging brings it back
        let mut copy = db.clone();
        copy.root_mut().add_entry().set_unprotected("Title", "new one");
        let s = merge_into(&mut db, &copy).unwrap();
        assert_eq!(s.created, 1);
        assert_eq!(db.iter_all_entries().count(), 2);
        assert_eq!(merge_into(&mut db, &copy).unwrap().created, 0);
    }
}
