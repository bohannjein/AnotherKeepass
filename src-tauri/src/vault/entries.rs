//! Commands on entries and folders: save, import, secrets, TOTP, copy, move, trash, history, attachments.

use super::*;

// ---------------------------------------------------------------- commands: entries

/// Writes the edit payload into an entry (history is handled by the caller).
pub(super) fn apply_item(e: &mut keepass::db::EntryMut<'_>, item: &ItemInput, is_new: bool) -> R<()> {
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
    // passkey data (KeePassXC KPEX_PASSKEY_*) isn't edited in the UI: carry it over
    for (k, v) in old {
        if (k.starts_with("KPEX_PASSKEY") || k.starts_with("KPXC_PASSKEY")) && !e.fields.contains_key(&k) {
            e.fields.insert(k, v);
        }
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
pub(super) fn save_item(db: &mut Database, item: &ItemInput) -> R<String> {
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
    pub(super) path: Vec<String>,
    pub(super) item: ItemInput,
}

/// Find or create the folder path below parent.
pub(super) fn ensure_path(db: &mut Database, parent: GroupId, path: &[String]) -> R<GroupId> {
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
pub(super) fn import_items(db: &mut Database, parent: Option<&str>, items: Vec<ImportInput>) -> R<usize> {
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
pub fn entry_import(
    state: tauri::State<'_, Vaults>,
    vault: String,
    parent: Option<String>,
    items: Vec<ImportInput>,
) -> R<(usize, VaultDto)> {
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
        Ok(e.fields.iter().filter(|(_, val)| val.is_protected()).map(|(k, val)| (k.clone(), val.get().clone())).collect())
    })
}

/// TOTP for a field. Accepts otpauth:// URIs (KeePassXC) and, for the `otp` field,
/// KeePass 2.47+ native fields (TimeOtp-Secret-Base32, TimeOtp-Period, TimeOtp-Length).
pub(super) fn totp_of(e: &keepass::db::Entry, field: &str) -> R<keepass::db::TOTP> {
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
pub(super) fn padded_secret(uri: &str) -> String {
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

pub(super) fn group_or_root(db: &Database, folder: Option<&str>) -> R<GroupId> {
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

pub(super) fn move_to_vault(map: &mut HashMap<String, OpenVault>, src: &str, eid: EntryId, dst: &str, folder: Option<&str>) -> R<()> {
    if map.get(dst).is_some_and(|d| d.remote.is_some()) {
        let e = map.get(src).ok_or("vault_closed")?.db.entry(eid).ok_or("not_found")?;
        if e.attachments_named().next().is_some() || e.fields.keys().any(|k| k.starts_with("KPEX_")) {
            return Err("remote_move_loses_data".into()); // attachments / passkeys would be lost
        }
    }
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

pub(super) fn duplicate_entry(db: &mut Database, eid: EntryId, suffix: &str) -> R<EntryId> {
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
        let target = db.entry(eid).ok_or("not_found")?.previous_parent().map(|g| g.id()).filter(|g| Some(*g) != bin).unwrap_or(root);
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
pub fn entry_history_restore(state: tauri::State<'_, Vaults>, vault: String, id: String, index: usize) -> R<VaultDto> {
    mutate(&state, &vault, |db| {
        let eid = EntryId::from(parse_uuid(&id)?);
        let old =
            db.entry(eid).ok_or("not_found")?.history.as_ref().and_then(|h| h.get_entries().get(index).cloned()).ok_or("not_found")?;
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
pub fn attachment_save(state: tauri::State<'_, Vaults>, vault: String, id: String, name: String, dest: String) -> R<()> {
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
