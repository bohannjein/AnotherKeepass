//! Passkey actions (register / get) on top of crate::passkeys, stored KeePassXC-compatible in entries.

use super::*;

// ---------------------------------------------------------------- passkeys

/// Vaults the extension may use (associated; only the active one unless "search all").
pub(super) fn usable_vaults(host: &dyn Host, p: &Value) -> Vec<String> {
    let mut ids = associated_vaults(host, &keys_of(p));
    if !host.prefs().search_all {
        let active = active_id(host);
        ids.retain(|v| Some(v) == active.as_ref());
    }
    ids
}

pub(super) fn field(e: &Entry, name: &str) -> String {
    e.get(name).unwrap_or_default().to_string()
}

/// Passkey entries for an RP: (vault, entry, credential id).
pub(super) fn passkey_entries(host: &dyn Host, vaults: &[String], rp: &str) -> Vec<(String, EntryId, String)> {
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

pub(super) fn entry_brief(map: &HashMap<String, OpenVault>, vid: &str, id: EntryId) -> Option<Value> {
    let e = map.get(vid)?.db().entry(id)?;
    let user = e.get(passkeys::USERNAME).filter(|u| !u.is_empty()).or_else(|| e.get_username()).unwrap_or_default();
    Some(json!({ "vault": vid, "uuid": uuid_hex(id.uuid()), "title": e.get_title().unwrap_or_default(), "username": user }))
}

pub(super) fn write_passkey(e: &mut keepass::db::EntryMut<'_>, reg: &passkeys::Registration, cred_id: &str, pem: &str) {
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

pub(super) fn passkey_reply(v: Value) -> ActionResult {
    Ok(params(&[("response", v)]))
}

pub(super) fn passkeys_register(host: &dyn Host, s: &mut Session, p: &Value) -> ActionResult {
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

pub(super) fn passkeys_get(host: &dyn Host, s: &mut Session, p: &Value) -> ActionResult {
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
