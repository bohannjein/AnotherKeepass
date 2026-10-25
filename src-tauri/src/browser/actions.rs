//! Protocol actions: associate, logins (URL matching after KeePassXC), save login, TOTP, groups, delete.

use super::*;

// ---------------------------------------------------------------- actions

pub(super) fn associate(host: &dyn Host, s: &mut Session, p: &Value) -> ActionResult {
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

pub(super) fn test_associate(host: &dyn Host, s: &mut Session, p: &Value) -> ActionResult {
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

pub(super) struct Site {
    scheme: String,
    host: String,
    port: Option<u16>,
    full: String,
    no_query: String,
}

pub(super) fn site(raw: &str) -> Option<Site> {
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
pub(super) fn score(entry_url: &str, page: &Site, form: Option<&Site>, match_scheme: bool) -> u32 {
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

pub(super) fn entry_score(e: &Entry, page: &Site, form: Option<&Site>, match_scheme: bool) -> u32 {
    let mut urls: Vec<&str> = e.get_url().into_iter().collect();
    urls.extend(e.fields.iter().filter(|(k, _)| k.starts_with(ADDITIONAL_URL)).map(|(_, v)| v.get().as_str()));
    urls.into_iter().map(|u| score(u, page, form, match_scheme)).max().unwrap_or(0)
}

/// Per-entry browser permissions, stored like KeePassXC: {"Allow":[hosts],"Deny":[hosts],"Realm":""}
pub(super) fn entry_settings(e: &Entry) -> Value {
    cd_string(e.custom_data.get(ENTRY_SETTINGS)).and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_else(|| json!({}))
}

pub(super) fn host_in(settings: &Value, list: &str, host: &str) -> bool {
    settings[list].as_array().is_some_and(|a| a.iter().any(|h| h.as_str() == Some(host)))
}

pub(super) fn set_permission(e: &mut Entry, host: &str, allow: bool) {
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

pub(super) fn entry_json(e: &Entry, group: &str, kph: bool, expired: bool) -> Value {
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

pub(super) fn get_logins(host: &dyn Host, s: &mut Session, p: &Value) -> ActionResult {
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

pub(super) fn active_hash_locked(map: &HashMap<String, OpenVault>, host: &dyn Host) -> String {
    host.active_vault().and_then(|id| map.get(&id)).or_else(|| map.values().next()).map(|v| db_hash(v.db())).unwrap_or_default()
}

pub(super) fn generate_password() -> Map<String, Value> {
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

pub(super) fn default_group(db: &mut Database) -> GroupId {
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

pub(super) fn set_login(host: &dyn Host, s: &mut Session, p: &Value) -> ActionResult {
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

pub(super) fn get_totp(host: &dyn Host, s: &mut Session, p: &Value) -> ActionResult {
    if !s.associated {
        return Err(E_ASSOCIATION_FAILED);
    }
    let uuid = p["uuid"].as_str().and_then(parse_uuid_hex).ok_or(E_NO_VALID_UUID)?;
    let allowed = allowed_vaults(host, s, p);
    let map = host.vaults().0.lock().map_err(|_| E_NO_VALID_UUID)?;
    let e = map.iter().filter(|(k, _)| allowed.contains(*k)).find_map(|(_, v)| v.db().entry(EntryId::from(uuid))).ok_or(E_NO_VALID_UUID)?;
    Ok(params(&[("totp", json!(crate::vault::totp_code(&e, fields::OTP).unwrap_or_default()))]))
}

pub(super) fn group_tree(db: &Database, id: GroupId, bin: Option<GroupId>) -> Value {
    let g = db.group(id).expect("group exists");
    let children: Vec<Value> = g.group_ids().filter(|c| Some(*c) != bin).map(|c| group_tree(db, c, bin)).collect();
    json!({ "name": g.name, "uuid": uuid_hex(id.uuid()), "children": children })
}

pub(super) fn database_groups(host: &dyn Host, s: &mut Session) -> ActionResult {
    if !s.associated {
        return Err(E_ASSOCIATION_FAILED);
    }
    let vid = active_id(host).ok_or(E_DB_NOT_OPENED)?;
    let map = host.vaults().0.lock().map_err(|_| E_NO_GROUPS)?;
    let db = map.get(&vid).ok_or(E_NO_GROUPS)?.db();
    let tree = group_tree(db, db.root().id(), db.recycle_bin().map(|g| g.id()));
    Ok(params(&[("defaultGroup", json!("")), ("defaultGroupAlwaysAllow", json!(false)), ("groups", json!({ "groups": [tree] }))]))
}

pub(super) fn create_group(host: &dyn Host, s: &mut Session, p: &Value) -> ActionResult {
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

pub(super) fn delete_entry(host: &dyn Host, s: &mut Session, p: &Value) -> ActionResult {
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
