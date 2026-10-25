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
    let logins = c.call(&host, &mut s2, "get-logins", json!({ "action": "get-logins", "url": "https://github.com/session", "keys": keys }));
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
