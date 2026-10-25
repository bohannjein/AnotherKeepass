use super::*;

fn temp_path(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("akp-test-{}-{name}.kdbx", Uuid::new_v4()))
}

#[test]
fn roundtrip_create_edit_trash_reopen() {
    let state = Vaults::default();
    let path = temp_path("rt");
    let p = path.to_string_lossy().to_string();
    let key = make_key(Some("pw"), None).unwrap();

    // create (direct, no tauri State needed)
    let mut db = Database::with_config(new_config());
    db.meta.database_name = Some("Test".into());
    ensure_recycle_bin(&mut db);
    let mut v = OpenVault { path: path.clone(), db, key: key.clone(), remote: None };
    write_db(&mut v).unwrap();
    let root = v.db.root().id().to_string();
    state.0.lock().unwrap().insert(p.clone(), v);

    // add folder + entry with protected field, custom data, attachment, expiry
    let mut folder_id = String::new();
    with_vault(&state, &p, |v| {
        let id = v.db.root_mut().add_group().edit(|g| g.name = "Work".into()).id();
        folder_id = id.to_string();
        write_db(v)
    })
    .unwrap();
    let _ = root;
    let input = ItemInput {
        id: None,
        folder: folder_id.clone(),
        fields: vec![
            FieldDto { name: "Title".into(), value: Some("Mail".into()), protected: false },
            FieldDto { name: "Password".into(), value: Some("s3cret".into()), protected: true },
            FieldDto { name: "otp".into(), value: Some("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP".into()), protected: true },
        ],
        tags: vec!["pinned".into()],
        custom_data: HashMap::from([(CD_TYPE.into(), "login".into())]),
        expires: Some("2030-01-31".into()),
        keep_attachments: vec![],
        add_attachments: vec![NewAttachment { name: "a.txt".into(), base64: B64.encode(b"hello") }],
    };
    // emulate entry_save without tauri State
    let saved = save_for_test(&state, &p, input);

    // edit keeps secret when value is None, creates history
    let edit = ItemInput {
        id: Some(saved.clone()),
        folder: folder_id.clone(),
        fields: vec![
            FieldDto { name: "Title".into(), value: Some("Mail 2".into()), protected: false },
            FieldDto { name: "Password".into(), value: None, protected: true },
            FieldDto { name: "otp".into(), value: None, protected: true },
        ],
        tags: vec![],
        custom_data: HashMap::from([(CD_TYPE.into(), "login".into())]),
        expires: None,
        keep_attachments: vec!["a.txt".into()],
        add_attachments: vec![],
    };
    save_for_test(&state, &p, edit);

    // reopen from disk with the key
    let mut f = fs::File::open(&path).unwrap();
    let db = Database::open(&mut f, key.clone()).unwrap();
    let e = db.entry(EntryId::from(Uuid::parse_str(&saved).unwrap())).unwrap();
    assert_eq!(e.get_title(), Some("Mail 2"));
    assert_eq!(e.get_password(), Some("s3cret"));
    assert!(e.fields["Password"].is_protected());
    assert_eq!(e.history.as_ref().unwrap().get_entries().len(), 1);
    assert_eq!(e.attachment_by_name("a.txt").unwrap().data.get(), b"hello");
    assert!(e.get_otp().is_ok());
    assert_eq!(e.parent().name, "Work");
    assert!(matches!(
        e.custom_data.get(CD_TYPE).and_then(|c| c.value.clone()),
        Some(keepass::db::CustomDataValue::String(s)) if s == "login"
    ));

    // wrong key is rejected
    let mut f = fs::File::open(&path).unwrap();
    assert!(Database::open(&mut f, make_key(Some("nope"), None).unwrap()).is_err());

    // trash + restore + delete
    with_vault(&state, &p, |v| {
        let bin = ensure_recycle_bin(&mut v.db);
        v.db.entry_mut(EntryId::from(Uuid::parse_str(&saved).unwrap())).unwrap().move_to(bin).unwrap();
        assert!(dto(&p, v).items.iter().any(|i| i.trashed));
        Ok(())
    })
    .unwrap();

    // new vault config is Argon2id with real memory cost
    assert!(matches!(new_config().kdf_config, KdfConfig::Argon2id { memory, .. } if memory >= 64 * 1024 * 1024));
    let _ = fs::remove_file(path);
}

fn open_temp(state: &Vaults, name: &str) -> (String, String) {
    let path = temp_path(name);
    let p = path.to_string_lossy().to_string();
    let mut db = Database::with_config(new_config());
    ensure_recycle_bin(&mut db);
    let root = db.root().id().to_string();
    let mut v = OpenVault { path, db, key: make_key(Some("pw"), None).unwrap(), remote: None };
    write_db(&mut v).unwrap();
    state.0.lock().unwrap().insert(p.clone(), v);
    (p, root)
}

fn login(folder: &str, title: &str) -> ItemInput {
    ItemInput {
        id: None,
        folder: folder.into(),
        fields: vec![
            FieldDto { name: "Title".into(), value: Some(title.into()), protected: false },
            FieldDto { name: "Password".into(), value: Some("pw-".to_string() + title), protected: true },
        ],
        tags: vec!["work".into()],
        custom_data: HashMap::new(),
        expires: None,
        keep_attachments: vec![],
        add_attachments: vec![NewAttachment { name: "f.txt".into(), base64: B64.encode(b"data") }],
    }
}

#[test]
fn import_creates_folders_once() {
    let mut db = Database::new();
    let item = |title: &str| ItemInput {
        id: Some("ignored".into()),
        folder: String::new(),
        fields: vec![FieldDto { name: "Title".into(), value: Some(title.into()), protected: false }],
        tags: vec![],
        custom_data: HashMap::new(),
        expires: None,
        keep_attachments: vec![],
        add_attachments: vec![],
    };
    let items = vec![
        ImportInput { path: vec!["Work".into(), "Mail".into()], item: item("a") },
        ImportInput { path: vec!["Work".into(), "Mail".into()], item: item("b") },
        ImportInput { path: vec![], item: item("c") },
    ];
    assert_eq!(import_items(&mut db, None, items).unwrap(), 3);
    assert_eq!(db.iter_all_groups().filter(|g| g.name == "Mail").count(), 1);
    assert_eq!(db.iter_all_entries().count(), 3);
}

#[test]
fn weak_kdf_detection() {
    assert!(weak_kdf(&KdfConfig::Aes { rounds: 6000 }));
    assert!(!weak_kdf(&new_config().kdf_config));
    assert!(weak_kdf(&DatabaseConfig::default().kdf_config)); // crate default: 1 MiB Argon2
}

#[test]
fn backup_pattern() {
    let vault = Path::new("C:/vaults/work.kdbx");
    assert_eq!(backup_target(vault, "{DB_FILENAME}.old.kdbx").unwrap(), Path::new("C:/vaults/work.old.kdbx"));
    let t = backup_target(vault, "backup/{DB_FILENAME}_{TIME:yyyyMMdd}.kdbx").unwrap();
    let name = t.file_name().unwrap().to_string_lossy().to_string();
    assert!(name.starts_with("work_20") && name.len() == "work_20261020.kdbx".len(), "{name}");
}

#[test]
fn totp_variants() {
    let mut db = Database::new();
    let mut root = db.root_mut();
    let mut e = root.add_entry();
    // unpadded secret (Google Authenticator style): 10 chars needs padding to 16
    e.set_protected("otp", "otpauth://totp/x?secret=jbswy3dpeh&digits=6");
    e.set_protected("TimeOtp-Secret-Base32", "JBSWY3DPEHPK3PXP");
    let id = e.id();
    let e = db.entry(id).unwrap();
    assert!(totp_of(&e, "otp").is_ok());
    assert_eq!(padded_secret("otpauth://totp/x?secret=abc&p=1"), "otpauth://totp/x?secret=ABC=====&p=1");
    // KeePass 2 native fields when no otp string exists
    let mut db = Database::new();
    let mut root = db.root_mut();
    let mut e = root.add_entry();
    e.set_protected("TimeOtp-Secret-Base32", "JBSWY3DPEHPK3PXP");
    let id = e.id();
    let e = db.entry(id).unwrap();
    assert_eq!(totp_of(&e, "otp").unwrap().value_at(59).code.len(), 6);
    assert!(totp_of(&e, "Custom").is_err());
}

#[test]
fn move_duplicate_and_cross_vault() {
    let state = Vaults::default();
    let (a, a_root) = open_temp(&state, "a");
    let (b, b_root) = open_temp(&state, "b");
    let id = save_for_test(&state, &a, login(&a_root, "Mail"));
    let eid = EntryId::from(Uuid::parse_str(&id).unwrap());

    // duplicate keeps secrets + attachment, new id, suffixed title
    let dup = mutate(&state, &a, |db| duplicate_entry(db, eid, " (copy)").map(|_| ())).unwrap();
    assert_eq!(dup.items.len(), 2);
    assert!(dup.items.iter().any(|i| i.fields.iter().any(|f| f.value.as_deref() == Some("Mail (copy)"))));

    // move into a folder of the same vault
    let folder = with_vault(&state, &a, |v| Ok(v.db.root_mut().add_group().edit(|g| g.name = "F".into()).id().to_string())).unwrap();
    mutate(&state, &a, |db| {
        db.entry_mut(eid).unwrap().move_to(GroupId::from_uuid(Uuid::parse_str(&folder).unwrap())).unwrap();
        Ok(())
    })
    .unwrap();

    move_to_vault(&mut state.0.lock().unwrap(), &a, eid, &b, Some(&b_root)).unwrap();
    // reopen b from disk: same UUID, secret and attachment arrived
    let pb = PathBuf::from(&b);
    let db = Database::open(&mut fs::File::open(&pb).unwrap(), make_key(Some("pw"), None).unwrap()).unwrap();
    let e = db.entry(eid).expect("moved entry keeps its UUID");
    assert_eq!(e.get_password(), Some("pw-Mail"));
    assert!(e.fields["Password"].is_protected());
    assert_eq!(e.attachment_by_name("f.txt").unwrap().data.get(), b"data");
    assert_eq!(e.tags, vec!["work".to_string()]);
    let pa = PathBuf::from(&a);
    let db = Database::open(&mut fs::File::open(&pa).unwrap(), make_key(Some("pw"), None).unwrap()).unwrap();
    assert!(db.entry(eid).is_none());
    assert_eq!(db.iter_all_entries().count(), 1); // the duplicate stays in a
    let _ = (fs::remove_file(pa), fs::remove_file(pb));
}

// Compatibility checks against KeePassXC (run by hand, see README):
//   AKP_COMPAT_DIR=<dir> cargo test --lib compat -- --ignored
fn compat_dir() -> PathBuf {
    PathBuf::from(std::env::var("AKP_COMPAT_DIR").expect("set AKP_COMPAT_DIR"))
}

#[test]
#[ignore]
fn compat_write_for_keepassxc() {
    let path = compat_dir().join("ours.kdbx");
    let p = path.to_string_lossy().to_string();
    let state = Vaults::default();
    let mut db = Database::with_config(new_config());
    db.meta.database_name = Some("Ours".into());
    ensure_recycle_bin(&mut db);
    let work = db.root_mut().add_group().edit(|g| g.name = "Work".into()).id().to_string();
    let mut v = OpenVault { path, db, key: make_key(Some("compat-pw"), None).unwrap(), remote: None };
    write_db(&mut v).unwrap();
    state.0.lock().unwrap().insert(p.clone(), v);
    save_for_test(
        &state,
        &p,
        ItemInput {
            id: None,
            folder: work,
            fields: vec![
                FieldDto { name: "Title".into(), value: Some("Mail".into()), protected: false },
                FieldDto { name: "UserName".into(), value: Some("bob".into()), protected: false },
                FieldDto { name: "Password".into(), value: Some("s3cret-Pa55".into()), protected: true },
                FieldDto { name: "URL".into(), value: Some("https://example.org".into()), protected: false },
                FieldDto {
                    name: "otp".into(),
                    value: Some("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&period=30&digits=6".into()),
                    protected: true,
                },
                FieldDto { name: "Card number".into(), value: Some("4111".into()), protected: true },
            ],
            tags: vec!["pinned".into()],
            custom_data: HashMap::from([(CD_TYPE.into(), "login".into())]),
            expires: None,
            keep_attachments: vec![],
            add_attachments: vec![NewAttachment { name: "hello.txt".into(), base64: B64.encode(b"hello from AnotherKeepass") }],
        },
    );
}

#[test]
#[ignore]
fn compat_edit_keepassxc_file() {
    let path = compat_dir().join("theirs.kdbx");
    let p = path.to_string_lossy().to_string();
    let key = make_key(Some("compat-pw"), None).unwrap();
    let db = Database::open(&mut fs::File::open(&path).unwrap(), key.clone()).unwrap();
    let e = db.iter_all_entries().find(|e| e.get_title() == Some("Mail")).expect("entry from KeePassXC");
    assert_eq!(e.get_username(), Some("alice"));
    let (id, folder) = (e.id().to_string(), e.parent().id().to_string());
    let state = Vaults::default();
    state.0.lock().unwrap().insert(p.clone(), OpenVault { path, db, key, remote: None });
    save_for_test(
        &state,
        &p,
        ItemInput {
            id: Some(id),
            folder,
            fields: vec![
                FieldDto { name: "Title".into(), value: Some("Mail edited".into()), protected: false },
                FieldDto { name: "UserName".into(), value: Some("alice".into()), protected: false },
                FieldDto { name: "Password".into(), value: None, protected: true },
            ],
            tags: vec![],
            custom_data: HashMap::new(),
            expires: Some("2031-12-31".into()),
            keep_attachments: vec![],
            add_attachments: vec![],
        },
    );
}

fn save_for_test(state: &Vaults, vault: &str, item: ItemInput) -> String {
    let mut out = String::new();
    mutate(state, vault, |db| {
        out = save_item(db, &item)?;
        Ok(())
    })
    .unwrap();
    out
}
