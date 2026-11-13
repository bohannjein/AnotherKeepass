use super::*;

fn temp_path(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("akp-test-{}-{name}.kdbx", Uuid::new_v4()))
}

#[test]
fn roundtrip_create_edit_trash_reopen() {
    let state = Vaults::default();
    let path = temp_path("rt");
    let p = path.to_string_lossy().to_string();
    let key = make_key(Some("pw"), None, None).unwrap();

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

    // reopen from disk with the key (after the background save)
    writer::flush(&path).unwrap();
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
    assert!(Database::open(&mut f, make_key(Some("nope"), None, None).unwrap()).is_err());

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
    let mut v = OpenVault { path, db, key: make_key(Some("pw"), None, None).unwrap(), remote: None };
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
    let db = Database::open(&mut fs::File::open(&pb).unwrap(), make_key(Some("pw"), None, None).unwrap()).unwrap();
    let e = db.entry(eid).expect("moved entry keeps its UUID");
    assert_eq!(e.get_password(), Some("pw-Mail"));
    assert!(e.fields["Password"].is_protected());
    assert_eq!(e.attachment_by_name("f.txt").unwrap().data.get(), b"data");
    assert_eq!(e.tags, vec!["work".to_string()]);
    let pa = PathBuf::from(&a);
    let db = Database::open(&mut fs::File::open(&pa).unwrap(), make_key(Some("pw"), None, None).unwrap()).unwrap();
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
    let mut v = OpenVault { path, db, key: make_key(Some("compat-pw"), None, None).unwrap(), remote: None };
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
    let key = make_key(Some("compat-pw"), None, None).unwrap();
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

/// A change that fails after it touched the database leaves no trace in memory.
#[test]
fn failed_change_is_rolled_back() {
    let state = Vaults::default();
    let (p, root) = open_temp(&state, "rb");
    save_for_test(&state, &p, login(&root, "Keep"));
    let before = with_vault(&state, &p, |v| Ok(v.db.iter_all_entries().count())).unwrap();
    let res = mutate(&state, &p, |db| {
        db.root_mut().add_entry().set_unprotected("Title", "Half done");
        Err("boom".into())
    });
    assert_eq!(res.err().as_deref(), Some("boom"));
    let after = with_vault(&state, &p, |v| Ok(v.db.iter_all_entries().count())).unwrap();
    assert_eq!(before, after);
    writer::flush(Path::new(&p)).unwrap();
    let _ = fs::remove_file(&p);
}

/// A save that cannot be written is reported by `flush`, not silently dropped.
#[test]
fn failed_background_save_is_reported() {
    let path = std::env::temp_dir().join(format!("akp-missing-{}", Uuid::new_v4())).join("v.kdbx");
    let mut v = OpenVault::new_for_test(path.clone(), Database::with_config(new_config()));
    write_db_later(&mut v).unwrap();
    assert!(writer::flush(&path).is_err());
    // a newer state that can be written clears the failure
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    write_db_later(&mut v).unwrap();
    assert!(writer::flush(&path).is_ok());
    let _ = fs::remove_dir_all(path.parent().unwrap());
}

/// Someone else (cloud sync, KeePassXC) changes the file; our next save must keep their entry.
#[test]
fn save_merges_external_change() {
    let state = Vaults::default();
    let (p, root) = open_temp(&state, "ext");
    save_for_test(&state, &p, login(&root, "Mine"));
    let path = PathBuf::from(&p);
    writer::flush(&path).unwrap();

    // external edit: read the file, add an entry, write it back without telling us
    let key = make_key(Some("pw"), None, None).unwrap();
    let mut other = Database::open(&mut fs::File::open(&path).unwrap(), key.clone()).unwrap();
    other.root_mut().add_entry().set_unprotected("Title", "Theirs");
    std::thread::sleep(std::time::Duration::from_millis(50));
    let mut buf = Vec::new();
    other.save(&mut buf, key.clone()).unwrap();
    fs::write(&path, buf).unwrap();

    save_for_test(&state, &p, login(&root, "Later"));
    writer::flush(&path).unwrap();
    let disk = Database::open(&mut fs::File::open(&path).unwrap(), key).unwrap();
    let titles: Vec<_> = disk.iter_all_entries().filter_map(|e| e.get_title().map(String::from)).collect();
    for t in ["Mine", "Theirs", "Later"] {
        assert!(titles.iter().any(|x| x == t), "{t} missing in {titles:?}");
    }
    let _ = fs::remove_file(path);
}

/// Challenge-response key (what a YubiKey slot computes): needed to open and kept on save.
/// A software HMAC-SHA1 secret stands in for the hardware key.
#[test]
fn challenge_response_key_roundtrip() {
    use keepass::ChallengeResponseKey;
    let dir = std::env::temp_dir().join(format!("akp-cr-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join("cr.kdbx");
    let secret = "0102030405060708090a0b0c0d0e0f1011121314".to_string();
    let key =
        || make_key(Some("pw"), None, None).unwrap().with_challenge_response_key(ChallengeResponseKey::LocalChallenge(secret.clone()));
    let mut db = Database::new();
    db.root_mut().name = "cr".into();
    db.save(&mut fs::File::create(&path).unwrap(), key()).unwrap();
    assert!(Database::open(&mut fs::File::open(&path).unwrap(), key()).is_ok(), "opens with the response");
    assert!(
        Database::open(&mut fs::File::open(&path).unwrap(), make_key(Some("pw"), None, None).unwrap()).is_err(),
        "password alone is not enough"
    );
    assert_eq!(make_key(Some("pw"), None, Some("3")).err().as_deref(), Some("yubikey:slot"));
    let _ = fs::remove_dir_all(dir);
}

/// Changes save in the background; several quick ones end in one file with the newest state,
/// and `flush` waits for it.
#[test]
fn background_save_coalesces_and_flushes() {
    let path = temp_path("bg");
    let key = make_key(Some("pw"), None, None).unwrap();
    let mut db = Database::with_config(new_config());
    db.meta.database_name = Some("A".into());
    let mut v = OpenVault { path: path.clone(), db, key: key.clone(), remote: None };
    write_db(&mut v).unwrap();
    for name in ["B", "C", "D", "E"] {
        v.db.meta.database_name = Some(name.into());
        write_db_later(&mut v).unwrap();
    }
    writer::flush(&path).unwrap();
    assert!(!writer::busy(&path));
    let reopened = Database::open(&mut fs::File::open(&path).unwrap(), key).unwrap();
    assert_eq!(reopened.meta.database_name.as_deref(), Some("E"), "the newest state is on disk");
    // a direct save after queued ones never gets overwritten by an older snapshot
    v.db.meta.database_name = Some("F".into());
    write_db_later(&mut v).unwrap();
    v.db.meta.database_name = Some("G".into());
    write_db(&mut v).unwrap();
    writer::flush(&path).unwrap();
    let reopened = Database::open(&mut fs::File::open(&path).unwrap(), make_key(Some("pw"), None, None).unwrap()).unwrap();
    assert_eq!(reopened.meta.database_name.as_deref(), Some("G"));
    let _ = fs::remove_file(path);
}

/// The file on disk became unreadable for us (damaged by a sync client, another password): a
/// save never overwrites it. Our state goes to a copy next to it and `flush` reports the failure.
#[test]
fn unreadable_file_is_never_overwritten() {
    let dir = std::env::temp_dir().join(format!("akp-conflict-{}", Uuid::new_v4()));
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join("v.kdbx");
    let mut db = Database::with_config(new_config());
    db.meta.database_name = Some("Ours".into());
    let mut v = OpenVault::new_for_test(path.clone(), db);
    write_db(&mut v).unwrap();

    std::thread::sleep(std::time::Duration::from_millis(50));
    fs::write(&path, b"not a database").unwrap();
    v.db.meta.database_name = Some("Ours, changed".into());
    write_db_later(&mut v).unwrap();
    let err = writer::flush(&path).unwrap_err();
    assert!(err.starts_with("conflict:"), "{err}");
    assert_eq!(fs::read(&path).unwrap(), b"not a database", "the foreign file is untouched");

    let rescue = path.with_extension("unsaved.kdbx");
    let saved = Database::open(&mut fs::File::open(&rescue).unwrap(), v.key.clone()).unwrap();
    assert_eq!(saved.meta.database_name.as_deref(), Some("Ours, changed"), "our change is in the copy");
    let _ = fs::remove_dir_all(dir);
}

/// Saving goes through a temp file that is renamed over the vault. After many saves, and after
/// a failed one, nothing but the vault (and the rescue copy) is left in the folder.
#[test]
fn saves_leave_no_temp_files() {
    let dir = std::env::temp_dir().join(format!("akp-tmp-{}", Uuid::new_v4()));
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join("v.kdbx");
    let mut v = OpenVault::new_for_test(path.clone(), Database::with_config(new_config()));
    write_db(&mut v).unwrap();
    for i in 0..10 {
        v.db.meta.database_name = Some(format!("n{i}"));
        write_db_later(&mut v).unwrap();
        if i % 3 == 0 {
            writer::flush(&path).unwrap();
        }
    }
    writer::flush(&path).unwrap();
    let names = |dir: &Path| {
        let mut n: Vec<String> = fs::read_dir(dir).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
        n.sort();
        n
    };
    assert_eq!(names(&dir), ["v.kdbx"]);
    let reopened = Database::open(&mut fs::File::open(&path).unwrap(), v.key.clone()).unwrap();
    assert_eq!(reopened.meta.database_name.as_deref(), Some("n9"));

    // a save that fails (conflict with an unreadable file) cleans up as well
    std::thread::sleep(std::time::Duration::from_millis(50));
    fs::write(&path, b"x").unwrap();
    write_db_later(&mut v).unwrap();
    assert!(writer::flush(&path).is_err());
    assert_eq!(names(&dir), ["v.kdbx", "v.unsaved.kdbx"]);
    let _ = fs::remove_dir_all(dir);
}

/// A crash or power cut in the middle of a save leaves a partial temp file next to the vault.
/// The vault itself is still the last complete version, and later saves work as usual.
#[test]
fn leftover_temp_file_does_no_harm() {
    let dir = std::env::temp_dir().join(format!("akp-crash-{}", Uuid::new_v4()));
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join("v.kdbx");
    let mut db = Database::with_config(new_config());
    db.meta.database_name = Some("complete".into());
    let mut v = OpenVault::new_for_test(path.clone(), db);
    write_db(&mut v).unwrap();
    let whole = fs::read(&path).unwrap();
    fs::write(path.with_extension("0123abcd.tmp"), &whole[..whole.len() / 2]).unwrap();

    let reopened = Database::open(&mut fs::File::open(&path).unwrap(), v.key.clone()).unwrap();
    assert_eq!(reopened.meta.database_name.as_deref(), Some("complete"));
    v.db.meta.database_name = Some("next".into());
    write_db_later(&mut v).unwrap();
    writer::flush(&path).unwrap();
    let reopened = Database::open(&mut fs::File::open(&path).unwrap(), v.key.clone()).unwrap();
    assert_eq!(reopened.meta.database_name.as_deref(), Some("next"));
    let _ = fs::remove_dir_all(dir);
}

/// A failed save left `<file>.unsaved.kdbx`. Opening the vault again merges it back in and
/// removes the copy; a copy with another key is left alone.
#[test]
fn unsaved_copy_is_recovered_on_open() {
    let dir = std::env::temp_dir().join(format!("akp-recover-{}", Uuid::new_v4()));
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join("v.kdbx");
    let rescue = path.with_extension("unsaved.kdbx");
    let mut db = Database::with_config(new_config());
    db.root_mut().add_entry().set_unprotected("Title", "On disk");
    let mut v = OpenVault::new_for_test(path.clone(), db);
    write_db(&mut v).unwrap();

    // a copy we cannot read stays, and nothing changes
    let other = make_key(Some("other"), None, None).unwrap();
    write_plain(&rescue, &v.db, other).unwrap();
    assert!(!recover_unsaved(&mut v));
    assert!(rescue.is_file());

    // the state that could not be saved: one more entry
    let mut lost = v.db.clone();
    lost.root_mut().add_entry().set_unprotected("Title", "Not saved");
    write_plain(&rescue, &lost, v.key.clone()).unwrap();
    let db = Database::open(&mut fs::File::open(&path).unwrap(), v.key.clone()).unwrap();
    let mut reopened = OpenVault::new_for_test(path.clone(), db);
    assert!(recover_unsaved(&mut reopened));
    assert!(!rescue.exists(), "the copy is removed once it is merged");
    let disk = Database::open(&mut fs::File::open(&path).unwrap(), v.key.clone()).unwrap();
    let titles: Vec<_> = disk.iter_all_entries().filter_map(|e| e.get_title().map(String::from)).collect();
    for t in ["On disk", "Not saved"] {
        assert!(titles.iter().any(|x| x == t), "{t} missing in {titles:?}");
    }
    let _ = fs::remove_dir_all(dir);
}
