use super::*;

#[test]
fn parse_mode_passthrough() {
    assert!(matches!(parse_mode("passthrough", RuleMode::Deny), RuleMode::Passthrough));
}

#[test]
fn parse_mode_allow() {
    assert!(matches!(parse_mode("allow", RuleMode::Deny), RuleMode::Passthrough));
}

#[test]
fn parse_mode_deny() {
    assert!(matches!(parse_mode("deny", RuleMode::Passthrough), RuleMode::Deny));
}

#[test]
fn parse_mode_cow() {
    assert!(matches!(parse_mode("cow", RuleMode::Passthrough), RuleMode::Cow));
}

#[test]
fn parse_mode_redirect() {
    assert!(matches!(parse_mode("redirect", RuleMode::Passthrough), RuleMode::Redirect));
}

#[test]
fn parse_mode_unknown_returns_default() {
    assert!(matches!(parse_mode("bogus", RuleMode::Cow), RuleMode::Cow));
    assert!(matches!(parse_mode("", RuleMode::Deny), RuleMode::Deny));
}

#[test]
fn decode_rule_roundtrip() {
    let row = RuleRow { id: String::new(), prefix: String::new(), mode_read: RuleMode::Cow, mode_write: RuleMode::Deny, when: None };
    let enc = bincode::serde::encode_to_vec(&row, bincode::config::standard()).unwrap();
    let dec = decode_rule(&enc).unwrap();
    assert!(matches!(dec.mode_read, RuleMode::Cow));
    assert!(matches!(dec.mode_write, RuleMode::Deny));
}

#[test]
fn decode_rule_garbage_returns_none() {
    assert!(decode_rule(b"\xde\xad\xbe\xef").is_none());
    assert!(decode_rule(b"").is_none());
}

// Table-driven equivalent of the parse_mode_* tests above, kept as a
// template for future enum→string mappings.
#[rstest::rstest]
#[case("passthrough", RuleMode::Deny, RuleMode::Passthrough)]
#[case("allow",       RuleMode::Deny, RuleMode::Passthrough)]
#[case("deny",        RuleMode::Passthrough, RuleMode::Deny)]
#[case("cow",         RuleMode::Passthrough, RuleMode::Cow)]
#[case("redirect",    RuleMode::Passthrough, RuleMode::Redirect)]
#[case("bogus",       RuleMode::Cow, RuleMode::Cow)]
#[case("",            RuleMode::Deny, RuleMode::Deny)]
fn parse_mode_table(#[case] input: &str, #[case] default: RuleMode, #[case] expected: RuleMode) {
    assert!(matches!(parse_mode(input, default), m if std::mem::discriminant(&m) == std::mem::discriminant(&expected)));
}

// ── best_rule_match tests ───────────────────────────────────────────────

fn make_db_with_rules(rules: &[(&str, RuleMode, RuleMode)]) -> (tempfile::TempDir, redb::Database) {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test.redb");
    let db = redb::Database::create(&db_path).unwrap();
    {
        let txn = db.begin_write().unwrap();
        {
            let mut table = txn.open_table(RULES).unwrap();
            let default_row = RuleRow { id: String::new(), prefix: String::new(), mode_read: RuleMode::Passthrough, mode_write: RuleMode::Cow, when: None };
            let enc = bincode::serde::encode_to_vec(&default_row, bincode::config::standard()).unwrap();
            table.insert("", enc.as_slice()).unwrap();
            for (prefix, mr, mw) in rules {
                let pfx = prefix.to_lowercase();
                let row = RuleRow { id: generate_id("rule", &[&pfx]), prefix: pfx.clone(), mode_read: *mr, mode_write: *mw, when: None };
                let enc = bincode::serde::encode_to_vec(&row, bincode::config::standard()).unwrap();
                table.insert(prefix.to_lowercase().as_str(), enc.as_slice()).unwrap();
            }
        }
        txn.commit().unwrap();
    }
    (dir, db)
}

#[test]
fn best_rule_match_default_only() {
    let (_dir, db) = make_db_with_rules(&[]);
    let txn = db.begin_read().unwrap();
    let rule = best_rule_match(&txn, r"c:\unknown\path", None, None).unwrap();
    assert!(matches!(rule.mode_read, RuleMode::Passthrough));
    assert!(matches!(rule.mode_write, RuleMode::Cow));
}

#[test]
fn best_rule_match_exact_prefix() {
    let (_dir, db) = make_db_with_rules(&[
        (r"c:\test", RuleMode::Deny, RuleMode::Deny),
    ]);
    let txn = db.begin_read().unwrap();
    let rule = best_rule_match(&txn, r"c:\test\sub\file", None, None).unwrap();
    assert!(matches!(rule.mode_read, RuleMode::Deny));
}

#[test]
fn best_rule_match_most_specific_wins() {
    let (_dir, db) = make_db_with_rules(&[
        (r"c:\users", RuleMode::Passthrough, RuleMode::Cow),
        (r"c:\users\alice\.ssh", RuleMode::Deny, RuleMode::Deny),
    ]);
    let txn = db.begin_read().unwrap();
    let rule = best_rule_match(&txn, r"c:\users\alice\.ssh\id_rsa", None, None).unwrap();
    assert!(matches!(rule.mode_read, RuleMode::Deny));
}

#[test]
fn best_rule_match_glob_pattern() {
    let (_dir, db) = make_db_with_rules(&[
        (r"c:\users\*", RuleMode::Deny, RuleMode::Deny),
    ]);
    let txn = db.begin_read().unwrap();
    let rule = best_rule_match(&txn, r"c:\users\alice\file", None, None).unwrap();
    assert!(matches!(rule.mode_read, RuleMode::Deny));
}

#[test]
fn best_rule_match_no_match_returns_default() {
    let (_dir, db) = make_db_with_rules(&[
        (r"c:\restricted", RuleMode::Deny, RuleMode::Deny),
    ]);
    let txn = db.begin_read().unwrap();
    let rule = best_rule_match(&txn, r"c:\public\file", None, None).unwrap();
    assert!(matches!(rule.mode_read, RuleMode::Passthrough));
}

// ── find_mock_payload tests ─────────────────────────────────────────────

fn make_db_with_mocks(mocks: &[(&str, &[u8])]) -> (tempfile::TempDir, redb::Database) {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test.redb");
    let db = redb::Database::create(&db_path).unwrap();
    {
        let txn = db.begin_write().unwrap();
        {
            let mut table = txn.open_table(MOCKS).unwrap();
            for (path, payload) in mocks {
                table.insert(path.to_lowercase().as_str(), *payload).unwrap();
            }
        }
        txn.commit().unwrap();
    }
    (dir, db)
}

#[test]
fn find_mock_exact_match() {
    let (_dir, db) = make_db_with_mocks(&[
        (r"c:\fake\token.txt", b"secret"),
    ]);
    let txn = db.begin_read().unwrap();
    let payload = find_mock_payload(&txn, r"c:\fake\token.txt").unwrap();
    assert_eq!(payload, b"secret");
}

#[test]
fn find_mock_glob_match() {
    let (_dir, db) = make_db_with_mocks(&[
        (r"c:\fake\*.txt", b"text_file"),
    ]);
    let txn = db.begin_read().unwrap();
    let payload = find_mock_payload(&txn, r"c:\fake\token.txt").unwrap();
    assert_eq!(payload, b"text_file");
}

#[test]
fn find_mock_no_match() {
    let (_dir, db) = make_db_with_mocks(&[
        (r"c:\fake\token.txt", b"secret"),
    ]);
    let txn = db.begin_read().unwrap();
    assert!(find_mock_payload(&txn, r"c:\fake\other.exe").is_none());
}

#[test]
fn find_mock_empty_payload() {
    let (_dir, db) = make_db_with_mocks(&[
        (r"c:\empty.dat", b""),
    ]);
    let txn = db.begin_read().unwrap();
    let payload = find_mock_payload(&txn, r"c:\empty.dat").unwrap();
    assert!(payload.is_empty());
}

// ── matched_mock_dir tests ──────────────────────────────────────────────

fn make_db_with_mock_dirs(dirs: &[&str]) -> (tempfile::TempDir, redb::Database) {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test.redb");
    let db = redb::Database::create(&db_path).unwrap();
    {
        let txn = db.begin_write().unwrap();
        {
            let mut table = txn.open_table(MOCK_DIRS).unwrap();
            for prefix in dirs {
                table.insert(prefix.to_lowercase().as_str(), ()).unwrap();
            }
        }
        txn.commit().unwrap();
    }
    (dir, db)
}

#[test]
fn matched_mock_dir_hit() {
    let (_dir, db) = make_db_with_mock_dirs(&[r"c:\fake"]);
    let txn = db.begin_read().unwrap();
    let result = matched_mock_dir(&txn, r"c:\fake\sub\file.txt");
    assert!(result.is_some());
}

#[test]
fn matched_mock_dir_miss() {
    let (_dir, db) = make_db_with_mock_dirs(&[r"c:\fake"]);
    let txn = db.begin_read().unwrap();
    assert!(matched_mock_dir(&txn, r"c:\real\file.txt").is_none());
}

#[test]
fn matched_mock_dir_most_specific() {
    let (_dir, db) = make_db_with_mock_dirs(&[
        r"c:\fake",
        r"c:\fake\deep",
    ]);
    let txn = db.begin_read().unwrap();
    let result = matched_mock_dir(&txn, r"c:\fake\deep\file.txt");
    assert_eq!(result.unwrap(), r"c:\fake\deep");
}

#[test]
fn matched_mock_dir_empty_db() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test.redb");
    let db = redb::Database::create(&db_path).unwrap();
    {
        let txn = db.begin_write().unwrap();
        {
            let _ = txn.open_table(MOCK_DIRS).unwrap();
        }
        txn.commit().unwrap();
    }
    let txn = db.begin_read().unwrap();
    assert!(matched_mock_dir(&txn, r"c:\anything").is_none());
}

// ── apply_config tests ──────────────────────────────────────────────────

#[test]
fn when_filter_deserialization_from_ktav() {
    let ktav = r#"
defaults: {
read: passthrough
write: cow
}

rules: [
{
    prefix: c:\test
    write: deny
    when: {
        depth: 1
        exe: c:\bin\target-app.exe
    }
}
]
"#;
    let cfg: Config = ktav::from_str(ktav).unwrap();
    assert_eq!(cfg.rules.len(), 1);
    let rule = &cfg.rules[0];
    assert_eq!(rule.prefix, r"c:\test");
    let when = rule.when.as_ref().unwrap();
    assert_eq!(when.depth, Some(1));
    assert_eq!(when.exe.as_deref(), Some(r"c:\bin\target-app.exe"));
}

#[test]
fn when_filter_depth_only_deserialization() {
    let ktav = "defaults: {\n\
        \x20   read: passthrough\n\
        \x20   write: cow\n\
        }\n\
        \n\
        rules: [\n\
        \x20   {\n\
        \x20       prefix: c:\\test\n\
        \x20       write: deny\n\
        \x20       when: {\n\
        \x20           depth: 2\n\
        \x20       }\n\
        \x20   }\n\
        ]";
    let cfg: Config = ktav::from_str(ktav).unwrap();
    let when = cfg.rules[0].when.as_ref().unwrap();
    assert_eq!(when.depth, Some(2));
    assert_eq!(when.exe, None);
}

#[test]
fn when_filter_exe_only_deserialization() {
    let ktav = "defaults: {\n\
        \x20   read: passthrough\n\
        \x20   write: cow\n\
        }\n\
        \n\
        rules: [\n\
        \x20   {\n\
        \x20       prefix: c:\\test\n\
        \x20       write: deny\n\
        \x20       when: {\n\
        \x20           exe: c:\\app.exe\n\
        \x20       }\n\
        \x20   }\n\
        ]";
    let cfg: Config = ktav::from_str(ktav).unwrap();
    let when = cfg.rules[0].when.as_ref().unwrap();
    assert_eq!(when.depth, None);
    assert_eq!(when.exe.as_deref(), Some(r"c:\app.exe"));
}

#[test]
fn rule_without_when_is_none() {
    let ktav = "defaults: {\n\
    \x20   read: passthrough\n\
    \x20   write: cow\n\
    }\n\
    \n\
    rules: [\n\
    \x20   {\n\
    \x20       prefix: c:\\test\n\
    \x20       write: deny\n\
    \x20   }\n\
    ]";
    let cfg: Config = ktav::from_str(ktav).unwrap();
    assert!(cfg.rules[0].when.is_none());
}

#[test]
fn apply_config_replaces_rules() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test.redb");
    let db = redb::Database::create(&db_path).unwrap();
    {
        let txn = db.begin_write().unwrap();
        {
            txn.open_table(RULES).unwrap();
            txn.open_table(MOCKS).unwrap();
            txn.open_table(MOCK_DIRS).unwrap();
        }
        txn.commit().unwrap();
    }

    let cfg1 = Config {
        sandbox_root: None,
        defaults: Defaults { read: "passthrough".into(), write: "cow".into() },
        rules: vec![RuleEntry { prefix: r"c:\old".into(), read: Some("deny".into()), write: None, when: None }],
        mocks: vec![],
        mock_dirs: vec![],
        log_level: None,
        network: None,
    };
    apply_config(&db, &cfg1).unwrap();

    let cfg2 = Config {
        sandbox_root: None,
        defaults: Defaults { read: "passthrough".into(), write: "cow".into() },
        rules: vec![RuleEntry { prefix: r"c:\new".into(), read: Some("deny".into()), write: None, when: None }],
        mocks: vec![],
        mock_dirs: vec![],
        log_level: None,
        network: None,
    };
    apply_config(&db, &cfg2).unwrap();

    let txn = db.begin_read().unwrap();
    // Old rule should be gone
    let rule = best_rule_match(&txn, r"c:\old\path", None, None);
    assert!(matches!(rule.unwrap().mode_read, RuleMode::Passthrough));

    // New rule should match
    let rule = best_rule_match(&txn, r"c:\new\path", None, None);
    assert!(matches!(rule.unwrap().mode_read, RuleMode::Deny));
}

#[test]
fn apply_config_adds_mocks() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test.redb");
    let db = redb::Database::create(&db_path).unwrap();
    {
        let txn = db.begin_write().unwrap();
        {
            txn.open_table(RULES).unwrap();
            txn.open_table(MOCKS).unwrap();
            txn.open_table(MOCK_DIRS).unwrap();
        }
        txn.commit().unwrap();
    }

    let cfg = Config {
        sandbox_root: None,
        defaults: Defaults::default(),
        rules: vec![],
        mocks: vec![MockEntry { path: r"c:\mock.txt".into(), content_inline: Some("hello".into()) }],
        mock_dirs: vec![],
        log_level: None,
        network: None,
    };
    apply_config(&db, &cfg).unwrap();

    let txn = db.begin_read().unwrap();
    let payload = find_mock_payload(&txn, r"c:\mock.txt").unwrap();
    assert_eq!(payload, b"hello");
}

// ── when filter tests ───────────────────────────────────────────────────

fn make_db_with_rules_and_when(
    rules: &[(&str, RuleMode, RuleMode, Option<WhenFilter>)],
) -> (tempfile::TempDir, redb::Database) {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test.redb");
    let db = redb::Database::create(&db_path).unwrap();
    {
        let txn = db.begin_write().unwrap();
        {
            let mut table = txn.open_table(RULES).unwrap();
            let default_row = RuleRow { id: String::new(), prefix: String::new(), mode_read: RuleMode::Passthrough, mode_write: RuleMode::Cow, when: None };
            let enc = bincode::serde::encode_to_vec(&default_row, bincode::config::standard()).unwrap();
            table.insert("", enc.as_slice()).unwrap();
            for (prefix, mr, mw, when) in rules {
                let pfx = prefix.to_lowercase();
                let row = RuleRow { id: generate_id("rule", &[&pfx]), prefix: pfx.clone(), mode_read: *mr, mode_write: *mw, when: when.clone() };
                let enc = bincode::serde::encode_to_vec(&row, bincode::config::standard()).unwrap();
                table.insert(prefix.to_lowercase().as_str(), enc.as_slice()).unwrap();
            }
        }
        txn.commit().unwrap();
    }
    (dir, db)
}

#[test]
fn when_depth_filter_pass() {
    let (_dir, db) = make_db_with_rules_and_when(&[
        (r"c:\test", RuleMode::Deny, RuleMode::Deny, Some(WhenFilter { depth: Some(1), exe: None })),
    ]);
    let txn = db.begin_read().unwrap();
    // depth=1 >= required depth=1 → rule applies
    let rule = best_rule_match(&txn, r"c:\test\file", Some(1), None).unwrap();
    assert!(matches!(rule.mode_read, RuleMode::Deny));
}

#[test]
fn when_depth_filter_too_shallow() {
    let (_dir, db) = make_db_with_rules_and_when(&[
        (r"c:\test", RuleMode::Deny, RuleMode::Deny, Some(WhenFilter { depth: Some(1), exe: None })),
    ]);
    let txn = db.begin_read().unwrap();
    // depth=0 < required depth=1 → rule skipped, falls to default
    let rule = best_rule_match(&txn, r"c:\test\file", Some(0), None).unwrap();
    assert!(matches!(rule.mode_read, RuleMode::Passthrough));
}

#[test]
fn when_depth_filter_none_is_max_permissive() {
    let (_dir, db) = make_db_with_rules_and_when(&[
        (r"c:\test", RuleMode::Deny, RuleMode::Deny, Some(WhenFilter { depth: Some(1), exe: None })),
    ]);
    let txn = db.begin_read().unwrap();
    // depth=None (legacy caller) → treated as max-permissive → rule applies
    let rule = best_rule_match(&txn, r"c:\test\file", None, None).unwrap();
    assert!(matches!(rule.mode_read, RuleMode::Deny));
}

#[test]
fn when_exe_filter_match() {
    let (_dir, db) = make_db_with_rules_and_when(&[
        (r"c:\test", RuleMode::Deny, RuleMode::Deny, Some(WhenFilter {
            depth: None,
            exe: Some(r"c:\bin\target-app.exe".into()),
        })),
    ]);
    let txn = db.begin_read().unwrap();
    let rule = best_rule_match(&txn, r"c:\test\file", Some(0), Some(r"c:\bin\target-app.exe")).unwrap();
    assert!(matches!(rule.mode_read, RuleMode::Deny));
}

#[test]
fn when_exe_filter_miss() {
    let (_dir, db) = make_db_with_rules_and_when(&[
        (r"c:\test", RuleMode::Deny, RuleMode::Deny, Some(WhenFilter {
            depth: None,
            exe: Some(r"c:\bin\target-app.exe".into()),
        })),
    ]);
    let txn = db.begin_read().unwrap();
    // exe doesn't match → skip rule → default passthrough
    let rule = best_rule_match(&txn, r"c:\test\file", Some(0), Some(r"c:\bin\other.exe")).unwrap();
    assert!(matches!(rule.mode_read, RuleMode::Passthrough));
}

#[test]
fn when_exe_filter_none_exe_skips() {
    let (_dir, db) = make_db_with_rules_and_when(&[
        (r"c:\test", RuleMode::Deny, RuleMode::Deny, Some(WhenFilter {
            depth: None,
            exe: Some(r"c:\bin\target-app.exe".into()),
        })),
    ]);
    let txn = db.begin_read().unwrap();
    // exe_lower=None but rule requires exe → skip
    let rule = best_rule_match(&txn, r"c:\test\file", Some(0), None).unwrap();
    assert!(matches!(rule.mode_read, RuleMode::Passthrough));
}

#[test]
fn when_both_filters_must_match() {
    let (_dir, db) = make_db_with_rules_and_when(&[
        (r"c:\test", RuleMode::Deny, RuleMode::Deny, Some(WhenFilter {
            depth: Some(2),
            exe: Some(r"c:\dir\app.exe".into()),
        })),
    ]);
    let txn = db.begin_read().unwrap();
    // Both match
    let rule = best_rule_match(&txn, r"c:\test\file", Some(3), Some(r"c:\dir\app.exe")).unwrap();
    assert!(matches!(rule.mode_read, RuleMode::Deny));
    // Depth ok but exe wrong
    let rule = best_rule_match(&txn, r"c:\test\file", Some(3), Some(r"c:\dir\other.exe")).unwrap();
    assert!(matches!(rule.mode_read, RuleMode::Passthrough));
    // Exe ok but depth too shallow
    let rule = best_rule_match(&txn, r"c:\test\file", Some(1), Some(r"c:\dir\app.exe")).unwrap();
    assert!(matches!(rule.mode_read, RuleMode::Passthrough));
}

#[test]
fn specificity_with_when_higher() {
    let (_dir, db) = make_db_with_rules_and_when(&[
        (r"c:\test", RuleMode::Passthrough, RuleMode::Cow, None),
        (r"c:\test", RuleMode::Deny, RuleMode::Deny, Some(WhenFilter { depth: Some(0), exe: None })),
    ]);
    let txn = db.begin_read().unwrap();
    // Rule with when has +1 specificity bonus → wins
    let rule = best_rule_match(&txn, r"c:\test\file", Some(0), None).unwrap();
    assert!(matches!(rule.mode_read, RuleMode::Deny));
}

#[test]
fn back_compat_rule_without_when() {
    let (_dir, db) = make_db_with_rules(&[
        (r"c:\test", RuleMode::Deny, RuleMode::Deny),
    ]);
    let txn = db.begin_read().unwrap();
    // Rule without when works regardless of depth/exe
    let rule = best_rule_match(&txn, r"c:\test\file", Some(5), Some(r"anything.exe")).unwrap();
    assert!(matches!(rule.mode_read, RuleMode::Deny));
    let rule = best_rule_match(&txn, r"c:\test\file", None, None).unwrap();
    assert!(matches!(rule.mode_read, RuleMode::Deny));
}

// ── canonical case-fold (ASCII) tests ──────────────────────────────────

#[test]
fn when_exe_filter_mixed_case_pattern_matches_lowered_exe() {
    let (_dir, db) = make_db_with_rules_and_when(&[
        (r"c:\locked", RuleMode::Deny, RuleMode::Deny,
         Some(WhenFilter { depth: None, exe: Some(r"C:\Tools\MyApp.EXE".into()) })),
    ]);
    let txn = db.begin_read().unwrap();
    // Stored pattern is raw mixed case; the read-side fold must make it
    // match the already-lowered exe.
    let rule = best_rule_match(&txn, r"c:\locked\f.txt", None, Some(r"c:\tools\myapp.exe")).unwrap();
    assert!(matches!(rule.mode_read, RuleMode::Deny));
}

#[test]
fn apply_config_folds_rule_prefix_and_when_exe() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test.redb");
    let db = redb::Database::create(&db_path).unwrap();
    {
        let txn = db.begin_write().unwrap();
        {
            txn.open_table(RULES).unwrap();
            txn.open_table(MOCKS).unwrap();
            txn.open_table(MOCK_DIRS).unwrap();
        }
        txn.commit().unwrap();
    }

    let cfg = Config {
        sandbox_root: None,
        defaults: Defaults::default(),
        rules: vec![RuleEntry {
            prefix: "C:\\Klas\u{0130}r".into(),
            read: Some("deny".into()),
            write: None,
            when: Some(WhenFilter { depth: None, exe: Some(r"C:\Tools\APP.EXE".into()) }),
        }],
        mocks: vec![],
        mock_dirs: vec![],
        log_level: None,
        network: None,
    };
    apply_config(&db, &cfg).unwrap();

    let txn = db.begin_read().unwrap();
    // Old behavior fails: prefix stored Unicode-folded (İ → i + U+0307)
    // while the lookup path is ASCII-folded (İ unchanged), and the raw
    // when.exe never matched the lowered exe.
    let rule = best_rule_match(&txn, "c:\\klas\u{0130}r\\f", None, Some(r"c:\tools\app.exe")).unwrap();
    assert!(matches!(rule.mode_read, RuleMode::Deny));
}

#[test]
fn rule_upsert_folds_prefix_and_when_exe_at_choke_point() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test.redb");
    let db = redb::Database::create(&db_path).unwrap();
    {
        let txn = db.begin_write().unwrap();
        txn.open_table(RULES).unwrap();
        txn.commit().unwrap();
    }
    let row = RuleRow {
        id: "rule-test".into(),
        prefix: r"d:\Locked".into(),
        mode_read: RuleMode::Deny,
        mode_write: RuleMode::Deny,
        when: Some(WhenFilter { depth: None, exe: Some(r"C:\Tools\MyApp.EXE".into()) }),
    };
    rule_upsert(&db, &row).unwrap();

    let txn = db.begin_read().unwrap();
    let t = txn.open_table(RULES).unwrap();
    assert!(t.get("d:\\locked").unwrap().is_some());
    assert!(t.get("d:\\Locked").unwrap().is_none());
    let stored = decode_rule(t.get("d:\\locked").unwrap().unwrap().value()).unwrap();
    assert_eq!(stored.prefix, "d:\\locked");
    assert_eq!(stored.when.as_ref().unwrap().exe.as_deref(), Some("c:\\tools\\myapp.exe"));
}

#[test]
fn reg_mock_upsert_folds_non_ascii_path() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test.redb");
    let db = redb::Database::create(&db_path).unwrap();
    {
        let txn = db.begin_write().unwrap();
        txn.open_table(REG_MOCKS).unwrap();
        txn.commit().unwrap();
    }
    reg_mock_upsert(&db, "hklm\\soft\\Klas\u{0130}r\\Val", b"x").unwrap();

    let txn = db.begin_read().unwrap();
    let t = txn.open_table(REG_MOCKS).unwrap();
    assert!(t.get("hklm\\soft\\klas\u{0130}r\\val").unwrap().is_some());
    assert!(t.get("hklm\\soft\\Klas\u{0130}r\\Val").unwrap().is_none());
}
