use super::make_policy_with_project;
use crate::path::{fold_u16_unit, nt_case_fold, nt_case_fold_utf16};
use crate::{db, Mode, Policy};
use std::io::Write;

// ── S11: canonical NTFS-identity case fold ──────────────────────────────
//
// Oracles below are hardcoded literals, NOT calls to the fold under test.
// The kernel facts they pin were probe-verified on this machine's ntdll
// (see path::case_fold module docs); if any of these FAIL, the OS table
// differs from the probe and the design brief must be revisited — do not
// weaken the assertions.

// (a) fold pairs: Cyrillic and Greek case classes merge; final sigma ς is
// its own class (the kernel upcase table leaves ς identity, so it never
// merges with σ/Σ).
#[test]
fn fold_merges_cyrillic_and_greek_case_pairs() {
    assert_eq!(nt_case_fold("СЕКРЕТ").as_ref(), "секрет");
    assert_eq!(nt_case_fold("секрет").as_ref(), "секрет");
    assert_eq!(nt_case_fold("Секрет").as_ref(), "секрет");
    // Greek: every capital folds to its lowercase partner (Ι → ι etc.).
    assert_eq!(nt_case_fold("ΣΟΦΙΑ").as_ref(), "σοφια");
    // ΧΩΡΟΣ folds to "χωροσ" — the final Σ → REGULAR sigma U+03C3.
    assert_eq!(nt_case_fold("ΧΩΡΟΣ").as_ref(), "χωρο\u{3c3}");
    // Final sigma keeps its distinct class: χώρος (ending U+03C2) folds to
    // itself — NOT to the regular-sigma spelling "χωροσ" (U+03C3).
    assert_ne!(nt_case_fold("χώρος").as_ref(), "χωρο\u{3c3}");
    assert_eq!(nt_case_fold("ς").as_ref(), "ς");
}

// (b) kernel-conservative letters: the kernel table does NOT fold İ, ı, ς,
// ß, ẞ, KELVIN — the opposite divergence direction from Rust's casing.
#[test]
fn fold_is_conservative_where_kernel_table_is() {
    assert_eq!(nt_case_fold("\u{0130}").as_ref(), "\u{0130}"); // İ
    assert_eq!(nt_case_fold("\u{0131}").as_ref(), "\u{0131}"); // ı
    assert_eq!(nt_case_fold("\u{00DF}").as_ref(), "\u{00DF}"); // ß
    assert_eq!(nt_case_fold("\u{1E9E}").as_ref(), "\u{1E9E}"); // ẞ
    // KELVIN SIGN is its own class — never merged with ASCII k/K.
    assert_eq!(fold_u16_unit(0x212A), 0x212A);
    assert_eq!(fold_u16_unit(b'K' as u16), b'k' as u16);
    assert_eq!(fold_u16_unit(b'k' as u16), b'k' as u16);
    assert_eq!(nt_case_fold("K\u{212A}").as_ref(), "k\u{212A}");
}

// (c) surrogate pairs: folding is per UTF-16 unit, surrogate units pass
// through, so supplementary-plane characters survive byte-identical.
#[test]
fn fold_passes_supplementary_planes_through() {
    assert_eq!(
        nt_case_fold("привет \u{1F600} мир").as_ref(),
        "привет \u{1F600} мир"
    );
    assert_eq!(
        nt_case_fold("ПРИВЕТ \u{1F600} МИР").as_ref(),
        "привет \u{1F600} мир"
    );
    // Deseret capital/small pair (U+10400/U+10428) passes through — the
    // kernel tables are BMP-only.
    assert_eq!(
        nt_case_fold("\u{10400}\u{10428}").as_ref(),
        "\u{10400}\u{10428}"
    );
    // UTF-16 twin: well-formed input folds without panic into well-formed
    // UTF-16 (ASCII 'a' and the emoji pair are identity under F).
    let units: Vec<u16> = "a\u{1F600}".encode_utf16().collect();
    let folded = nt_case_fold_utf16(&units);
    assert!(String::from_utf16(&folded).is_ok());
    assert_eq!(folded, units);
    // A lone surrogate passes through unchanged — folding never creates one,
    // never destroys one.
    assert_eq!(nt_case_fold_utf16(&[0xD83D]), &[0xD83D]);
    assert_eq!(nt_case_fold_utf16(&[0xDE00]), &[0xDE00]);
}

// (d) idempotence: fold(fold(s)) == fold(s).
#[test]
fn fold_is_idempotent() {
    let s = "Смесь İ Station \u{1F600}path";
    let once = nt_case_fold(s);
    let twice = nt_case_fold(&once);
    assert_eq!(once, twice);
}

// (e) END-TO-END S11 repro: a rule stored with a Cyrillic UPPERCASE prefix
// must decide a lowercase Cyrillic request path (and vice versa) — under
// the old ASCII-only fold these could never meet.
#[test]
fn s11_cyrillic_rule_and_request_case_variants_match() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("policy.redb");
    let sandbox = dir.path().join("sb");
    let mock_dirs = dir.path().join("md");
    let project = dir.path().join("proj");
    std::fs::create_dir_all(&sandbox).unwrap();
    std::fs::create_dir_all(&mock_dirs).unwrap();
    std::fs::create_dir_all(&project).unwrap();

    {
        let rdb = redb::Database::create(&db_path).unwrap();
        {
            let txn = rdb.begin_write().unwrap();
            txn.open_table(db::RULES).unwrap();
            txn.commit().unwrap();
        }
        // Stored as authored (UPPERCASE); rule_upsert folds it to the
        // canonical form via ensure_lower before writing the key.
        db::rule_upsert(&rdb, &db::RuleRow {
            id: "deny-secret".into(),
            prefix: r"d:\СЕКРЕТ".into(),
            mode_read: db::RuleMode::Deny,
            mode_write: db::RuleMode::Deny,
            when: None,
        })
        .unwrap();
    } // drop the raw handle before the Policy opens the same file

    let p = Policy::open_or_create(&db_path, sandbox, mock_dirs, project).unwrap();
    // Lowercase request must hit the UPPERCASE-stored rule (the S11 repro).
    let d = p.decide(r"d:\секрет\план.txt", true);
    assert_eq!(d.mode, Mode::Deny, "lowercase request must match uppercase rule prefix");
    // Reverse direction: mixed/uppercase request against the canonical key.
    let d = p.decide(r"d:\Секрет\ПЛАН.txt", false);
    assert_eq!(d.mode, Mode::Deny, "uppercase request must match the folded rule prefix");
}

// (e2) Same fold through the mock-table read path: a mock stored with a
// Cyrillic path must serve a differently-cased request with Mock content.
#[test]
fn s11_cyrillic_mock_matches_case_variant_read() {
    let (_dir, p, _project) = make_policy_with_project("proj");
    let cfg_path = _dir.path().join("config.ktv");
    let mut f = std::fs::File::create(&cfg_path).unwrap();
    write!(
        f,
        "defaults: {{\n    read: passthrough\n    write: cow\n}}\n\n\
         mocks: [\n    {{\n        path: c:\\подделка\\token.txt\n        \
         content_inline: secret data\n    }}\n]\n"
    )
    .unwrap();
    drop(f);
    p.load_config(&cfg_path).unwrap();

    let d = p.decide(r"c:\ПОДДЕЛКА\token.txt", false);
    assert_eq!(d.mode, Mode::Mock);
    assert_eq!(d.mock_payload.unwrap(), b"secret data");
}

// (f) record_overlay_case guard is fold-relative: a Cyrillic basename with
// a case pair (Секрет) IS recorded; a canonical-folded basename is skipped.
#[test]
fn record_overlay_case_stores_cyrillic_case_pairs() {
    let (_dir, p, _project) = make_policy_with_project("proj");
    let lower_path = r"d:\данные\секрет";
    p.record_overlay(lower_path, r"C:\sb\данные\секрет").unwrap();
    p.record_overlay_case(lower_path, "Секрет");
    let pairs = p.overlay_children_with_case(r"d:\данные");
    assert_eq!(pairs.len(), 1, "Секрет has a case pair vs the fold — must be stored");
    assert_eq!(pairs[0].0, "секрет");
    assert_eq!(pairs[0].1, "Секрет");

    // An already-canonical basename (here: lowercase Cyrillic, which the
    // fold leaves unchanged) is still skipped.
    p.record_overlay(r"d:\данные\тихо", r"C:\sb\данные\тихо").unwrap();
    p.record_overlay_case(r"d:\данные\тихо", "тихо");
    let pairs = p.overlay_children_with_case(r"d:\данные");
    assert_eq!(pairs.len(), 1, "canonical-folded basename must not be stored");
}
