// Mock-based integration tests for depth/exe/when-filter features.
// Tests the full policy stack (config → db → best_rule_match → decide_with_context)
// without requiring real processes or DLL injection.
//
// NOTE: Each test uses unique paths to avoid cache cross-contamination between
// calls with different depth/exe context (the policy cache keys on path+write,
// not on depth/exe).

use policy::Policy;
use std::io::Write;

fn setup(name: &str) -> (tempfile::TempDir, Policy) {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("policy.redb");
    let sandbox = dir.path().join("sb");
    let mock_dirs = dir.path().join("md");
    let project = dir.path().join("proj");
    std::fs::create_dir_all(&sandbox).unwrap();
    std::fs::create_dir_all(&mock_dirs).unwrap();
    std::fs::create_dir_all(&project).unwrap();

    let p = Policy::open_or_create(&db_path, sandbox, mock_dirs, project).unwrap();
    (dir, p)
}

fn write_config(dir: &tempfile::TempDir, policy: &Policy, extra_rules: &str) {
    let cfg_path = dir.path().join("config.ktv");
    let mut f = std::fs::File::create(&cfg_path).unwrap();
    let cfg = format!(
        "defaults: {{\n\
        \x20   read: passthrough\n\
        \x20   write: cow\n\
        }}\n\
        \n\
        rules: [\n\
        \x20   {{\n\
        \x20       prefix: C:\\Windows\n\
        \x20       read: passthrough\n\
        \x20       write: deny\n\
        \x20   }}\n\
        {extra_rules}\
        ]\n"
    );
    write!(f, "{}", cfg).unwrap();
    drop(f);
    policy.load_config(&cfg_path).unwrap();
}

// ── Test 1: Depth>=1 rule — root is unaffected, children are restricted ───

#[test]
fn depth_ge_1_rule_restricts_children_not_root() {
    let (dir, policy) = setup("depth1");

    write_config(&dir, &policy, "\
        \x20   {\n\
        \x20       prefix: C:\\Restricted\n\
        \x20       write: deny\n\
        \x20       when: {\n\
        \x20           depth: 1\n\
        \x20       }\n\
        \x20   }\n");

    // Root (depth=0): depth filter skips (0 < 1) → no explicit rule applies,
    // so the merged-view default kicks in: external write → Cow (isolated).
    let d = policy.decide_with_context(r"c:\restricted\root-file", true, Some(0), None);
    assert_eq!(d.mode, policy::Mode::Cow, "depth=0 should be cow (default isolation)");

    // Child (depth=1): depth filter passes → deny
    let d = policy.decide_with_context(r"c:\restricted\child-file", true, Some(1), None);
    assert_eq!(d.mode, policy::Mode::Deny, "depth=1 should deny");

    // Grandchild (depth=2): depth=2 >= 1 → deny
    let d = policy.decide_with_context(r"c:\restricted\grandchild-file", true, Some(2), None);
    assert_eq!(d.mode, policy::Mode::Deny, "depth=2 should deny");
}

// ── Test 2: Depth>=2 rule — only deep processes ───────────────────────────

#[test]
fn depth_ge_2_rule_applies_only_to_deep_processes() {
    let (dir, policy) = setup("depth2");

    write_config(&dir, &policy, "\
        \x20   {\n\
        \x20       prefix: C:\\Deep\n\
        \x20       write: deny\n\
        \x20       when: {\n\
        \x20           depth: 2\n\
        \x20       }\n\
        \x20   }\n");

    // Root (depth=0): depth filter skips → no explicit rule → default Cow
    let d = policy.decide_with_context(r"c:\deep\at-root", true, Some(0), None);
    assert_eq!(d.mode, policy::Mode::Cow);

    // Child (depth=1): depth filter skips → no explicit rule → default Cow
    let d = policy.decide_with_context(r"c:\deep\at-child", true, Some(1), None);
    assert_eq!(d.mode, policy::Mode::Cow);

    // Grandchild (depth=2): applies
    let d = policy.decide_with_context(r"c:\deep\at-grandchild", true, Some(2), None);
    assert_eq!(d.mode, policy::Mode::Deny);

    // Great-grandchild (depth=3): applies
    let d = policy.decide_with_context(r"c:\deep\at-greatgrandchild", true, Some(3), None);
    assert_eq!(d.mode, policy::Mode::Deny);
}

// ── Test 3: Exe filter ────────────────────────────────────────────────────

#[test]
fn exe_filter_applies_only_to_matching_process() {
    let (dir, policy) = setup("exe-filter");

    write_config(&dir, &policy, "\
        \x20   {\n\
        \x20       prefix: C:\\AppData\n\
        \x20       write: deny\n\
        \x20       when: {\n\
        \x20           exe: c:\\bin\\target-app.exe\n\
        \x20       }\n\
        \x20   }\n");

    // Matching exe: deny
    let d = policy.decide_with_context(
        r"c:\appdata\config-matching", true, Some(0), Some(r"c:\bin\target-app.exe"),
    );
    assert_eq!(d.mode, policy::Mode::Deny, "matching exe should deny");

    // Different exe: exe filter skips → no explicit rule → default Cow
    let d = policy.decide_with_context(
        r"c:\appdata\config-other", true, Some(0), Some(r"c:\bin\other.exe"),
    );
    assert_eq!(d.mode, policy::Mode::Cow, "non-matching exe should get default cow");

    // No exe info: exe filter skips → no explicit rule → default Cow
    let d = policy.decide_with_context(r"c:\appdata\config-legacy", true, Some(0), None);
    assert_eq!(d.mode, policy::Mode::Cow, "no exe info should get default cow");
}

// ── Test 4: Rules without when still work regardless of depth/exe ──────────

#[test]
fn back_compat_rules_without_when() {
    let (dir, policy) = setup("backcompat");

    write_config(&dir, &policy, "");

    // Windows rule has no when → applies regardless of depth/exe
    let d = policy.decide_with_context(
        r"c:\windows\system32\kernel32.dll", true, Some(5), Some(r"anything.exe"),
    );
    assert_eq!(d.mode, policy::Mode::Deny, "Windows rule should deny write regardless of depth/exe");

    let d = policy.decide_with_context(r"c:\windows\system32\other.dll", false, Some(0), None);
    assert_eq!(d.mode, policy::Mode::Passthrough, "Windows read should be passthrough");
}

// ── Test 5: ** glob in prefix ──────────────────────────────────────────────

#[test]
fn double_star_glob_in_prefix() {
    let (dir, policy) = setup("globstar");

    let cfg_path = dir.path().join("config.ktv");
    let mut f = std::fs::File::create(&cfg_path).unwrap();
    write!(f, "defaults: {{\n\
        \x20   read: passthrough\n\
        \x20   write: cow\n\
        }}\n\
        \n\
        rules: [\n\
        \x20   {{\n\
        \x20       prefix: C:\\Users\\**\\.ssh\n\
        \x20       write: deny\n\
        \x20   }}\n\
        ]").unwrap();
    drop(f);
    policy.load_config(&cfg_path).unwrap();

    // Direct child
    let d = policy.decide_with_context(r"c:\users\alice\.ssh\id_rsa", true, None, None);
    assert_eq!(d.mode, policy::Mode::Deny);

    // Nested
    let d = policy.decide_with_context(r"c:\users\alice\subdir\.ssh\known_hosts", true, None, None);
    assert_eq!(d.mode, policy::Mode::Deny);

    // No match: outside project_root, no explicit rule → default Cow
    let d = policy.decide_with_context(r"c:\users\alice\docs\resume.pdf", true, None, None);
    assert_eq!(d.mode, policy::Mode::Cow);
}

// ── Test 6: Combined depth + exe filter ────────────────────────────────────

#[test]
fn combined_depth_and_exe_filter() {
    let (dir, policy) = setup("combo");

    write_config(&dir, &policy, "\
        \x20   {\n\
        \x20       prefix: C:\\Secure\n\
        \x20       write: deny\n\
        \x20       when: {\n\
        \x20           depth: 1\n\
        \x20           exe: c:\\bin\\target-app.exe\n\
        \x20       }\n\
        \x20   }\n");

    // Both match: depth=1, exe matches → deny
    let d = policy.decide_with_context(
        r"c:\secure\both-match", true, Some(1), Some(r"c:\bin\target-app.exe"),
    );
    assert_eq!(d.mode, policy::Mode::Deny);

    // Depth ok but exe wrong → rule skipped → no explicit rule → default Cow
    let d = policy.decide_with_context(
        r"c:\secure\depth-ok-exe-bad", true, Some(1), Some(r"c:\bin\other.exe"),
    );
    assert_eq!(d.mode, policy::Mode::Cow);

    // Exe ok but depth wrong → rule skipped → no explicit rule → default Cow
    let d = policy.decide_with_context(
        r"c:\secure\depth-bad-exe-ok", true, Some(0), Some(r"c:\bin\target-app.exe"),
    );
    assert_eq!(d.mode, policy::Mode::Cow);
}

// ── Test 7: Legacy callers (depth=None) treated as max-permissive ──────────

#[test]
fn legacy_caller_none_depth_passes_depth_filter() {
    let (dir, policy) = setup("legacy");

    write_config(&dir, &policy, "\
        \x20   {\n\
        \x20       prefix: C:\\Test\n\
        \x20       write: deny\n\
        \x20       when: {\n\
        \x20           depth: 2\n\
        \x20       }\n\
        \x20   }\n");

    // depth=None (legacy) → passes through depth filter → rule applies
    let d = policy.decide_with_context(r"c:\test\legacy-file", true, None, None);
    assert_eq!(d.mode, policy::Mode::Deny, "legacy caller should pass depth filter");
}
