use crate::*;
use std::io::Write;
use super::make_policy_with_project;

#[test]
fn out_of_project_write_isolated_to_overlay() {
    // Path outside project_root + write, no explicit rule → CoW with an
    // overlay target INSIDE sandbox_root. Real disk is never touched.
    let (_dir, p, _project) = make_policy_with_project("proj");
    let d = p.decide(r"d:\winrsbox_get_test\.git\head", true);
    assert_eq!(d.mode, Mode::Cow, "out-of-project write must be isolated (Cow)");
    assert!(d.overlay.is_some(), "overlay must be formed for out-of-project write");
}

#[test]
fn out_of_project_read_falls_through_to_real_disk() {
    // Path outside project_root + read, no prior overlay entry →
    // Passthrough (read-through on the real disk). The read-through branch
    // still consults OVERLAY_IDX; with nothing recorded there, it falls
    // through to Passthrough.
    let (_dir, p, _project) = make_policy_with_project("proj");
    let d = p.decide(r"d:\winrsbox_get_test\.git\head", false);
    assert_eq!(d.mode, Mode::Passthrough);
    assert!(d.overlay.is_none());
}

#[test]
fn inside_project_write_still_passthrough() {
    // Paths inside project_root remain passthrough (agent mutates its own
    // dir for real). No regression of the project_root short-circuit.
    let (_dir, p, project) = make_policy_with_project("proj");
    let inside = project.join("src").join("main.rs");
    let d = p.decide(inside.to_str().unwrap(), true);
    assert_eq!(d.mode, Mode::Passthrough);
    assert!(d.overlay.is_none());
}

#[test]
fn explicit_deny_outside_project_still_deny() {
    // An explicit deny rule on a path outside project_root must still
    // take effect (isolation of C:\Windows etc. is not weakened).
    let (dir, p, _project) = make_policy_with_project("proj");
    let cfg_path = dir.path().join("config.ktv");
    let mut f = std::fs::File::create(&cfg_path).unwrap();
    write!(f, "defaults: {{\n    read: passthrough\n    write: cow\n}}\n\nrules: [\n    {{\n        prefix: c:\\windows\n        read: passthrough\n        write: deny\n    }}\n]").unwrap();
    drop(f);
    p.load_config(&cfg_path).unwrap();

    let d = p.decide(r"c:\windows\system32\evil.dll", true);
    assert_eq!(d.mode, Mode::Deny, "explicit deny rule must still apply outside project_root");
}

#[test]
fn explicit_passthrough_rule_outside_project_overrides_default() {
    // Explicit passthrough rule overrides the default Cow isolation — the
    // operator can whitelist a specific external path to hit the real disk.
    let (dir, p, _project) = make_policy_with_project("proj");
    let cfg_path = dir.path().join("config.ktv");
    let mut f = std::fs::File::create(&cfg_path).unwrap();
    write!(f, "defaults: {{\n    read: deny\n    write: deny\n}}\n\nrules: [\n    {{\n        prefix: d:\\allowed\n        read: passthrough\n        write: passthrough\n    }}\n]").unwrap();
    drop(f);
    p.load_config(&cfg_path).unwrap();

    let d = p.decide(r"d:\allowed\file.txt", true);
    assert_eq!(d.mode, Mode::Passthrough);
    let d = p.decide(r"d:\allowed\file.txt", false);
    assert_eq!(d.mode, Mode::Passthrough);
}

// ── Isolation invariant tests (regression guards) ─────────────────────
//
// These exist so the isolation cannot silently regress again: they check
// not just the mode but the *target* of the overlay, and the read-through
// behavior for a previously-recorded external file.

#[test]
fn external_write_never_targets_real_disk() {
    // A write to a path outside project_root must (a) be CoW and (b)
    // redirect INTO sandbox_root — never back at the original external
    // path. This is the precise guarantee the bug broke.
    let (dir, p, _project) = make_policy_with_project("proj");
    let sandbox_root = dir.path().join("sb");
    let d = p.decide(r"d:\external\data\file.bin", true);
    assert_eq!(d.mode, Mode::Cow, "external write must be Cow");
    let overlay = d.overlay.expect("overlay must be present");
    let overlay_lower = overlay.to_string_lossy().to_lowercase();
    let sandbox_lower = sandbox_root.to_string_lossy().to_lowercase();
    assert!(
        overlay_lower.starts_with(&sandbox_lower),
        "overlay {:?} must live inside sandbox_root {:?}, not at the external path",
        overlay_lower, sandbox_lower,
    );
    // And specifically must NOT equal the original external path.
    assert_ne!(overlay_lower, r"d:\external\data\file.bin");
}

#[test]
fn external_create_then_read_through() {
    // Simulate the hook recording an overlay entry for an external file
    // (record_overlay), then read the same path: the read must resolve to
    // Mode::Cow pointing at the recorded overlay (read-through).
    let (dir, p, _project) = make_policy_with_project("proj");
    let sandbox_root = dir.path().join("sb");
    let orig = r"d:\created\file.txt";
    let overlay_target = sandbox_root.join("d").join("created").join("file.txt");
    std::fs::create_dir_all(overlay_target.parent().unwrap()).unwrap();
    std::fs::write(&overlay_target, b"isolated").unwrap();
    p.record_overlay(orig, overlay_target.to_str().unwrap()).unwrap();

    let d = p.decide(orig, false);
    assert_eq!(d.mode, Mode::Cow, "read of recorded external file must hit the overlay (Cow)");
    assert_eq!(
        d.overlay.as_ref().map(|o| o.to_string_lossy().to_lowercase()),
        Some(overlay_target.to_string_lossy().to_lowercase()),
        "read-through must return the same recorded overlay path",
    );
}

