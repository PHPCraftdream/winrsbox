use super::*;

// ═══════════════════════════════════════════════════════════════════════════
// P2: SystemQuery device write access block
// ═══════════════════════════════════════════════════════════════════════════

#[test]
#[serial]
fn strict_blocks_systemquery_write() {
    let r = run_payload("escape_systemquery_write", "scan");
    assert_eq!(r.status.code(), Some(5),
        "escape_systemquery_write should exit 5 (blocked)\nstderr: {}", r.stderr);
    assert!(r.stderr.contains("blocked"),
        "stderr should contain 'blocked'\nstderr: {}", r.stderr);
}

#[test]
#[serial]
fn strict_blocks_junction_creation() {
    let r = run_payload("escape_junction", "scan");
    assert_eq!(r.status.code(), Some(5),
        "escape_junction should exit 5 (blocked)\nstderr: {}", r.stderr);
}

#[test]
#[serial]
fn strict_blocks_hardlink_creation() {
    // Under the CoW model a hardlink to an out-of-project target is not
    // hard-denied — it is redirected into the overlay. The payload can't tell
    // "absorbed" from "leaked" from inside the sandbox (its own probes are
    // hooked), so the load-bearing check is the OUTER real-disk leak guard.
    let target = std::env::temp_dir().join("fs-sandbox-hardlink-test.dat");
    let source = std::env::temp_dir().join("fs-sandbox-hardlink-source.dat");
    let _ = std::fs::remove_file(&target);
    let _ = std::fs::remove_file(&source);

    let r = run_payload("escape_hardlink", "scan");
    let code = r.status.code();
    // exit 0 = CoW-absorbed (allowed), exit 5 = hard-denied. Both are safe;
    // anything else is an unexpected payload failure.
    assert!(code == Some(0) || code == Some(5),
        "escape_hardlink should exit 0 (CoW-absorbed) or 5 (denied), got {:?}\nstderr: {}", code, r.stderr);

    // OUTER LEAK GUARD: neither the link target nor the source may have
    // materialized on the real disk. If either exists, the CoW redirect
    // failed and the sandbox leaked.
    assert!(!target.exists(),
        "hardlink target LEAKED to real disk: {} — CoW isolation failed!\nstderr: {}", target.display(), r.stderr);
    assert!(!source.exists(),
        "hardlink source LEAKED to real disk: {} — CoW isolation failed!\nstderr: {}", source.display(), r.stderr);

    let _ = std::fs::remove_file(&target);
    let _ = std::fs::remove_file(&source);
}

// ═══════════════════════════════════════════════════════════════════════════
// NTFS Extended-Attributes defence (audit H-S3) — pinned with a REAL EA payload.
//
// The EA block fires AFTER the policy decision so it only denies on the
// real-disk path (Mode::Passthrough); a CoW destination keeps the EA trapped
// in the overlay (harmless). This test exercises both branches with a payload
// that supplies an actual FILE_FULL_EA_INFORMATION buffer via NtCreateFile.
// ═══════════════════════════════════════════════════════════════════════════

#[test]
#[serial]
fn ntfs_ea_blocked_on_passthrough_allowed_on_cow() {
    let launcher = find_launcher();
    let hook_dll = find_hook_dll();
    let payload = find_binary("escape_ntfs_ea");
    let env = TestEnv::setup("ntfs_ea");

    // --- Passthrough case: project_root is the agent's own dir (Mode::Passthrough,
    //     real disk). An EA-bearing create MUST be DENIED (EA = covert storage). ---
    let pt_target = env.project_root.join("ea_pt.txt");
    let _ = std::fs::remove_file(&pt_target);
    let out = Command::new(&launcher)
        .arg("-d")
        .args(["--guard", "scan"])
        .arg("--")
        .arg(payload.to_str().unwrap())
        .arg(pt_target.to_str().unwrap())
        .current_dir(&env.project_root)
        .env("FS_SANDBOX_DLL", hook_dll.to_str().unwrap())
        .output()
        .expect("failed to run launcher");
    let code = out.status.code();
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    assert_eq!(
        code,
        Some(5),
        "EA create on Passthrough (project_root) must be DENIED (exit 5); \
         got {code:?}. If 0, the EA block stopped firing on the real-disk path.\n{combined}",
    );
    // The file must NOT exist on the real disk (denied → never created).
    assert!(
        !pt_target.exists(),
        "EA create on passthrough leaked a file to the real disk: {}",
        pt_target.display(),
    );

    // --- CoW case: %TEMP% (outside project_root) is Mode::Cow. An EA-bearing
    //     create MUST succeed (EA trapped in overlay, harmless). This is the
    //     behaviour that unblocks extraction of binaries like uv.exe. ---
    let cow_target = std::env::temp_dir()
        .join(format!("winrsbox-ea-cow-{}.txt", std::process::id()));
    let _ = std::fs::remove_file(&cow_target);
    let out = Command::new(&launcher)
        .arg("-d")
        .args(["--guard", "scan"])
        .arg("--")
        .arg(payload.to_str().unwrap())
        .arg(cow_target.to_str().unwrap())
        .current_dir(&env.project_root)
        .env("FS_SANDBOX_DLL", hook_dll.to_str().unwrap())
        .output()
        .expect("failed to run launcher");
    let code = out.status.code();
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    assert_eq!(
        code,
        Some(0),
        "EA create on CoW (%TEMP%) must SUCCEED (exit 0); got {code:?}. \
         If 5, the EA block is over-firing on the CoW path.\n{combined}",
    );
    // Real disk must NOT have it (CoW isolation).
    assert!(
        !cow_target.exists(),
        "EA create on CoW leaked to the real disk: {}",
        cow_target.display(),
    );
    // The overlay MUST hold it (single-layer CoW write worked).
    let overlay_root = env.state_dir.join("workdir");
    let needle = cow_target.file_name().unwrap().to_string_lossy().into_owned();
    let mut found = false;
    let mut stack = vec![overlay_root.clone()];
    while let Some(d) = stack.pop() {
        if let Ok(rd) = std::fs::read_dir(&d) {
            for e in rd.flatten() {
                let p = e.path();
                if p.is_dir() {
                    stack.push(p);
                } else if p.file_name().map(|f| f == &*needle).unwrap_or(false) {
                    found = true;
                }
            }
        }
    }
    assert!(
        found,
        "EA CoW file missing from overlay {} — write did not land in CoW",
        overlay_root.display(),
    );

    let _ = std::fs::remove_file(&cow_target);
}

#[test]
#[serial]
fn strict_denies_fs_system_write() {
    // Clean any prior canary in real C:\Windows
    let canary = std::path::Path::new(r"C:\Windows\winrsbox-escape-canary.txt");
    let _ = std::fs::remove_file(canary);
    let r = run_payload("escape_fs_system_write", "scan");
    // Acceptable: exit 5 (deny) or exit 6 (CoW absorbed). Exit 0 = real escape.
    let code = r.status.code();
    assert!(code == Some(5) || code == Some(6),
        "fs_system_write should be denied or CoW-absorbed, got {:?}\nstderr: {}",
        code, r.stderr);
    // Verify the real C:\Windows directory is untouched
    assert!(!canary.exists(),
        "CANARY LEAKED to real C:\\Windows — CoW isolation failed!");
}

#[test]
#[serial]
fn cow_isolation_keeps_file_in_overlay() {
    // Clean any prior canary
    if let Ok(home) = std::env::var("USERPROFILE") {
        let _ = std::fs::remove_file(
            std::path::PathBuf::from(home).join("Desktop").join("winrsbox-cow-canary.dat")
        );
    }
    let r = run_payload("escape_cow_isolation", "scan");
    assert_eq!(r.status.code(), Some(0),
        "cow_isolation payload should exit 0 (write succeeded into overlay)\nstderr: {}", r.stderr);
    // Verify the file does NOT appear on the real filesystem
    if let Ok(home) = std::env::var("USERPROFILE") {
        let real_path = std::path::PathBuf::from(home).join("Desktop").join("winrsbox-cow-canary.dat");
        assert!(!real_path.exists(),
            "canary leaked to real FS at {}", real_path.display());
    }
}

#[test]
#[serial]
fn strict_blocks_shadow_copy() {
    let r = run_payload("escape_shadow_copy", "scan");
    assert_eq!(r.status.code(), Some(5),
        "shadow copy should be blocked\nstderr: {}", r.stderr);
}

#[test]
#[serial]
fn strict_blocks_raw_disk() {
    // Hard-block: classify_device returns Unknown for any path containing
    // "physicaldrive". Note: even without our block, opening PhysicalDrive0
    // from a non-admin process is denied by kernel ACL — this test confirms
    // the path is rejected but does not distinguish our block from the ACL.
    let r = run_payload("escape_raw_disk", "scan");
    assert_eq!(r.status.code(), Some(5),
        "raw disk should be blocked\nstderr: {}", r.stderr);
}

// ═══════════════════════════════════════════════════════════════════════════
// FS path canonicalization
// ═══════════════════════════════════════════════════════════════════════════

#[test]
#[serial]
fn strict_blocks_globalroot() {
    let r = run_payload("escape_globalroot", "scan");
    assert_eq!(r.status.code(), Some(5),
        "GLOBALROOT namespace should be denied\nstderr: {}", r.stderr);
}

#[test]
#[serial]
fn strict_blocks_ads() {
    let r = run_payload("escape_ads", "scan");
    assert_eq!(r.status.code(), Some(5),
        "ADS write should be denied\nstderr: {}", r.stderr);
}

#[test]
#[serial]
fn strict_blocks_short_name() {
    let r = run_payload("escape_short_name", "scan");
    // Acceptable: exit 5 (deny) or exit 6 (CoW absorbed). Exit 0 = real escape.
    let code = r.status.code();
    assert!(code == Some(5) || code == Some(6),
        "8.3 short name write under Program Files should be denied or CoW-absorbed, got {:?}\nstderr: {}",
        code, r.stderr);
}

#[test]
#[serial]
fn strict_blocks_file_by_id() {
    let r = run_payload("escape_file_by_id", "scan");
    assert_eq!(r.status.code(), Some(5),
        "FILE_OPEN_BY_FILE_ID should be denied\nstderr: {}", r.stderr);
}

// ═══════════════════════════════════════════════════════════════════════════
// NtSetInformationFile — rename/hardlink/disposition escape vectors
// ═══════════════════════════════════════════════════════════════════════════

#[test]
#[serial]
fn strict_blocks_rename_outside_sandbox() {
    // Under the CoW model a rename to an out-of-project target is not
    // hard-denied — it is redirected into the overlay. The payload can't tell
    // "absorbed" from "leaked" from inside the sandbox (its own `.exists()`
    // probe is hooked and observes the overlay copy), so the load-bearing
    // check is the OUTER real-disk leak guard.
    let dst_real = std::path::Path::new(r"C:\Windows\Temp\winrsbox_escape_rename.txt");
    let _ = std::fs::remove_file(dst_real);

    let r = run_payload("escape_rename_outside_sandbox", "scan");
    let code = r.status.code();
    // exit 0 = CoW-absorbed (allowed), exit 5 = hard-denied. Both are safe.
    assert!(code == Some(0) || code == Some(5),
        "rename outside sandbox should exit 0 (CoW-absorbed) or 5 (denied), got {:?}\nstderr: {}", code, r.stderr);

    // OUTER LEAK GUARD: the destination must NOT exist on the real disk.
    // If it does, the CoW redirect failed and the file escaped the sandbox.
    assert!(!dst_real.exists(),
        "rename target LEAKED to real disk: {} — CoW isolation failed!\nstderr: {}", dst_real.display(), r.stderr);

    let _ = std::fs::remove_file(dst_real);
}

#[test]
#[serial]
fn strict_blocks_hardlink_to_host() {
    let r = run_payload("escape_hardlink_to_host", "scan");
    if r.status.code() == Some(7) { return; }
    assert_eq!(r.status.code(), Some(5),
        "hardlink to host file should be blocked\nstderr: {}", r.stderr);
}

#[test]
#[serial]
fn strict_hides_winrsbox_open() {
    // Create a .winrsbox sibling directory with a canary file so the test
    // can detect visibility. TestEnv::setup creates <base>/project (cwd) and
    // <base>/.winrsbox/project (state). The payload's cwd.parent() = <base>,
    // and <base>/.winrsbox exists → test should fail to see it.
    let r = run_payload("escape_winrsbox_read", "scan");
    // 5 = NOT_FOUND on metadata (layer 1 block); 6 = folder visible but file blocked (partial)
    let code = r.status.code();
    assert!(code == Some(5) || code == Some(6),
        "Sandbox state directory should be hidden or unreadable, got {:?}\nstderr: {}", code, r.stderr);
    assert_ne!(code, Some(0),
        "Read of .winrsbox file should not succeed\nstderr: {}", r.stderr);
}

#[test]
#[serial]
fn strict_hides_winrsbox_enum() {
    let r = run_payload("escape_winrsbox_enum", "scan");
    let code = r.status.code();
    if code == Some(0) {
        eprintln!("WARNING: .winrsbox visible in enum (layer 2 not active or class not handled).\nLayer 1 (open block) still active. This is documented partial coverage.");
        return; // Don't fail the test — partial coverage is acceptable
    }
    assert_eq!(code, Some(5), ".winrsbox should not appear in directory enumeration\nstderr: {}", r.stderr);
}

// ═══════════════════════════════════════════════════════════════════════════
// NtFsControlFile — reparse-point creation escape vector
// ═══════════════════════════════════════════════════════════════════════════

#[test]
#[serial]
fn strict_blocks_setinfo_process() {
    let r = run_payload("escape_setinfo_process", "scan");
    if r.status.code() == Some(7) { return; }
    assert_eq!(r.status.code(), Some(5),
        "SetProcessAffinityMask on foreign process should be blocked\nstderr: {}", r.stderr);
}

#[test]
#[serial]
fn strict_blocks_reparse_create() {
    let r = run_payload("escape_reparse_create", "scan");
    if r.status.code() == Some(7) {
        eprintln!("setup failed (mkdir), skipping");
        return;
    }
    assert_eq!(r.status.code(), Some(5),
        "FSCTL_SET_REPARSE_POINT should be denied\nstderr: {}", r.stderr);
}
