use super::*;

// ═══════════════════════════════════════════════════════════════════════════
// P9-B: Registry runtime hooks — persistence vector denial
// ═══════════════════════════════════════════════════════════════════════════

#[test]
#[serial]
fn strict_denies_reg_appinit_persistence() {
    let r = run_payload("escape_reg_appinit", "full");
    // Payload exits with code 5 (ERROR_ACCESS_DENIED) when registry write
    // is correctly denied by our hook+IPC.
    let stderr_lower = r.stderr.to_ascii_lowercase();
    assert!(
        r.status.code() == Some(5) || stderr_lower.contains("status=5"),
        "payload should report ERROR_ACCESS_DENIED on registry write to persistence path\nexit={:?}\nstderr: {}",
        r.status.code(), r.stderr
    );
}

#[test]
#[serial]
fn strict_denies_reg_ifeo_debugger() {
    let r = run_payload("escape_reg_ifeo", "full");
    // IFEO Debugger write should be denied — either our hook returns deny on
    // NtCreateKey/NtSetValueKey, or OS ACL denies non-admin HKLM write.
    // Acceptable: exit 5 (access denied) or exit 2 (HKLM key creation failed).
    let code = r.status.code();
    assert!(
        code == Some(5) || code == Some(2),
        "IFEO Debugger write should be denied, got {:?}\nstderr: {}",
        code, r.stderr
    );
}

#[test]
#[serial]
fn strict_denies_reg_silentprocessexit() {
    let r = run_payload("escape_reg_silentexit", "full");
    let code = r.status.code();
    assert!(
        code == Some(5) || code == Some(2),
        "SilentProcessExit MonitorProcess write should be denied, got {:?}\nstderr: {}",
        code, r.stderr
    );
}

#[test]
#[serial]
fn strict_denies_reg_service_imagepath() {
    let r = run_payload("escape_reg_service", "full");
    let code = r.status.code();
    assert!(
        code == Some(5) || code == Some(2),
        "Services ImagePath write should be denied, got {:?}\nstderr: {}",
        code, r.stderr
    );
}

#[test]
#[serial]
fn lolbas_regsvr32_blocked() {
    let r = run_payload("escape_lolbas_regsvr32", "scan");
    assert_ne!(r.status.code(), Some(0),
        "regsvr32 LOLBAS should not succeed\nstderr: {}", r.stderr);
}

// ═══════════════════════════════════════════════════════════════════════════
// Service guard: SCM / service handle escape vectors
// ═══════════════════════════════════════════════════════════════════════════

#[test]
#[serial]
fn strict_blocks_scm_open() {
    let r = run_payload("escape_scm_open", "scan");
    assert_eq!(r.status.code(), Some(5),
        "OpenSCManagerW with ALL_ACCESS should be blocked\nstderr: {}", r.stderr);
}

#[test]
#[serial]
fn strict_blocks_service_changeconfig() {
    let r = run_payload("escape_service_changeconfig", "scan");
    if r.status.code() == Some(7) {
        eprintln!("SCM connect failed (rare permission issue), skipping");
        return;
    }
    assert_eq!(r.status.code(), Some(5),
        "OpenServiceW with CHANGE_CONFIG should be blocked\nstderr: {}", r.stderr);
}
