use super::*;
use std::path::PathBuf;

#[test]
fn cidr_parse_basic() {
    let c = CidrV4::parse("192.168.0.0/16").unwrap();
    assert_eq!(c.addr, 0xC0A80000);
    assert_eq!(c.prefix, 16);
    assert_eq!(c.mask(), 0xFFFF0000);
}

#[test]
fn cidr_parse_8() {
    let c = CidrV4::parse("10.0.0.0/8").unwrap();
    assert_eq!(c.addr, 0x0A000000);
    assert_eq!(c.mask(), 0xFF000000);
}

#[test]
fn cidr_parse_32() {
    let c = CidrV4::parse("1.2.3.4/32").unwrap();
    assert_eq!(c.addr, 0x01020304);
    assert_eq!(c.mask(), 0xFFFFFFFF);
}

#[test]
fn cidr_parse_0() {
    let c = CidrV4::parse("0.0.0.0/0").unwrap();
    assert_eq!(c.addr, 0);
    assert_eq!(c.mask(), 0);
}

#[test]
fn cidr_parse_masks_low_bits() {
    let c = CidrV4::parse("192.168.1.5/24").unwrap();
    assert_eq!(c.addr, 0xC0A80100); // .5 masked out
}

#[test]
fn cidr_parse_invalid_prefix_33() {
    assert!(CidrV4::parse("1.2.3.4/33").is_none());
}

#[test]
fn cidr_parse_no_slash() {
    assert!(CidrV4::parse("192.168.0.0").is_none());
}

#[test]
fn cidr_parse_too_many_octets() {
    assert!(CidrV4::parse("1.2.3.4.5/8").is_none());
}

#[test]
fn cidr_contains_match() {
    let c = CidrV4::parse("10.0.0.0/8").unwrap();
    assert!(c.contains(0x0A010203)); // 10.1.2.3
    assert!(c.contains(0x0AFFFFFF)); // 10.255.255.255
    assert!(!c.contains(0x0B000001)); // 11.0.0.1
}

#[test]
fn cidr_contains_exact() {
    let c = CidrV4::parse("8.8.8.8/32").unwrap();
    assert!(c.contains(0x08080808));
    assert!(!c.contains(0x08080809));
}

#[test]
fn cidr_contains_all() {
    let c = CidrV4::parse("0.0.0.0/0").unwrap();
    assert!(c.contains(0));
    assert!(c.contains(0xFFFFFFFF));
}

#[test]
fn cidr_v6_parse_basic() {
    let c = CidrV6::parse("fc00::/7").unwrap();
    assert_eq!(c.prefix, 7);
    assert_eq!(c.addr[0], 0xfc);
    assert_eq!(c.addr[1], 0x00);
}

#[test]
fn cidr_v6_parse_loopback() {
    let c = CidrV6::parse("::1/128").unwrap();
    assert_eq!(c.prefix, 128);
    assert_eq!(c.addr[15], 1);
    assert_eq!(c.addr[0], 0);
}

#[test]
fn cidr_v6_parse_link_local() {
    let c = CidrV6::parse("fe80::/10").unwrap();
    assert_eq!(c.prefix, 10);
    assert_eq!(c.addr[0], 0xfe);
    assert_eq!(c.addr[1], 0x80);
}

#[test]
fn cidr_v6_mask_bytes() {
    let m = CidrV6::mask_bytes(10);
    assert_eq!(m[0], 0xFF);
    assert_eq!(m[1], 0xC0); // 1100_0000
    assert_eq!(m[2], 0x00);
}

#[test]
fn cidr_v6_parse_invalid_prefix() {
    assert!(CidrV6::parse("::1/129").is_none());
}

// ----- audit Medium "WFP": APP_ID scoping + loud non-elevated failure -----

fn unique_temp_file(name: &str) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join(name);
    std::fs::write(&p, b"").unwrap();
    (dir, p)
}

#[test]
fn app_id_blob_is_nt_path_of_image() {
    let (_dir, p) = unique_temp_file("wfp_probe_image.exe");
    let blob = app_id_from_path(&p).unwrap();
    assert!(!blob.is_empty());
    // The WFP app id blob is the NT path as UTF-16 wide chars,
    // NUL-terminated (the producer includes the terminator).
    assert_eq!(blob.len() % 2, 0, "wide-char blob must be even-sized");
    let wide: Vec<u16> = blob
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    let s = String::from_utf16(&wide)
        .unwrap()
        .trim_end_matches('\0')
        .to_lowercase();
    assert!(s.starts_with('\\'), "app id must be an NT device path, got: {s}");
    assert!(s.ends_with("wfp_probe_image.exe"), "got: {s}");
}

#[test]
fn app_id_blob_rejects_missing_file() {
    // The image path must be verifiable BEFORE any filter is installed --
    // an unverifiable path must never degrade into machine-wide filters.
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("does_not_exist.exe");
    let err = app_id_from_path(&p).unwrap_err().to_string();
    assert!(
        err.contains("canonicalize"),
        "must fail before touching the engine, got: {err}"
    );
}

#[test]
fn strip_verbatim_prefix_local_unc_and_plain() {
    assert_eq!(
        strip_verbatim_prefix(Path::new(r"\\?\C:\x\y.exe")),
        PathBuf::from(r"C:\x\y.exe")
    );
    assert_eq!(
        strip_verbatim_prefix(Path::new(r"\\?\UNC\srv\share\x.exe")),
        PathBuf::from(r"\\srv\share\x.exe")
    );
    assert_eq!(
        strip_verbatim_prefix(Path::new(r"C:\already\plain.exe")),
        PathBuf::from(r"C:\already\plain.exe")
    );
}

/// The loud-failure contract for a refused filter add: the message must
/// name the lost guarantee ("NOT ENFORCED") so an operator grepping the
/// log finds it, and must carry the OS status text. Deliberately does NOT
/// guess the cause -- unelevation was the historical suspect, but
/// unelevated dynamic-session adds are observed to succeed on Win10 19045.
#[test]
fn probe_failure_message_names_lost_guarantee() {
    let msg = probe_failure_message("WIN32_ERROR(5)");
    assert!(msg.contains("NOT ENFORCED"), "got: {msg}");
    assert!(msg.contains("WIN32_ERROR(5)"), "must carry the status, got: {msg}");
}

/// Live smoke test: the engine accepts the canary add and it is deleted
/// again (dynamic-session objects also die with the session regardless).
/// Requires the Base Filtering Engine service; where it is stopped this
/// test fails with the containment-lost error -- exactly the condition
/// the canary exists to surface.
#[test]
fn open_smoke_engine_accepts_probe_and_cleans_up() {
    let engine = WfpEngine::open()
        .expect("WfpEngine::open failed -- is the Base Filtering Engine service running?");
    assert_eq!(engine.filter_count(), 0);
}

/// Audit Medium "WFP" fix verification, live path: the engine must accept
/// an APP_ID-scoped CIDR filter. FwpmFilterAdd0 validates every condition
/// against the layer schema, so a structurally wrong APP_ID condition
/// (wrong GUID, wrong value type, dangling blob) is rejected here instead
/// of silently installed. Engine-side enumeration to re-read the stored
/// conditions was attempted and is NOT possible for this token
/// (FwpmFilterCreateEnumHandle0 -> ERROR_ACCESS_DENIED with a UAC-filtered
/// admin token; FwpmFilterAdd0 leaves its out-param id at 0 in a dynamic
/// session, so FwpmFilterGetById0 has nothing to look up).
#[test]
fn add_filter_installs_app_id_and_cidr_conditions_live() {
    let (_dir, image) = unique_temp_file("wfp_live_image.exe");
    let cidr = CidrV4::parse("127.0.0.0/8").unwrap();
    let mut engine = WfpEngine::open()
        .expect("WfpEngine::open failed -- is the Base Filtering Engine service running?");
    engine
        .block_outbound_cidr(&image, &cidr)
        .expect("APP_ID-scoped block filter rejected by the engine");
    assert_eq!(engine.filter_count(), 1);
    // Dynamic-session objects die with the engine session, so dropping
    // here is the cleanup path; nothing persists beyond this process.
    drop(engine);
}

/// Every containment filter must be bound to the sandboxed image.
///
/// `block_outbound_cidr_v6`, `block_outbound_port` and
/// `block_outbound_port_v6` were each built with a single condition and no
/// `FWPM_CONDITION_ALE_APP_ID`, so they matched EVERY process on the
/// machine: while any sandbox ran, the whole host lost SMB egress on
/// 445/139 and connectivity to the private IPv6 ranges. A sandbox must
/// not reconfigure the operator's network.
///
/// Source-level because building a filter needs a live WFP engine and
/// elevation-dependent state; the property to protect is structural — a
/// new `block_outbound_*` helper added without an `app_path` parameter is
/// the regression, and it is visible in the signature.
#[test]
fn every_block_filter_is_scoped_to_an_app_path() {
    let src = include_str!("mod.rs");
    let mut unscoped: Vec<&str> = Vec::new();
    for line in src.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix("pub fn block_outbound_") else { continue };
        // `app_path: &Path` is what carries the APP_ID condition.
        if !rest.contains("app_path: &Path") {
            unscoped.push(line);
        }
    }
    assert!(
        unscoped.is_empty(),
        "these filter helpers take no app_path, so they would match every              process on the machine: {unscoped:#?}",
    );
}

// ----- S08: fail-closed `install_outbound_filters` -----

/// With guarded network off (either switch) nothing may be installed and no
/// engine may be opened — the launch may proceed with no trace.
#[test]
fn install_not_requested_when_guard_off() {
    let (_dir, exe) = unique_temp_file("wfp_install_off_target.exe");
    assert!(
        matches!(
            install_outbound_filters(false, false, false, &exe),
            WfpInstall::NotRequested
        ),
        "nothing requested must be NotRequested"
    );
    assert!(
        matches!(
            install_outbound_filters(true, false, false, &exe),
            WfpInstall::NotRequested
        ),
        "guard off must be NotRequested even with net_guarded on"
    );
    assert!(
        matches!(
            install_outbound_filters(false, true, false, &exe),
            WfpInstall::NotRequested
        ),
        "net_guarded off must be NotRequested even with guard on"
    );
}

/// Under guarded network a `.bat`/`.cmd` target must be Refused — the root
/// process is cmd.exe, so APP_ID scoping cannot bind and the kernel layer
/// the security policy promises cannot exist. The refusal must name the
/// target and the APP_ID limitation.
#[test]
fn install_refused_for_script_target_under_guard() {
    let (_dir, bat) = unique_temp_file("wfp_install_script.bat");
    let result = install_outbound_filters(true, true, false, &bat);
    let WfpInstall::Refused(msg) = result else {
        panic!("guarded script target must be Refused, got another outcome");
    };
    assert!(
        msg.contains(bat.to_string_lossy().as_ref()),
        "refusal must name the target, got: {msg}"
    );
    assert!(
        msg.to_lowercase().contains("app_id"),
        "refusal must explain the APP_ID limitation, got: {msg}"
    );
}

/// Live-engine: a guarded install whose target path cannot be verified must
/// be Refused, never Installed. Depending on the environment either the
/// engine cannot open (no Base Filtering Engine) or the first APP_ID build
/// fails on the unverifiable path — both are Refused, so only the variant
/// is asserted, not the reason.
#[test]
fn install_refused_when_app_id_cannot_be_built() {
    let missing = Path::new(r"Z:\definitely\missing\target.exe");
    let result = install_outbound_filters(true, true, false, missing);
    assert!(
        matches!(result, WfpInstall::Refused(_)),
        "a guarded install against an unverifiable path must be Refused"
    );
}

/// All-or-nothing, live: a failed filter add must leave nothing registered.
/// The caller drops the engine on Err and Drop deletes every filter added
/// before the failure, so a partial set never persists.
#[test]
fn add_all_filters_all_or_nothing_on_unusable_path() {
    let mut engine = WfpEngine::open()
        .expect("WfpEngine::open failed -- is the Base Filtering Engine service running?");
    let missing = Path::new(r"Z:\definitely\missing\target.exe");
    assert!(
        add_all_filters(&mut engine, missing, false).is_err(),
        "an unusable app id must abort the install"
    );
    assert_eq!(
        engine.filter_count(),
        0,
        "no filter may survive a failed install"
    );
    // Dynamic-session objects die with the engine session, so dropping
    // here is the cleanup path; nothing persists beyond this process.
    drop(engine);
}
