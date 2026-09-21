use super::*;

#[test]
fn dangerous_port_detection() {
    // COM activation brokers — blocked in EVERY tier.
    assert!(is_dangerous_port("actkernel_port"));
    assert!(is_dangerous_port("ComLaunch"));
    assert!(is_dangerous_port(r"\RPC Control\dcomlaunch"));

    // NEW — security service patterns
    //
    // LSARPC is intentionally NOT denied (see denylist comment): blocking
    // it added no real defense (medium-IL ACL on the policy object
    // already gates dangerous LSA calls) and broke Cygwin/MSYS2 bash
    // initialization. Pin the inverted expectation.
    assert!(!is_dangerous_port(r"\RPC Control\lsarpc"));
    assert!(is_dangerous_port(r"\RPC Control\samr"));
    assert!(is_dangerous_port(r"\RPC Control\winreg"));
    assert!(is_dangerous_port(r"\RPC Control\seclogon"));
    assert!(is_dangerous_port("WMsgKMessagePort"));

    // Print Spooler RPC (PrintNightmare class)
    assert!(is_dangerous_port(r"\RPC Control\spoolss"));

    // WMI direct ALPC bypass patterns — ALWAYS blocked (bug #88 re-audit):
    // allowing them opens Win32_Process.Create via the generic DCOM
    // object-exporter channel (full escape). Read-only WMI cannot be
    // distinguished from write-methods at the ALPC layer.
    assert!(is_dangerous_port(r"\RPC Control\WMI_RPC_12345"));
    assert!(is_dangerous_port(r"\RPC Control\WbemLevel1Login"));

    // Task Scheduler direct LRPC
    assert!(is_dangerous_port(r"\RPC Control\schedule"));

    // Audit M-S4: UAC / deployment / session / reporting brokers
    assert!(is_dangerous_port(r"\RPC Control\appinfo"));
    assert!(is_dangerous_port(r"\RPC Control\appxsvc"));
    assert!(is_dangerous_port(r"\RPC Control\dcomlaunch"));
    assert!(is_dangerous_port(r"\RPC Control\pchsvc"));
    assert!(is_dangerous_port(r"\RPC Control\terminalserver"));
    assert!(is_dangerous_port(r"\RPC Control\iiscertobj"));
    // "appx" is a prefix of "appxsvc" — any port starting with "appx"
    // matches (intended: covers \RPC Control\AppXDeploymentClient etc.).
    assert!(is_dangerous_port(r"\RPC Control\AppXDeploymentClient"));

    // Negative — must NOT be blocked
    assert!(!is_dangerous_port("lsass"));
    assert!(!is_dangerous_port("epmapper"));
    assert!(!is_dangerous_port("DnsResolver"));

    // Audit M-S4 regression: bare common prefixes must NOT match — only
    // segments that start with a full denied token. The check is
    // `segment.starts_with(pattern)`, so a shorter segment like "app"
    // cannot start with the longer pattern "appinfo" / "appx".
    assert!(!is_dangerous_port(r"\RPC Control\app"));
    assert!(!is_dangerous_port(r"\RPC Control\dcom"));

    // False-positive regression: "ole" substring inside a segment
    // must NOT match when the segment does not start with "ole".
    assert!(!is_dangerous_port(r"\RPC Control\Console"));
    assert!(!is_dangerous_port(r"\RPC Control\ConsoleNotificationPort"));
    assert!(!is_dangerous_port(r"\BaseNamedObjects\GoogleChromeServiceSocket"));
}

#[test]
fn escape_class_ports_trigger_kill() {
    // COM/DCOM activation + WMI + priv-esc + persistence brokers → Kill.
    // A sandboxed process connecting to any of these is a deliberate
    // containment-escape attempt; fail-stop rather than politely deny.
    for p in [
        r"\RPC Control\actkernel",
        r"\RPC Control\comlaunch",
        r"\RPC Control\dcomlaunch",
        r"\RPC Control\samr",
        r"\RPC Control\seclogon",
        r"\RPC Control\appinfo",
        r"\RPC Control\schedule",
    ] {
        assert_eq!(classify_port(p), PortAction::Kill, "expected Kill for {p}");
    }
}

#[test]
fn deny_only_ports_do_not_kill() {
    // Defense-in-depth endpoints legit software probes and handles a refusal
    // for → Deny (ACCESS_DENIED), NEVER Kill. Killing here would break benign
    // workloads (printer enumeration, registry probes, AppX installers, and
    // WMI reads like tasklist / Get-CimInstance). The WMI ports (ole/wmi/wbem)
    // are here — the escape is blocked upstream by com_guard's CLSID deny, so
    // killing them would only take out benign WMI readers as collateral.
    for p in [
        r"\RPC Control\OLE58BCCC182C1065EBB0",
        r"\RPC Control\OLE12345",
        r"\RPC Control\WMI_RPC_12345",
        r"\RPC Control\WbemLevel1Login",
        r"\RPC Control\winreg",
        r"\RPC Control\spoolss",
        r"\RPC Control\appxsvc",
        r"\RPC Control\AppXDeploymentClient",
        r"\RPC Control\pchsvc",
        r"\RPC Control\terminalserver",
        r"\RPC Control\iiscertobj",
        r"WMsgKMessagePort",
    ] {
        assert_eq!(classify_port(p), PortAction::Deny, "expected Deny for {p}");
    }
}

#[test]
fn safe_ports_allowed() {
    // Legit endpoints normal workloads use (verified empirically via trace):
    // epmapper (COM endpoint resolution), keysvc, ntsvcs, LSARPC, DNS.
    for p in [
        r"\RPC Control\epmapper",
        r"\RPC Control\keysvc",
        r"\RPC Control\ntsvcs",
        r"\RPC Control\LSARPC_ENDPOINT",
        r"\RPC Control\lsarpc",
        r"\RPC Control\DnsResolver",
    ] {
        assert_eq!(classify_port(p), PortAction::Allow, "expected Allow for {p}");
    }
}

#[test]
fn ole_dcom_port_always_blocked() {
    // Bug #88 re-audit: the generic \RPC Control\OLE<hex> DCOM object-exporter
    // port is ALWAYS blocked. Allowing it (as an earlier #88 fix attempt did)
    // lets Win32_Process.Create — a method call marshalled over this same
    // channel — spawn arbitrary host processes via the un-hooked wmiprvse.exe,
    // a full containment escape. Read-only WMI cannot be distinguished from
    // write-methods at the ALPC layer, so there is no safe partial allow.
    assert!(is_dangerous_port(r"\RPC Control\OLE58BCCC182C1065EBB0"));
    assert!(is_dangerous_port(r"\RPC Control\OLE12345"));

    // The COM activation brokers stay denied too.
    assert!(is_dangerous_port(r"\RPC Control\dcomlaunch"));
    assert!(is_dangerous_port("actkernel_port"));
    assert!(is_dangerous_port("ComLaunch"));
}

// -- classify_port_name -----------------------------------------------------
//
// Pure inputs reproduce every shape `hook_nt_alpc_connect_port` cares about
// — including the previously fail-open "hostile UNICODE_STRING" shapes the
// connect hook now refuses with STATUS_ACCESS_DENIED.

#[test]
fn classify_empty_passthrough() {
    // ObjectAttributes-only caller — Length=0 must NOT trigger a deny;
    // the legitimate code path here is to keep going and let the kernel
    // honour ObjectAttributes->ObjectName.
    assert_eq!(classify_port_name(0, 0,  true),  PortNameStatus::Empty);
    assert_eq!(classify_port_name(0, 64, false), PortNameStatus::Empty);
}

#[test]
fn classify_valid_normal_name() {
    // Realistic ALPC port name length range.
    assert_eq!(classify_port_name(16,  16, false), PortNameStatus::Valid);
    assert_eq!(classify_port_name(128, 256, false), PortNameStatus::Valid);
    assert_eq!(classify_port_name(MAX_PORT_NAME_CHARS, MAX_PORT_NAME_CHARS, false),
               PortNameStatus::Valid);
}

#[test]
fn classify_inconsistent_length_exceeds_maxlength() {
    // Hostile: Length > MaximumLength advertises a longer string than
    // Buffer was allocated for. Refuse — was a fail-open path pre-#55.
    let got = classify_port_name(64, 32, false);
    assert!(matches!(got, PortNameStatus::Malformed(_)),
        "expected Malformed for length>maximum, got {got:?}");
}

#[test]
fn classify_oversized_port_name_denied() {
    // Hostile: char_count > MAX_PORT_NAME_CHARS would drive an OOB read
    // if we read all of it. Refuse instead of clamping or skipping.
    let got = classify_port_name(MAX_PORT_NAME_CHARS + 1,
                                 MAX_PORT_NAME_CHARS + 1, false);
    assert!(matches!(got, PortNameStatus::Malformed(_)),
        "oversized name must be malformed (got {got:?})");
}

#[test]
fn classify_null_buffer_with_nonzero_length() {
    // Hostile: Length>0 but Buffer is null. Old code skipped the deny
    // check; we now refuse.
    let got = classify_port_name(8, 16, true);
    assert!(matches!(got, PortNameStatus::Malformed(_)),
        "null Buffer + nonzero Length must be malformed (got {got:?})");
}

#[test]
fn classify_zero_length_with_null_buffer_is_empty_not_malformed() {
    // Both zero is the "no name, see ObjectAttributes" legitimate case —
    // a null Buffer is fine when Length is 0 (caller didn't allocate).
    assert_eq!(classify_port_name(0, 0, true), PortNameStatus::Empty);
}

// -- ObjectAttributes addressing (P1-02) -----------------------------------
//
// `NtAlpcConnectPort` accepts the port name through `PortName` OR through
// `ObjectAttributes->ObjectName`. These tests fabricate real
// UNICODE_STRING / OBJECT_ATTRIBUTES structs (the same layouts the kernel
// ABI hands the hook) and drive `decide_connect` directly, so the
// ObjectAttributes path is exercised end-to-end without a live port.

/// UTF-16 backing buffer for a fabricated `UNICODE_STRING` (NUL-terminated;
/// Length counts chars only, MaximumLength covers the NUL).
fn utf16_buf(s: &str) -> Vec<u16> {
    let mut buf: Vec<u16> = s.encode_utf16().collect();
    buf.push(0);
    buf
}

fn ustr_for(buf: &mut [u16]) -> UNICODE_STRING {
    let chars = buf.len() - 1; // exclude the NUL
    UNICODE_STRING {
        Length: (chars * 2) as u16,
        MaximumLength: (buf.len() * 2) as u16,
        Buffer: buf.as_mut_ptr(),
    }
}

fn oa_with_name(name: *mut UNICODE_STRING) -> OBJECT_ATTRIBUTES {
    OBJECT_ATTRIBUTES {
        Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: std::ptr::null_mut(),
        ObjectName: name,
        Attributes: 0,
        SecurityDescriptor: std::ptr::null_mut(),
        SecurityQualityOfService: std::ptr::null_mut(),
    }
}

fn empty_ustr() -> UNICODE_STRING {
    UNICODE_STRING { Length: 0, MaximumLength: 0, Buffer: std::ptr::null_mut() }
}

#[test]
fn object_attributes_escape_port_is_classified() {
    // P1-02 regression: PortName = NULL, the escape-class Task Scheduler
    // port addressed via ObjectAttributes->ObjectName only. Pre-fix the
    // guard fell straight through to call_original() and this connect
    // reached the broker unguarded; it must classify as Kill.
    let mut buf = utf16_buf(r"\RPC Control\schedule");
    let name = ustr_for(&mut buf);
    let oa = oa_with_name(&name as *const _ as *mut _);
    let got = unsafe { decide_connect(std::ptr::null(), &oa) };
    assert_eq!(
        got,
        ConnectDecision::Classified {
            name: r"\RPC Control\schedule".to_string(),
            action: PortAction::Kill,
        },
        "escape port via ObjectAttributes must classify as Kill"
    );
}

#[test]
fn object_attributes_benign_port_still_allowed() {
    // The benign counterpart: same addressing shape, allowed endpoint —
    // the fallback must not fail closed for legitimate callers.
    let mut buf = utf16_buf(r"\RPC Control\epmapper");
    let name = ustr_for(&mut buf);
    let oa = oa_with_name(&name as *const _ as *mut _);
    let got = unsafe { decide_connect(std::ptr::null(), &oa) };
    assert_eq!(
        got,
        ConnectDecision::Classified {
            name: r"\RPC Control\epmapper".to_string(),
            action: PortAction::Allow,
        },
    );

    // Empty PortName (Length == 0) must ALSO fall through to
    // ObjectAttributes, not short-circuit to passthrough.
    let empty = empty_ustr();
    let got = unsafe { decide_connect(&empty, &oa) };
    assert_eq!(
        got,
        ConnectDecision::Classified {
            name: r"\RPC Control\epmapper".to_string(),
            action: PortAction::Allow,
        },
        "empty PortName must consult ObjectAttributes",
    );
}

#[test]
fn object_attributes_deny_port_gets_deny() {
    // Deny-class endpoint via ObjectAttributes: refused, not killed.
    let mut buf = utf16_buf(r"\RPC Control\winreg");
    let name = ustr_for(&mut buf);
    let oa = oa_with_name(&name as *const _ as *mut _);
    let got = unsafe { decide_connect(std::ptr::null(), &oa) };
    assert_eq!(
        got,
        ConnectDecision::Classified {
            name: r"\RPC Control\winreg".to_string(),
            action: PortAction::Deny,
        },
    );
}

#[test]
fn port_name_takes_precedence_over_object_attributes() {
    // Both sources carry a name: PortName is the connection-port name and
    // is the one classified; ObjectAttributes (client-port attributes)
    // must not override it. The OA name here is escape-class — it must be
    // IGNORED, i.e. the decision stays Allow on the benign PortName.
    let mut pn_buf = utf16_buf(r"\RPC Control\epmapper");
    let port_name = ustr_for(&mut pn_buf);
    let mut oa_buf = utf16_buf(r"\RPC Control\schedule");
    let oa_name = ustr_for(&mut oa_buf);
    let oa = oa_with_name(&oa_name as *const _ as *mut _);
    let got = unsafe { decide_connect(&port_name, &oa) };
    assert_eq!(
        got,
        ConnectDecision::Classified {
            name: r"\RPC Control\epmapper".to_string(),
            action: PortAction::Allow,
        },
    );
}

#[test]
fn both_names_absent_is_unnamed() {
    let got = unsafe { decide_connect(std::ptr::null(), std::ptr::null()) };
    assert_eq!(got, ConnectDecision::Unnamed);

    // OA present but ObjectName null: still unnamed.
    let oa = oa_with_name(std::ptr::null_mut());
    let got = unsafe { decide_connect(std::ptr::null(), &oa) };
    assert_eq!(got, ConnectDecision::Unnamed);

    // Empty PortName, no OA at all: unnamed.
    let empty = empty_ustr();
    let got = unsafe { decide_connect(&empty, std::ptr::null()) };
    assert_eq!(got, ConnectDecision::Unnamed);
}

#[test]
fn object_attributes_malformed_name_fails_closed() {
    // Hostile OA name: Length > MaximumLength. Must fail closed rather
    // than slip past the classifier.
    let mut buf = utf16_buf(r"\RPC Control\schedule");
    let mut name = ustr_for(&mut buf);
    name.Length = 64;
    name.MaximumLength = 32;
    let oa = oa_with_name(&mut name);
    let got = unsafe { decide_connect(std::ptr::null(), &oa) };
    assert_eq!(
        got,
        ConnectDecision::Malformed(MalformedPortName {
            source: PortNameSource::ObjectAttributes,
            reason: "length>maximum_length",
            length: 64,
            maximum_length: 32,
            buffer_is_null: false,
        }),
    );
}

#[test]
fn port_name_malformed_fails_closed_before_oa() {
    // Malformed PortName fails closed immediately; ObjectAttributes is
    // not consulted (the connect is refused either way).
    let mut pn_buf = utf16_buf(r"\RPC Control\epmapper");
    let mut port_name = ustr_for(&mut pn_buf);
    port_name.Length = 64;
    port_name.MaximumLength = 32;
    let got = unsafe { decide_connect(&port_name, std::ptr::null()) };
    assert!(matches!(got, ConnectDecision::Malformed(_)), "got {got:?}");
    let ConnectDecision::Malformed(m) = got else { unreachable!("matched above") };
    assert_eq!(m.source, PortNameSource::PortName);
}

// -----------------------------------------------------------------
// Sibling-entry closure (audit High): NtAlpcConnectPortEx /
// NtSecureConnectPort must reach the same classifier the classic hook
// uses. The direct hook-body calls below take the DENY path, which
// returns before the trampoline is ever touched (the detour is not
// installed under --lib tests), so they are safe to drive here. The
// KILL class is asserted only through the pure decide_connect_ex —
// invoking a Kill-classified hook body would terminate the test
// process, exactly like the real escape path.
// -----------------------------------------------------------------

#[test]
fn connect_port_ex_hook_denies_deny_port_via_object_attributes() {
    // The attack shape the audit confirmed: port name ONLY in
    // ObjectAttributes->ObjectName, addressed through the Ex entry point.
    // Pre-fix this call sailed straight to the broker unguarded.
    let mut buf = utf16_buf(r"\RPC Control\winreg");
    let name = ustr_for(&mut buf);
    let mut oa = oa_with_name(&name as *const _ as *mut _);
    // SAFETY: hook body with a Deny-classified port returns
    // STATUS_ACCESS_DENIED without touching the (uninstalled) trampoline.
    let got = unsafe {
        hook_nt_alpc_connect_port_ex(
            std::ptr::null_mut(), // PortHandle (out)
            &mut oa,              // connection-port OBJECT_ATTRIBUTES
            std::ptr::null_mut(), // client-port OBJECT_ATTRIBUTES
            std::ptr::null_mut(), // PortAttributes
            0,                    // Flags
            std::ptr::null_mut(), // ServerSecurityRequirements
            std::ptr::null_mut(), // ConnectionMessage
            std::ptr::null_mut(), // BufferLength
            std::ptr::null_mut(), // OutMessageAttributes
            std::ptr::null_mut(), // InMessageAttributes
            std::ptr::null_mut(), // Timeout
        )
    };
    assert_eq!(got, STATUS_ACCESS_DENIED, "Ex hook must deny the winreg port");
}

#[test]
fn connect_port_ex_hook_fails_closed_on_malformed_name() {
    // Hostile UNICODE_STRING via ObjectAttributes: refused, not passed.
    let mut buf = utf16_buf(r"\RPC Control\schedule");
    let mut name = ustr_for(&mut buf);
    name.Length = 64;
    name.MaximumLength = 32;
    let mut oa = oa_with_name(&mut name);
    // SAFETY: Malformed decision also returns before call_original.
    let got = unsafe {
        hook_nt_alpc_connect_port_ex(
            std::ptr::null_mut(),
            &mut oa,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(got, STATUS_ACCESS_DENIED, "Ex hook must fail closed on malformed name");
}

#[test]
fn secure_connect_port_hook_denies_deny_port() {
    let mut buf = utf16_buf(r"\RPC Control\winreg");
    let mut port_name = ustr_for(&mut buf);
    // SAFETY: Deny-classified port returns before call_original.
    let got = unsafe {
        hook_nt_alpc_secure_connect_port(
            std::ptr::null_mut(), // PortHandle (out)
            &mut port_name,       // PortName
            std::ptr::null_mut(), // SecurityQos
            std::ptr::null_mut(), // ClientView
            std::ptr::null_mut(), // RequiredServerSid
            std::ptr::null_mut(), // ServerView
            std::ptr::null_mut(), // MaxMessageLength
            std::ptr::null_mut(), // ConnectionInformation
            std::ptr::null_mut(), // ConnectionInformationLength
        )
    };
    assert_eq!(got, STATUS_ACCESS_DENIED, "SecureConnectPort hook must deny winreg");
}

#[test]
fn decide_connect_ex_kill_classifies_escape_port() {
    // Pure decision: the Ex entry point classifies an escape-class port
    // as Kill (the hook body would report + terminate). Asserted here
    // WITHOUT invoking the kill path.
    let mut buf = utf16_buf(r"\RPC Control\schedule");
    let name = ustr_for(&mut buf);
    let oa = oa_with_name(&name as *const _ as *mut _);
    let got = decide_connect_ex(&oa);
    assert_eq!(
        got,
        ConnectDecision::Classified {
            name: r"\RPC Control\schedule".to_string(),
            action: PortAction::Kill,
        },
        "escape port via the Ex entry decision must classify as Kill"
    );
}

#[test]
fn decide_connect_ex_benign_port_allowed() {
    let mut buf = utf16_buf(r"\RPC Control\epmapper");
    let name = ustr_for(&mut buf);
    let oa = oa_with_name(&name as *const _ as *mut _);
    let got = decide_connect_ex(&oa);
    assert_eq!(
        got,
        ConnectDecision::Classified {
            name: r"\RPC Control\epmapper".to_string(),
            action: PortAction::Allow,
        },
        "benign ports must stay allowed through the Ex decision"
    );

    // Null ObjectAttributes (kernel would fail the call on its own):
    // decision must be Unnamed (passthrough), never a deny.
    assert_eq!(decide_connect_ex(std::ptr::null()), ConnectDecision::Unnamed);
}

#[test]
fn connect_refusal_malformed_and_deny_return_access_denied() {
    // The refusal handler the Ex/Secure hooks apply: Malformed and Deny
    // both refuse; Unnamed passes through. (Kill arm diverges — not
    // drivable here.)
    let malformed = ConnectDecision::Malformed(MalformedPortName {
        source: PortNameSource::PortName,
        reason: "oversized_port_name",
        length: 4096,
        maximum_length: 4096,
        buffer_is_null: false,
    });
    assert_eq!(connect_refusal(malformed), Some(STATUS_ACCESS_DENIED));
    assert_eq!(connect_refusal(ConnectDecision::Unnamed), None);
    assert_eq!(
        connect_refusal(ConnectDecision::Classified {
            name: r"\RPC Control\spoolss".to_string(),
            action: PortAction::Deny,
        }),
        Some(STATUS_ACCESS_DENIED)
    );
}

/// Export-name tripwire: if any of the three ALPC entries is renamed /
/// typo'd in install(), the detour silently never attaches (all installers
/// skip on a missing export). Pin resolution on a supported host.
#[test]
fn alpc_sibling_exports_resolve_in_ntdll() {
    // SAFETY: ntdll_export is a GetProcAddress wrapper safe to call
    // anywhere; ntdll is always loaded.
    unsafe {
        for name in [
            "NtAlpcConnectPort\0",
            "NtAlpcConnectPortEx\0",
            "NtSecureConnectPort\0",
        ] {
            let addr = crate::hooks::ntdll_export(name.as_bytes());
            assert!(addr.is_some(), "ntdll export must resolve: {name}");
        }
    }
}
