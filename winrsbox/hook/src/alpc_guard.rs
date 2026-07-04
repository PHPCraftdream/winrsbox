// ALPC guard — blocks sandboxed processes from connecting to dangerous
// RPC/COM endpoints via ALPC (Advanced Local Procedure Call).
//
// COM, WMI, Service Control Manager, Task Scheduler — all communicate
// via ALPC. Without this guard, sandboxed processes can escape by
// calling CoCreateInstance → WMI → Win32_Process.Create.
//
// Strategy: hook NtAlpcConnectPort. Block connections to known-dangerous
// ALPC port names. Allow connections to safe system services (DNS, RPC
// endpoint mapper for non-dangerous calls).
//
// Known dangerous ports (substring match on port ObjectName):
//   - "epmapper" — RPC endpoint mapper (gateway to everything)
//   - "IUserProfile" — user profile service
//   - "OLE" — COM activation (OLE/COM runtime)
//   - "actkernel" — COM activation kernel
//   - "WMsgKMessagePort" — Window message dispatch
//
// In strict mode we block epmapper+OLE which prevents ALL COM/RPC activation.
// In scan mode we allow epmapper (needed for DNS, print, etc.) but block OLE.

use std::sync::OnceLock;

use detour2::GenericDetour;
use ntapi::winapi::shared::ntdef::{HANDLE, NTSTATUS, OBJECT_ATTRIBUTES, UNICODE_STRING};
use winapi::ctypes::c_void;

use crate::anti_rec;
use crate::hooks::STATUS_ACCESS_DENIED;

type FnNtAlpcConnectPort = unsafe extern "system" fn(
    *mut HANDLE,            // PortHandle (out)
    *mut UNICODE_STRING,    // PortName
    *mut OBJECT_ATTRIBUTES, // ObjectAttributes
    *mut c_void,            // PortAttributes (ALPC_PORT_ATTRIBUTES*)
    u32,                    // Flags
    *mut c_void,            // RequiredServerSid
    *mut c_void,            // ConnectionMessage (PORT_MESSAGE*)
    *mut u32,               // BufferLength
    *mut c_void,            // OutMessageAttributes
    *mut c_void,            // InMessageAttributes
    *mut i64,               // Timeout
) -> NTSTATUS;

static HOOK_ALPC_CONNECT: OnceLock<GenericDetour<FnNtAlpcConnectPort>> = OnceLock::new();

// Action to take on an ALPC connect to a matched endpoint.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) enum PortAction {
    /// Not a guarded endpoint — pass the connect through.
    Allow,
    /// Guarded, but legitimate software commonly probes it and handles the
    /// refusal gracefully. Return STATUS_ACCESS_DENIED and let the caller live.
    Deny,
    /// Escape-class endpoint (COM-activation / DCOM object-exporter / WMI /
    /// privilege-escalation / persistence broker). There is NO legitimate use
    /// for these from inside the sandbox, so a connect attempt is a deliberate
    /// containment-escape attempt. Fail-stop: report a violation and terminate
    /// the process rather than politely denying (a denied process just keeps
    /// probing other escape vectors).
    Kill,
}

// ESCAPE-CLASS endpoints → terminate the process on connect.
//
// These brokers spawn processes / activate out-of-proc COM as SYSTEM / enumerate
// the SAM / elevate — none of which a sandboxed process has any legitimate reason
// to reach. Empirically verified (trace runs) that normal workloads (PowerShell,
// in-proc COM, git, node/python toolchains) never connect to any of these; only
// deliberate escape/priv-esc/persistence attempts do.
const ESCAPE_CLASS_PORT_SUBSTRINGS: &[&str] = &[
    // COM/DCOM activation brokers (spawn out-of-proc / SYSTEM COM servers)
    "actkernel",    // COM activation kernel port
    "comlaunch",    // COM launch service
    "dcomlaunch",   // \RPC Control\dcomlaunch — DcomLaunch (spawns COM servers as SYSTEM)
    // Privilege-escalation / credential brokers
    "samr",         // \RPC Control\samr — SAM database (password hashes / account enum)
    "seclogon",     // \RPC Control\seclogon — secondary logon / RunAs (priv escalation)
    "appinfo",      // \RPC Control\appinfo — UAC elevation broker (AppInfo service)
    // Persistence
    "schedule",     // \RPC Control\schedule — Task Scheduler direct LRPC
                    // (bypass for Schedule.Service COM which com_guard blocks)
];

// DENY-ONLY endpoints → STATUS_ACCESS_DENIED, process keeps running.
//
// Defense-in-depth: these are dangerous enough to block, but legitimate software
// (printer enumeration, registry probes, AppX-aware installers, WMI reads like
// tasklist / Get-CimInstance) may touch them and is written to handle the refusal
// gracefully. Killing on these would break benign workloads, so we only deny.
//
// WMI (bug #88 re-audit): `\RPC Control\OLE<hex>` is the generic per-object DCOM
// data channel; `WMI*` / `WBEM*` are the WMI core/scripting LRPC. The
// Win32_Process.Create escape is already fully blocked upstream by com_guard's
// graceful CLSID deny (no proxy → no spawn method), so these ports need only be
// denied, not killed — killing them would take out benign WMI readers (tasklist,
// systeminfo, Get-CimInstance) as collateral for no added security. WMI-dependent
// tools use `--guard none`.
//
// `lsarpc` is intentionally NOT guarded at all. Cygwin/MSYS2 bash and most
// Windows runtimes call `LsaOpenPolicy(POLICY_LOOKUP_NAMES)` very early during
// init for SID↔name resolution; a block there doesn't stop them (they warn and
// fall through) but pollutes every shell session. The dangerous LSA operations
// (`LsaAddAccountRights`, etc.) require rights a medium-IL sandbox token cannot
// acquire from `LsaOpenPolicy` in the first place — Windows' own ACL is the gate.
const DENY_PORT_SUBSTRINGS: &[&str] = &[
    "ole",          // \RPC Control\OLE<hex> — generic DCOM object exporter (WMI reads)
    "wmi",          // \RPC Control\WMI* — WMI core service
    "wbem",         // \RPC Control\WBEM* — WMI scripting service
    "winreg",       // \RPC Control\winreg — remote registry
    "wmsgk",        // WMsgKMessagePort — window message dispatch
    "spool",        // \RPC Control\spoolss — Print Spooler RPC (PrintNightmare class)
    // Deployment / session / reporting brokers
    "appxsvc",      // \RPC Control\appxsvc — AppX deployment service
    "appx",         // \RPC Control\appx* — AppX activation (prefix also matches appxsvc)
    "pchsvc",       // \RPC Control\pchsvc — Problem Reports / PCH service (RPC named pipe)
    "terminalserver", // \RPC Control\terminalserver — Terminal Services RPC
    "iiscertobj",   // \RPC Control\iiscertobj — IIS Cert (rarely present, defense in depth)
    // NOTE: "epmapper" intentionally NOT blocked — COM activation needs it
    // for endpoint resolution; com_guard catches dangerous CLSIDs before
    // epmapper is contacted. Blocking epmapper breaks legit COM (verified
    // in earlier audit revert).
];

/// Domain cap for the attacker-controlled `UNICODE_STRING.Length` on the ALPC
/// port name. ALPC port names are short object-manager paths (e.g.
/// `\RPC Control\epmapper`), so 1024 WCHARs is well above any legitimate name.
/// `Length` is a u16 the *target process* (the adversary) fully controls — up
/// to 65534 bytes / 32767 chars. A large value combined with a small `Buffer`
/// allocation would make `from_raw_parts` read out of bounds. Above this cap we
/// treat the name as unresolvable and fall through to the original (we never
/// deny on it — that could break legit ALPC; we only refuse the oversized read).
const MAX_PORT_NAME_CHARS: usize = 1024;

/// Classify an ALPC port name into Allow / Deny / Kill.
///
/// Escape-class matches take precedence over deny-only. Matching is on the last
/// path segment (after the final `\` or `/`) with `starts_with`, so `"ole"` in
/// `Console` / `GoogleChrome...` does not false-positive.
fn classify_port(name: &str) -> PortAction {
    let lower = name.to_ascii_lowercase();
    let segment = match lower.rfind(|c| c == '\\' || c == '/') {
        Some(idx) => &lower[idx + 1..],
        None => &lower,
    };
    if ESCAPE_CLASS_PORT_SUBSTRINGS.iter().any(|&p| segment.starts_with(p)) {
        return PortAction::Kill;
    }
    if DENY_PORT_SUBSTRINGS.iter().any(|&p| segment.starts_with(p)) {
        return PortAction::Deny;
    }
    PortAction::Allow
}

/// True when the port is guarded at all (Deny OR Kill). Retained as a thin
/// wrapper so the broad denylist regression tests read naturally.
#[cfg(test)]
fn is_dangerous_port(name: &str) -> bool {
    classify_port(name) != PortAction::Allow
}


// SAFETY: Called by detour2 dispatcher with ntdll!NtAlpcConnectPort ABI.
unsafe extern "system" fn hook_nt_alpc_connect_port(
    port_handle: *mut HANDLE,
    port_name: *mut UNICODE_STRING,
    object_attributes: *mut OBJECT_ATTRIBUTES,
    port_attributes: *mut c_void,
    flags: u32,
    required_server_sid: *mut c_void,
    connection_message: *mut c_void,
    buffer_length: *mut u32,
    out_message_attributes: *mut c_void,
    in_message_attributes: *mut c_void,
    timeout: *mut i64,
) -> NTSTATUS {
    let call_original = || {
        // SAFETY: detour2 trampoline matches FnNtAlpcConnectPort ABI.
        HOOK_ALPC_CONNECT.get().unwrap().call(
            port_handle, port_name, object_attributes, port_attributes,
            flags, required_server_sid, connection_message, buffer_length,
            out_message_attributes, in_message_attributes, timeout,
        )
    };

    let Some(_guard) = anti_rec::enter() else {
        return call_original();
    };

    if !port_name.is_null() {
        // SAFETY: deref of the non-null UNICODE_STRING pointer the kernel ABI
        // hands us. The caller is the (possibly hostile) target process, so
        // every field below is treated as adversary-controlled and validated
        // before any read derived from it.
        let ustr = &*port_name;
        let char_count = (ustr.Length / 2) as usize;
        // Length must not exceed MaximumLength for a well-formed UNICODE_STRING.
        let max_chars = (ustr.MaximumLength / 2) as usize;
        match classify_port_name(char_count, max_chars, ustr.Buffer.is_null()) {
            PortNameStatus::Empty => {
                // Legitimate (caller is using ObjectAttributes instead).
                // Passthrough.
            }
            PortNameStatus::Valid => {
                // SAFETY: classifier verified char_count > 0,
                // <= MAX_PORT_NAME_CHARS, <= max_chars, and Buffer non-null.
                let name_slice = std::slice::from_raw_parts(ustr.Buffer, char_count);
                let name = String::from_utf16_lossy(name_slice);
                match classify_port(&name) {
                    PortAction::Kill => {
                        // Escape-class endpoint: fail-stop. Reports the violation
                        // over IPC and never returns (terminates the process).
                        crate::hooks::report_and_terminate_escape("alpc-port", &name);
                    }
                    PortAction::Deny => {
                        if crate::hooks::is_trace() {
                            crate::hooks::ipc_log_violation(ipc::Req::Log {
                                pid: winapi::um::processthreadsapi::GetCurrentProcessId(),
                                level: ipc::LogLevel::Warn,
                                msg: format!("ALPC DENY: {name}"),
                            });
                        }
                        return STATUS_ACCESS_DENIED;
                    }
                    PortAction::Allow => {
                        // Diagnostic: log every ALLOWED connect under trace. Pure
                        // visibility — needed to spot DNS / SChannel / proxy
                        // resolvers that travel through unfamiliar port names.
                        if crate::hooks::is_trace() {
                            crate::hooks::ipc_log(ipc::LogLevel::Trace,
                                format!("alpc_connect: {name}"));
                        }
                    }
                }
            }
            PortNameStatus::Malformed(reason) => {
                // Fail closed: an oversized / inconsistent / null-Buffer
                // UNICODE_STRING is either a hostile probe trying to slip
                // past our denylist by tripping the classifier, or genuinely
                // broken caller code. Either way, refusing the connect is
                // the safe posture (mirrors fs_metadata_guard's
                // unresolvable-rename-dest -> ACCESS_DENIED).
                crate::hooks::ipc_log_violation(ipc::Req::Log {
                    pid: winapi::um::processthreadsapi::GetCurrentProcessId(),
                    level: ipc::LogLevel::Warn,
                    msg: format!(
                        "ALPC DENY (malformed port_name): {reason} len={} max={} buf_null={}",
                        ustr.Length, ustr.MaximumLength, ustr.Buffer.is_null()
                    ),
                });
                return STATUS_ACCESS_DENIED;
            }
        }
    }

    call_original()
}

/// Outcome of classifying a port-name `UNICODE_STRING` against ALPC's
/// real-world domain. Pure over its inputs so the malformed-detection logic
/// can be unit-tested without fabricating a `UNICODE_STRING` + a hostile
/// kernel ABI surface.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PortNameStatus {
    /// Length == 0 — caller is using ObjectAttributes for the name. Let it
    /// pass through; this is the legitimate `NtAlpcConnectPort(...)` shape
    /// when the name lives in `ObjectAttributes->ObjectName`.
    Empty,
    /// Well-formed and within the domain cap; safe to read `char_count`
    /// WCHARs from `Buffer`.
    Valid,
    /// Hostile or buggy struct. Caller must fail closed (ACCESS_DENIED) so
    /// the unparseable name cannot bypass `is_dangerous_port`.
    Malformed(&'static str),
}

pub(crate) fn classify_port_name(
    char_count: usize,
    max_chars: usize,
    buffer_is_null: bool,
) -> PortNameStatus {
    if char_count == 0 {
        return PortNameStatus::Empty;
    }
    if char_count > max_chars {
        return PortNameStatus::Malformed("length>maximum_length");
    }
    if char_count > MAX_PORT_NAME_CHARS {
        return PortNameStatus::Malformed("oversized_port_name");
    }
    if buffer_is_null {
        return PortNameStatus::Malformed("null_buffer_nonzero_length");
    }
    PortNameStatus::Valid
}

/// # SAFETY
/// Must be called from install_hooks() in DllMain context with anti_rec entered.
pub unsafe fn install() -> Result<(), Box<dyn std::error::Error>> {
    let addr = crate::hooks::ntdll_export("NtAlpcConnectPort\0".as_bytes())
        .ok_or("NtAlpcConnectPort not found")?;
    // SAFETY: transmute of ntdll export address; ABI matches FnNtAlpcConnectPort signature.
    let target: FnNtAlpcConnectPort = std::mem::transmute(addr as usize);
    let hook_ptr: FnNtAlpcConnectPort = hook_nt_alpc_connect_port;
    let detour = GenericDetour::<FnNtAlpcConnectPort>::new(target, hook_ptr)
        .map_err(|e| format!("detour init NtAlpcConnectPort: {e:?}"))?;
    let _ = HOOK_ALPC_CONNECT.set(detour);
    HOOK_ALPC_CONNECT.get().expect("set above").enable()
        .map_err(|e| format!("detour enable NtAlpcConnectPort: {e:?}"))?;
    Ok(())
}

/// # SAFETY
/// Must be called from DLL_PROCESS_DETACH only.
pub unsafe fn uninstall() {
    if let Some(h) = HOOK_ALPC_CONNECT.get() { let _ = h.disable(); }
}

#[cfg(test)]
mod tests {
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
}
