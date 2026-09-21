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
use crate::hooks::{nt_call_original, STATUS_ACCESS_DENIED};

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

// -- Sibling entry points (audit 2026-09-19 High: "guarded API, unguarded
// sibling"). Both are detoured with the SAME denylist/kill policy as the
// classic hook by calling the same decide_connect / classify_port machinery
// — only the ABI differs.
//
// NtAlpcConnectPortEx (Win8+): the connection port is addressed THROUGH
// ObjectAttributes->ObjectName (param 2) and there is no PortName parameter.
// Empirically confirmed on Win10 19045: the classic NtAlpcConnectPort does
// NOT resolve a port name from ObjectAttributes (STATUS_OBJECT_NAME_INVALID
// even for a live port), so every hardened check above was bypassable by
// calling the Ex variant with the port name in ObjectAttributes. Parameter
// layout mirrors ntapi 0.4's EXTERN! block (11 params); declaring the full
// arity keeps the stack passthrough exact — only param 2 is inspected.
type FnNtAlpcConnectPortEx = unsafe extern "system" fn(
    *mut HANDLE,            // PortHandle (out)
    *mut OBJECT_ATTRIBUTES, // ConnectionPortObjectAttributes — port name lives here
    *mut OBJECT_ATTRIBUTES, // ClientPortObjectAttributes
    *mut c_void,            // PortAttributes (ALPC_PORT_ATTRIBUTES*)
    u32,                    // Flags
    *mut c_void,            // ServerSecurityRequirements (PSECURITY_DESCRIPTOR)
    *mut c_void,            // ConnectionMessage (PORT_MESSAGE*)
    *mut usize,             // BufferLength (PSIZE_T)
    *mut c_void,            // OutMessageAttributes
    *mut c_void,            // InMessageAttributes
    *mut i64,               // Timeout (PLARGE_INTEGER)
) -> NTSTATUS;

// NtSecureConnectPort (LPC-era): resolves the port by name like the classic
// hook, with a SecurityQos / view-parameters ABI instead of ObjectAttributes.
type FnNtSecureConnectPort = unsafe extern "system" fn(
    *mut HANDLE,            // PortHandle (out)
    *mut UNICODE_STRING,    // PortName
    *mut c_void,            // SecurityQos (PSECURITY_QUALITY_OF_SERVICE)
    *mut c_void,            // ClientView (PPORT_VIEW)
    *mut c_void,            // RequiredServerSid (PSID)
    *mut c_void,            // ServerView (PREMOTE_PORT_VIEW)
    *mut u32,               // MaxMessageLength (PULONG)
    *mut c_void,            // ConnectionInformation
    *mut u32,               // ConnectionInformationLength (PULONG)
) -> NTSTATUS;

static HOOK_ALPC_CONNECT_EX: OnceLock<GenericDetour<FnNtAlpcConnectPortEx>> = OnceLock::new();
static HOOK_ALPC_SECURE_CONNECT: OnceLock<GenericDetour<FnNtSecureConnectPort>> = OnceLock::new();

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
        nt_call_original!(
            &HOOK_ALPC_CONNECT,
            "NtAlpcConnectPort",
            (port_handle, port_name, object_attributes, port_attributes,
             flags, required_server_sid, connection_message, buffer_length,
             out_message_attributes, in_message_attributes, timeout)
        )
    };

    let Some(_guard) = anti_rec::enter() else {
        return call_original();
    };

    match decide_connect(port_name, object_attributes) {
        ConnectDecision::Unnamed => {}
        ConnectDecision::Classified { name, action } => match action {
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
        },
        ConnectDecision::Malformed(m) => {
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
                    "ALPC DENY (malformed {}): {} len={} max={} buf_null={}",
                    m.source.label(), m.reason, m.length, m.maximum_length, m.buffer_is_null
                ),
            });
            return STATUS_ACCESS_DENIED;
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
    /// Length == 0 — no name in this `UNICODE_STRING`. The caller may be
    /// addressing the port through `ObjectAttributes->ObjectName`, which
    /// `decide_connect` classifies separately (P1-02).
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

/// Where a connect's port name came from. `NtAlpcConnectPort` accepts the
/// port name through the `PortName` parameter; `ObjectAttributes` carries
/// the client-port attributes, whose `ObjectName` field can name the port
/// instead (P1-02). The guard classifies whichever name is present.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PortNameSource {
    PortName,
    ObjectAttributes,
}

impl PortNameSource {
    fn label(self) -> &'static str {
        match self {
            PortNameSource::PortName => "port_name",
            PortNameSource::ObjectAttributes => "object_attributes.object_name",
        }
    }
}

/// A non-empty but malformed port-name `UNICODE_STRING` (Length >
/// MaximumLength, oversized, or null Buffer). Fail closed (ACCESS_DENIED)
/// so an unparseable name cannot slip past the denylist.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct MalformedPortName {
    pub(crate) source: PortNameSource,
    pub(crate) reason: &'static str,
    pub(crate) length: u16,
    pub(crate) maximum_length: u16,
    pub(crate) buffer_is_null: bool,
}

/// Hook-level outcome for one connect attempt, resolved by `decide_connect`.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ConnectDecision {
    /// Neither source carries a usable name — passthrough.
    Unnamed,
    /// A port name was resolved and classified.
    Classified { name: String, action: PortAction },
    /// Malformed name struct — fail closed.
    Malformed(MalformedPortName),
}

/// Resolve + validate one candidate port-name `UNICODE_STRING`.
///
/// # SAFETY
/// `ustr` must point to a readable `UNICODE_STRING` (or be null) and, when
/// `Length > 0`, `Buffer` must be readable for `Length` bytes for the
/// duration of the call. Read-only: nothing derived outlives the call.
unsafe fn try_resolve_ustr(
    source: PortNameSource,
    ustr: *const UNICODE_STRING,
) -> Result<Option<String>, MalformedPortName> {
    if ustr.is_null() {
        return Ok(None);
    }
    // SAFETY: non-null, readable UNICODE_STRING per the contract above. The
    // caller (the target process) controls every field, so each one is
    // validated through classify_port_name before any read derived from it.
    let ustr = &*ustr;
    let char_count = (ustr.Length / 2) as usize;
    let max_chars = (ustr.MaximumLength / 2) as usize;
    match classify_port_name(char_count, max_chars, ustr.Buffer.is_null()) {
        PortNameStatus::Empty => Ok(None),
        PortNameStatus::Valid => {
            // SAFETY: classifier verified char_count > 0,
            // <= MAX_PORT_NAME_CHARS, <= max_chars, and Buffer non-null.
            let name_slice = std::slice::from_raw_parts(ustr.Buffer, char_count);
            Ok(Some(String::from_utf16_lossy(name_slice)))
        }
        PortNameStatus::Malformed(reason) => Err(MalformedPortName {
            source,
            reason,
            length: ustr.Length,
            maximum_length: ustr.MaximumLength,
            buffer_is_null: ustr.Buffer.is_null(),
        }),
    }
}

/// Resolve the effective port name of one `NtAlpcConnectPort` call and
/// classify it (P1-02). `PortName` wins when it carries a name; when it is
/// null or empty, `ObjectAttributes->ObjectName` is classified instead —
/// classifying a name the kernel would ignore is harmless, while skipping
/// one it honours is a bypass. A malformed name from either source fails
/// closed immediately.
///
/// Pure over its inputs (no IPC, no termination), so the decision can be
/// unit-tested without fabricating the kernel ABI surface.
///
/// # SAFETY
/// Both pointers must be null or satisfy [`try_resolve_ustr`]'s contract;
/// when `object_attributes` is non-null it must additionally be a readable
/// `OBJECT_ATTRIBUTES`.
unsafe fn decide_connect(
    port_name: *const UNICODE_STRING,
    object_attributes: *const OBJECT_ATTRIBUTES,
) -> ConnectDecision {
    match try_resolve_ustr(PortNameSource::PortName, port_name) {
        Err(malformed) => ConnectDecision::Malformed(malformed),
        Ok(Some(name)) => ConnectDecision::Classified {
            action: classify_port(&name),
            name,
        },
        Ok(None) => {
            // PortName absent or empty: the caller is addressing the port
            // through ObjectAttributes (P1-02). Classify that name too —
            // classifying a name the kernel would ignore is harmless, while
            // skipping one it honours is a bypass. PortName wins when it
            // carries a name (phnt: ObjectAttributes are the client-port
            // attributes; the Win8+ Ex variant is the one that takes the
            // connection port via ObjectAttributes).
            let object_name = if object_attributes.is_null() {
                std::ptr::null_mut()
            } else {
                // SAFETY: non-null, readable OBJECT_ATTRIBUTES per the
                // contract above; only the ObjectName field is read.
                let oa = &*object_attributes;
                oa.ObjectName
            };
            match try_resolve_ustr(PortNameSource::ObjectAttributes, object_name) {
                Err(malformed) => ConnectDecision::Malformed(malformed),
                Ok(Some(name)) => ConnectDecision::Classified {
                    action: classify_port(&name),
                    name,
                },
                Ok(None) => ConnectDecision::Unnamed,
            }
        }
    }
}

/// Hook-level decision for `NtAlpcConnectPortEx`: the connection port is
/// addressed through `ObjectAttributes->ObjectName` ONLY (there is no
/// PortName parameter), so the decision is exactly `decide_connect` with a
/// null PortName. Shares try_resolve_ustr / classify_port with the classic
/// hook — the denylist, the escape-class kill and the fail-closed malformed
/// handling are identical by construction.
///
/// The CLIENT-port OBJECT_ATTRIBUTES (param 3) name the client port the
/// kernel creates, not the endpoint being reached — classifying it would
/// only produce false denies on legitimately-named client ports, so it is
/// not consulted (same precedence the classic hook applies: PortName /
/// connection-port name wins).
///
/// Pure over its inputs (no IPC, no termination); tests fabricate the
/// OBJECT_ATTRIBUTES and drive the full decision the Ex hook applies.
pub(crate) fn decide_connect_ex(
    object_attributes: *const OBJECT_ATTRIBUTES,
) -> ConnectDecision {
    unsafe { decide_connect(std::ptr::null(), object_attributes) }
}

/// Apply a resolved connect decision for the Ex / Secure hooks. Returns
/// `Some(STATUS_ACCESS_DENIED)` when the connect must be refused, `None`
/// when it may proceed to the original. Kill diverges via
/// report_and_terminate_escape and never returns. Decision handling mirrors
/// hook_nt_alpc_connect_port one-for-one (same trace logs, same fail-closed
/// malformed policy).
fn connect_refusal(decision: ConnectDecision) -> Option<NTSTATUS> {
    match decision {
        ConnectDecision::Unnamed => None,
        ConnectDecision::Classified { name, action } => match action {
            PortAction::Kill => {
                // Escape-class endpoint: fail-stop. Reports the violation
                // over IPC and never returns (terminates the process).
                crate::hooks::report_and_terminate_escape("alpc-port", &name)
            }
            PortAction::Deny => {
                if crate::hooks::is_trace() {
                    // SAFETY: GetCurrentProcessId is always safe to call.
                    let pid = unsafe {
                        winapi::um::processthreadsapi::GetCurrentProcessId()
                    };
                    crate::hooks::ipc_log_violation(ipc::Req::Log {
                        pid,
                        level: ipc::LogLevel::Warn,
                        msg: format!("ALPC DENY: {name}"),
                    });
                }
                Some(STATUS_ACCESS_DENIED)
            }
            PortAction::Allow => {
                if crate::hooks::is_trace() {
                    crate::hooks::ipc_log(ipc::LogLevel::Trace,
                        format!("alpc_connect: {name}"));
                }
                None
            }
        },
        ConnectDecision::Malformed(m) => {
            // Fail closed on a hostile / inconsistent UNICODE_STRING — same
            // posture as the classic hook (see its Malformed arm).
            // SAFETY: GetCurrentProcessId is always safe to call.
            let pid = unsafe {
                winapi::um::processthreadsapi::GetCurrentProcessId()
            };
            crate::hooks::ipc_log_violation(ipc::Req::Log {
                pid,
                level: ipc::LogLevel::Warn,
                msg: format!(
                    "ALPC DENY (malformed {}): {} len={} max={} buf_null={}",
                    m.source.label(), m.reason, m.length, m.maximum_length, m.buffer_is_null
                ),
            });
            Some(STATUS_ACCESS_DENIED)
        }
    }
}

// SAFETY: Called by detour2 dispatcher with ntdll!NtAlpcConnectPortEx ABI.
unsafe extern "system" fn hook_nt_alpc_connect_port_ex(
    port_handle: *mut HANDLE,
    connection_port_object_attributes: *mut OBJECT_ATTRIBUTES,
    client_port_object_attributes: *mut OBJECT_ATTRIBUTES,
    port_attributes: *mut c_void,
    flags: u32,
    server_security_requirements: *mut c_void,
    connection_message: *mut c_void,
    buffer_length: *mut usize,
    out_message_attributes: *mut c_void,
    in_message_attributes: *mut c_void,
    timeout: *mut i64,
) -> NTSTATUS {
    let call_original = || {
        nt_call_original!(
            &HOOK_ALPC_CONNECT_EX,
            "NtAlpcConnectPortEx",
            (port_handle, connection_port_object_attributes,
             client_port_object_attributes, port_attributes, flags,
             server_security_requirements, connection_message, buffer_length,
             out_message_attributes, in_message_attributes, timeout)
        )
    };

    let Some(_guard) = anti_rec::enter() else {
        return call_original();
    };

    // The connection port arrives ONLY through ObjectAttributes (param 2).
    if let Some(status) =
        connect_refusal(decide_connect_ex(connection_port_object_attributes))
    {
        return status;
    }

    call_original()
}

// SAFETY: Called by detour2 dispatcher with ntdll!NtSecureConnectPort ABI.
unsafe extern "system" fn hook_nt_alpc_secure_connect_port(
    port_handle: *mut HANDLE,
    port_name: *mut UNICODE_STRING,
    security_qos: *mut c_void,
    client_view: *mut c_void,
    required_server_sid: *mut c_void,
    server_view: *mut c_void,
    max_message_length: *mut u32,
    connection_information: *mut c_void,
    connection_information_length: *mut u32,
) -> NTSTATUS {
    let call_original = || {
        nt_call_original!(
            &HOOK_ALPC_SECURE_CONNECT,
            "NtSecureConnectPort",
            (port_handle, port_name, security_qos, client_view,
             required_server_sid, server_view, max_message_length,
             connection_information, connection_information_length)
        )
    };

    let Some(_guard) = anti_rec::enter() else {
        return call_original();
    };

    // Same shape as the classic hook: the port is named by the PortName
    // parameter. This ABI carries SecurityQos instead of ObjectAttributes,
    // so there is no fallback name source to consult.
    if let Some(status) =
        connect_refusal(decide_connect(port_name, std::ptr::null()))
    {
        return status;
    }

    call_original()
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

    // NtAlpcConnectPortEx (Win8+) — audit High sibling closure. Present on
    // every supported build (Win10 1709+); a missing export here is treated
    // as fatal like the classic hook, same fail-closed posture.
    let addr = crate::hooks::ntdll_export("NtAlpcConnectPortEx\0".as_bytes())
        .ok_or("NtAlpcConnectPortEx not found")?;
    // SAFETY: transmute of ntdll export address; ABI matches FnNtAlpcConnectPortEx.
    let target: FnNtAlpcConnectPortEx = std::mem::transmute(addr as usize);
    let hook_ptr: FnNtAlpcConnectPortEx = hook_nt_alpc_connect_port_ex;
    let detour = GenericDetour::<FnNtAlpcConnectPortEx>::new(target, hook_ptr)
        .map_err(|e| format!("detour init NtAlpcConnectPortEx: {e:?}"))?;
    let _ = HOOK_ALPC_CONNECT_EX.set(detour);
    HOOK_ALPC_CONNECT_EX.get().expect("set above").enable()
        .map_err(|e| format!("detour enable NtAlpcConnectPortEx: {e:?}"))?;

    // NtSecureConnectPort — LPC-era sibling, same denylist.
    let addr = crate::hooks::ntdll_export("NtSecureConnectPort\0".as_bytes())
        .ok_or("NtSecureConnectPort not found")?;
    // SAFETY: transmute of ntdll export address; ABI matches FnNtSecureConnectPort.
    let target: FnNtSecureConnectPort = std::mem::transmute(addr as usize);
    let hook_ptr: FnNtSecureConnectPort = hook_nt_alpc_secure_connect_port;
    let detour = GenericDetour::<FnNtSecureConnectPort>::new(target, hook_ptr)
        .map_err(|e| format!("detour init NtSecureConnectPort: {e:?}"))?;
    let _ = HOOK_ALPC_SECURE_CONNECT.set(detour);
    HOOK_ALPC_SECURE_CONNECT.get().expect("set above").enable()
        .map_err(|e| format!("detour enable NtSecureConnectPort: {e:?}"))?;
    Ok(())
}

/// # SAFETY
/// Must be called from DLL_PROCESS_DETACH only.
pub unsafe fn uninstall() {
    if let Some(h) = HOOK_ALPC_CONNECT.get() { let _ = h.disable(); }
    if let Some(h) = HOOK_ALPC_CONNECT_EX.get() { let _ = h.disable(); }
    if let Some(h) = HOOK_ALPC_SECURE_CONNECT.get() { let _ = h.disable(); }
}

/// Exports this module installs detours on. Kept in lockstep with install()
/// — the sibling-drift check in hooks.rs verifies every name here still
/// appears as an install literal in this file, and that guarded families
/// have no unhooked siblings.
pub(crate) const HOOKED_EXPORTS: &[&str] = &[
    "NtAlpcConnectPort",
    "NtAlpcConnectPortEx",
    "NtSecureConnectPort",
];
#[cfg(test)]
mod tests;
