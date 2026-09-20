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
}
