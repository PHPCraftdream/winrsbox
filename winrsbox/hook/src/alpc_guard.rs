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

const STATUS_ACCESS_DENIED: NTSTATUS = 0xC000_0022_u32 as NTSTATUS;

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

// Port name substrings that indicate dangerous RPC endpoints.
// These enable COM activation → WMI → process creation outside sandbox.
const DANGEROUS_PORT_SUBSTRINGS: &[&str] = &[
    // COM/OLE activation (existing)
    "ole",          // COM/OLE activation service
    "actkernel",    // COM activation kernel port
    "comlaunch",    // COM launch service
    // Security services (NEW)
    "lsarpc",       // \RPC Control\LSARPC — LSA policy queries
    "samr",         // \RPC Control\samr — SAM database (account enum)
    "winreg",       // \RPC Control\winreg — remote registry
    "seclogon",     // \RPC Control\seclogon — secondary logon / RunAs (priv escalation)
    "wmsgk",        // WMsgKMessagePort — window message dispatch
    // WMI direct ALPC bypass (sandbox uses direct LRPC to WMI service
    // instead of CoCreateInstance(WbemLocator) which com_guard catches)
    "wmi",          // \RPC Control\WMI* — WMI core service
    "wbem",         // \RPC Control\WBEM* — WMI scripting service
    "spool",        // \RPC Control\spoolss — Print Spooler RPC (PrintNightmare class)
    // NOTE: "epmapper" intentionally NOT blocked — COM activation needs it
    // for endpoint resolution; com_guard catches dangerous CLSIDs before
    // epmapper is contacted. Blocking epmapper breaks legit COM (verified
    // in earlier audit revert).
];

fn is_dangerous_port(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    // Get last path segment (after final \ or /) so that "ole" in
    // "Console" or "GoogleChrome..." does not false-positive.
    let segment = match lower.rfind(|c| c == '\\' || c == '/') {
        Some(idx) => &lower[idx + 1..],
        None => &lower,
    };
    DANGEROUS_PORT_SUBSTRINGS.iter().any(|&p| segment.starts_with(p))
}

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
        let ustr = &*port_name;
        let char_count = (ustr.Length / 2) as usize;
        if char_count > 0 && !ustr.Buffer.is_null() {
            let name_slice = std::slice::from_raw_parts(ustr.Buffer, char_count);
            let name = String::from_utf16_lossy(name_slice);
            if is_dangerous_port(&name) {
                if crate::hooks::is_trace() {
                    crate::hooks::ipc_log_violation(ipc::Req::Log {
                        pid: winapi::um::processthreadsapi::GetCurrentProcessId(),
                        level: ipc::LogLevel::Warn,
                        msg: format!("ALPC DENY: {name}"),
                    });
                }
                return STATUS_ACCESS_DENIED;
            }
        }
    }

    call_original()
}

pub unsafe fn install() -> Result<(), Box<dyn std::error::Error>> {
    let addr = crate::hooks::ntdll_export("NtAlpcConnectPort\0".as_bytes())
        .ok_or("NtAlpcConnectPort not found")?;
    let target: FnNtAlpcConnectPort = std::mem::transmute(addr as usize);
    let hook_ptr: FnNtAlpcConnectPort = hook_nt_alpc_connect_port;
    let detour = GenericDetour::<FnNtAlpcConnectPort>::new(target, hook_ptr)
        .map_err(|e| format!("detour init NtAlpcConnectPort: {e:?}"))?;
    let _ = HOOK_ALPC_CONNECT.set(detour);
    HOOK_ALPC_CONNECT.get().expect("set above").enable()
        .map_err(|e| format!("detour enable NtAlpcConnectPort: {e:?}"))?;
    Ok(())
}

pub unsafe fn uninstall() {
    if let Some(h) = HOOK_ALPC_CONNECT.get() { let _ = h.disable(); }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dangerous_port_detection() {
        // Existing — COM/OLE patterns
        assert!(is_dangerous_port(r"\RPC Control\OLE12345"));
        assert!(is_dangerous_port("actkernel_port"));
        assert!(is_dangerous_port("ComLaunch"));

        // NEW — security service patterns
        assert!(is_dangerous_port(r"\RPC Control\lsarpc"));
        assert!(is_dangerous_port(r"\RPC Control\samr"));
        assert!(is_dangerous_port(r"\RPC Control\winreg"));
        assert!(is_dangerous_port(r"\RPC Control\seclogon"));
        assert!(is_dangerous_port("WMsgKMessagePort"));

        // Print Spooler RPC (PrintNightmare class)
        assert!(is_dangerous_port(r"\RPC Control\spoolss"));

        // WMI direct ALPC bypass patterns
        assert!(is_dangerous_port(r"\RPC Control\WMI_RPC_12345"));
        assert!(is_dangerous_port(r"\RPC Control\WbemLevel1Login"));

        // Negative — must NOT be blocked
        assert!(!is_dangerous_port("lsass"));
        assert!(!is_dangerous_port("epmapper"));
        assert!(!is_dangerous_port("DnsResolver"));

        // False-positive regression: "ole" substring inside a segment
        // must NOT match when the segment does not start with "ole".
        assert!(!is_dangerous_port(r"\RPC Control\Console"));
        assert!(!is_dangerous_port(r"\RPC Control\ConsoleNotificationPort"));
        assert!(!is_dangerous_port(r"\BaseNamedObjects\GoogleChromeServiceSocket"));
    }
}
