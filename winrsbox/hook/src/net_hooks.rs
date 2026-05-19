// Network runtime hooks — enforce netrule deny policy via IPC.
//
// Minimal first iteration: hook ws2_32!connect (TCP/UDP connection initiator).
// IPv4 only — IPv6 + WSAConnect + ConnectEx + sendto + DNS in next iteration.
//
// Localhost (127.0.0.0/8) is always allowed (no policy check).

use std::sync::OnceLock;

use detour2::GenericDetour;
use winapi::ctypes::c_void;

use crate::anti_rec;

const AF_INET: u16 = 2;
const AF_INET6: u16 = 23;
const SOCKET_ERROR: i32 = -1;
const WSAEACCES: i32 = 10013;

// ws2_32!connect signature:
//   int connect(SOCKET s, const sockaddr* name, int namelen);
type FnConnect = unsafe extern "system" fn(
    usize,          // SOCKET (UINT_PTR)
    *const c_void,  // sockaddr*
    i32,            // namelen
) -> i32;

// ws2_32!WSASetLastError(int error)
type FnWsaSetLastError = unsafe extern "system" fn(i32);

static HOOK_CONNECT: OnceLock<GenericDetour<FnConnect>> = OnceLock::new();
static WSA_SET_LAST_ERROR: OnceLock<FnWsaSetLastError> = OnceLock::new();

// ---------------------------------------------------------------------------
// sockaddr parsing
// ---------------------------------------------------------------------------

/// Parse a sockaddr buffer into (host_string, port). Returns None on
/// unsupported family or short buffer.
pub unsafe fn parse_sockaddr(addr: *const c_void, len: i32) -> Option<(String, u16)> {
    if addr.is_null() || len < 16 {
        return None;
    }
    let family = *(addr as *const u16);
    match family {
        AF_INET => {
            // sockaddr_in: { u16 family; u16 port (BE); u8 addr[4]; ... }
            let port_be = *((addr as *const u8).add(2) as *const u16);
            let port = u16::from_be(port_be);
            let ip = std::slice::from_raw_parts((addr as *const u8).add(4), 4);
            Some((format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]), port))
        }
        AF_INET6 if len >= 28 => {
            // sockaddr_in6: { u16 family; u16 port (BE); u32 flowinfo; u8 addr[16]; u32 scope }
            let port_be = *((addr as *const u8).add(2) as *const u16);
            let port = u16::from_be(port_be);
            let ip = std::slice::from_raw_parts((addr as *const u8).add(8), 16);
            let s = format!(
                "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
                u16::from_be_bytes([ip[0], ip[1]]),
                u16::from_be_bytes([ip[2], ip[3]]),
                u16::from_be_bytes([ip[4], ip[5]]),
                u16::from_be_bytes([ip[6], ip[7]]),
                u16::from_be_bytes([ip[8], ip[9]]),
                u16::from_be_bytes([ip[10], ip[11]]),
                u16::from_be_bytes([ip[12], ip[13]]),
                u16::from_be_bytes([ip[14], ip[15]]),
            );
            Some((s, port))
        }
        _ => None,
    }
}

pub fn is_localhost(host: &str) -> bool {
    host.starts_with("127.") || host == "::1" || host == "0:0:0:0:0:0:0:1"
}

fn is_connection_denied(host: &str, port: u16) -> bool {
    let req = ipc::Req::NetDecide { host: host.to_owned(), port };
    if let Some(resp) = crate::hooks::ipc_send_and_recv(req) {
        if let ipc::Resp::NetDecision { allow } = resp {
            return !allow;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------

unsafe extern "system" fn hook_connect(
    s: usize,
    name: *const c_void,
    namelen: i32,
) -> i32 {
    let call_original = || {
        HOOK_CONNECT.get().unwrap().call(s, name, namelen)
    };

    let Some(_guard) = anti_rec::enter() else {
        return call_original();
    };

    if let Some((host, port)) = parse_sockaddr(name, namelen) {
        if is_localhost(&host) {
            return call_original();
        }
        if is_connection_denied(&host, port) {
            // Set WSAEACCES and return SOCKET_ERROR
            if let Some(set_err) = WSA_SET_LAST_ERROR.get() {
                set_err(WSAEACCES);
            }
            return SOCKET_ERROR;
        }
    }
    call_original()
}

// ---------------------------------------------------------------------------
// Install / Uninstall
// ---------------------------------------------------------------------------

/// # SAFETY
/// Must be called from install_hooks() in DllMain context with anti_rec entered.
pub unsafe fn install() -> Result<(), Box<dyn std::error::Error>> {
    use winapi::um::libloaderapi::{LoadLibraryW, GetProcAddress};
    // Ensure ws2_32 is loaded
    let ws2_w: Vec<u16> = "ws2_32.dll\0".encode_utf16().collect();
    let hmod = LoadLibraryW(ws2_w.as_ptr());
    if hmod.is_null() {
        return Err("ws2_32.dll not available".into());
    }

    // Resolve WSASetLastError for setting error code on deny
    let set_err_addr = GetProcAddress(hmod, b"WSASetLastError\0".as_ptr() as *const i8);
    if !set_err_addr.is_null() {
        let f: FnWsaSetLastError = std::mem::transmute(set_err_addr as usize);
        let _ = WSA_SET_LAST_ERROR.set(f);
    }

    // Hook connect
    let connect_addr = GetProcAddress(hmod, b"connect\0".as_ptr() as *const i8);
    if connect_addr.is_null() {
        return Err("ws2_32!connect not found".into());
    }
    let target: FnConnect = std::mem::transmute(connect_addr as usize);
    let hook_ptr: FnConnect = hook_connect;
    let detour = GenericDetour::<FnConnect>::new(target, hook_ptr)
        .map_err(|e| format!("detour init connect: {:?}", e))?;
    HOOK_CONNECT.set(detour).ok();
    HOOK_CONNECT.get().expect("set above").enable()
        .map_err(|e| format!("detour enable connect: {:?}", e))?;

    Ok(())
}

/// # SAFETY
/// Must be called from DLL_PROCESS_DETACH only.
pub unsafe fn uninstall() {
    if let Some(h) = HOOK_CONNECT.get() { let _ = h.disable(); }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_sockaddr_in(ip: [u8; 4], port: u16) -> Vec<u8> {
        let mut buf = vec![0u8; 16];
        buf[0..2].copy_from_slice(&AF_INET.to_le_bytes());
        buf[2..4].copy_from_slice(&port.to_be_bytes());
        buf[4..8].copy_from_slice(&ip);
        buf
    }

    fn make_sockaddr_in6(ip: [u8; 16], port: u16) -> Vec<u8> {
        let mut buf = vec![0u8; 28];
        buf[0..2].copy_from_slice(&AF_INET6.to_le_bytes());
        buf[2..4].copy_from_slice(&port.to_be_bytes());
        buf[8..24].copy_from_slice(&ip);
        buf
    }

    #[test]
    fn parse_ipv4_basic() {
        let buf = make_sockaddr_in([1, 2, 3, 4], 443);
        let parsed = unsafe { parse_sockaddr(buf.as_ptr() as *const _, 16) };
        assert_eq!(parsed, Some(("1.2.3.4".into(), 443)));
    }

    #[test]
    fn parse_ipv4_high_port() {
        let buf = make_sockaddr_in([192, 168, 1, 1], 65535);
        let parsed = unsafe { parse_sockaddr(buf.as_ptr() as *const _, 16) };
        assert_eq!(parsed, Some(("192.168.1.1".into(), 65535)));
    }

    #[test]
    fn parse_ipv6_loopback() {
        let mut ip = [0u8; 16];
        ip[15] = 1; // ::1
        let buf = make_sockaddr_in6(ip, 80);
        let parsed = unsafe { parse_sockaddr(buf.as_ptr() as *const _, 28) };
        let (host, port) = parsed.unwrap();
        assert_eq!(port, 80);
        assert!(host.ends_with(":1"));
    }

    #[test]
    fn parse_null_returns_none() {
        let parsed = unsafe { parse_sockaddr(std::ptr::null(), 16) };
        assert_eq!(parsed, None);
    }

    #[test]
    fn parse_short_buffer_returns_none() {
        let buf = vec![0u8; 8];
        let parsed = unsafe { parse_sockaddr(buf.as_ptr() as *const _, 8) };
        assert_eq!(parsed, None);
    }

    #[test]
    fn parse_unknown_family() {
        let mut buf = vec![0u8; 16];
        buf[0..2].copy_from_slice(&99u16.to_le_bytes()); // bogus family
        let parsed = unsafe { parse_sockaddr(buf.as_ptr() as *const _, 16) };
        assert_eq!(parsed, None);
    }

    #[test]
    fn is_localhost_ipv4() {
        assert!(is_localhost("127.0.0.1"));
        assert!(is_localhost("127.255.255.255"));
        assert!(!is_localhost("128.0.0.1"));
        assert!(!is_localhost("8.8.8.8"));
    }

    #[test]
    fn is_localhost_ipv6() {
        assert!(is_localhost("::1"));
        assert!(is_localhost("0:0:0:0:0:0:0:1"));
        assert!(!is_localhost("2001:db8::1"));
    }
}
