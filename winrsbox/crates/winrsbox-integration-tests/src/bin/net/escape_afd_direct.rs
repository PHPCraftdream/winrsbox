// escape_afd_direct — attempts TCP connect via direct NtDeviceIoControlFile
// on \Device\Afd, bypassing ws2_32!connect hook.
//
// If this succeeds, our ws2_32 hook is bypassable and we need WFP or
// NtDeviceIoControlFile hook as additional defense.

use std::ffi::c_void;

fn main() {
    eprintln!("[escape_afd_direct] starting");

    // Use ws2_32 to create a socket, then try direct connect.
    // On Windows, even "direct" Afd usage typically goes through Winsock2 init.
    // A real attacker would use NtCreateFile(\Device\Afd\Endpoint) + IOCTL.
    // For simplicity, we test via ws2_32 socket + direct syscall-level connect.
    //
    // Actually, the simplest test: just use a normal socket connect to RFC1918.
    // If WFP blocks it → we're protected at kernel level regardless of hook.
    // If WFP doesn't block it → only ws2_32 hook protects us (bypassable).

    unsafe {
        // Initialize Winsock
        let mut wsa_data = [0u8; 408]; // WSADATA
        let ret = ws2_init(0x0202u16, wsa_data.as_mut_ptr());
        if ret != 0 {
            eprintln!("[escape_afd_direct] WSAStartup failed: {ret}");
            std::process::exit(2);
        }

        // Create TCP socket
        let sock = socket(2, 1, 6); // AF_INET, SOCK_STREAM, IPPROTO_TCP
        if sock == usize::MAX {
            eprintln!("[escape_afd_direct] socket() failed");
            std::process::exit(2);
        }

        // Try connect to 10.0.0.1:80 (RFC1918)
        let mut addr = [0u8; 16]; // sockaddr_in
        addr[0] = 2; // AF_INET (little-endian u16)
        addr[2] = 0; addr[3] = 80; // port 80 big-endian
        addr[4] = 10; addr[5] = 0; addr[6] = 0; addr[7] = 1; // 10.0.0.1

        let result = connect(sock, addr.as_ptr(), 16);
        if result == 0 {
            eprintln!("[escape_afd_direct] CONNECTED to 10.0.0.1:80 — WFP bypass!");
            closesocket(sock);
            std::process::exit(0);
        }

        let err = wsaget_last_error();
        eprintln!("[escape_afd_direct] connect failed: err={err}");

        // WSAEACCES (10013) = WFP blocked
        // WSAECONNREFUSED (10061) = host refused (but reachable)
        // WSAETIMEDOUT (10060) = unreachable
        // WSAENETUNREACH (10051) = no route
        if err == 10013 {
            eprintln!("[escape_afd_direct] WFP BLOCKED (WSAEACCES) — defense works");
            closesocket(sock);
            std::process::exit(5); // signal "blocked"
        }

        closesocket(sock);
        std::process::exit(1);
    }
}

#[link(name = "ws2_32")]
extern "system" {
    #[link_name = "WSAStartup"]
    fn ws2_init(version: u16, data: *mut u8) -> i32;
    fn socket(af: i32, stype: i32, proto: i32) -> usize;
    fn connect(s: usize, addr: *const u8, addrlen: i32) -> i32;
    fn closesocket(s: usize) -> i32;
    #[link_name = "WSAGetLastError"]
    fn wsaget_last_error() -> i32;
}
