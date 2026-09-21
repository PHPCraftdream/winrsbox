// escape_smb_egress — tries TCP connect to port 445 (SMB) on a public IP.
// WFP filter should block (no SMB egress allowed).

fn main() {
    eprintln!("[escape_smb_egress] starting");

    unsafe {
        let mut wsa_data = [0u8; 408];
        if ws2_init(0x0202u16, wsa_data.as_mut_ptr()) != 0 {
            eprintln!("[escape_smb_egress] WSAStartup failed");
            std::process::exit(2);
        }

        let sock = socket(2, 1, 6);
        if sock == usize::MAX {
            eprintln!("[escape_smb_egress] socket failed");
            std::process::exit(2);
        }

        // Set short timeout so test doesn't hang
        let timeout: u32 = 3000;
        let _ = setsockopt(sock, 0xFFFF, 0x1005, &timeout as *const _ as *const _, 4);

        // 1.1.1.1:445 — Cloudflare DNS, public, doesn't actually accept SMB
        // (host:port chosen because public IP needed; WFP blocks port 445)
        let mut addr = [0u8; 16];
        addr[0] = 2;
        addr[2] = 0x01; addr[3] = 0xBD; // port 445 big-endian
        addr[4] = 1; addr[5] = 1; addr[6] = 1; addr[7] = 1;

        let result = connect(sock, addr.as_ptr(), 16);
        let err = wsa_get_last_error();
        closesocket(sock);

        if result == 0 {
            eprintln!("[escape_smb_egress] CONNECTED to 1.1.1.1:445 — WFP SMB block failed!");
            std::process::exit(0);
        }
        // 10013 (WSAEACCES) — blocked by WFP
        // 10060 (WSAETIMEDOUT) — also fine (no route or dropped)
        // 10049 (WSAEADDRNOTAVAIL) — also blocked
        eprintln!("[escape_smb_egress] blocked: err={err}");
        std::process::exit(5);
    }
}

#[link(name = "ws2_32")]
extern "system" {
    #[link_name = "WSAStartup"] fn ws2_init(v: u16, d: *mut u8) -> i32;
    fn socket(af: i32, st: i32, p: i32) -> usize;
    fn connect(s: usize, a: *const u8, l: i32) -> i32;
    fn closesocket(s: usize) -> i32;
    fn setsockopt(s: usize, level: i32, opt: i32, val: *const u8, len: i32) -> i32;
    #[link_name = "WSAGetLastError"] fn wsa_get_last_error() -> i32;
}
