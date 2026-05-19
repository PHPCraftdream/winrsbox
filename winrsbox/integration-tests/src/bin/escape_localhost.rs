// escape_localhost — tries TCP connect to 127.0.0.1.
// With --block-localhost: should be blocked by WFP.
// Without: should succeed (loopback allowed by default).

fn main() {
    eprintln!("[escape_localhost] starting");
    unsafe {
        let mut wsa = [0u8; 408];
        if ws2_init(0x0202, wsa.as_mut_ptr()) != 0 {
            eprintln!("[escape_localhost] WSAStartup failed");
            std::process::exit(2);
        }

        // Start a tiny TCP server on loopback
        let srv = socket(2, 1, 6); // AF_INET, SOCK_STREAM, TCP
        if srv == usize::MAX { std::process::exit(2); }

        let mut srv_addr = [0u8; 16];
        srv_addr[0] = 2; // AF_INET
        srv_addr[2] = 0x4D; srv_addr[3] = 0x43; // port 19779
        srv_addr[4] = 127; srv_addr[5] = 0; srv_addr[6] = 0; srv_addr[7] = 1;
        if bind(srv, srv_addr.as_ptr(), 16) != 0 {
            eprintln!("[escape_localhost] bind failed");
            closesocket(srv);
            std::process::exit(2);
        }
        listen(srv, 1);

        // Connect to our own server on loopback
        let cli = socket(2, 1, 6);
        let timeout: u32 = 3000;
        let _ = setsockopt(cli, 0xFFFF, 0x1005, &timeout as *const _ as *const _, 4);
        let result = connect(cli, srv_addr.as_ptr(), 16);
        let err = wsa_get_last_error();
        closesocket(cli);
        closesocket(srv);

        if result == 0 {
            eprintln!("[escape_localhost] CONNECTED to 127.0.0.1 — loopback accessible");
            std::process::exit(0);
        }
        eprintln!("[escape_localhost] blocked: err={err}");
        std::process::exit(5);
    }
}

#[link(name = "ws2_32")]
extern "system" {
    #[link_name = "WSAStartup"] fn ws2_init(v: u16, d: *mut u8) -> i32;
    fn socket(af: i32, st: i32, p: i32) -> usize;
    fn bind(s: usize, a: *const u8, l: i32) -> i32;
    fn listen(s: usize, b: i32) -> i32;
    fn connect(s: usize, a: *const u8, l: i32) -> i32;
    fn closesocket(s: usize) -> i32;
    fn setsockopt(s: usize, level: i32, opt: i32, val: *const u8, len: i32) -> i32;
    #[link_name = "WSAGetLastError"] fn wsa_get_last_error() -> i32;
}
