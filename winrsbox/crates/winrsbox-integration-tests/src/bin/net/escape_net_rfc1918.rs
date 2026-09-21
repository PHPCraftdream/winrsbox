// Escape payload: TCP connect to RFC1918 private IP (lateral movement).
// Expected: blocked by WFP kernel filter → connect fails.

fn main() {
    eprintln!("[escape_net_rfc1918] starting");
    let result = std::net::TcpStream::connect_timeout(
        &"10.255.255.1:80".parse().unwrap(),
        std::time::Duration::from_secs(3),
    );
    match result {
        Ok(_) => {
            eprintln!("[escape_net_rfc1918] CONNECTED (should have been blocked)");
            std::process::exit(0);
        }
        Err(e) => {
            eprintln!("[escape_net_rfc1918] connect error: {e}");
            // WFP block typically returns ConnectionRefused or TimedOut
            std::process::exit(2);
        }
    }
}
