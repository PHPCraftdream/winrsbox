use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetMode {
    Allow,
    Deny,
    Log,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetRule {
    pub id: String,
    pub host_pattern: String,
    pub port: Option<u16>,
    pub mode: NetMode,
}

pub fn match_host(pattern: &str, host: &str) -> bool {
    let p = pattern.to_lowercase();
    let h = host.to_lowercase();
    if p == h { return true; }
    if p == "*" { return true; }
    if let Some(suffix) = p.strip_prefix("*.") {
        let dot_suffix = format!(".{suffix}");
        return h.ends_with(&dot_suffix) || h == suffix;
    }
    crate::path::segment_match(&p, &h)
}

pub fn parse_cidr(cidr: &str) -> Option<(u32, u32)> {
    let (ip_str, bits_str) = cidr.split_once('/')?;
    let bits: u32 = bits_str.parse().ok()?;
    if bits > 32 { return None; }
    let ip = parse_ipv4(ip_str)?;
    let mask = if bits == 0 { 0 } else { !0u32 << (32 - bits) };
    Some((ip & mask, mask))
}

pub fn parse_ipv4(s: &str) -> Option<u32> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 { return None; }
    let a: u32 = parts[0].parse().ok()?;
    let b: u32 = parts[1].parse().ok()?;
    let c: u32 = parts[2].parse().ok()?;
    let d: u32 = parts[3].parse().ok()?;
    if a > 255 || b > 255 || c > 255 || d > 255 { return None; }
    Some((a << 24) | (b << 16) | (c << 8) | d)
}

pub fn ip_in_cidr(ip: u32, network: u32, mask: u32) -> bool {
    (ip & mask) == network
}

pub fn is_localhost(host: &str) -> bool {
    let h = host.to_lowercase();
    h == "localhost" || h == "127.0.0.1" || h == "::1" || h == "0.0.0.0"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn match_host_exact() {
        assert!(match_host("api.github.com", "api.github.com"));
        assert!(match_host("API.GitHub.COM", "api.github.com"));
        assert!(!match_host("api.github.com", "evil.com"));
    }

    #[test]
    fn match_host_wildcard_subdomain() {
        assert!(match_host("*.github.com", "api.github.com"));
        assert!(match_host("*.github.com", "raw.github.com"));
        assert!(!match_host("*.github.com", "github.io"));
        assert!(!match_host("*.github.com", "evil.github.com.evil.org"));
    }

    #[test]
    fn match_host_star_all() {
        assert!(match_host("*", "anything.com"));
        assert!(match_host("*", "127.0.0.1"));
    }

    #[test]
    fn parse_cidr_basic() {
        let (net, mask) = parse_cidr("10.0.0.0/8").unwrap();
        assert_eq!(net, 0x0A000000);
        assert_eq!(mask, 0xFF000000);
    }

    #[test]
    fn parse_cidr_24() {
        let (net, mask) = parse_cidr("192.168.1.0/24").unwrap();
        assert_eq!(net, 0xC0A80100);
        assert_eq!(mask, 0xFFFFFF00);
    }

    #[test]
    fn parse_cidr_32() {
        let (net, mask) = parse_cidr("1.2.3.4/32").unwrap();
        assert_eq!(net, 0x01020304);
        assert_eq!(mask, 0xFFFFFFFF);
    }

    #[test]
    fn parse_cidr_invalid() {
        assert!(parse_cidr("not_ip/8").is_none());
        assert!(parse_cidr("10.0.0.0/33").is_none());
        assert!(parse_cidr("10.0.0.0").is_none());
    }

    #[test]
    fn ip_in_cidr_works() {
        let (net, mask) = parse_cidr("10.0.0.0/8").unwrap();
        assert!(ip_in_cidr(parse_ipv4("10.1.2.3").unwrap(), net, mask));
        assert!(ip_in_cidr(parse_ipv4("10.255.255.255").unwrap(), net, mask));
        assert!(!ip_in_cidr(parse_ipv4("11.0.0.1").unwrap(), net, mask));
    }

    #[test]
    fn parse_ipv4_basic() {
        assert_eq!(parse_ipv4("192.168.1.1"), Some(0xC0A80101));
        assert_eq!(parse_ipv4("0.0.0.0"), Some(0));
        assert_eq!(parse_ipv4("255.255.255.255"), Some(0xFFFFFFFF));
    }

    #[test]
    fn parse_ipv4_invalid() {
        assert!(parse_ipv4("256.0.0.0").is_none());
        assert!(parse_ipv4("1.2.3").is_none());
        assert!(parse_ipv4("abc").is_none());
    }

    #[test]
    fn is_localhost_works() {
        assert!(is_localhost("localhost"));
        assert!(is_localhost("127.0.0.1"));
        assert!(is_localhost("::1"));
        assert!(is_localhost("0.0.0.0"));
        assert!(!is_localhost("10.0.0.1"));
        assert!(!is_localhost("google.com"));
    }

    #[test]
    fn match_host_no_false_suffix() {
        assert!(!match_host("*.github.com", "notgithub.com"));
    }
}
