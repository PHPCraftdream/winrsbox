use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeviceKind {
    HarddiskVolume,
    NamedPipe,
    Socket,
    Console,
    Null,
    Unknown,
}

pub fn nt_to_device_path(raw: &[u16]) -> Option<String> {
    let s = String::from_utf16_lossy(raw);
    let s = s.trim_end_matches('\0');
    let lower = s.to_lowercase();

    if let Some(rest) = lower.strip_prefix(r"\??\globalroot\") {
        return Some(rest.to_owned());
    }
    if let Some(rest) = lower.strip_prefix(r"\\.\") {
        return Some(format!(r"device\{rest}"));
    }
    if lower.starts_with(r"\device\") {
        return Some(lower.to_owned());
    }
    if lower.starts_with(r"\??\") {
        let inner = &lower[4..];
        if inner.starts_with(r"device\") || !inner.chars().nth(1).map_or(false, |c| c == ':') {
            return Some(inner.to_owned());
        }
    }
    None
}

pub fn classify_device(path: &str) -> DeviceKind {
    let lower = path.to_lowercase();
    if lower.starts_with(r"device\harddiskvolume") { return DeviceKind::HarddiskVolume; }
    if lower.starts_with(r"\device\harddiskvolume") { return DeviceKind::HarddiskVolume; }
    if lower.contains(r"namedpipe") || lower.contains(r"named_pipe") { return DeviceKind::NamedPipe; }
    if lower.starts_with(r"device\afd") || lower.starts_with(r"\device\afd") { return DeviceKind::Socket; }
    if lower.starts_with(r"device\tcp") || lower.starts_with(r"\device\tcp") { return DeviceKind::Socket; }
    if lower.starts_with(r"device\udp") || lower.starts_with(r"\device\udp") { return DeviceKind::Socket; }
    if lower.contains("condrv") || lower.contains("console") { return DeviceKind::Console; }
    if lower.contains(r"device\null") { return DeviceKind::Null; }
    DeviceKind::Unknown
}

pub fn is_safe_default(kind: DeviceKind) -> bool {
    matches!(kind, DeviceKind::HarddiskVolume | DeviceKind::NamedPipe | DeviceKind::Console | DeviceKind::Null)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nt_to_device_cldflt() {
        let raw: Vec<u16> = r"\Device\CldFlt".encode_utf16().collect();
        assert_eq!(nt_to_device_path(&raw), Some(r"\device\cldflt".into()));
    }

    #[test]
    fn nt_to_device_globalroot() {
        let raw: Vec<u16> = r"\??\GLOBALROOT\Device\Foo\Bar".encode_utf16().collect();
        assert_eq!(nt_to_device_path(&raw), Some(r"device\foo\bar".into()));
    }

    #[test]
    fn nt_to_device_dot_prefix() {
        let raw: Vec<u16> = r"\\.\PhysicalDrive0".encode_utf16().collect();
        assert_eq!(nt_to_device_path(&raw), Some(r"device\physicaldrive0".into()));
    }

    #[test]
    fn nt_to_device_named_pipe() {
        let raw: Vec<u16> = r"\Device\NamedPipe\winrsbox-pipe".encode_utf16().collect();
        assert_eq!(nt_to_device_path(&raw), Some(r"\device\namedpipe\winrsbox-pipe".into()));
    }

    #[test]
    fn nt_to_device_dos_path_returns_none() {
        let raw: Vec<u16> = r"\??\C:\foo".encode_utf16().collect();
        assert_eq!(nt_to_device_path(&raw), None);
    }

    #[test]
    fn nt_to_device_trailing_nul() {
        let mut raw: Vec<u16> = r"\Device\Afd".encode_utf16().collect();
        raw.push(0);
        assert_eq!(nt_to_device_path(&raw), Some(r"\device\afd".into()));
    }

    #[test]
    fn nt_to_device_empty() {
        assert_eq!(nt_to_device_path(&[]), None);
    }

    #[test]
    fn classify_harddisk() {
        assert_eq!(classify_device(r"\device\harddiskvolume3"), DeviceKind::HarddiskVolume);
        assert_eq!(classify_device(r"device\harddiskvolume1\foo"), DeviceKind::HarddiskVolume);
    }

    #[test]
    fn classify_named_pipe() {
        assert_eq!(classify_device(r"\device\namedpipe\foo"), DeviceKind::NamedPipe);
    }

    #[test]
    fn classify_socket() {
        assert_eq!(classify_device(r"\device\afd"), DeviceKind::Socket);
        assert_eq!(classify_device(r"device\tcp"), DeviceKind::Socket);
        assert_eq!(classify_device(r"device\udp"), DeviceKind::Socket);
    }

    #[test]
    fn classify_console() {
        assert_eq!(classify_device(r"\device\condrv"), DeviceKind::Console);
    }

    #[test]
    fn classify_null() {
        assert_eq!(classify_device(r"\device\null"), DeviceKind::Null);
    }

    #[test]
    fn classify_unknown() {
        assert_eq!(classify_device(r"\device\cldflt"), DeviceKind::Unknown);
        assert_eq!(classify_device(r"device\physicaldrive0"), DeviceKind::Unknown);
        assert_eq!(classify_device(r"\device\mountpointmanager"), DeviceKind::Unknown);
    }

    #[test]
    fn safe_default_allows_expected() {
        assert!(is_safe_default(DeviceKind::HarddiskVolume));
        assert!(is_safe_default(DeviceKind::NamedPipe));
        assert!(is_safe_default(DeviceKind::Console));
        assert!(is_safe_default(DeviceKind::Null));
        assert!(!is_safe_default(DeviceKind::Socket));
        assert!(!is_safe_default(DeviceKind::Unknown));
    }
}
