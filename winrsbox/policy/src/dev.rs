use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeviceKind {
    HarddiskVolume,
    NamedPipe,
    Socket,
    Console,
    Null,
    /// Known read-only system query devices (MountPointManager, IPT, etc.).
    /// Used by Win32 APIs and .NET BCL for system metadata queries. Allowing
    /// these is safe — they don't grant filesystem or network escape vectors.
    SystemQuery,
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
    // Block volume shadow copies — give access to historical file versions
    // bypassing current-state deny rules. \Device\HarddiskVolumeShadowCopyN\
    if lower.contains("shadowcopy") { return DeviceKind::Unknown; }
    if lower.starts_with(r"device\harddiskvolume") { return DeviceKind::HarddiskVolume; }
    if lower.starts_with(r"\device\harddiskvolume") { return DeviceKind::HarddiskVolume; }
    // Named pipes: full form `\Device\NamedPipe\…` and DOS-form short `pipe\…`
    if lower.contains(r"namedpipe") || lower.contains(r"named_pipe")
        || lower.starts_with(r"pipe\") || lower.starts_with(r"\pipe\")
    {
        // Block pipes to dangerous RPC services (SCM, Task Scheduler, PsExec)
        if is_dangerous_pipe(&lower) { return DeviceKind::Unknown; }
        return DeviceKind::NamedPipe;
    }
    if lower.starts_with(r"device\afd") || lower.starts_with(r"\device\afd") { return DeviceKind::Socket; }
    if lower.starts_with(r"device\tcp") || lower.starts_with(r"\device\tcp") { return DeviceKind::Socket; }
    if lower.starts_with(r"device\udp") || lower.starts_with(r"\device\udp") { return DeviceKind::Socket; }
    // NSI (Network Store Interface) — required for DNS resolver to query network
    // configuration (DNS server addresses, interface state). Without it, all
    // name resolution fails (getaddrinfo → EAI_FAIL).
    if lower == "nsi" || lower.ends_with(r"\nsi") || lower.contains(r"device\nsi") { return DeviceKind::Socket; }
    // Console: \Device\ConDrv, "console", and CONIN$/CONOUT$ pseudo-devices.
    if lower.contains("condrv") || lower.contains("console") { return DeviceKind::Console; }
    if lower == "conin$" || lower == "conout$" || lower.ends_with(r"\conin$") || lower.ends_with(r"\conout$") {
        return DeviceKind::Console;
    }
    if lower.contains(r"device\null") || lower == "nul" || lower.ends_with(r"\nul") {
        return DeviceKind::Null;
    }
    // Known read-only system query devices used by Win32 / .NET BCL.
    const SYSTEM_QUERY_DEVICES: &[&str] = &[
        "mountpointmanager",  // \Device\MountPointManager — volume mount queries
        "ipt",                // \Device\IPT — Intel Processor Trace
        "kernelobjects",      // \KernelObjects — synchronization primitive lookup
        "dfs",                // \Device\Dfs — DFS path resolution
    ];
    for name in SYSTEM_QUERY_DEVICES {
        if lower.contains(name) {
            return DeviceKind::SystemQuery;
        }
    }
    DeviceKind::Unknown
}

/// Pipes that give access to dangerous system services.
fn is_dangerous_pipe(lower_path: &str) -> bool {
    const DANGEROUS_PIPES: &[&str] = &[
        "svcctl",       // Service Control Manager → start/stop services
        "atsvc",        // Task Scheduler → create scheduled tasks
        "psexesvc",     // PsExec remote execution
        "srvsvc",       // Server service → share management
        "winreg",       // Remote registry access
    ];
    DANGEROUS_PIPES.iter().any(|&p| lower_path.contains(p))
}

pub fn is_safe_default(kind: DeviceKind) -> bool {
    matches!(kind, DeviceKind::HarddiskVolume | DeviceKind::NamedPipe | DeviceKind::Console | DeviceKind::Null | DeviceKind::Socket)
}

/// Stricter check for SystemQuery devices: allow read, deny write.
/// MountPointManager IOCTL_MOUNTMGR_CREATE_POINT needs write access +
/// SeRestorePrivilege; NSI NsiSetParameter needs write access.
/// Limiting to read-only access removes these vectors even without
/// relying on privilege checks.
pub fn is_safe_with_access(kind: DeviceKind, write: bool) -> bool {
    match kind {
        DeviceKind::SystemQuery => !write,
        _ => is_safe_default(kind),
    }
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
    fn classify_nul_device_short_form() {
        // Rust's Stdio::null() opens \??\NUL which parses to "nul"
        assert_eq!(classify_device("nul"), DeviceKind::Null);
        assert!(is_safe_default(classify_device("nul")));
    }

    #[test]
    fn classify_nul_with_path_prefix() {
        assert_eq!(classify_device(r"some\path\nul"), DeviceKind::Null);
    }

    #[test]
    fn classify_device_null_long_form() {
        assert_eq!(classify_device(r"\device\null"), DeviceKind::Null);
        assert_eq!(classify_device(r"device\null"), DeviceKind::Null);
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
    }

    #[test]
    fn dangerous_pipes_blocked() {
        assert_eq!(classify_device(r"\device\namedpipe\svcctl"), DeviceKind::Unknown);
        assert_eq!(classify_device(r"pipe\atsvc"), DeviceKind::Unknown);
        assert_eq!(classify_device(r"\device\namedpipe\psexesvc"), DeviceKind::Unknown);
        // Safe pipes still allowed
        assert_eq!(classify_device(r"\device\namedpipe\lsarpc"), DeviceKind::NamedPipe);
        assert_eq!(classify_device(r"pipe\fs-sandbox-1234"), DeviceKind::NamedPipe);
    }

    #[test]
    fn classify_shadow_copy_blocked() {
        assert_eq!(classify_device(r"\device\harddiskvolumeshadowcopy3"), DeviceKind::Unknown);
        assert_eq!(classify_device(r"device\harddiskvolumeshadowcopy1\windows\system32"), DeviceKind::Unknown);
        assert!(!is_safe_default(DeviceKind::Unknown));
    }

    #[test]
    fn classify_console_pseudo_devices() {
        assert_eq!(classify_device("conout$"), DeviceKind::Console);
        assert_eq!(classify_device("conin$"), DeviceKind::Console);
        assert_eq!(classify_device(r"\??\conout$"), DeviceKind::Console);
    }

    #[test]
    fn classify_short_pipe_form() {
        assert_eq!(classify_device(r"pipe\foo"), DeviceKind::NamedPipe);
        assert_eq!(classify_device(r"\pipe\bar"), DeviceKind::NamedPipe);
    }

    #[test]
    fn classify_system_query_devices() {
        assert_eq!(classify_device(r"\device\mountpointmanager"), DeviceKind::SystemQuery);
        assert_eq!(classify_device(r"device\ipt"), DeviceKind::SystemQuery);
        assert!(is_safe_with_access(DeviceKind::SystemQuery, false));
        assert!(!is_safe_with_access(DeviceKind::SystemQuery, true));
    }

    #[test]
    fn safe_default_allows_expected() {
        assert!(is_safe_default(DeviceKind::HarddiskVolume));
        assert!(is_safe_default(DeviceKind::NamedPipe));
        assert!(is_safe_default(DeviceKind::Console));
        assert!(is_safe_default(DeviceKind::Null));
        assert!(is_safe_default(DeviceKind::Socket));
        assert!(!is_safe_default(DeviceKind::SystemQuery));
        assert!(!is_safe_default(DeviceKind::Unknown));
    }

    #[test]
    fn system_query_read_only() {
        assert!(is_safe_with_access(DeviceKind::SystemQuery, false));
        assert!(!is_safe_with_access(DeviceKind::SystemQuery, true));
        assert!(is_safe_with_access(DeviceKind::Socket, false));
        assert!(is_safe_with_access(DeviceKind::Socket, true));
    }
}
