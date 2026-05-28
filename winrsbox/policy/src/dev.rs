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
    // === Hard blocks: actual escape vectors ===
    // Volume shadow copies — give access to historical file versions
    // bypassing current-state deny rules. \Device\HarddiskVolumeShadowCopyN\
    if lower.contains("shadowcopy") { return DeviceKind::Unknown; }
    // Raw physical drive — bypass file system entirely.
    if lower.contains("physicaldrive") { return DeviceKind::Unknown; }
    // Raw partition / volume bitmap access.
    if lower.contains(r"device\harddisk") && !lower.contains("harddiskvolume") {
        return DeviceKind::Unknown;
    }

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
    // Credential-extraction surfaces — deny by default (audit M-S1).
    // KsecDD brokers LSASS calls; certain IOCTL_KSEC_* opcodes leak LSA-isolated
    // data and DPAPI master keys without ever opening a handle to LSASS itself.
    // CNG / CNGBootInfo expose similar key-material / boot-time crypto info-leaks.
    // Previously these fell through to SystemQuery (read-OK); now explicit deny.
    // Check CNGBootInfo before CNG so the longer prefix wins.
    if is_device_name(&lower, "cngbootinfo")
        || is_device_name(&lower, "ksecdd")
        || is_device_name(&lower, "cng")
    {
        return DeviceKind::Unknown;
    }
    // Default: SystemQuery (read OK, write denied).
    // Modern GUI/UWP/Node processes open many internal device handles during
    // startup (CMNotify, DeviceApi, Lanmanredirector, UWP services). Denying
    // all unknown devices by default broke notepad and node — the actual
    // escape vectors are covered by other layers: CoW for files, WFP for
    // network, ALPC guard for COM/RPC, dangerous-pipe list, raw-disk blocks,
    // and credential-surface blocks (KsecDD/CNG) above. SystemQuery permits
    // read access (mount queries, device info) and denies writes through
    // unrecognized device handles.
    DeviceKind::SystemQuery
}

/// Matches the canonical NT device-object forms for a given device name,
/// e.g. for `name = "ksecdd"`: `\device\ksecdd`, `device\ksecdd`, and
/// either form followed by `\` + sub-path. Input `lower` must already be
/// lowercased.
fn is_device_name(lower: &str, name: &str) -> bool {
    let backslash = format!(r"\device\{name}");
    let bare = &backslash[1..]; // "device\\<name>"
    if lower == backslash || lower == bare { return true; }
    let backslash_sub = format!(r"\device\{name}\");
    let bare_sub = &backslash_sub[1..];
    lower.starts_with(&backslash_sub) || lower.starts_with(bare_sub)
}

/// Pipes that give access to dangerous system services.
fn is_dangerous_pipe(lower_path: &str) -> bool {
    const DANGEROUS_PIPES: &[&str] = &[
        "svcctl",       // Service Control Manager → start/stop services
        "atsvc",        // Task Scheduler → create scheduled tasks
        "psexesvc",     // PsExec remote execution
        "srvsvc",       // Server service → share management
        "winreg",       // Remote registry access
        "lsass",        // LSASS — credential dump / privilege escalation
        "spoolss",      // Print spooler — PrintNightmare class exploits
        "samr",         // SAMR — local account enumeration
        "netlogon",     // Netlogon — domain auth / Zerologon class
        "wkssvc",       // Workstation service → session enumeration
        "lsarpc",       // LSA RPC — policy/privelege queries
        "eventlog",     // Event log — log manipulation / info leak
        "browser",      // Browser service — network recon
        "epmapper",     // RPC endpoint mapper — service enumeration
    ];
    let segment = match lower_path.rfind(|c: char| c == '\\' || c == '/') {
        Some(idx) => &lower_path[idx + 1..],
        None => lower_path,
    };
    DANGEROUS_PIPES.iter().any(|&p| segment == p)
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
    fn classify_unknown_devices_default_to_system_query() {
        // CldFlt is the Cloud Files filter driver — legitimately opened by Explorer
        // and modern apps; treated as SystemQuery (read-only safe) by default.
        assert_eq!(classify_device(r"\device\cldflt"), DeviceKind::SystemQuery);
    }

    #[test]
    fn classify_raw_disk_blocked() {
        // Raw physical drive bypasses file system — explicitly blocked.
        assert_eq!(classify_device(r"device\physicaldrive0"), DeviceKind::Unknown);
        assert_eq!(classify_device(r"\device\physicaldrive1"), DeviceKind::Unknown);
        // Raw HarddiskN (without "volume") bypasses the volume layer.
        assert_eq!(classify_device(r"\device\harddisk0\partition1"), DeviceKind::Unknown);
    }

    #[test]
    fn dangerous_pipes_blocked() {
        assert_eq!(classify_device(r"\device\namedpipe\svcctl"), DeviceKind::Unknown);
        assert_eq!(classify_device(r"pipe\atsvc"), DeviceKind::Unknown);
        assert_eq!(classify_device(r"\device\namedpipe\psexesvc"), DeviceKind::Unknown);
        assert_eq!(classify_device(r"\device\namedpipe\winreg"), DeviceKind::Unknown);
        assert_eq!(classify_device(r"\device\namedpipe\srvsvc"), DeviceKind::Unknown);
        // Previously allowed — now blocked (audit gap fix)
        assert_eq!(classify_device(r"\device\namedpipe\lsass"), DeviceKind::Unknown);
        assert_eq!(classify_device(r"\device\namedpipe\spoolss"), DeviceKind::Unknown);
        assert_eq!(classify_device(r"\device\namedpipe\samr"), DeviceKind::Unknown);
        assert_eq!(classify_device(r"\device\namedpipe\netlogon"), DeviceKind::Unknown);
        assert_eq!(classify_device(r"\device\namedpipe\wkssvc"), DeviceKind::Unknown);
        assert_eq!(classify_device(r"\device\namedpipe\lsarpc"), DeviceKind::Unknown);
        assert_eq!(classify_device(r"\device\namedpipe\eventlog"), DeviceKind::Unknown);
        assert_eq!(classify_device(r"\device\namedpipe\browser"), DeviceKind::Unknown);
        assert_eq!(classify_device(r"\device\namedpipe\epmapper"), DeviceKind::Unknown);
        // Safe pipes still allowed
        assert_eq!(classify_device(r"pipe\fs-sandbox-1234"), DeviceKind::NamedPipe);
        assert_eq!(classify_device(r"\device\namedpipe\myapp-ipc"), DeviceKind::NamedPipe);
    }

    #[test]
    fn classify_shadow_copy_blocked() {
        assert_eq!(classify_device(r"\device\harddiskvolumeshadowcopy3"), DeviceKind::Unknown);
        assert_eq!(classify_device(r"device\harddiskvolumeshadowcopy1\windows\system32"), DeviceKind::Unknown);
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
    }

    #[test]
    fn classify_ksecdd_is_unknown() {
        // KsecDD brokers LSASS / DPAPI calls — credential-extraction surface.
        // Audit M-S1: moved from SystemQuery (read-OK) to Unknown (deny).
        assert_eq!(classify_device(r"\device\ksecdd"), DeviceKind::Unknown);
        assert_eq!(classify_device(r"device\ksecdd"), DeviceKind::Unknown);
    }

    #[test]
    fn classify_cng_is_unknown() {
        // CNG (Cryptography Next Generation) exposes key-material info-leaks.
        // Audit M-S1: moved from SystemQuery (read-OK) to Unknown (deny).
        assert_eq!(classify_device(r"\device\cng"), DeviceKind::Unknown);
        assert_eq!(classify_device(r"device\cng"), DeviceKind::Unknown);
    }

    #[test]
    fn classify_cngbootinfo_is_unknown() {
        // CNGBootInfo exposes boot-time crypto state / key material.
        // Audit M-S1: moved from SystemQuery (read-OK) to Unknown (deny).
        assert_eq!(classify_device(r"\device\cngbootinfo"), DeviceKind::Unknown);
        assert_eq!(classify_device(r"device\cngbootinfo"), DeviceKind::Unknown);
    }

    #[test]
    fn classify_credential_surface_does_not_overmatch() {
        // A pipe or filesystem path that merely contains "cng" or "ksecdd"
        // as a substring must NOT be misclassified — only canonical
        // \Device\<Name> forms.
        assert_eq!(classify_device(r"\device\namedpipe\cng"), DeviceKind::NamedPipe);
        assert_eq!(
            classify_device(r"\device\harddiskvolume1\windows\system32\drivers\cng.sys"),
            DeviceKind::HarddiskVolume,
        );
        // Different device whose name happens to start with "cng" must not match.
        assert_eq!(classify_device(r"\device\cngfoo"), DeviceKind::SystemQuery);
    }

    #[test]
    fn dangerous_pipe_exact_segment_match() {
        // Exact pipe name must match
        assert!(is_dangerous_pipe(r"\device\namedpipe\lsass"));
        assert!(is_dangerous_pipe(r"pipe\samr"));
        // Substring-only must NOT match (false positives before this fix)
        assert!(!is_dangerous_pipe(r"\device\namedpipe\myapp-eventlog"));
        assert!(!is_dangerous_pipe(r"\device\namedpipe\eventlog_extra"));
        assert!(!is_dangerous_pipe(r"\device\namedpipe\myappbrowser"));
        assert!(!is_dangerous_pipe(r"\device\namedpipe\samr_app_data"));
        assert!(!is_dangerous_pipe(r"pipe\some-browser-helper"));
    }
}
