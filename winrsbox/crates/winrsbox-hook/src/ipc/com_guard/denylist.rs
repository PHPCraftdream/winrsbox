use winapi::shared::guiddef::GUID;

// ---------------------------------------------------------------------------
// CLSID denylist
// ---------------------------------------------------------------------------

#[allow(non_snake_case)]
pub(super) const fn guid(d1: u32, d2: u16, d3: u16, d4: [u8; 8]) -> GUID {
    GUID { Data1: d1, Data2: d2, Data3: d3, Data4: d4 }
}

pub(super) struct DenyEntry {
    clsid: GUID,
    name: &'static str,
    /// When true, activating this CLSID from inside the sandbox is treated as a
    /// deliberate containment-escape attempt and the process is TERMINATED
    /// (fail-stop) instead of merely denied. Reserved for classes whose only
    /// purpose is to spawn processes / run commands / move laterally / reach
    /// WMI (`Win32_Process.Create`). Classes that legitimate software might
    /// activate for benign reasons (file I/O, background download) stay
    /// `terminate: false` — denied gracefully, not killed.
    terminate: bool,
}

pub(super) const CLSID_DENYLIST: &[DenyEntry] = &[
    // Shell escape — ShellExecute spawn / lateral. KILL.
    DenyEntry { clsid: guid(0x13709620, 0xC279, 0x11CE, [0xA4,0x9E,0x44,0x45,0x53,0x54,0x00,0x00]), name: "Shell.Application", terminate: true },
    DenyEntry { clsid: guid(0x9BA05972, 0xF6A8, 0x11CF, [0xA4,0x42,0x00,0xA0,0xC9,0x0A,0x8F,0x39]), name: "ShellWindows", terminate: true },

    // Scripting host — WScript.Shell.Run/Exec spawns processes. KILL.
    DenyEntry { clsid: guid(0x72C24DD5, 0xD70A, 0x438B, [0x8A,0x42,0x98,0x42,0x4B,0x88,0xAF,0xB8]), name: "WScript.Shell", terminate: true },
    DenyEntry { clsid: guid(0xF935DC22, 0x1CF0, 0x11D0, [0xAD,0xB9,0x00,0xC0,0x4F,0xD5,0x8A,0x0B]), name: "WScript.Shell.1", terminate: true },
    // FileSystemObject is file I/O only — it goes through our hooked file APIs
    // (no FS-containment bypass) and legitimate scripts use it. Deny, don't kill.
    DenyEntry { clsid: guid(0x0D43FE01, 0xF093, 0x11CF, [0x89,0x40,0x00,0xA0,0xC9,0x05,0x42,0x28]), name: "Scripting.FileSystemObject", terminate: false },

    // WMI (WbemLocator / SWbemLocator) — DENY, do NOT kill (bug #88 re-audit).
    //
    // Denying the locator activation already fully blocks the Win32_Process.Create
    // escape: without the proxy, the spawn method is never reachable. But WMI is
    // dual-use — benign tools (tasklist, systeminfo, Get-CimInstance reads) also
    // activate the locator. Killing on it would terminate those benign readers as
    // collateral while adding NO security (the escape is already blocked by the
    // deny). So WMI stays a graceful deny; genuine spawn/escape vectors below/above
    // are the ones that fail-stop. WMI-dependent tooling uses `--guard none`.
    DenyEntry { clsid: guid(0x4590F811, 0x1D3A, 0x11D0, [0x89,0x1F,0x00,0xAA,0x00,0x4B,0x2E,0x24]), name: "WbemLocator", terminate: false },
    DenyEntry { clsid: guid(0x76A64158, 0xCB41, 0x11D1, [0x8B,0x02,0x00,0x60,0x08,0x06,0xD9,0xB6]), name: "WbemScripting.SWbemLocator", terminate: false },

    // Task Scheduler — persistence + spawn. KILL.
    DenyEntry { clsid: guid(0x0F87369F, 0xA4E5, 0x4CFC, [0xBD,0x3E,0x73,0xE6,0x15,0x45,0x72,0xDD]), name: "Schedule.Service", terminate: true },
    DenyEntry { clsid: guid(0x148BD52A, 0xA2AB, 0x11CE, [0xB1,0x1F,0x00,0xAA,0x00,0x53,0x05,0x03]), name: "CTaskScheduler", terminate: true },

    // BITS — background download/persistence. Ambiguous enough (a benign updater
    // could reach for it) that we deny rather than kill.
    DenyEntry { clsid: guid(0x4991D34B, 0x80A1, 0x4291, [0x83,0xB6,0x33,0x28,0x36,0x6B,0x90,0x97]), name: "BackgroundCopyManager", terminate: false },

    // Office (macro / DDE spawn + lateral). KILL.
    DenyEntry { clsid: guid(0x00024500, 0x0000, 0x0000, [0xC0,0x00,0x00,0x00,0x00,0x00,0x00,0x46]), name: "Excel.Application", terminate: true },
    DenyEntry { clsid: guid(0x000209FF, 0x0000, 0x0000, [0xC0,0x00,0x00,0x00,0x00,0x00,0x00,0x46]), name: "Word.Application", terminate: true },
    DenyEntry { clsid: guid(0x0006F03A, 0x0000, 0x0000, [0xC0,0x00,0x00,0x00,0x00,0x00,0x00,0x46]), name: "Outlook.Application", terminate: true },

    // DCOM lateral-movement / in-proc script execution — all spawn/exec. KILL.
    DenyEntry { clsid: guid(0x49B2791A, 0xB1AE, 0x4C90, [0x9B,0x8E,0xE8,0x60,0xBA,0x07,0xF8,0x89]), name: "MMC20.Application", terminate: true },
    DenyEntry { clsid: guid(0xC08AFD90, 0xF2A1, 0x11D1, [0x84,0x55,0x00,0xA0,0xC9,0x1F,0x38,0x80]), name: "ShellBrowserWindow", terminate: true },
    DenyEntry { clsid: guid(0x0E59F1D5, 0x1FBE, 0x11D0, [0x8F,0xF2,0x00,0xA0,0xD1,0x00,0x38,0xBC]), name: "ScriptControl", terminate: true },
    DenyEntry { clsid: guid(0x0002DF01, 0x0000, 0x0000, [0xC0,0x00,0x00,0x00,0x00,0x00,0x00,0x46]), name: "InternetExplorer.Application", terminate: true },
];

fn clsid_eq(a: &GUID, b: &GUID) -> bool {
    a.Data1 == b.Data1 && a.Data2 == b.Data2 && a.Data3 == b.Data3 && a.Data4 == b.Data4
}

/// Returns `Some((name, terminate))` for a denylisted CLSID: `name` for logging,
/// `terminate` selecting fail-stop (kill) vs graceful deny. `None` if allowed.
pub(super) fn check_denylist(clsid: *const GUID) -> Option<(&'static str, bool)> {
    if clsid.is_null() { return None; }
    // SAFETY: deref of non-null GUID pointer — caller must ensure it points to a valid GUID.
    let clsid = unsafe { &*clsid };
    for entry in CLSID_DENYLIST {
        if clsid_eq(clsid, &entry.clsid) {
            return Some((entry.name, entry.terminate));
        }
    }
    None
}

// ---------------------------------------------------------------------------
// WinRT activation denylist (case-insensitive prefix match on runtime class name)
// ---------------------------------------------------------------------------

// DENYLIST PHILOSOPHY — block the tunnel, not the bed.
//
// We deny ONLY WinRT classes that let the guest cross the containment boundary:
// spawn/launch something outside the jail, modify the host, or set up
// delayed/persistent execution the sandbox can't see. We do NOT block classes
// the guest uses to arrange its own cell (CoreApplication, Threading,
// Notifications, Devices.Enumeration, Activation) — those broke legitimate
// apps (notepad's UWP host uses CoreApplication) without buying any
// containment. Pure info-leak / PII / recon classes (Diagnostics, UserProfile,
// Contacts, device sensors) are out of scope per the threat model
// (escape + system modification; network/clipboard/GUI/recon excluded), and
// network is handled by WFP, not here.
//
// Each entry below is justified by ESCAPE or HOST-MODIFICATION, not "scary".
pub(super) const WINRT_DENY_PREFIXES: &[&str] = &[
    // ── spawn / launch outside the jail (escape) ──
    "windows.system.launcher",                  // LaunchUriAsync / LaunchFileAsync → external app
    "windows.system.remotelauncher",            // launch on a remote device
    "windows.system.remotedesktop",             // remote-desktop session
    "windows.system.remotesystems",             // cross-device app launch
    "windows.applicationmodel.appservice",      // IPC channel into another package
    "windows.storage.pickers",                  // broker-mediated file handle outside the CoW overlay
    // ── host modification ──
    "windows.management.deployment",            // PackageManager — installs/removes AppX
    "windows.system.power",                     // PowerManager.RequestShutdown/Restart (pairs w/ NtShutdownSystem hook)
    // ── persistence / delayed execution outside our process ──
    "windows.system.scheduler",                 // TaskScheduler equivalent
    "windows.applicationmodel.background",      // BackgroundTaskRegistration — system runs it later
    // ── credential theft (in scope, consistent with LSA/SAM ALPC blocks) ──
    "windows.security.credentials",             // PasswordVault.RetrieveAll
];

/// Returns true if `name` matches any denied WinRT activation class prefix
/// (case-insensitive). Extracted as a free function so it's unit-testable
/// without touching any FFI or detour state.
pub(super) fn is_winrt_class_denied(name: &str) -> bool {
    // We do per-byte ASCII lowercase comparison to avoid allocating a lowercased
    // copy of every incoming class name. All denylist entries and all valid WinRT
    // runtime class names are ASCII per Windows.Foundation rules.
    let bytes = name.as_bytes();
    for prefix in WINRT_DENY_PREFIXES {
        let p = prefix.as_bytes();
        if bytes.len() < p.len() { continue; }
        let mut ok = true;
        for i in 0..p.len() {
            if bytes[i].to_ascii_lowercase() != p[i] {
                ok = false;
                break;
            }
        }
        if ok {
            // For a "prefix" match, accept either end-of-string or a separator
            // (`.`) immediately after the prefix to avoid the prefix accidentally
            // matching a longer unrelated identifier.
            if bytes.len() == p.len() {
                return true;
            }
            let next = bytes[p.len()];
            if next == b'.' {
                return true;
            }
        }
    }
    false
}
