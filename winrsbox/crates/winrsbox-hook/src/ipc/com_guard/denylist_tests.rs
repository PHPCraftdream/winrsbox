// CLSID denylist + WinRT classifier tests for com_guard.
//
// Moved verbatim out of the former single-file com_guard.rs `mod tests` to
// keep it under the workspace's 1000-line file budget; `#[cfg(test)]` lives
// on the `mod denylist_tests;` declaration in mod.rs, like every other
// sibling `*_tests` file in the tree.

use super::denylist::{
    CLSID_DENYLIST, WINRT_DENY_PREFIXES, check_denylist, guid, is_winrt_class_denied,
};

#[test]
fn winrt_deny_matches_prefix_case_insensitive() {
    // Exact match.
    assert!(is_winrt_class_denied("Windows.System.Launcher"));
    // Sub-class under denied prefix.
    assert!(is_winrt_class_denied("Windows.System.Launcher.LaunchUriParameters"));
    // Case-insensitive — uppercased prefix segment.
    assert!(is_winrt_class_denied("WINDOWS.System.Launcher"));
    // Fully uppercase.
    assert!(is_winrt_class_denied("WINDOWS.SYSTEM.LAUNCHER.LAUNCHURIPARAMETERS"));

    // Other denylist entries.
    assert!(is_winrt_class_denied("Windows.Management.Deployment.PackageManager"));
    assert!(is_winrt_class_denied("Windows.Storage.Pickers.FileOpenPicker"));
    assert!(is_winrt_class_denied("Windows.System.Power.PowerManager"));
    assert!(is_winrt_class_denied("Windows.ApplicationModel.AppService.AppServiceConnection"));

    // NOT denied — different sub-namespace under Windows.
    assert!(!is_winrt_class_denied("Windows.UI.Xaml.Controls.Button"));
    assert!(!is_winrt_class_denied("Windows.Foundation.Uri"));
    assert!(!is_winrt_class_denied("Windows.Data.Json.JsonObject"));

    // Empty string must not match.
    assert!(!is_winrt_class_denied(""));

    // Regression: prefix must be bounded on a `.` separator — a class whose
    // first segment shares a prefix-string with a denied entry but is a
    // distinct identifier must NOT match.
    assert!(!is_winrt_class_denied("Windows.System.LauncherEx"));
    assert!(!is_winrt_class_denied("Windows.System.SchedulerService"));
}

/// Smoke-check every entry in `WINRT_DENY_PREFIXES` so a typo or stray
/// uppercase character in the table is caught at test time. Iterates the
/// full list and asserts both the exact prefix and a `.<sub>` form match.
#[test]
fn coverage_of_every_listed_winrt_prefix() {
    for p in WINRT_DENY_PREFIXES {
        // Exact-prefix form must match.
        assert!(
            is_winrt_class_denied(p),
            "expected to be denied (exact): {p}"
        );
        // Sub-namespace form (`prefix.Child`) must also match.
        let sub = format!("{p}.Child");
        assert!(
            is_winrt_class_denied(&sub),
            "expected to be denied (sub): {sub}"
        );
        // Uppercased form must match (case-insensitive guarantee).
        let upper: String = p.to_ascii_uppercase();
        assert!(
            is_winrt_class_denied(&upper),
            "expected to be denied (uppercased): {upper}"
        );
        // Every entry must itself be stored in lowercase or the
        // case-insensitive comparison will silently miss it.
        assert_eq!(
            *p,
            p.to_ascii_lowercase(),
            "WINRT_DENY_PREFIXES entry not lowercased: {p}"
        );
    }
}

/// Pins the size of the WinRT denylist so silent regressions (an entry
/// accidentally deleted during a merge) are caught at test time.
/// Update this number deliberately when adding/removing entries.
#[test]
fn winrt_deny_list_count_pinned() {
    assert_eq!(WINRT_DENY_PREFIXES.len(), 11);
}

/// Boundary-crossing classes (escape / host-modification / persistence /
/// credential theft) MUST be denied.
#[test]
fn winrt_boundary_crossing_classes_denied() {
    // spawn / launch outside the jail
    assert!(is_winrt_class_denied("Windows.System.Launcher.LaunchUriAsync"));
    assert!(is_winrt_class_denied("Windows.System.RemoteLauncher.RemoteLauncher"));
    assert!(is_winrt_class_denied("Windows.System.RemoteDesktop.InteractiveSession"));
    assert!(is_winrt_class_denied("Windows.System.RemoteSystems.RemoteSystem"));
    assert!(is_winrt_class_denied("Windows.ApplicationModel.AppService.AppServiceConnection"));
    assert!(is_winrt_class_denied("Windows.Storage.Pickers.FileOpenPicker"));
    // host modification
    assert!(is_winrt_class_denied("Windows.Management.Deployment.PackageManager"));
    assert!(is_winrt_class_denied("Windows.System.Power.PowerManager"));
    // persistence / delayed execution
    assert!(is_winrt_class_denied("Windows.System.Scheduler.TaskScheduler"));
    assert!(is_winrt_class_denied("Windows.ApplicationModel.Background.BackgroundTaskRegistration"));
    // credential theft
    assert!(is_winrt_class_denied("Windows.Security.Credentials.PasswordVault"));
}

/// Self-arrangement / info-leak / device / network classes are NOT denied —
/// blocking them broke legitimate apps (notepad's UWP host uses
/// CoreApplication) without any containment benefit. This is the M4/#2
/// "block the tunnel, not the bed" stance; these assertions guard against a
/// future over-broad re-expansion of the denylist.
#[test]
fn winrt_self_arrangement_classes_allowed() {
    // The notepad case — UWP app host. Must NOT be blocked.
    assert!(!is_winrt_class_denied("Windows.ApplicationModel.Core.CoreApplication"));
    assert!(!is_winrt_class_denied("Windows.ApplicationModel.Activation.LaunchActivatedEventArgs"));
    // In-process timers / threading — guest arranging its own callbacks.
    assert!(!is_winrt_class_denied("Windows.System.Threading.ThreadPoolTimer"));
    // Device enumeration / sensors — info-leak at most, out of scope; and
    // Devices.Enumeration is used by many ordinary apps.
    assert!(!is_winrt_class_denied("Windows.Devices.Enumeration.DeviceInformation"));
    assert!(!is_winrt_class_denied("Windows.Devices.Bluetooth.BluetoothDevice"));
    // Recon / PII — out of scope per threat model.
    assert!(!is_winrt_class_denied("Windows.System.Diagnostics.ProcessDiagnosticInfo"));
    assert!(!is_winrt_class_denied("Windows.System.Profile.AnalyticsInfo"));
    assert!(!is_winrt_class_denied("Windows.ApplicationModel.Contacts.Contact"));
    // Notifications — GUI, out of scope.
    assert!(!is_winrt_class_denied("Windows.UI.Notifications.ToastNotificationManager"));
    // Network — handled by WFP, not here.
    assert!(!is_winrt_class_denied("Windows.Networking.Sockets.StreamSocket"));
}

// ── CLSID denylist coverage ─────────────────────────────────────────────

#[test]
fn clsid_denylist_count_pinned() {
    assert_eq!(CLSID_DENYLIST.len(), 17);
}

#[test]
fn clsid_mmc20_application_denied() {
    let clsid = guid(0x49B2791A, 0xB1AE, 0x4C90, [0x9B,0x8E,0xE8,0x60,0xBA,0x07,0xF8,0x89]);
    assert_eq!(check_denylist(&clsid), Some(("MMC20.Application", true)));
}

#[test]
fn clsid_shell_browser_window_denied() {
    let clsid = guid(0xC08AFD90, 0xF2A1, 0x11D1, [0x84,0x55,0x00,0xA0,0xC9,0x1F,0x38,0x80]);
    assert_eq!(check_denylist(&clsid), Some(("ShellBrowserWindow", true)));
}

#[test]
fn clsid_script_control_denied() {
    let clsid = guid(0x0E59F1D5, 0x1FBE, 0x11D0, [0x8F,0xF2,0x00,0xA0,0xD1,0x00,0x38,0xBC]);
    assert_eq!(check_denylist(&clsid), Some(("ScriptControl", true)));
}

#[test]
fn clsid_internet_explorer_denied() {
    let clsid = guid(0x0002DF01, 0x0000, 0x0000, [0xC0,0x00,0x00,0x00,0x00,0x00,0x00,0x46]);
    assert_eq!(check_denylist(&clsid), Some(("InternetExplorer.Application", true)));
}

#[test]
fn clsid_benign_not_denied() {
    let clsid = guid(0xDEADBEEF, 0x1234, 0x5678, [0x9A,0xBC,0xDE,0xF0,0x12,0x34,0x56,0x78]);
    assert_eq!(check_denylist(&clsid), None);
}

#[test]
fn clsid_null_not_denied() {
    assert_eq!(check_denylist(std::ptr::null()), None);
}

// ── WMI/WBEM blocked, DENY not kill (bug #88 re-audit) ──────────────────
//
// WbemLocator / WbemScripting.SWbemLocator MUST be blocked in EVERY tier
// (the deny fully prevents the Win32_Process.Create escape). But WMI is
// dual-use — benign tools (tasklist, systeminfo, Get-CimInstance reads) also
// activate the locator — so it is a graceful deny, NOT a fail-stop kill
// (terminate = false). WMI-dependent tools use --guard none.

#[test]
fn wbem_locator_blocked_but_not_killed() {
    let clsid = guid(0x4590F811, 0x1D3A, 0x11D0, [0x89,0x1F,0x00,0xAA,0x00,0x4B,0x2E,0x24]);
    assert_eq!(check_denylist(&clsid), Some(("WbemLocator", false)));
}

#[test]
fn wbem_scripting_locator_blocked_but_not_killed() {
    let clsid = guid(0x76A64158, 0xCB41, 0x11D1, [0x8B,0x02,0x00,0x60,0x08,0x06,0xD9,0xB6]);
    assert_eq!(check_denylist(&clsid), Some(("WbemScripting.SWbemLocator", false)));
}

#[test]
fn spawn_class_clsids_terminate() {
    // Shell / scripting-host / DCOM-lateral classes exist only to spawn or
    // run commands → fail-stop (terminate = true).
    let shell = guid(0x13709620, 0xC279, 0x11CE, [0xA4,0x9E,0x44,0x45,0x53,0x54,0x00,0x00]);
    assert_eq!(check_denylist(&shell), Some(("Shell.Application", true)));
    let wscript = guid(0x72C24DD5, 0xD70A, 0x438B, [0x8A,0x42,0x98,0x42,0x4B,0x88,0xAF,0xB8]);
    assert_eq!(check_denylist(&wscript), Some(("WScript.Shell", true)));
    let sched = guid(0x0F87369F, 0xA4E5, 0x4CFC, [0xBD,0x3E,0x73,0xE6,0x15,0x45,0x72,0xDD]);
    assert_eq!(check_denylist(&sched), Some(("Schedule.Service", true)));
}

#[test]
fn ambiguous_clsids_deny_but_do_not_terminate() {
    // FileSystemObject (hooked file I/O, legit scripts use it) and BITS
    // (benign updaters) are denied but NOT killed — terminate = false.
    let fso = guid(0x0D43FE01, 0xF093, 0x11CF, [0x89,0x40,0x00,0xA0,0xC9,0x05,0x42,0x28]);
    assert_eq!(check_denylist(&fso), Some(("Scripting.FileSystemObject", false)));
    let bits = guid(0x4991D34B, 0x80A1, 0x4291, [0x83,0xB6,0x33,0x28,0x36,0x6B,0x90,0x97]);
    assert_eq!(check_denylist(&bits), Some(("BackgroundCopyManager", false)));
}
