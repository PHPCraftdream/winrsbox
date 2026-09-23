//! R04 F4 structural pins for com_guard's install policy: the three primary
//! COM activation exports fail closed (return Err — install_hooks propagates
//! via `install()?` → DllMain FALSE), while the WinRT sibling closures
//! degrade loudly via the buffered install error (S10 degraded-init event).

fn install_body() -> String {
    let src = crate::hooks::module_source("com_guard");
    let start = src.find("pub unsafe fn install()").expect("install() must exist");
    let end = src.find("pub unsafe fn uninstall()").expect("uninstall() must follow install()");
    src[start..end].to_string()
}

/// R04 F4: the primary COM activation exports are a SECURITY.md in-scope
/// promise, and a combase bearing any of them exports all three — so a
/// missing export must abort the install, not silently skip the detour.
#[test]
fn primary_com_exports_fail_closed_on_missing_export() {
    let body = install_body();
    for sym in ["CoCreateInstance", "CoCreateInstanceEx", "CoGetClassObject"] {
        assert!(
            body.contains(&format!("return Err(\"com_guard: combase.dll export {sym} not found\"")),
            "missing {sym} must abort the install (return Err), not log-and-continue"
        );
        assert!(
            !body.contains(&format!("export {sym} not found — skipping")),
            "{sym} must not have a skip arm"
        );
    }
}

/// R04 F4: only the WinRT sibling closures degrade — every one of them is
/// buffered (driving S10's degraded-init event) instead of being swallowed by
/// a silent Warn log.
#[test]
fn winrt_sibling_closures_degrade_via_buffer_not_silent_log() {
    let body = install_body();
    for sym in ["WindowsGetStringRawBuffer", "RoGetActivationFactory", "RoActivateInstance"] {
        assert!(
            body.contains(&format!("\"com_guard: combase.dll export {sym} not found")),
            "missing {sym} must be buffered (drives the S10 degraded-init event), not ipc_log'd"
        );
    }
    assert_eq!(
        body.matches("buffer_install_error").count(),
        3,
        "exactly the three WinRT sibling closures may degrade via buffer_install_error"
    );
    // The old silent path is gone from the installer entirely: every Warn
    // previously went through ipc_log; install() may only keep the Trace log.
    assert!(
        !body.contains("ipc_log(ipc::LogLevel::Warn"),
        "install() must not swallow missing exports via ipc_log(Warn)"
    );
    // Detour creation/enable failures keep propagating via `?`.
    assert!(body.contains("detour init CoCreateInstance:"), "detour init failures must still propagate");
    assert!(body.contains("detour enable CoCreateInstance:"), "detour enable failures must still propagate");
}
