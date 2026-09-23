//! R04 F4 structural pins for shell_guard's install policy: all four
//! ShellExecute* exports fail closed on missing export (the ShellExecute verb
//! allow-list is a documented SECURITY.md containment behavior, so a missing
//! export must abort the install, not degrade silently).

fn install_body() -> String {
    let src = crate::hooks::module_source("shell_guard");
    let start = src.find("pub unsafe fn install()").expect("install() must exist");
    let end = src.find("pub unsafe fn uninstall()").expect("uninstall() must follow install()");
    src[start..end].to_string()
}

/// R04 F4: shell32 has exported all four since Win95 and the ShellExecute
/// verb allow-list is documented SECURITY.md behavior — a missing export must
/// abort the install rather than leave the shell escape path unguarded.
#[test]
fn shell_execute_exports_fail_closed_on_missing_export() {
    let body = install_body();
    for sym in ["ShellExecuteW", "ShellExecuteExW", "ShellExecuteA", "ShellExecuteExA"] {
        assert!(
            body.contains(&format!("return Err(\"shell_guard: shell32 export {sym} not found\"")),
            "missing {sym} must abort the install (return Err), not log-and-continue"
        );
        assert!(
            !body.contains(&format!("export {sym} not found — skipping")),
            "{sym} must not have a skip arm"
        );
    }
    assert!(
        !body.contains("ipc_log(ipc::LogLevel::Warn"),
        "install() must not swallow missing exports via ipc_log(Warn)"
    );
    assert!(body.contains("detour init ShellExecuteW:"), "detour init failures must still propagate");
}
