use super::*;

#[test]
#[serial]
fn strict_blocks_alpc_com_activation() {
    // Bug #88 re-audit: the generic \RPC Control\OLE<hex> DCOM object-exporter
    // port is ALWAYS blocked (including scan). Allowing it lets
    // Win32_Process.Create — a method call over the same DCOM channel — spawn
    // arbitrary host processes via the un-hooked wmiprvse.exe. Read-only WMI
    // cannot be distinguished from write-methods at the ALPC layer, so there is
    // no safe partial allow; WMI-dependent tools must use --guard none.
    let r = run_payload("escape_alpc_com", "scan");
    assert_eq!(r.status.code(), Some(5),
        "escape_alpc_com should exit 5 (blocked)\nstderr: {}", r.stderr);
}

#[test]
#[serial]
fn strict_blocks_token_privilege_enable() {
    let r = run_payload("escape_token_priv", "scan");
    assert_eq!(r.status.code(), Some(5),
        "escape_token_priv should exit 5 (blocked)\nstderr: {}", r.stderr);
}

#[test]
#[serial]
fn strict_blocks_token_open_foreign() {
    // NtOpenProcessTokenEx on explorer.exe with TOKEN_DUPLICATE
    let r = run_payload("escape_token_open", "scan");
    assert_eq!(r.status.code(), Some(5),
        "escape_token_open should exit 5 (blocked)\nstderr: {}", r.stderr);
}

#[test]
#[serial]
fn strict_blocks_token_duplicate_primary() {
    // NtDuplicateToken with TokenPrimary type
    let r = run_payload("escape_token_duplicate", "scan");
    assert_eq!(r.status.code(), Some(5),
        "escape_token_duplicate should exit 5 (blocked)\nstderr: {}", r.stderr);
}

#[test]
#[serial]
fn allows_self_token_impersonation() {
    // NtSetInformationThread(ThreadImpersonationToken) on the CURRENT thread
    // with the process's OWN token (OpenProcessToken(GetCurrentProcess())).
    //
    // token_guard policy (see hook/src/token_guard.rs): self-impersonation —
    // NtCurrentThread pseudo-handle or a handle to one of our own threads —
    // is ALLOWED, because the token can only be our own process token (no
    // privilege escalation) and Schannel/TLS + the .NET networking stack
    // legitimately do it during a TLS handshake. Blocking it broke HTTPS
    // under the sandbox. The real escalation vector — impersonating a FOREIGN
    // token — is blocked upstream at NtOpenProcessTokenEx (escape_token_open)
    // and NtImpersonateThread on foreign threads (escape_impersonate_thread).
    //
    // So this payload (own token + own thread) must be ALLOWED: exit 0.
    // (exit 5 would be a regression — self-impersonation blocked again.)
    let r = run_payload("escape_token_impersonate", "scan");
    assert_eq!(r.status.code(), Some(0),
        "self-impersonation with own process token must be ALLOWED \
         (exit 0); got {:?} — if exit 5, the allow-self token_guard policy \
         regressed.\nstderr: {}", r.status.code(), r.stderr);
}

#[test]
#[serial]
fn strict_blocks_impersonate_thread() {
    // NtImpersonateThread on foreign (explorer) thread
    let r = run_payload("escape_impersonate_thread", "scan");
    assert_eq!(r.status.code(), Some(5),
        "escape_impersonate_thread should exit 5 (blocked)\nstderr: {}", r.stderr);
}

#[test]
#[serial]
fn strict_blocks_open_thread_token() {
    // NtOpenThreadTokenEx on foreign thread with TOKEN_IMPERSONATE
    let r = run_payload("escape_open_thread_token", "scan");
    assert_eq!(r.status.code(), Some(5),
        "escape_open_thread_token should exit 5 (blocked)\nstderr: {}", r.stderr);
}

#[test]
#[serial]
fn strict_blocks_pipe_scm() {
    let r = run_payload("escape_pipe_scm", "scan");
    assert_eq!(r.status.code(), Some(5),
        "SCM pipe should be blocked\nstderr: {}", r.stderr);
}

// ═══════════════════════════════════════════════════════════════════════════
// COM guard: out-of-proc COM activation escape
// ═══════════════════════════════════════════════════════════════════════════

#[test]
#[serial]
fn strict_blocks_com_shell() {
    let r = run_payload("escape_com_shell", "scan");
    assert_eq!(r.status.code(), Some(EXIT_FAIL_STOP),
        "Shell.Application CoCreateInstance is escape-class: the payload must be \
         terminated, not handed an error\nstderr: {}", r.stderr);
}

#[test]
#[serial]
fn strict_blocks_com_wscript() {
    let r = run_payload("escape_com_wscript", "scan");
    assert_eq!(r.status.code(), Some(EXIT_FAIL_STOP),
        "WScript.Shell CoCreateInstance is escape-class: the payload must be \
         terminated, not handed an error\nstderr: {}", r.stderr);
}

#[test]
#[serial]
fn strict_blocks_com_wmi() {
    // Bug #88 re-audit: WbemLocator / WbemScripting.SWbemLocator activation is
    // ALWAYS blocked (including scan). Allowing it to enable read-only WMI also
    // exposes Win32_Process.Create over the same DCOM proxy (full escape via the
    // un-hooked wmiprvse.exe). No safe partial allow exists.
    let r = run_payload("escape_com_wmi", "scan");
    assert_eq!(r.status.code(), Some(5),
        "WbemLocator CoCreateInstance should be blocked\nstderr: {}", r.stderr);
}

#[test]
#[serial]
fn strict_blocks_com_taskscheduler() {
    let r = run_payload("escape_com_taskscheduler", "scan");
    assert_eq!(r.status.code(), Some(EXIT_FAIL_STOP),
        "Schedule.Service CoCreateInstance is escape-class: the payload must be \
         terminated, not handed an error\nstderr: {}", r.stderr);
}

#[test]
#[serial]
fn strict_blocks_com_classobject() {
    let r = run_payload("escape_com_classobject", "scan");
    assert_eq!(r.status.code(), Some(EXIT_FAIL_STOP),
        "Shell.Application CoGetClassObject is escape-class: the payload must be \
         terminated, not handed an error\nstderr: {}", r.stderr);
}

#[test]
#[serial]
fn strict_blocks_pipe_impersonate() {
    let r = run_payload("escape_pipe_impersonate", "scan");
    let code = r.status.code();
    if code == Some(7) || code == Some(8) {
        eprintln!("setup failure (CreateNamedPipe/Connect), skipping");
        return;
    }
    assert_eq!(code, Some(5),
        "ImpersonateNamedPipeClient should be blocked\nstderr: {}", r.stderr);
}
