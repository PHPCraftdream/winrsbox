use super::*;

// ── R04-1c: launch_suspended now creates the root guest under a
//    privilege-reduced token via CreateProcessAsUserW ──────────────────

/// `launch_suspended` with a harmless real target (`cmd.exe`, same
/// convention `probe.rs::probe_child` uses) must produce a suspended
/// child whose ACTUAL primary token is privilege-reduced — verified the
/// same way `guest_token.rs`'s own tests and `probe.rs` do
/// (`OpenProcessToken` + `GetTokenInformation`, here via
/// `guest_token::verify_guest_token_shape`, the exact function
/// `launch_suspended` itself already ran internally before returning).
/// The child is terminated here without ever being resumed — same
/// cleanup discipline every other suspended-process test in this
/// codebase (`probe.rs::probe_child`) already follows.
#[test]
fn launch_suspended_produces_a_privilege_reduced_child_token() {
    let cwd = std::env::temp_dir();
    let target_args = vec!["cmd.exe".to_string(), "/c".to_string(), "exit".to_string()];
    struct RootEvents {
        handles: [HANDLE; 3],
        _error_buffer: super::launch_prep::InitErrorBuffer,
    }
    impl Drop for RootEvents {
        fn drop(&mut self) {
            std::env::remove_var("FS_SANDBOX_INIT_EVENT");
            std::env::remove_var("FS_SANDBOX_INIT_DEGRADED_EVENT");
            std::env::remove_var("FS_SANDBOX_INIT_ERROR_BUFFER");
            // SAFETY: these are the event handles created by this test.
            unsafe {
                CloseHandle(self.handles[0]).ok();
                CloseHandle(self.handles[1]).ok();
            }
        }
    }
    let error_buffer =
        super::launch_prep::create_init_error_buffer().expect("create init error buffer");
    let events = RootEvents {
        handles: [
            super::launch_prep::create_init_event().expect("create init event"),
            super::launch_prep::create_degraded_event().expect("create degraded event"),
            error_buffer.handle(),
        ],
        _error_buffer: error_buffer,
    };

    let pi = launch_suspended(&cwd, &target_args, crate::GuardLevel::None, events.handles)
        .expect("launch_suspended must succeed for a harmless cmd.exe target");

    // Independent re-verification (launch_suspended already ran this
    // check internally before returning Ok — this proves the guarantee
    // holds from the OUTSIDE too, not just that the internal check ran).
    let mut child_token = HANDLE::default();
    // SAFETY: pi.hProcess is the valid suspended process handle just
    // returned by launch_suspended above; TOKEN_QUERY is read-only.
    let opened = unsafe { OpenProcessToken(pi.hProcess, TOKEN_QUERY, &mut child_token) };

    // Compute the expected shape the same way launch_suspended did: this
    // process's own Administrators-enabled state at the time of launch.
    let own_token_for_check = unsafe {
        let mut t = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut t).ok();
        t
    };
    let source_admin_enabled = guest_token::administrators_state(own_token_for_check)
        .map(|(enabled, _)| enabled)
        .unwrap_or(false);
    unsafe { CloseHandle(own_token_for_check).ok() };

    let verify_result = opened
        .context("OpenProcessToken(child) failed")
        .and_then(|_| guest_token::verify_guest_token_shape(child_token, source_admin_enabled));
    if child_token != HANDLE::default() {
        // SAFETY: child_token was opened by us above (if opened.is_ok()).
        unsafe { CloseHandle(child_token).ok() };
    }

    // Cleanup FIRST (never let an assertion failure leak a live suspended
    // process): terminate, never resume, then close both handles.
    // SAFETY: pi.hProcess/pi.hThread are our own just-created handles;
    // the process is still CREATE_SUSPENDED — TerminateProcess is safe.
    unsafe {
        let _ = TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hThread).ok();
        CloseHandle(pi.hProcess).ok();
    }

    verify_result.expect(
        "child process token must pass verify_guest_token_shape \
             (privilege-reduced, Administrators deny-only if source was admin-enabled)",
    );
}

/// `build_guest_token`'s own failure path (forced via an invalid source
/// token handle) must surface as an `Err` all the way through — this is
/// the failure-surfacing contract `launch_suspended` relies on to abort
/// the launch instead of falling back to an unrestricted token.
/// `launch_suspended` itself always opens a VALID source token
/// internally, so this test exercises the same underlying guarantee one
/// layer down, at the boundary `launch_suspended` depends on — mirroring
/// `guest_token.rs`'s own `build_guest_token_propagates_error_on_invalid_handle`.
#[test]
fn build_guest_token_failure_does_not_panic_and_is_an_err() {
    let bogus = HANDLE(0xDEAD_BEEF_usize as *mut std::ffi::c_void);
    let result = winrsbox::contain::guest::build_guest_token(bogus);
    assert!(
        result.is_err(),
        "build_guest_token must return Err (not panic) for an invalid token handle — \
             this is what makes launch_suspended's '?' on the same call abort the launch \
             instead of silently continuing with an unrestricted token"
    );
}
