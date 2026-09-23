//! R04 Этап 1 — builds a derived, privilege-reduced token for the guest
//! process. This module ONLY constructs and validates the token handle; it
//! does not call `CreateProcessAsUserW` and does not touch the launch path
//! (see `sandbox::launch_suspended`, `sandbox::launch_prep` for that
//! wiring). See `docs/R04-implementation-plan-t1-light-t2.md`, section
//! "Этап 1. Токен гостя".
//!
//! Split (layout-guard, ≤1000 lines/file) into:
//!   - `mod.rs` (this file) — shared low-level SID/token-buffer helpers,
//!     the `GuestToken` RAII wrapper, and re-exports.
//!   - `build.rs` — `build_guest_token` and everything it needs to
//!     construct the derived token.
//!   - `verify.rs` — `verify_guest_token_shape`, the post-creation check
//!     that inspects a REAL child process token rather than trusting the
//!     request.
//!   - `env_guard.rs` — environment variable sanitization before spawn
//!     (moved in from the former sibling `contain::env_guard`; grouped
//!     here because both concerns are "what the guest process receives at
//!     creation time" — restricted token and scrubbed environment).
//!
//! ## Privilege-removal approach
//!
//! `CreateRestrictedToken`'s `DISABLE_MAX_PRIVILEGE` flag only *disables*
//! privileges (`SE_PRIVILEGE_ENABLED` cleared) — Microsoft documents that a
//! disabled-but-still-present privilege can be re-enabled by the process
//! holding the token
//! (<https://learn.microsoft.com/en-us/windows/win32/secbp/changing-privileges-in-a-token>).
//! `DISABLE_MAX_PRIVILEGE` also makes `PrivilegesToDelete` documented as
//! ignored. So this module does NOT pass `DISABLE_MAX_PRIVILEGE`: instead it
//! queries the source token's actual `TokenPrivileges` and passes every
//! privilege except `SeChangeNotifyPrivilege` as `PrivilegesToDelete` on the
//! `CreateRestrictedToken` call itself. Deletion (vs. disable) removes the
//! privilege from the new token's privilege array entirely — there is
//! nothing left for the guest to re-enable. This was chosen over "build then
//! `AdjustTokenPrivileges(..., SE_PRIVILEGE_REMOVED)`" because it is a single
//! atomic call with no window where an intermediate token exists with the
//! full privilege set, and it doesn't depend on `AdjustTokenPrivileges`
//! silently succeeding (that API can report success while
//! `GetLastError()==ERROR_NOT_ALL_ASSIGNED`, so a second class of failure
//! mode is avoided by not relying on it for the primary removal step).
//!
//! ## Administrators / integrity / owner / DACL handling
//!
//! Ground truth for this environment is documented in the plan's "R04-0"
//! section. For a source token where `BUILTIN\Administrators`
//! (`S-1-5-32-544`) is present AND enabled (not already deny-only) in
//! `TokenGroups` — the actual signal, NOT `TokenElevationType` alone, which
//! can read `Default` for an admin account under some configurations — the
//! derived token additionally:
//!   - gets Administrators disabled (deny-only) via `CreateRestrictedToken`'s
//!     `SidsToDisable`,
//!   - gets its integrity level explicitly lowered to Medium,
//!   - gets `TokenOwner` set to the original `TokenUser` SID,
//!   - gets `TokenDefaultDacl` rewritten to grant only the user SID and
//!     SYSTEM (dropping the Administrators-group ACE the source token's
//!     default DACL carries).
//!
//! For a non-administrative source token (Administrators absent or already
//! not enabled), none of the above four steps run — only the privilege
//! removal applies, per the plan's explicit "close to a no-op" requirement.

use anyhow::{Context, Result};
use std::ffi::c_void;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Security::{GetTokenInformation, PSID};

pub mod env_guard;

mod build;
mod verify;
#[cfg(test)]
mod tests;

pub use build::{administrators_state, build_guest_token};
pub use verify::verify_guest_token_shape;
// Only reached today via the direct `super::verify::try_reenable_privilege`
// path used by the `tests` submodule; kept re-exported at crate visibility
// for any future crate-wide caller, same rationale as the function's own
// `#[allow(dead_code)]` in verify.rs.
#[allow(unused_imports)]
pub(crate) use verify::try_reenable_privilege;

// Not exported by the `windows` crate's `Win32_Security` feature surface used
// here (only the enabled/disabled attribute flags are); values match
// winnt.h verbatim, same pattern `probe.rs` already uses for
// `SE_GROUP_ENABLED`/`SE_GROUP_USE_FOR_DENY_ONLY`. Shared by `build` and
// `verify` (both classify the same Administrators-group attributes).
const SE_GROUP_ENABLED: u32 = 0x0000_0004;
const SECURITY_MANDATORY_MEDIUM_RID: u32 = 0x0000_2000;
const ADMINISTRATORS_SID_STR: &str = "S-1-5-32-544";

/// RAII wrapper owning a derived guest token handle. Closes the handle on
/// drop, following the same pattern as `session_section::SessionSectionHandle`.
pub struct GuestToken {
    handle: HANDLE,
}

impl GuestToken {
    /// Borrow the raw handle (e.g. to pass to `CreateProcessAsUserW` later).
    /// Callers must not close this handle themselves — `GuestToken` owns it.
    pub fn handle(&self) -> HANDLE {
        self.handle
    }
}

impl Drop for GuestToken {
    fn drop(&mut self) {
        if !self.handle.is_invalid() {
            // SAFETY: handle was obtained from CreateRestrictedToken below;
            //         no other code closes it.
            unsafe { CloseHandle(self.handle).ok() };
        }
    }
}

// SAFETY: HANDLE is a raw pointer type but kernel token objects are
//         thread-safe; the handle is opaque to callers.
unsafe impl Send for GuestToken {}
unsafe impl Sync for GuestToken {}

/// Two-step `GetTokenInformation` into an owned buffer — same helper shape as
/// `probe.rs::get_token_info_buf`, duplicated here since it's a different
/// crate module and the task spec says not to import across files. Shared by
/// `build` and `verify` (both read raw token-information structs).
fn get_token_info_buf(
    token: HANDLE,
    class: windows::Win32::Security::TOKEN_INFORMATION_CLASS,
) -> Result<Vec<u8>> {
    let mut needed: u32 = 0;
    // SAFETY: sizing call.
    let _ = unsafe { GetTokenInformation(token, class, None, 0, &mut needed) };
    if needed == 0 {
        anyhow::bail!("GetTokenInformation({class:?}) size query returned 0");
    }
    let mut buf = vec![0u8; needed as usize];
    let mut got: u32 = 0;
    // SAFETY: buf sized to `needed`.
    unsafe {
        GetTokenInformation(
            token,
            class,
            Some(buf.as_mut_ptr() as *mut _),
            needed,
            &mut got,
        )
    }
    .with_context(|| format!("GetTokenInformation({class:?}) failed"))?;
    Ok(buf)
}

/// Shared by `build` (Administrators SID lookup, DACL trustee resolution)
/// and `verify` (Administrators SID lookup on the child token).
fn sid_to_string(sid: PSID) -> Result<String> {
    use windows::Win32::Foundation::{HLOCAL, LocalFree};
    if sid.is_invalid() {
        anyhow::bail!("invalid SID");
    }
    let mut pwstr: *mut u16 = std::ptr::null_mut();
    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn ConvertSidToStringSidW(sid: PSID, stringsid: *mut *mut u16) -> i32;
    }
    // SAFETY: sid is a caller-provided valid SID pointer (checked above).
    let ok = unsafe { ConvertSidToStringSidW(sid, &mut pwstr) };
    if ok == 0 || pwstr.is_null() {
        anyhow::bail!("ConvertSidToStringSidW failed");
    }
    // SAFETY: pwstr is a NUL-terminated wide string from LocalAlloc.
    let s = unsafe {
        let mut len = 0usize;
        while *pwstr.add(len) != 0 {
            len += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(pwstr, len))
    };
    // SAFETY: pwstr came from LocalAlloc; LocalFree is the matched deallocator.
    unsafe {
        let _ = LocalFree(Some(HLOCAL(pwstr as *mut c_void)));
    }
    Ok(s)
}
