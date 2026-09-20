//! Publishes a `SessionConfig` snapshot via a session-scoped named shared
//! section so hooked processes can recover the pipe name even when their
//! environment has been scrubbed (notably MSYS2's first-run helper children,
//! which inherit an empty env).
//!
//! The section name is RANDOM per session (`Local\WinRsBoxSession-{32 hex}`)
//! and reaches every injected process through the injection channel: the
//! launcher exports it as `FS_SANDBOX_SECTION` before CreateProcessW builds
//! the root target's environment, and every child spawned inside the sandbox
//! has the same variable appended to its environment block cross-process by
//! the spawn hook while the child is still suspended
//! (`hook/src/inject.rs::patch_child_env_section`). A process that never
//! received the name cannot open the section — there is nothing left to
//! guess. Env-scrubbed children stay covered because the patch lands before
//! any guest code runs.
//!
//! The handle returned by [`publish`] MUST be kept alive for the launcher's
//! whole runtime — closing the last handle to a named section destroys it
//! immediately, breaking late-arriving hook readers.

use anyhow::{anyhow, Context, Result};
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use windows::core::{w, PCWSTR};
use windows::Win32::Foundation::{
    CloseHandle, HLOCAL, HANDLE, INVALID_HANDLE_VALUE, LocalFree,
};
use windows::Win32::Security::Cryptography::{
    BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG,
};
use windows::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
use windows::Win32::System::Memory::{
    CreateFileMappingW, MapViewOfFile, OpenFileMappingW, UnmapViewOfFile, FILE_MAP_READ,
    FILE_MAP_WRITE, MEMORY_MAPPED_VIEW_ADDRESS, PAGE_READWRITE,
};

/// RAII guard owning the kernel object behind the session's randomly named
/// section. The section is reclaimed by the kernel when the last handle
/// closes; we hold ours until launcher exit so all child hook DLLs can keep
/// reading.
pub struct SessionSectionHandle {
    handle: HANDLE,
}

impl Drop for SessionSectionHandle {
    fn drop(&mut self) {
        if !self.handle.is_invalid() {
            // SAFETY: handle was obtained from CreateFileMappingW above; no
            //         other code closes it.
            unsafe { CloseHandle(self.handle).ok() };
        }
    }
}

// SAFETY: HANDLE is a raw pointer but kernel objects are thread-safe; the
//         handle is opaque to user code after publish() returns.
unsafe impl Send for SessionSectionHandle {}
unsafe impl Sync for SessionSectionHandle {}

/// Generate a fresh per-session section name:
/// `Local\WinRsBoxSession-{32 lowercase hex}` — 128 bits from the OS CSPRNG
/// (`BCryptGenRandom`), the same entropy budget as the launcher's init-event
/// name and a UUID. The `Local\` prefix scopes the object to this logon
/// session, exactly like the old constant name did.
///
/// Unlike the init-event name there is deliberately NO predictable fallback:
/// a guessable section name is precisely the defect this change removes (a
/// same-user guest could open and rewrite the config), so RNG failure fails
/// the launch instead of degrading security.
pub fn generate_session_section_name() -> Result<String> {
    let mut rand_bytes = [0u8; 16];
    // SAFETY: FFI call to bcrypt!BCryptGenRandom; rand_bytes is a valid
    //         mutable 16-byte slice; BCRYPT_USE_SYSTEM_PREFERRED_RNG means
    //         the algorithm parameter is unused.
    let status = unsafe {
        BCryptGenRandom(None, &mut rand_bytes, BCRYPT_USE_SYSTEM_PREFERRED_RNG)
    };
    if status.0 < 0 {
        anyhow::bail!(
            "BCryptGenRandom failed ({status:?}) — refusing to publish the session \
             section under a guessable name"
        );
    }
    let mut suffix = String::with_capacity(32);
    for b in rand_bytes.iter() {
        use std::fmt::Write;
        let _ = write!(&mut suffix, "{:02x}", b);
    }
    Ok(format!("Local\\WinRsBoxSession-{suffix}"))
}

/// Serialize `cfg` and publish it into a freshly named, random per-session
/// section. Returns the owning handle AND the generated name — the caller
/// MUST deliver the name to every injected child through the injection
/// channel (launcher main.rs exports it as `FS_SANDBOX_SECTION`; the spawn
/// hook patches it into each child's env block cross-process before the
/// child runs). Dropping the handle releases the section.
pub fn publish(cfg: &ipc::SessionConfig) -> Result<(SessionSectionHandle, String)> {
    let name = generate_session_section_name()?;
    let handle = publish_named(&name, cfg)?;
    Ok((handle, name))
}

/// [`publish`] against an explicit section name.
///
/// The name is a parameter rather than a hardcoded constant for two reasons.
/// The immediate one is testability: the squatter check below makes any test
/// that publishes under a shared constant fail whenever ANOTHER process on
/// the machine holds that name — a second `cargo test` in a sibling worktree,
/// a parallel CI job, or a live launcher. That is ambient-state coupling, and
/// it produced exactly that failure once already.
///
/// The second reason is that a per-session random name is now load-bearing
/// (audit 2026-09-19, Critical #3): a name nobody else can guess is what
/// stops a same-user guest from opening and rewriting the config. The name
/// travels only through the injection channel (`FS_SANDBOX_SECTION`, patched
/// into each child's env block before it runs); no code path falls back to
/// the retired constant `ipc::SESSION_CONFIG_SECTION_NAME`.
pub fn publish_named(section_name: &str, cfg: &ipc::SessionConfig) -> Result<SessionSectionHandle> {
    let bytes = cfg
        .to_section_bytes()
        .map_err(|e| anyhow!("session config encode failed: {e}"))?;

    let name_wide: Vec<u16> = OsStr::new(section_name)
        .encode_wide()
        .chain(Some(0))
        .collect();

    // Explicit DACL — DEFENCE IN DEPTH, not the fix. It grants the object
    // owner (the creating user) SECTION_QUERY | SECTION_MAP_READ only, and
    // explicitly denies SECTION_MAP_WRITE to everyone:
    //   D:(D;;0x0002;;;WD)(A;;0x0005;;;OW)
    // An OWNER_RIGHTS ACE also suppresses the owner's implicit WRITE_DAC /
    // READ_CONTROL, so a same-user process cannot simply rewrite the DACL to
    // grant itself write. It does NOT stop a determined same-user guest with
    // admin privileges (SeTakeOwnership / SeDebugPrivilege), and the guest
    // can still READ the config (it is the same user) — the random name is
    // what keeps uninvited processes out; this DACL is what removes the
    // rewrite primitive even when a guest learns the name.
    // The launcher itself needs no post-create write access: it writes the
    // config through the full-access handle CreateFileMappingW returns.
    let sddl = w!("D:(D;;0x0002;;;WD)(A;;0x0005;;;OW)");
    let mut psd = PSECURITY_DESCRIPTOR(std::ptr::null_mut());
    // SAFETY: psd is a valid out-pointer; SDDL_REVISION_1 is the only
    //         documented revision; sddl is a NUL-terminated literal valid
    //         for the duration of the call.
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl,
            SDDL_REVISION_1,
            &mut psd,
            None,
        )
    }
    .context("build session section security descriptor")?;
    let sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: psd.0,
        bInheritHandle: false.into(),
    };

    // The last-error value MUST be captured in the same unsafe block, before
    // anything else runs. `GetLastError` is per-thread and any intervening
    // code — an allocation inside `.context(...)`, a formatting call, the
    // error path of the `windows` binding itself — can overwrite it. Reading
    // it even one statement later produced a test that passed when run alone
    // and failed in the full suite, which is exactly the shape of a latent
    // heisenbug: the value was being clobbered by whatever ran in between.
    //
    // SAFETY: INVALID_HANDLE_VALUE means "backed by the system pagefile"; the
    //         size and name pointer are valid for the duration of the call;
    //         `sa` borrows `psd`, which outlives the call; GetLastError only
    //         reads this thread's last-error slot.
    let (create_result, last_error) = unsafe {
        let r = CreateFileMappingW(
            INVALID_HANDLE_VALUE,
            Some(&sa),
            PAGE_READWRITE,
            0,
            ipc::SESSION_CONFIG_SECTION_SIZE as u32,
            PCWSTR(name_wide.as_ptr()),
        );
        let e = windows::Win32::Foundation::GetLastError();
        (r, e)
    };
    // The kernel copied the security descriptor during the call above, so the
    // SDDL buffer can be released on every path from here on.
    // SAFETY: psd.0 was allocated by
    //         ConvertStringSecurityDescriptorToSecurityDescriptorW above and
    //         is freed exactly once here.
    unsafe { LocalFree(Some(HLOCAL(psd.0))) };

    let handle = create_result.context("CreateFileMappingW for session section")?;

    // Squatter check (audit 2026-09-19, Critical #3).
    //
    // CreateFileMappingW returns a valid handle and sets ERROR_ALREADY_EXISTS
    // when it opened an existing object instead of creating one; this is the
    // only point where the difference is visible. With a random per-session
    // name a collision is vanishingly unlikely, but the check still carries
    // its full weight: a hostile process that LEARNED the name (e.g. by
    // reading an env var out of a compromised child) must not be able to
    // pre-create the object and have the launcher publish into a section the
    // attacker controls.
    //
    // There is no safe recovery: we cannot tell a hostile squatter from a
    // stale object left by a crashed launcher, and guessing wrong in either
    // direction is worse than refusing. Refuse and let the operator resolve it.
    //
    // NOTE: the name and this check confine WHO can open the section at all;
    // the explicit DACL above is what stops an in-session process that knows
    // the name from mapping it for write.
    if last_error == windows::Win32::Foundation::ERROR_ALREADY_EXISTS {
        // SAFETY: handle is the valid handle CreateFileMappingW just returned.
        unsafe { CloseHandle(handle).ok() };
        return Err(anyhow!(
            "session section {} already exists — refusing to publish into an \
             object this launcher did not create. Another winrsbox launcher may \
             still be running; if not, a process in this logon session is \
             squatting the name.",
            section_name
        ));
    }

    // SAFETY: handle is valid (CreateFileMappingW succeeded). Map the entire
    //         section for write access. View is unmapped via the
    //         scoped-guard pattern below so a write failure cannot leak it.
    let view: MEMORY_MAPPED_VIEW_ADDRESS = unsafe {
        MapViewOfFile(
            handle,
            FILE_MAP_WRITE,
            0,
            0,
            ipc::SESSION_CONFIG_SECTION_SIZE,
        )
    };
    if view.Value.is_null() {
        // SAFETY: handle is valid.
        unsafe { CloseHandle(handle).ok() };
        return Err(anyhow!("MapViewOfFile returned null"));
    }

    // SAFETY: view points to a writeable mapping of at least
    //         SESSION_CONFIG_SECTION_SIZE bytes; bytes.len() <= that bound
    //         (enforced by to_section_bytes).
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), view.Value as *mut u8, bytes.len());
    }
    // SAFETY: view was just returned by MapViewOfFile.
    unsafe { UnmapViewOfFile(view).ok() };

    Ok(SessionSectionHandle { handle })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Squatter refusal (audit 2026-09-19, Critical #3).
    ///
    /// Pre-create the section under the real name, then call `publish_named`.
    /// Before the fix it returned Ok and wrote the launcher's config into the
    /// pre-existing object — from then on every hooked process would read a
    /// section the squatter can rewrite, including `pipe_name` and `dll_path`.
    ///
    /// This test necessarily conflicts with `publish_and_read_roundtrip`,
    /// which publishes under the same style of name: if they ran under ONE
    /// shared constant name in parallel, each would be the other's squatter.
    ///
    /// Both tests therefore publish under a UNIQUE name via `publish_named`
    /// rather than a shared constant. An in-process mutex is not enough:
    /// the name lives in the session-wide `Local\` object namespace, so a
    /// second `cargo test` in a sibling worktree, a parallel CI job, or a
    /// live launcher squats on it from another process. That is not
    /// hypothetical — it failed exactly that way once, while a parallel
    /// agent ran the same suite in its own worktree.
    fn unique_section_name(tag: &str) -> String {
        use std::sync::atomic::{AtomicU32, Ordering};
        static SEQ: AtomicU32 = AtomicU32::new(0);
        format!(
            r"Local\WinRsBoxSessionTest-{}-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed),
            tag
        )
    }

    fn test_cfg(pipe_suffix: &str, trace: bool) -> ipc::SessionConfig {
        ipc::SessionConfig {
            pipe_name: format!(r"\\.\pipe\winrsbox-{pipe_suffix}-{}", std::process::id()),
            dll_path: r"D:\bin\hook.dll".into(),
            cwd: r"D:\sandbox".into(),
            sandbox_root: r"D:\sandbox_root".into(),
            overlay_roots: vec![],
            trace,
            guard: "scan".into(),
            allow_rwx: false,
            disable_hooks: String::new(),
        }
    }

    fn open_read(name: &str) -> Result<HANDLE> {
        let name_wide: Vec<u16> = OsStr::new(name)
            .encode_wide()
            .chain(Some(0))
            .collect();
        // SAFETY: name_wide is a null-terminated UTF-16 name; no inheritance.
        unsafe { OpenFileMappingW(FILE_MAP_READ.0, false, PCWSTR(name_wide.as_ptr())) }
            .map_err(|e| anyhow!("OpenFileMappingW({name}) failed: {e}"))
    }

    #[test]
    fn publish_refuses_when_the_name_is_already_taken() {
        let section = unique_section_name("squat");
        let name_wide: Vec<u16> = OsStr::new(&section)
            .encode_wide()
            .chain(Some(0))
            .collect();
        // SAFETY: pagefile-backed section, valid name pointer, size matches the
        // constant the launcher uses.
        let squatter = unsafe {
            CreateFileMappingW(
                INVALID_HANDLE_VALUE,
                None,
                PAGE_READWRITE,
                0,
                ipc::SESSION_CONFIG_SECTION_SIZE as u32,
                PCWSTR(name_wide.as_ptr()),
            )
            .expect("squatter section must be creatable")
        };

        let cfg = test_cfg("squat-test", false);
        // `SessionSectionHandle` is not Debug, so match rather than expect_err.
        let err = match publish_named(&section, &cfg) {
            Err(e) => e,
            Ok(_) => panic!("publish must refuse a pre-existing section"),
        };
        assert!(
            err.to_string().contains("already exists"),
            "unexpected error: {err}"
        );

        // SAFETY: squatter is the handle created above and not closed yet.
        unsafe { CloseHandle(squatter).ok() };
    }

    #[test]
    fn publish_and_read_roundtrip() {
        let section = unique_section_name("roundtrip");
        let cfg = test_cfg("roundtrip-test", true);
        let _h = publish_named(&section, &cfg).expect("publish ok");

        // Read it back via OpenFileMappingW + MapViewOfFile.
        let reader = open_read(&section).expect("OpenFileMappingW");
        let view = unsafe {
            MapViewOfFile(
                reader,
                FILE_MAP_READ,
                0,
                0,
                ipc::SESSION_CONFIG_SECTION_SIZE,
            )
        };
        assert!(!view.Value.is_null());
        let slice = unsafe {
            std::slice::from_raw_parts(
                view.Value as *const u8,
                ipc::SESSION_CONFIG_SECTION_SIZE,
            )
        };
        let dec = ipc::SessionConfig::from_section_bytes(slice).unwrap();
        assert_eq!(dec.pipe_name, cfg.pipe_name);
        assert_eq!(dec.dll_path, cfg.dll_path);
        assert!(dec.trace);
        unsafe { UnmapViewOfFile(view).ok() };
        unsafe { CloseHandle(reader).ok() };
    }

    /// The random name is the whole security argument: it must differ per
    /// call, carry 128 bits of OS entropy, and never equal the retired
    /// constant. Old behaviour: a fixed `Local\WinRsBoxSession` known to
    /// every process in the logon session.
    #[test]
    fn generated_names_are_random_and_unguessable() {
        let a = generate_session_section_name().expect("name 1");
        let b = generate_session_section_name().expect("name 2");
        assert_ne!(a, b, "two sessions (or two publishes) must never share a name");
        assert_ne!(a, ipc::SESSION_CONFIG_SECTION_NAME);
        assert_ne!(b, ipc::SESSION_CONFIG_SECTION_NAME);
        let prefix = "Local\\WinRsBoxSession-";
        for name in [&a, &b] {
            assert!(
                name.starts_with(prefix),
                "unexpected name shape: {name}"
            );
            let suffix = &name[prefix.len()..];
            assert_eq!(suffix.len(), 32, "128 bits as 32 hex chars: {name}");
            assert!(
                suffix.bytes().all(|c| c.is_ascii_hexdigit()
                    && !c.is_ascii_uppercase()),
                "suffix must be lowercase hex: {name}"
            );
        }
    }

    /// THE acceptance property: a process that did NOT receive the random
    /// name through the injection channel cannot find this session's config
    /// by guessing the old constant. Old behaviour: `publish` wrote the
    /// config under `Local\WinRsBoxSession`, so the guess was guaranteed to
    /// hit OUR object, writable by the guessing guest.
    ///
    /// If a stale launcher from an OLD build still holds a section under the
    /// legacy name on this machine, opening it may succeed — the invariant
    /// that must hold either way is that it is not THIS test's config.
    #[test]
    fn non_injected_process_cannot_find_the_section_via_the_legacy_constant() {
        let cfg = test_cfg("guess-test", false);
        let (_handle, name) = publish(&cfg).expect("publish ok");

        assert_ne!(name, ipc::SESSION_CONFIG_SECTION_NAME);

        match open_read(ipc::SESSION_CONFIG_SECTION_NAME) {
            Err(_) => {
                // Expected on a clean machine: nothing is published under a
                // guessable name, so the guess finds nothing at all.
            }
            Ok(reader) => {
                // A legacy object exists (old launcher still running). The
                // guesser may map it — but it must not decode to OUR config,
                // because OUR config lives under the unguessable name.
                let view = unsafe {
                    MapViewOfFile(
                        reader,
                        FILE_MAP_READ,
                        0,
                        0,
                        ipc::SESSION_CONFIG_SECTION_SIZE,
                    )
                };
                assert!(!view.Value.is_null());
                let slice = unsafe {
                    std::slice::from_raw_parts(
                        view.Value as *const u8,
                        ipc::SESSION_CONFIG_SECTION_SIZE,
                    )
                };
                match ipc::SessionConfig::from_section_bytes(slice) {
                    Ok(dec) => assert_ne!(
                        dec.pipe_name, cfg.pipe_name,
                        "our config must not be reachable via the legacy constant"
                    ),
                    Err(_) => { /* not even a valid session section — fine */ }
                }
                unsafe { UnmapViewOfFile(view).ok() };
                unsafe { CloseHandle(reader).ok() };
            }
        }
    }

    /// The explicit DACL is defence in depth: it must DENY
    /// SECTION_MAP_WRITE to the owner (the same user the guest runs as) —
    /// with ACCESS_DENIED, proving the denial comes from the DACL and not
    /// from the object being absent — while keeping the legitimate
    /// read-only path (hook children) working. Old behaviour: default DACL,
    /// so a same-user write open succeeded and could rewrite the config.
    #[test]
    fn dacl_denies_write_and_allows_read_to_the_owner() {
        let section = unique_section_name("dacl");
        let cfg = test_cfg("dacl-test", false);
        let _h = publish_named(&section, &cfg).expect("publish ok");

        let name_wide: Vec<u16> = OsStr::new(&section)
            .encode_wide()
            .chain(Some(0))
            .collect();
        // SAFETY: name_wide is a null-terminated UTF-16 name; no inheritance.
        let denied = unsafe {
            OpenFileMappingW(FILE_MAP_WRITE.0, false, PCWSTR(name_wide.as_ptr()))
        };
        match denied {
            Ok(h) => {
                unsafe { CloseHandle(h).ok() };
                panic!("the explicit DACL must deny SECTION_MAP_WRITE to the owner");
            }
            Err(e) => {
                assert_eq!(
                    e.code(),
                    windows::core::HRESULT::from_win32(
                        windows::Win32::Foundation::ERROR_ACCESS_DENIED.0
                    ),
                    "write open must fail with ACCESS_DENIED, got: {e}"
                );
            }
        }

        // The legitimate reader path stays open (hooks map read-only).
        let reader = open_read(&section).expect("read open must remain allowed");
        let view = unsafe {
            MapViewOfFile(
                reader,
                FILE_MAP_READ,
                0,
                0,
                ipc::SESSION_CONFIG_SECTION_SIZE,
            )
        };
        assert!(!view.Value.is_null());
        let slice = unsafe {
            std::slice::from_raw_parts(
                view.Value as *const u8,
                ipc::SESSION_CONFIG_SECTION_SIZE,
            )
        };
        let dec = ipc::SessionConfig::from_section_bytes(slice).expect("decode");
        assert_eq!(dec.pipe_name, cfg.pipe_name);
        unsafe { UnmapViewOfFile(view).ok() };
        unsafe { CloseHandle(reader).ok() };
    }
}
