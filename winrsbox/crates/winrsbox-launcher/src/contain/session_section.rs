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
//! (`hook/src/inject.rs::patch_child_env_pairs`). A process that never
//! received the name cannot open the section — there is nothing left to
//! guess. Env-scrubbed children stay covered because the patch lands before
//! any guest code runs.
//!
//! The handle returned by [`publish`] MUST be kept alive for the launcher's
//! whole runtime — closing the last handle to a named section destroys it
//! immediately, breaking late-arriving hook readers.
//!
//! Also houses the MP-1 folder-level counterparts
//! (`docs/multiprocess-broker-plan.md`) that share this exact "named
//! section, random name, owner-RW/everyone-read DACL" shape: [`FolderSection`]
//! (the RAII owner around `ipc::FolderSectionView`'s layout) and
//! `broker.json` ([`BrokerJson`]/[`write_broker_json`]/[`read_broker_json`]),
//! the state-dir file a joining launcher reads to find the broker.

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{
    CloseHandle, DuplicateHandle, DUPLICATE_HANDLE_OPTIONS, HLOCAL, HANDLE, INVALID_HANDLE_VALUE,
    LocalFree,
};
use windows::Win32::Security::Cryptography::{
    BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG,
};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
    SDDL_REVISION_1,
};
use windows::Win32::Security::{
    GetTokenInformation, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_ADJUST_DEFAULT,
    TOKEN_ADJUST_SESSIONID, TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_QUERY, TOKEN_USER,
    TokenUser,
};
use windows::Win32::System::Memory::{
    CreateFileMappingW, MapViewOfFile, UnmapViewOfFile,
    FILE_MAP_WRITE, MEMORY_MAPPED_VIEW_ADDRESS, PAGE_READWRITE, SECTION_MAP_READ,
    SECTION_MAP_WRITE, SECTION_QUERY,
};
#[cfg(test)]
use windows::Win32::System::Memory::{OpenFileMappingW, FILE_MAP_READ};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

pub(crate) fn current_user_sid_string() -> Result<String> {
    let mut token = HANDLE::default();
    // SAFETY: GetCurrentProcess is a pseudo-handle; TOKEN_QUERY is read-only.
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }
        .context("OpenProcessToken for session-section owner failed")?;

    let result = (|| {
        let mut needed = 0u32;
        // SAFETY: the null buffer is the documented size-query call.
        let _ = unsafe { GetTokenInformation(token, TokenUser, None, 0, &mut needed) };
        anyhow::ensure!(needed >= std::mem::size_of::<TOKEN_USER>() as u32);
        let words = (needed as usize).div_ceil(std::mem::size_of::<usize>());
        let mut buffer = vec![0usize; words];
        // SAFETY: buffer is aligned and has at least `needed` writable bytes.
        unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                Some(buffer.as_mut_ptr().cast()),
                needed,
                &mut needed,
            )
        }
        .context("GetTokenInformation(TokenUser) failed")?;
        // SAFETY: successful TokenUser query filled a TOKEN_USER at buffer start.
        let user = unsafe { &*(buffer.as_ptr().cast::<TOKEN_USER>()) };
        let mut sid = PWSTR::null();
        // SAFETY: user.User.Sid is the valid SID returned in the token buffer.
        unsafe { ConvertSidToStringSidW(user.User.Sid, &mut sid) }
            .context("ConvertSidToStringSidW(TokenUser) failed")?;
        anyhow::ensure!(!sid.0.is_null(), "ConvertSidToStringSidW returned null");
        let mut length = 0usize;
        // SAFETY: ConvertSidToStringSidW returns a null-terminated string.
        unsafe {
            while *sid.0.add(length) != 0 {
                length += 1;
            }
        }
        let value = unsafe { String::from_utf16_lossy(std::slice::from_raw_parts(sid.0, length)) };
        // SAFETY: sid is allocated by ConvertSidToStringSidW.
        unsafe { LocalFree(Some(HLOCAL(sid.0.cast()))) };
        Ok(value)
    })();

    // SAFETY: token was opened above and is closed exactly once.
    unsafe { CloseHandle(token).ok() };
    result
}

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
/// 128 bits of OS CSPRNG entropy (`BCryptGenRandom`) as 32 lowercase hex
/// chars. Shared by every per-folder-object random-name generator (session
/// section, folder section, ...) — a guessable name is exactly the defect
/// each of these random names removes, so there is deliberately NO
/// predictable fallback: RNG failure fails the caller instead of degrading
/// security.
pub(crate) fn random_hex_suffix() -> Result<String> {
    let mut rand_bytes = [0u8; 16];
    // SAFETY: FFI call to bcrypt!BCryptGenRandom; rand_bytes is a valid
    //         mutable 16-byte slice; BCRYPT_USE_SYSTEM_PREFERRED_RNG means
    //         the algorithm parameter is unused.
    let status = unsafe {
        BCryptGenRandom(None, &mut rand_bytes, BCRYPT_USE_SYSTEM_PREFERRED_RNG)
    };
    if status.0 < 0 {
        anyhow::bail!(
            "BCryptGenRandom failed ({status:?}) — refusing to publish a shared \
             object under a guessable name"
        );
    }
    let mut suffix = String::with_capacity(32);
    for b in rand_bytes.iter() {
        use std::fmt::Write;
        let _ = write!(&mut suffix, "{:02x}", b);
    }
    Ok(suffix)
}

/// Generate a fresh per-session section name:
/// `Local\WinRsBoxSession-{32 lowercase hex}` — 128 bits from the OS CSPRNG,
/// the same entropy budget as the launcher's init-event name and a UUID.
/// The `Local\` prefix scopes the object to this logon session, exactly
/// like the old constant name did.
///
/// Unlike the init-event name there is deliberately NO predictable fallback:
/// a guessable section name is precisely the defect this change removes (a
/// same-user guest could open and rewrite the config), so RNG failure fails
/// the launch instead of degrading security.
pub fn generate_session_section_name() -> Result<String> {
    Ok(format!("Local\\WinRsBoxSession-{}", random_hex_suffix()?))
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
/// Create a named, pagefile-backed section whose DACL denies
/// `SECTION_MAP_WRITE` to Everyone and grants `SECTION_QUERY |
/// SECTION_MAP_READ` to the current token's owner SID, and refuses (closing
/// the handle) if `name` was already taken by another object — see
/// `publish_named`'s doc for the squatter threat this defends against. The
/// handle this function returns is granted full requested access (RW)
/// regardless of the DACL: Windows grants the creating handle the access it
/// asked for independently of the security descriptor it just installed.
///
/// Shared by every named section this crate publishes with this exact
/// access shape (session section, folder section, ...) so the DACL/SDDL
/// construction and the squatter check are not duplicated per caller.
pub(crate) fn create_owned_readonly_section(name: &str, size: u32) -> Result<HANDLE> {
    let name_wide: Vec<u16> = OsStr::new(name).encode_wide().chain(Some(0)).collect();

    // The random name gates disclosure; this DACL denies map-write and grants
    // read/query to TokenUser. Explicit owner SID keeps restricted guests
    // independent of the elevated launcher token default owner.
    let user_sid = current_user_sid_string()?;
    let sddl = format!("O:{user_sid}D:(D;;0x0002;;;WD)(A;;0x0005;;;OW)");
    let sddl_wide: Vec<u16> = OsStr::new(&sddl)
        .encode_wide()
        .chain(Some(0))
        .collect();
    let mut psd = PSECURITY_DESCRIPTOR(std::ptr::null_mut());
    // SAFETY: psd is a valid out-pointer; sddl_wide is NUL-terminated and
    //         remains alive for the conversion call.
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl_wide.as_ptr()),
            SDDL_REVISION_1,
            &mut psd,
            None,
        )
    }
    .context("build named section security descriptor")?;
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
            size,
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

    let handle = create_result.context("CreateFileMappingW for named section")?;

    // Squatter check (audit 2026-09-19, Critical #3).
    //
    // CreateFileMappingW returns a valid handle and sets ERROR_ALREADY_EXISTS
    // when it opened an existing object instead of creating one; this is the
    // only point where the difference is visible. With a random per-object
    // name a collision is vanishingly unlikely, but the check still carries
    // its full weight: a hostile process that LEARNED the name (e.g. by
    // reading an env var out of a compromised child) must not be able to
    // pre-create the object and have the caller publish into a section the
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
            "section {} already exists — refusing to publish into an object \
             this process did not create. Another winrsbox process may still \
             be running; if not, a process in this logon session is \
             squatting the name.",
            name
        ));
    }

    Ok(handle)
}

pub fn publish_named(section_name: &str, cfg: &ipc::SessionConfig) -> Result<SessionSectionHandle> {
    let bytes = cfg
        .to_section_bytes()
        .map_err(|e| anyhow!("session config encode failed: {e}"))?;

    let handle = create_owned_readonly_section(section_name, ipc::SESSION_CONFIG_SECTION_SIZE as u32)?;

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

// ─── Folder section (MP-1) ──────────────────────────────────────────────────

/// Read-only access mask a guest's duplicated section handle gets:
/// `SECTION_QUERY | SECTION_MAP_READ`.
pub const FOLDER_SECTION_READ_ACCESS: u32 = SECTION_QUERY.0 | SECTION_MAP_READ.0;
/// Read-write access mask a joining launcher's duplicated section handle
/// gets.
pub const FOLDER_SECTION_RW_ACCESS: u32 = SECTION_QUERY.0 | SECTION_MAP_READ.0 | SECTION_MAP_WRITE.0;

/// Generate a fresh per-folder section name: `Local\WinRsBoxFolder-{32
/// lowercase hex}` — same entropy budget and unguessability rationale as
/// [`generate_session_section_name`].
pub fn generate_folder_section_name() -> Result<String> {
    Ok(format!("Local\\WinRsBoxFolder-{}", random_hex_suffix()?))
}

/// Generate a fresh broker pipe name: `\\.\pipe\fs-sandbox-{32 lowercase
/// hex}` — same entropy budget and unguessability rationale as
/// [`generate_session_section_name`]. Unlike the old `fs-sandbox-<pid>`
/// scheme, a guest cannot precompute this name (the broker's PID is public —
/// visible via `broker.json`/Task Manager — but the name is not): a guest
/// racing to pre-create a pipe under the predicted name before the real
/// broker/failover winner does would win `FILE_FLAG_FIRST_PIPE_INSTANCE` and
/// make the legitimate broker's bind fail (fatal — MP-10 §A / plan's "Что не
/// делаем" adjacent finding).
pub fn random_pipe_name() -> Result<String> {
    Ok(format!(r"\\.\pipe\fs-sandbox-{}", random_hex_suffix()?))
}

/// RAII owner of the folder section's kernel object and this process's
/// mapped view. The handle/view MUST be kept alive for the broker's whole
/// runtime — closing the last handle destroys the section immediately,
/// breaking every launcher/guest reader.
pub struct FolderSection {
    handle: HANDLE,
    view: MEMORY_MAPPED_VIEW_ADDRESS,
}

impl FolderSection {
    /// Create a fresh, randomly-named folder section: RW-mapped for this
    /// (broker) process, read-only for anyone else in the session (DACL via
    /// [`create_owned_readonly_section`]). The caller must call
    /// [`view`](Self::view)`.`[`init`](ipc::FolderSectionView::init) before
    /// publishing `name` to any other process. Returns the owner and the
    /// generated name (the caller writes it into `broker.json`).
    pub fn create() -> Result<(Self, String)> {
        let name = generate_folder_section_name()?;
        let handle = create_owned_readonly_section(&name, ipc::FOLDER_SECTION_SIZE as u32)?;
        // SAFETY: handle was just created with RW access (granted
        //         independently of the DACL, per
        //         `create_owned_readonly_section`'s doc); FILE_MAP_WRITE
        //         maps the entire section read-write for this process.
        let view: MEMORY_MAPPED_VIEW_ADDRESS =
            unsafe { MapViewOfFile(handle, FILE_MAP_WRITE, 0, 0, ipc::FOLDER_SECTION_SIZE) };
        if view.Value.is_null() {
            // SAFETY: handle is valid (CreateFileMappingW succeeded above).
            unsafe { CloseHandle(handle).ok() };
            return Err(anyhow!("MapViewOfFile returned null for folder section {name}"));
        }
        Ok((Self { handle, view }, name))
    }

    /// Wrap an ALREADY-duplicated, RW-accessible section handle (e.g.
    /// `AttachedFolder::folder_section_handle`, duplicated into this process
    /// by the broker's `Attach` response with [`FOLDER_SECTION_RW_ACCESS`])
    /// instead of creating a brand new kernel section object via
    /// [`create`](Self::create). MP-7: the failover winner reuses the SAME
    /// folder section every client already held a working RW handle to —
    /// there is exactly one folder section per folder for the folder's
    /// whole lifetime (see the architecture table), so wrapping, never
    /// creating a second one, is the correct move. Maps the whole section
    /// for RW and takes ownership of `handle` on success (closed on Drop,
    /// same as `create`); on failure `handle` is left untouched — the
    /// caller still owns it and decides what to do (this mirrors every
    /// other best-effort handle-cleanup path in this module: a failure this
    /// deep into folder-object plumbing is not escalated further).
    pub fn from_duplicated_handle(handle: HANDLE) -> Result<Self> {
        // SAFETY: handle is a valid, still-open section handle with at
        //         least SECTION_MAP_WRITE access — the caller's contract
        //         (exactly what FOLDER_SECTION_RW_ACCESS grants).
        let view: MEMORY_MAPPED_VIEW_ADDRESS =
            unsafe { MapViewOfFile(handle, FILE_MAP_WRITE, 0, 0, ipc::FOLDER_SECTION_SIZE) };
        if view.Value.is_null() {
            return Err(anyhow!(
                "MapViewOfFile returned null for a duplicated folder section handle"
            ));
        }
        Ok(Self { handle, view })
    }

    /// A view over the mapped payload. Cheap, `Copy`, safe to hand to any
    /// thread as long as `self` outlives every use of it (Drop below unmaps
    /// the memory `view` points into).
    pub fn view(&self) -> ipc::FolderSectionView {
        // SAFETY: `self.view.Value` points to `FOLDER_SECTION_SIZE` bytes of
        //         RW-mapped memory that stays valid for `self`'s lifetime
        //         (Drop unmaps it, not before); page-aligned per
        //         `MapViewOfFile`'s contract, which satisfies
        //         `FolderSectionView::new`'s alignment requirement.
        unsafe { ipc::FolderSectionView::new(self.view.Value.cast()) }
    }

    /// Duplicate the section handle into `target_process`'s handle table
    /// with exactly `access` rights — [`FOLDER_SECTION_READ_ACCESS`] for a
    /// guest, [`FOLDER_SECTION_RW_ACCESS`] for a joining launcher. Like
    /// `FolderJob::duplicate_into` (`contain::jobctl`), the returned
    /// `HANDLE` value is only meaningful inside `target_process`.
    pub fn duplicate_into(&self, target_process: HANDLE, access: u32) -> Result<HANDLE> {
        let mut dup = HANDLE::default();
        // SAFETY: self.handle is a valid section handle owned by this
        //         process; target_process must be a valid, open process
        //         handle (caller's contract); dup is a valid out-pointer.
        unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                self.handle,
                target_process,
                &mut dup,
                access,
                false,
                DUPLICATE_HANDLE_OPTIONS(0),
            )
        }
        .context("DuplicateHandle(folder section -> target process)")?;
        Ok(dup)
    }
}

impl Drop for FolderSection {
    fn drop(&mut self) {
        if !self.view.Value.is_null() {
            // SAFETY: view was returned by MapViewOfFile in create() and is
            //         unmapped exactly once here.
            unsafe { UnmapViewOfFile(self.view).ok() };
        }
        if !self.handle.is_invalid() {
            // SAFETY: handle was created by CreateFileMappingW (via
            //         create_owned_readonly_section) and is closed exactly
            //         once here.
            unsafe { CloseHandle(self.handle).ok() };
        }
    }
}

// SAFETY: HANDLE/MEMORY_MAPPED_VIEW_ADDRESS carry no thread affinity; every
//         access goes through documented kernel calls or the
//         volatile/atomic-safe `ipc::FolderSectionView` API.
unsafe impl Send for FolderSection {}
unsafe impl Sync for FolderSection {}

// ─── broker.json (MP-1) ──────────────────────────────────────────────────────

pub const BROKER_JSON_VERSION: u32 = 1;
pub const BROKER_JSON_FILE_NAME: &str = "broker.json";

/// The state-dir entry point for a joining launcher: broker identity, pipe
/// name and folder-section name. Not a secret — the actual connection is
/// authenticated by the kernel (job membership, SID, image path — MP-3),
/// not by knowledge of this file's contents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrokerJson {
    pub version: u32,
    pub broker_pid: u32,
    pub broker_create_time: u64,
    pub pipe_name: String,
    pub folder_section_name: String,
    pub generation: u64,
}

/// Write `doc` to `path` atomically: encode to a sibling `.tmp` file, then
/// `rename` over the destination (Windows `MoveFileExW` with
/// `MOVEFILE_REPLACE_EXISTING`, same tmp+rename convention as
/// `observe::hot_stats::HotStats::maybe_flush`) — a reader never observes a
/// partially-written file.
pub fn write_broker_json(path: &Path, doc: &BrokerJson) -> Result<()> {
    let json = serde_json::to_vec_pretty(doc).context("serialize broker.json")?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, &json).with_context(|| format!("write {}", tmp.display()))?;
    std::fs::rename(&tmp, path)
        .with_context(|| format!("rename {} -> {}", tmp.display(), path.display()))?;
    Ok(())
}

/// Read and validate `broker.json`. A version mismatch or any empty
/// identity field is treated as corruption, not a value to trust.
pub fn read_broker_json(path: &Path) -> Result<BrokerJson> {
    let bytes = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let doc: BrokerJson =
        serde_json::from_slice(&bytes).with_context(|| format!("parse {}", path.display()))?;
    anyhow::ensure!(
        doc.version == BROKER_JSON_VERSION,
        "broker.json version mismatch: {} (expected {BROKER_JSON_VERSION})",
        doc.version,
    );
    anyhow::ensure!(doc.broker_pid != 0, "broker.json broker_pid is zero");
    anyhow::ensure!(!doc.pipe_name.is_empty(), "broker.json pipe_name is empty");
    anyhow::ensure!(
        !doc.folder_section_name.is_empty(),
        "broker.json folder_section_name is empty"
    );
    Ok(doc)
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
            guard: ipc::GuardLevel::Scan,
            launcher_pid: 0,
            launcher_create_time: 0,
            allow_rwx: false,
            disable_hooks: String::new(),
            folder_section_name: String::new(),
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

    #[test]
    fn restricted_guest_can_read_session_section() {
        let section = unique_section_name("restricted-reader");
        let cfg = test_cfg("restricted-reader", false);
        let _owner = publish_named(&section, &cfg).expect("publish ok");

        let mut source = HANDLE::default();
        let access = TOKEN_QUERY
            | TOKEN_DUPLICATE
            | TOKEN_ASSIGN_PRIMARY
            | TOKEN_ADJUST_DEFAULT
            | TOKEN_ADJUST_SESSIONID;
        // SAFETY: GetCurrentProcess is a pseudo-handle; access is the minimal
        // token set used by the launcher to derive the guest token.
        unsafe { OpenProcessToken(GetCurrentProcess(), access, &mut source) }
            .expect("OpenProcessToken failed");
        let guest = crate::contain::guest::build_guest_token(source)
            .expect("build restricted guest token");
        unsafe { CloseHandle(source).ok() };

        // SAFETY: guest is a valid restricted token for the current user.
        unsafe { windows::Win32::Security::ImpersonateLoggedOnUser(guest.handle()) }
        .expect("ImpersonateLoggedOnUser failed");
        let read_result = open_read(&section);
        let name_wide: Vec<u16> = OsStr::new(&section)
            .encode_wide()
            .chain(Some(0))
            .collect();
        let write_result = unsafe {
            OpenFileMappingW(FILE_MAP_WRITE.0, false, PCWSTR(name_wide.as_ptr()))
        };
        // SAFETY: this test impersonated guest above and must restore the
        // original thread token before assertions or returning.
        unsafe { windows::Win32::Security::RevertToSelf() }
            .expect("RevertToSelf failed");

        let reader = read_result.expect("restricted guest must open read-only config");
        unsafe { CloseHandle(reader).ok() };
        match write_result {
            Ok(handle) => {
                unsafe { CloseHandle(handle).ok() };
                panic!("restricted guest must not open the section for write");
            }
            Err(error) => assert_eq!(
                error.code(),
                windows::core::HRESULT::from_win32(
                    windows::Win32::Foundation::ERROR_ACCESS_DENIED.0
                ),
                "restricted write must fail with ACCESS_DENIED"
            ),
        }
    }

    // ─── FolderSection ───────────────────────────────────────────────────

    #[test]
    fn folder_section_write_open_denied_read_open_sees_creators_writes() {
        let (section, name) = FolderSection::create().expect("create folder section");
        section
            .view()
            .init(4242, 0xAAAA_BBBB, r"\\.\pipe\winrsbox-broker-test")
            .expect("init folder section");

        let name_wide: Vec<u16> = OsStr::new(&name).encode_wide().chain(Some(0)).collect();

        // A write-access open must be denied by the DACL.
        // SAFETY: name_wide is NUL-terminated; no inheritance.
        let write_open =
            unsafe { OpenFileMappingW(FILE_MAP_WRITE.0, false, PCWSTR(name_wide.as_ptr())) };
        match write_open {
            Ok(h) => {
                unsafe { CloseHandle(h).ok() };
                panic!("folder section DACL must deny SECTION_MAP_WRITE to a plain open");
            }
            Err(e) => assert_eq!(
                e.code(),
                windows::core::HRESULT::from_win32(
                    windows::Win32::Foundation::ERROR_ACCESS_DENIED.0
                ),
                "write open must fail with ACCESS_DENIED, got: {e}"
            ),
        }

        // A read-access open must succeed and see exactly what the creator
        // (RW) view wrote.
        // SAFETY: name_wide is NUL-terminated; no inheritance.
        let read_handle =
            unsafe { OpenFileMappingW(FILE_MAP_READ.0, false, PCWSTR(name_wide.as_ptr())) }
                .expect("read-only open must be allowed");
        // SAFETY: read_handle is valid; maps the whole section read-only.
        let read_view =
            unsafe { MapViewOfFile(read_handle, FILE_MAP_READ, 0, 0, ipc::FOLDER_SECTION_SIZE) };
        assert!(!read_view.Value.is_null());
        // SAFETY: read_view maps FOLDER_SECTION_SIZE read-only bytes; only
        //         `snapshot()` (a read-only method) is called on this view,
        //         matching `FolderSectionView::new`'s documented contract
        //         for a read-only mapping.
        let reader = unsafe { ipc::FolderSectionView::new(read_view.Value.cast()) };
        let snap = reader.snapshot().expect("reader snapshot");
        assert_eq!(snap.broker_pid, 4242);
        assert_eq!(snap.broker_create_time, 0xAAAA_BBBB);
        assert_eq!(snap.pipe_name, r"\\.\pipe\winrsbox-broker-test");

        unsafe { UnmapViewOfFile(read_view).ok() };
        unsafe { CloseHandle(read_handle).ok() };
    }

    // ─── broker.json ─────────────────────────────────────────────────────

    fn sample_broker_json() -> BrokerJson {
        BrokerJson {
            version: BROKER_JSON_VERSION,
            broker_pid: 1234,
            broker_create_time: 0x1122_3344_5566_7788,
            pipe_name: r"\\.\pipe\winrsbox-broker-xyz".into(),
            folder_section_name: r"Local\WinRsBoxFolder-deadbeef".into(),
            generation: 6,
        }
    }

    #[test]
    fn broker_json_roundtrip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(BROKER_JSON_FILE_NAME);
        let doc = sample_broker_json();
        write_broker_json(&path, &doc).expect("write broker.json");
        let read_back = read_broker_json(&path).expect("read broker.json");
        assert_eq!(read_back, doc);
    }

    #[test]
    fn broker_json_rejects_corrupt_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(BROKER_JSON_FILE_NAME);
        std::fs::write(&path, b"{ not json").expect("write garbage");
        assert!(read_broker_json(&path).is_err());
    }

    #[test]
    fn broker_json_rejects_version_mismatch() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(BROKER_JSON_FILE_NAME);
        let mut doc = sample_broker_json();
        doc.version = 999;
        let json = serde_json::to_vec_pretty(&doc).unwrap();
        std::fs::write(&path, json).unwrap();
        assert!(read_broker_json(&path).is_err());
    }

    #[test]
    fn broker_json_write_replaces_atomically_and_leaves_no_tmp_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(BROKER_JSON_FILE_NAME);
        let tmp_path = path.with_extension("json.tmp");

        let mut doc = sample_broker_json();
        write_broker_json(&path, &doc).expect("first write");
        doc.generation = 7;
        doc.pipe_name = r"\\.\pipe\winrsbox-broker-after-failover".into();
        write_broker_json(&path, &doc).expect("second write (replace)");

        let read_back = read_broker_json(&path).expect("read after replace");
        assert_eq!(read_back.generation, 7);
        assert_eq!(read_back.pipe_name, doc.pipe_name);
        assert!(!tmp_path.exists(), "atomic write must not leave a .tmp file behind");
    }
}
