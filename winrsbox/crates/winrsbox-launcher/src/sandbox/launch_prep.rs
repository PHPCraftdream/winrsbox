use crate::{Cli, GuardLevel};
use std::path::Path;
use windows::{
    core::PCWSTR,
    Win32::{
        Foundation::HANDLE,
        Security::Cryptography::{BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG},
        System::Threading::CreateEventW,
    },
};

/// Build the kernel-Event name used by hook.dll to signal "initialised" to
/// the launcher (H1 fix). Format:
///     Local\fs-sandbox-init-<pid>-<32 lowercase hex chars>
///
/// The 32-char suffix is 16 bytes of cryptographically-strong entropy from
/// `BCryptGenRandom` — 128 bits, the same budget you'd spend on a UUID.
/// The launcher process keeps the only kernel handle returned by
/// `CreateEventW`; the hook.dll opens the same object by name via the
/// `FS_SANDBOX_INIT_EVENT` env var (set on this process and inherited by
/// the suspended child via CreateProcessW's environment block).
///
/// If `BCryptGenRandom` ever fails (it really shouldn't — the system RNG is
/// always available), we fall back to the predictable PID-only name so the
/// handshake still works. A panic here would brick every launch.
pub(crate) fn build_random_event_name(pid: u32) -> String {
    let mut rand_bytes = [0u8; 16];
    // SAFETY: FFI call to bcrypt!BCryptGenRandom; pbbuffer is a valid
    // mutable 16-byte slice and BCRYPT_USE_SYSTEM_PREFERRED_RNG means
    // halgorithm is unused.
    let status = unsafe {
        BCryptGenRandom(None, &mut rand_bytes, BCRYPT_USE_SYSTEM_PREFERRED_RNG)
    };
    if status.0 < 0 {
        // RNG unavailable — degrade to legacy predictable name rather than
        // brick the launch. The TOCTOU window is bounded by the 5-second
        // hello-handshake timeout in the launcher.
        return format!("Local\\fs-sandbox-init-{}", pid);
    }
    let mut suffix = String::with_capacity(32);
    for b in rand_bytes.iter() {
        use std::fmt::Write;
        let _ = write!(&mut suffix, "{:02x}", b);
    }
    format!("Local\\fs-sandbox-init-{}-{}", pid, suffix)
}

/// Detect whether THIS launcher was spawned inside an existing sandbox.
///
/// The outer launcher exports `FS_SANDBOX_PIPE` (its named-pipe path) into
/// the environment of every descendant — `CreateProcessW` inherits env
/// verbatim, so any nested `winrsbox.exe -- <target>` invocation inside the
/// sandbox will see the variable. Its presence is a reliable signal that we
/// are a descendant of an outer launcher, not the outer launcher itself.
///
/// Returning `true` here tells `main()` to skip the entire sandbox setup
/// (no state dir, no pipe, no overlay, no hook injection) and delegate the
/// target directly to the outer sandbox's process hook.
/// (issue C, #63)
pub(crate) fn is_nested_invocation() -> bool {
    std::env::var_os("FS_SANDBOX_PIPE").is_some()
}

/// Build the transparent-delegation `Command` used when this launcher is
/// itself running inside an outer sandbox (issue C, #63).
///
/// `target` is the full `cli.target` vector — `target[0]` is the executable
/// and `target[1..]` are its arguments, all forwarded verbatim. No sandbox
/// plumbing (pipe / overlay / hook / mitigations) is attached: the outer
/// sandbox's process hook in our parent observes the spawn and applies its
/// own containment, so a second nested layer would only duplicate work.
///
/// Extracted as a pure builder (no `.spawn()`/`.status()`) so a unit test can
/// assert every argument survives the handoff — a regression where only the
/// executable reached the child (e.g. dropping `target[1..]`) would otherwise
/// silently turn `cmd.exe /c "echo X"` into an interactive `cmd.exe`.
/// The hook categories to disable, given the operator's `--disable-hooks` and
/// whether network containment is on.
///
/// Network off means the `connect` detour is never installed, so the guest's
/// socket path is byte-for-byte the unsandboxed one and nothing in the system
/// attributes its traffic to winrsbox. Reusing the existing disable-hooks
/// channel rather than adding a second switch keeps one mechanism to reason
/// about — and makes the composition testable, which matters because a
/// mistake here fails silently: the hook would simply install and start
/// enforcing (or not) with no error anywhere.
fn disable_hooks_categories(cli_categories: Option<&str>, net_guarded: bool) -> String {
    let mut cats: Vec<String> = cli_categories
        .unwrap_or_default()
        .split(',')
        .map(|c| c.trim().to_ascii_lowercase())
        .filter(|c| !c.is_empty())
        .collect();
    if !net_guarded && !cats.iter().any(|c| c == "net") {
        cats.push("net".to_string());
    }
    cats.join(",")
}

pub(crate) fn build_delegation_command(target: &[String]) -> std::process::Command {
    // clap's `target` field has `required_unless_present = "init"`, and we
    // only enter the nested branch when `!cli.target.is_empty()`, so
    // `target[0]` is always safe here.
    let mut cmd = std::process::Command::new(&target[0]);
    if target.len() > 1 {
        cmd.args(&target[1..]);
    }
    // stdio is inherited by default — the outer sandbox captures the spawn
    // via its NtCreateUserProcess hook, so no FS_SANDBOX_* env is needed.
    cmd
}

/// Create kernel Event for hook.dll init signaling.
///
/// H1 fix: the event name embeds a 128-bit random suffix so a same-session
/// attacker cannot guess the name and SetEvent() it ahead of the real
/// hook.dll. The `Local\` namespace already scopes the object to this
/// logon session; the random suffix raises the bar from "any same-user
/// process can OpenEvent" to "attacker must enumerate the object-manager
/// directory or read our env vars" (the env var is propagated through
/// CreateProcessW's environment block to the target only).
pub(crate) fn create_init_event(pid: u32) -> anyhow::Result<HANDLE> {
    let init_event_name = build_random_event_name(pid);
    let event_name_wide: Vec<u16> = init_event_name.encode_utf16().chain(Some(0)).collect();
    let init_event = unsafe {
        CreateEventW(None, false, false, PCWSTR(event_name_wide.as_ptr()))
    }?;
    std::env::set_var("FS_SANDBOX_INIT_EVENT", &init_event_name);
    Ok(init_event)
}

/// Set env vars for child before CreateProcessW — child inherits them.
///
/// Returns the effective `--disable-hooks` category list (also exported as
/// `FS_SANDBOX_DISABLE_HOOKS` when non-empty) so the session-section
/// publisher can embed the same value.
#[allow(clippy::too_many_arguments)]
pub(crate) fn set_sandbox_environment(
    cli: &Cli,
    pipe_name: &str,
    dll_path: &Path,
    sandbox_root: &Path,
    _project_root: &Path,
    cwd_str: &str,
    net_guarded: bool,
    hook_trace: bool,
) -> String {
    std::env::set_var("FS_SANDBOX_PIPE", pipe_name);
    std::env::set_var("FS_SANDBOX_DLL", dll_path);
    // Help GUI terminal emulators (WezTerm, Windows Terminal) that ignore the inherited
    // CWD and fall back to the home directory when spawning their shell.
    std::env::set_var("WEZTERM_EXECUTABLE_ARGS_CWD", cwd_str);
    std::env::set_var("FS_SANDBOX_CWD", cwd_str);
    // Publish the sandbox overlay storage dir so the hook can recognise
    // overlay files on delete and convert them back to virtual DOS paths.
    std::env::set_var("FS_SANDBOX_ROOT", sandbox_root.to_string_lossy().as_ref());
    // Pass guard configuration to hook DLL via env vars
    std::env::set_var("FS_SANDBOX_GUARD", match cli.guard {
        GuardLevel::None => "none",
        GuardLevel::Scan => "scan",
        GuardLevel::Full => "full",
        GuardLevel::Static => "static",
    });
    if cli.allow_rwx {
        std::env::set_var("FS_SANDBOX_ALLOW_RWX", "1");
    }
    // Network containment off → tell the hook to skip the `net` category, so
    // `connect` is never detoured and the guest's socket path is byte-for-byte
    // the unsandboxed one. Reuses the existing, already-tested disable-hooks
    // mechanism rather than inventing a second switch.
    let disable_hooks_effective = disable_hooks_categories(cli.disable_hooks.as_deref(), net_guarded);
    if !disable_hooks_effective.is_empty() {
        std::env::set_var("FS_SANDBOX_DISABLE_HOOKS", &disable_hooks_effective);
    }
    // Hook-side trace gate. Triggered by EITHER the explicit `--trace` CLI
    // flag, OR an `effective_log_level == "trace"` (from CLI `--log-level` or
    // `log_level: trace` in sandbox.ktav). Without this, hook-side trace logs
    // (com_blocked clsid=..., per-decide path traces, etc.) stay silent even
    // when launcher-side JSONL filter is set to trace — they're two separate
    // gates and the launcher-side one only catches what the hook actually
    // sends.
    if hook_trace {
        std::env::set_var("FS_SANDBOX_TRACE", "1");
    }
    if cli.block_localhost {
        std::env::set_var("FS_SANDBOX_BLOCK_LOCALHOST", "1");
    }
    if cli.strict_clipboard {
        std::env::set_var("FS_SANDBOX_STRICT_CLIPBOARD", "1");
    }
    disable_hooks_effective
}

#[cfg(test)]
mod network_opt_in_tests {
    use super::disable_hooks_categories;

    /// Network containment is off by default, and "off" has to reach the
    /// hook — otherwise the `connect` detour installs anyway and the guest's
    /// traffic is no longer indistinguishable from running it unsandboxed.
    #[test]
    fn net_hook_is_disabled_when_network_is_not_guarded() {
        assert_eq!(disable_hooks_categories(None, false), "net");
        assert_eq!(disable_hooks_categories(Some(""), false), "net");
    }

    /// With guarding on, nothing is added — the detour installs.
    #[test]
    fn net_hook_stays_enabled_when_guarded() {
        assert_eq!(disable_hooks_categories(None, true), "");
        assert_eq!(disable_hooks_categories(Some("reg"), true), "reg");
    }

    /// The operator's own `--disable-hooks` list survives, and `net` is not
    /// duplicated when they already asked for it.
    #[test]
    fn operator_categories_are_preserved_and_net_not_duplicated() {
        assert_eq!(disable_hooks_categories(Some("reg,ui"), false), "reg,ui,net");
        assert_eq!(disable_hooks_categories(Some("net"), false), "net");
        assert_eq!(disable_hooks_categories(Some("net,reg"), false), "net,reg");
        // Whitespace and case in the operator's list must not defeat the
        // duplicate check.
        assert_eq!(disable_hooks_categories(Some(" NET , reg "), false), "net,reg");
        // Empty entries from sloppy input are dropped rather than passed on.
        assert_eq!(disable_hooks_categories(Some("reg,,"), true), "reg");
    }
}

#[cfg(test)]
mod hello_event_name_tests {
    //! H1 regression tests for the randomized hello-event name.

    use super::build_random_event_name;

    /// Asserts the new format exactly:
    ///     Local\fs-sandbox-init-<pid>-<32 lowercase hex chars>
    #[test]
    fn format_includes_pid_and_32_hex_suffix() {
        let name = build_random_event_name(4242);
        let prefix = "Local\\fs-sandbox-init-4242-";
        assert!(
            name.starts_with(prefix),
            "missing pid-anchored prefix: {name}",
        );
        let suffix = &name[prefix.len()..];
        assert_eq!(suffix.len(), 32, "suffix is not 32 chars: {name}");
        assert!(
            suffix.chars().all(|c| {
                c.is_ascii_hexdigit() && (!c.is_ascii_alphabetic() || c.is_ascii_lowercase())
            }),
            "suffix has non-lowercase-hex chars: {suffix}",
        );
    }

    /// Two consecutive runs must produce different names. Collision is
    /// 2^-128 per pair — effectively never on any real test bot. If this
    /// flakes, the RNG is broken and we have bigger problems.
    #[test]
    fn two_consecutive_calls_differ() {
        let a = build_random_event_name(1);
        let b = build_random_event_name(1);
        assert_ne!(a, b, "two random names collided: {a} vs {b}");
    }

    /// Sanity: a batch of 16 names are all distinct. Catches a wedged RNG
    /// that returns zeros more reliably than the two-sample test.
    #[test]
    fn batch_of_sixteen_all_distinct() {
        use std::collections::HashSet;
        let mut seen: HashSet<String> = HashSet::new();
        for _ in 0..16 {
            let name = build_random_event_name(7);
            assert!(seen.insert(name.clone()), "duplicate random name: {name}");
        }
    }
}

#[cfg(test)]
mod nested_detection_tests {
    //! Issue C (#63): nested-sandbox detection must fire exactly when
    //! `FS_SANDBOX_PIPE` is present in the environment, and never otherwise.
    //!
    //! These tests mutate the process environment, so they must not run in
    //! parallel with anything else that reads `FS_SANDBOX_PIPE`. Each test
    //! saves and restores the variable to avoid leaking state.

    use super::is_nested_invocation;

    /// Serializes the tests in this module against each other.
    ///
    /// The doc comment above states they must not run in parallel, but stating
    /// it did not enforce it: `cargo test` runs them on separate threads of one
    /// process, and the environment is process-wide. One test would set
    /// `FS_SANDBOX_PIPE` while another removed it, and whichever asserted second
    /// failed — observed as an intermittent failure of
    /// `not_nested_when_pipe_unset` or `empty_string_still_counts_as_nested`,
    /// depending on which thread lost the race. Each test now holds this lock
    /// for its whole body, so the set/assert/restore sequence is atomic with
    /// respect to its siblings.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Take the lock, ignoring poisoning: a panic in one test must not cascade
    /// into spurious failures of the others, which would hide the real one.
    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// RAII guard that restores `FS_SANDBOX_PIPE` to its prior state on drop.
    struct PipeGuard(Option<std::ffi::OsString>);
    impl PipeGuard {
        fn capture() -> Self {
            PipeGuard(std::env::var_os("FS_SANDBOX_PIPE"))
        }
    }
    impl Drop for PipeGuard {
        fn drop(&mut self) {
            match &self.0 {
                Some(v) => std::env::set_var("FS_SANDBOX_PIPE", v),
                None => std::env::remove_var("FS_SANDBOX_PIPE"),
            }
        }
    }

    #[test]
    fn detects_nested_when_pipe_set() {
        let _lock = env_lock();
        let _g = PipeGuard::capture();
        std::env::set_var("FS_SANDBOX_PIPE", r"\\.\pipe\fs-sandbox-99999");
        assert!(is_nested_invocation(), "FS_SANDBOX_PIPE set ⇒ nested");
    }

    #[test]
    fn not_nested_when_pipe_unset() {
        let _lock = env_lock();
        let _g = PipeGuard::capture();
        std::env::remove_var("FS_SANDBOX_PIPE");
        assert!(!is_nested_invocation(), "FS_SANDBOX_PIPE unset ⇒ not nested");
    }

    /// The detector must trigger on any non-empty value — including a
    /// pathological empty string. The outer launcher always sets a
    /// well-formed pipe name, but the contract is "presence ⇒ nested",
    /// not "non-empty ⇒ nested", so an empty string still counts.
    #[test]
    fn empty_string_still_counts_as_nested() {
        let _lock = env_lock();
        let _g = PipeGuard::capture();
        std::env::set_var("FS_SANDBOX_PIPE", "");
        assert!(is_nested_invocation(), "presence (not value) ⇒ nested");
    }
}

#[cfg(test)]
mod nested_delegation_tests {
    //! Issue C (#63): the nested-delegation builder must forward EVERY
    //! target argument to the child, not just the executable. A regression
    //! that drops `target[1..]` would silently turn
    //! `cmd.exe /c "echo X"` into an interactive `cmd.exe`.
    //!
    //! These tests inspect the built `Command`'s argv directly — no process
    //! is spawned — so they are deterministic and platform-independent.

    use super::build_delegation_command;

    /// `cmd.exe /c "echo DELEGATED_ARG_OK"` (3 target elements) must reach
    /// the child with both `/c` and the quoted echo intact.
    #[test]
    fn preserves_full_target_argv() {
        let target: Vec<String> = vec![
            "cmd.exe".into(),
            "/c".into(),
            "echo DELEGATED_ARG_OK".into(),
        ];
        let cmd = build_delegation_command(&target);
        assert_eq!(cmd.get_program(), std::ffi::OsStr::new("cmd.exe"));
        let args: Vec<&std::ffi::OsStr> = cmd.get_args().collect();
        assert_eq!(
            args,
            ["/c", "echo DELEGATED_ARG_OK"],
            "all target arguments after [0] must be forwarded verbatim",
        );
    }

    /// Pathological case: a target that is only the executable (no args).
    /// The builder must not panic on `target[1..]` and must produce zero
    /// child arguments.
    #[test]
    fn handles_executable_only_target() {
        let target: Vec<String> = vec!["cmd.exe".into()];
        let cmd = build_delegation_command(&target);
        assert_eq!(cmd.get_program(), std::ffi::OsStr::new("cmd.exe"));
        let args: Vec<&std::ffi::OsStr> = cmd.get_args().collect();
        assert!(args.is_empty(), "no args expected, got {args:?}");
    }

    /// Arguments that look like launcher flags (`-c`, `--flag`) must survive
    /// verbatim — clap already consumed the real launcher opts via `--`, so
    /// everything in `cli.target` is the child's argv, not ours.
    #[test]
    fn preserves_flag_like_arguments() {
        let target: Vec<String> = vec![
            "node".into(),
            "-e".into(),
            "console.log('hi')".into(),
            "--unhandled-rejections=strict".into(),
        ];
        let cmd = build_delegation_command(&target);
        let args: Vec<&std::ffi::OsStr> = cmd.get_args().collect();
        assert_eq!(
            args,
            [
                "-e",
                "console.log('hi')",
                "--unhandled-rejections=strict",
            ],
        );
    }

    /// Empty-string arguments (rare but legal) must round-trip — they must
    /// not be silently dropped, since the child's argv indexing depends on
    /// positional presence.
    #[test]
    fn preserves_empty_string_argument() {
        let target: Vec<String> = vec!["git".into(), "commit".into(), "".into(), "-m".into()];
        let cmd = build_delegation_command(&target);
        let args: Vec<&std::ffi::OsStr> = cmd.get_args().collect();
        assert_eq!(args, ["commit", "", "-m"], "empty-string arg preserved");
    }
}
