use super::Stats;
use ipc::Resp;
use policy::Policy;
use std::path::Path;
use std::sync::atomic::Ordering;
use winrsbox::observe::hot_stats::HotStats;
use winrsbox::observe::jsonl_log;

/// Registry-key substrings that always deny on write — every entry here
/// represents a well-known persistence / DLL-injection vector. Matching is
/// case-insensitive substring over the already-lowercased key path, so the
/// rules apply uniformly to HKLM\, HKCU\, HKCR\, and HKU\<SID>\ forms.
pub(crate) const PERSISTENCE_DENY_SUFFIXES: &[&str] = &[
    // ─── original 6 entries (kept verbatim) ─────────────────────────────────
    r"\software\microsoft\windows nt\currentversion\windows",
    r"\software\wow6432node\microsoft\windows nt\currentversion\windows",
    r"\software\microsoft\windows nt\currentversion\image file execution options",
    r"\software\microsoft\windows nt\currentversion\silentprocessexit",
    r"\system\currentcontrolset\control\session manager\appcertdlls",
    // No trailing backslash: segment-anchored matching denies both the
    // Services hive root and any subkey under it (sandbox must never write
    // a service registration anywhere).
    r"\system\currentcontrolset\services",

    // ─── H-S4 new entries ───────────────────────────────────────────────────
    // Classic autorun under HKCU and HKLM (Run / RunOnce / RunOnceEx and
    // the StartupApproved twin that controls whether disabled-via-UI entries
    // run anyway).
    r"\software\microsoft\windows\currentversion\run",
    r"\software\microsoft\windows\currentversion\runonce",
    r"\software\microsoft\windows\currentversion\runonceex",
    r"\software\microsoft\windows\currentversion\explorer\startupapproved\run",

    // Logon hooks — run as SYSTEM at every interactive logon.
    r"\software\microsoft\windows nt\currentversion\winlogon\userinit",
    r"\software\microsoft\windows nt\currentversion\winlogon\shell",
    r"\software\microsoft\windows nt\currentversion\winlogon\notify",

    // Legacy MCI drivers — Drivers32 entries are LoadLibrary'd at app startup.
    r"\software\microsoft\windows nt\currentversion\drivers32",

    // App Paths — hijacks ShellExecute("notepad.exe") and friends.
    r"\software\microsoft\windows\currentversion\app paths",

    // COM hijack — InprocServer32 / LocalServer32 under any CLSID loads
    // the attacker DLL into every COM client.
    r"\software\classes\clsid",

    // File / URL association hijack — the existing match is substring, so
    // `\shell\open\command` catches `HKCU\Software\Classes\<ext>\shell\open\command`
    // for every extension, plus the equivalent under HKLM and HKCR.
    r"\shell\open\command",
    r"\shellex\contextmenuhandlers",

    // cmd.exe autorun — runs on every cmd.exe invocation.
    r"\software\microsoft\command processor\autorun",

    // LSA package injection — adds an attacker DLL into LSASS / SAM.
    r"\system\currentcontrolset\control\lsa\notification packages",
    r"\system\currentcontrolset\control\lsa\authentication packages",
    r"\system\currentcontrolset\control\lsa\security packages",

    // Office "Trusted Locations" bypass — marks attacker paths as macro-safe.
    // Substring catches `\office\<ver>\<app>\security\trusted locations` for
    // every Office version (16.0, 15.0, ...) and every app (word, excel, ...).
    r"\security\trusted locations",

    // ─── per-user COM hijack (H2) ───────────────────────────────────────────
    // When HKCR\CLSID is opened for write, the kernel resolves to the per-user
    // classes hive: \Registry\User\<SID>_Classes\CLSID\... which nt_to_friendly
    // maps to hku\<sid>_classes\clsid\... — the \software\classes\clsid entry
    // above does not match this form. Use `_classes\clsid` to catch the
    // underscore-joined per-user hive segment.
    r"_classes\clsid",
    // ─── HKCU\Environment persistence (M6) ──────────────────────────────────
    // UserInitMprLogonScript, PATH manipulation, DLL search-order via env vars.
    r"\environment",
];

/// Value-name allowlist for persistence-denied keys. The key itself is a
/// persistence/dll-injection surface (so unknown value-names stay DENIED),
/// but a short, explicit list of benign env-var names is allowed through into
/// the CoW overlay so legitimate installers that write e.g. `HERMES_*` or
/// `PATH` don't break.
///
/// This is the PERSISTENCE-DENY exception: anything NOT in this list that
/// targets a deny-suffix key stays hard-DENIED. The dangerous names — the
/// actual logon/DLL-search-order vectors — are deliberately absent.
///
/// Naming convention:
///   - exact match (case-insensitive): `path`, `hermes_git_bash_path`
///   - `vendor_*` prefix: matches `hermes_*` (any value starting with the prefix)
#[allow(dead_code)]
const ENV_VALUE_NAME_ALLOWLIST: &[&str] = &[
    // PATH-like env vars that installers legitimately extend.
    "path",
    "pathext",
    // Toolchain homes / version env-vars written by installers. These are pure
    // data values read back by the toolchain itself — they are not consulted by
    // winlogon / the DLL loader, so they confer no persistence.
    "hermes_*",        // Hermes Agent installer (HERMES_HOME, HERMES_GIT_BASH_PATH, ...)
    "npm_config_*",    // npm global config
    "cargo_home",
    "rustup_home",
    "python*",
    "pip_*",
    "uv_*",
    "node_path",
    "node_options",
];

/// Return `true` if `fragment` occurs in `key_lower` aligned to path-segment
/// boundaries: the fragment starts with `\` (left-anchored to a segment edge)
/// and the character immediately after the match is either end-of-string or
/// `\` (right-anchored). This blocks mid-segment false positives — e.g. the
/// fragment `\run` must NOT match `...\runtime\...` or `...\brundlefly\...`,
/// only `...\run` (root) or `...\run\...` (subkey).
///
/// Note: a segment-aligned occurrence is denied wherever it appears in the
/// key, regardless of hive prefix — a sandboxed process must never write a
/// persistence key anywhere, even nested under an attacker-crafted parent.
pub(crate) fn segment_contains(key_lower: &str, fragment: &str) -> bool {
    let bytes = key_lower.as_bytes();
    let mut start = 0;
    while let Some(pos) = key_lower[start..].find(fragment) {
        let abs = start + pos;
        let after = abs + fragment.len();
        let right_ok = after == key_lower.len() || bytes[after] == b'\\';
        if right_ok {
            return true;
        }
        // Advance past this occurrence and keep scanning for a later,
        // properly-anchored match.
        start = abs + 1;
        if start >= key_lower.len() {
            break;
        }
    }
    false
}

/// Return `true` if `key_path` is a denied registry persistence vector.
/// Pure function — extracted from the RegDecide handler for unit testing.
/// Matching is case-insensitive (internal ASCII lowercase) and segment-anchored
/// (see `segment_contains`) so unrelated keys that merely contain a denied
/// fragment mid-segment are not over-matched.
pub(crate) fn is_persistence_denied(key_path: &str) -> bool {
    let lower = key_path.to_ascii_lowercase();
    PERSISTENCE_DENY_SUFFIXES
        .iter()
        .any(|s| segment_contains(&lower, s))
}

/// True if `value_name` matches the `ENV_VALUE_NAME_ALLOWLIST`. Matches are
/// case-insensitive. An entry ending in `_*` is a prefix match; otherwise an
/// exact match.
pub(crate) fn is_env_value_allowed(value_name: Option<&str>) -> bool {
    let Some(name) = value_name else { return false; };
    let lower = name.to_ascii_lowercase();
    ENV_VALUE_NAME_ALLOWLIST.iter().any(|pat| {
        if let Some(prefix) = pat.strip_suffix("*") {
            lower.starts_with(prefix)
        } else {
            lower == *pat
        }
    })
}

/// Audit 2026-09-19 Critical #2: record a rejected `Req::RecordOverlay` as a
/// violation — bump the launcher counters and persist an immediate JSONL
/// violation event. The guest-supplied value is included verbatim; this is an
/// escape attempt, not a mistake report.
fn log_record_overlay_violation(
    stats: &Stats,
    hot_stats: &HotStats,
    client_pid: u32,
    orig: &str,
    overlay: &str,
) {
    stats.violations.fetch_add(1, Ordering::Relaxed);
    hot_stats
        .totals
        .violations
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    jsonl_log::log_immediate(jsonl_log::Event::violation(
        client_pid,
        "RecordOverlayEscape",
        &format!("orig={orig} overlay={overlay}"),
    ));
}

/// Handle one `Req::RecordOverlay` (audit 2026-09-19 Critical #2). The wire
/// keeps carrying `overlay` (the hook legitimately sends the launcher-shaped
/// mirror), but the launcher no longer trusts it: the request is accepted only
/// when `overlay` equals `mirror(orig)` inside the published overlay roots or
/// the mock-dirs mirror (see `Policy::validate_record_overlay`). Rejections
/// are counted, logged as violations, and surfaced to the guest via `Resp::Err`
/// instead of being swallowed; DB errors are no longer swallowed either.
pub(crate) fn handle_record_overlay(
    policy: &Policy,
    stats: &Stats,
    hot_stats: &HotStats,
    client_pid: u32,
    orig: &str,
    overlay: &str,
) -> Resp {
    if policy.validate_record_overlay(orig, overlay) {
        match policy.record_overlay(orig, overlay) {
            Ok(()) => Resp::Ok,
            Err(e) => Resp::Err(format!("record_overlay: {e}")),
        }
    } else {
        log_record_overlay_violation(stats, hot_stats, client_pid, orig, overlay);
        Resp::Err(
            "record_overlay rejected: overlay must be mirror(orig) inside the overlay roots"
                .to_string(),
        )
    }
}

// --- NetDecide: userspace network policy (audit Medium, WFP finding) ------

/// DB-free reference decision path for "Req::NetDecide": compiles `rules`
/// into a `policy::net::NetSnapshot` and delegates to its compiled matcher —
/// the same single decision implementation the production snapshot path
/// (`handle_net_decide` → `Policy::net_rule_decide`) uses. Kept only as the
/// DB-free reference path exercised by pipe_server tests.
///
/// Semantics (the contract "winrsbox netrule add --help" documents):
/// - a rule matches when its host pattern matches the host string the hook
///   reports (exact, *, *.suffix, or a v4 CIDR like 10.0.0.0/8) AND its
///   optional port matches;
/// - any matching deny rule wins over any matching allow rule (fail-closed
///   on conflict);
/// - log rules never affect the decision (observability only);
/// - no matching rule -- including no rules at all -- allows, so the default
///   policy stays open; deny-by-default is opt-in via a --host='*' deny rule.
///
/// Returns (allow, matched rule id). Hostname patterns never match an IP
/// literal unless identical: the hook reports numeric addresses (DNS is not
/// hooked), so a rule for *.github.com does NOT govern connects to GitHub's
/// IPs -- pin IPs/CIDRs for range-level control.
// Production traffic now goes through the versioned snapshot path
// (`handle_net_decide` -> `Policy::net_rule_decide`); this reference core is
// exercised by tests only, hence the cfg-gated allow.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn net_decide(rules: &[policy::net::NetRule], host: &str, port: u16) -> (bool, Option<String>) {
    policy::net::NetSnapshot::from_rules(0, rules).decide(host, port)
}

/// NetDecide handler plumbing: decide via `Policy::net_rule_decide`, the
/// versioned net-rule snapshot path. The snapshot is built once per rule-set
/// generation (pre-parsed CIDR/ports), and the persisted generation counter
/// in policy.redb is the cross-process invalidation signal — `winrsbox
/// netrule ...` writes the same policy.redb from a separate process, so each
/// decide's O(1) generation probe observes CLI-side rule changes on the very
/// next call (no stale window). Publication of a rebuilt snapshot is atomic
/// (ArcSwap), so no guest ever sees a partially-applied rule set.
/// Fail-closed on ANY error: the hook already denies when the IPC
/// round-trip dies, and the launcher denies when it cannot read its own
/// policy, so a broken rules store can never silently reopen the network.
pub(crate) fn handle_net_decide(p: &Policy, host: &str, port: u16) -> (bool, Option<String>) {
    match p.net_rule_decide(host, port) {
        Ok(decision) => decision,
        Err(e) => {
            eprintln!("[net] net_rules read failed: {e} -- denying {host}:{port} (fail-closed)");
            (false, None)
        }
    }
}
// ──────────────────────────────────────────────────────────────────────────────
// violations.log serialization
//
// Every record appended to violations.log is produced by serde_json here.
// serde_json escapes quotes, backslashes and every control character
// (including newlines), so a guest-controlled string — exe path, escape
// detail, caller module — can never terminate its record early or forge
// additional ones: one Value serializes to exactly one log line. The
// previous hand-rolled format! + ad-hoc backslash/quote replacement left
// newlines unescaped and was forgeable (audit 2026-09-19).

/// Serialize one violation record to a single JSON line and append it to
/// violations.log. Best-effort, mirroring the previous behavior: a write
/// failure is not fatal to the sandboxed process.
pub(crate) fn append_violation_record(violations_log: &Path, record: serde_json::Value) {
    use std::io::Write;
    let mut line = match serde_json::to_string(&record) {
        Ok(l) => l,
        Err(_) => return,
    };
    line.push('\n');
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(violations_log)
    {
        let _ = f.write_all(line.as_bytes());
    }
}

pub(crate) fn injection_violation_record(
    pid: u32,
    exe: &str,
    kind: ipc::InjectKind,
    target_pid: u32,
    start_address: u64,
    caller_pc: u64,
    caller_module: Option<&str>,
    stack_top: &[u64],
) -> serde_json::Value {
    serde_json::json!({
        "pid": pid,
        "exe": exe,
        "kind": kind.to_string(),
        "target_pid": target_pid,
        "start_addr": format!("0x{start_address:x}"),
        "caller_pc": format!("0x{caller_pc:x}"),
        "caller_module": caller_module,
        "stack": stack_top.iter().map(|f| format!("0x{f:x}")).collect::<Vec<_>>(),
    })
}

pub(crate) fn memory_violation_record(
    pid: u32,
    exe: &str,
    kind: ipc::AllocKind,
    requested_protect: u32,
    region_size: u64,
    target_address: u64,
    caller_pc: u64,
    caller_module: Option<&str>,
    stack_top: &[u64],
) -> serde_json::Value {
    serde_json::json!({
        "pid": pid,
        "exe": exe,
        "kind": kind.to_string(),
        "protect": format!("0x{requested_protect:x}"),
        "size": region_size,
        "addr": format!("0x{target_address:x}"),
        "caller_pc": format!("0x{caller_pc:x}"),
        "caller_module": caller_module,
        "stack": stack_top.iter().map(|f| format!("0x{f:x}")).collect::<Vec<_>>(),
    })
}

pub(crate) fn escape_violation_record(
    pid: u32,
    exe: &str,
    vector: &str,
    detail: &str,
    caller_pc: u64,
    caller_module: Option<&str>,
    stack_top: &[u64],
) -> serde_json::Value {
    serde_json::json!({
        "pid": pid,
        "exe": exe,
        "kind": "Escape",
        "vector": vector,
        "detail": detail,
        "action": "terminate",
        "caller_pc": format!("0x{caller_pc:x}"),
        "caller_module": caller_module,
        "stack": stack_top.iter().map(|f| format!("0x{f:x}")).collect::<Vec<_>>(),
    })
}

// ──────────────────────────────────────────────────────────────────────────────
// NetDecide versioned-snapshot tests. Kept here rather than in
// pipe_server/tests.rs, which sits just under the <1000-line layout guard.
#[cfg(test)]
mod net_snapshot_tests {
    use super::*;

    /// Local replica of pipe_server/tests.rs's `net_rule` helper — test
    /// modules must not depend on each other.
    fn net_rule(
        id: &str,
        host: &str,
        port: Option<u16>,
        mode: policy::net::NetMode,
    ) -> policy::net::NetRule {
        policy::net::NetRule { id: id.into(), host_pattern: host.into(), port, mode }
    }

    /// A real policy DB, opened exactly like pipe_server/tests.rs does.
    fn open_policy() -> (tempfile::TempDir, policy::Policy) {
        let dir = tempfile::tempdir().unwrap();
        let p = policy::Policy::open_or_create(
            &dir.path().join("policy.redb"),
            dir.path().join("sb"),
            dir.path().join("md"),
            dir.path().join("proj"),
        )
        .unwrap();
        (dir, p)
    }

    #[test]
    fn net_snapshot_invalidated_on_rule_change_no_stale_window() {
        let (dir, p) = open_policy();

        // Fresh DB: no rules -> allow. No warmup, no other decides.
        let (allow, _) = handle_net_decide(&p, "8.8.8.8", 443);
        assert!(allow);

        // Simulates the CLI writing the same policy.redb from a separate
        // process: the persisted generation counter is the only
        // cross-process invalidation signal, so the very first decide after
        // the write must observe the new rule — no stale window.
        policy::db::net_rule_upsert(
            &p.db(),
            &net_rule("d1", "8.8.8.8", Some(443), policy::net::NetMode::Deny),
        )
        .unwrap();
        let (allow, rule) = handle_net_decide(&p, "8.8.8.8", 443);
        assert!(!allow, "first decide after the rule write must see it");
        assert_eq!(rule.as_deref(), Some("d1"));
        // Exactly one full rule-table re-read + recompile was needed.
        assert_eq!(p.net_snapshot_rebuild_count(), 1);
    }

    #[test]
    fn repeated_net_decide_on_unchanged_rules_do_not_reread_rule_table() {
        let (dir, p) = open_policy();

        // The O(1) generation probe runs per call, but the full rule-table
        // read + decode never does while the generation is unchanged — that
        // is exactly what the rebuild counter counts.
        for _ in 0..5 {
            let (allow, _) = handle_net_decide(&p, "8.8.8.8", 443);
            assert!(allow);
        }
        assert_eq!(p.net_snapshot_rebuild_count(), 0);

        // A Log rule must not change the allow outcome, but its write bumps
        // the persisted generation, forcing exactly one rebuild.
        policy::db::net_rule_upsert(
            &p.db(),
            &net_rule("l1", "8.8.8.8", Some(443), policy::net::NetMode::Log),
        )
        .unwrap();
        let (allow, rule) = handle_net_decide(&p, "8.8.8.8", 443);
        assert!(allow);
        assert_eq!(rule, None, "log rules are observability-only");
        assert_eq!(p.net_snapshot_rebuild_count(), 1);

        // Still unchanged: probes only, no further rebuilds.
        for _ in 0..3 {
            let _ = handle_net_decide(&p, "8.8.8.8", 443);
        }
        assert_eq!(p.net_snapshot_rebuild_count(), 1);
    }

    #[test]
    fn net_decide_reference_path_matches_snapshot_path() {
        // Belt-and-braces that the delegation is real: the rule set
        // exercises every matcher branch (CIDR deny, exact-host allow,
        // wildcard log, port-scoped deny) and the pure reference path must
        // agree with the compiled snapshot for every query.
        let rules = [
            net_rule("d-cidr", "10.0.0.0/8", None, policy::net::NetMode::Deny),
            net_rule("a-exact", "api.example.com", None, policy::net::NetMode::Allow),
            net_rule("l-wild", "*.example.com", None, policy::net::NetMode::Log),
            net_rule("d-port", "8.8.8.8", Some(53), policy::net::NetMode::Deny),
        ];
        let snapshot = policy::net::NetSnapshot::from_rules(0, &rules);
        let queries = [
            ("10.1.2.3", 443),        // inside the CIDR -> deny d-cidr
            ("11.0.0.1", 443),        // outside the CIDR
            ("api.example.com", 443), // exact allow id
            ("api.example.com", 1),   // rule has no port -> matches any
            ("www.example.com", 80),  // only the log rule matches -> plain allow
            ("example.com", 80),      // bare domain: no rule
            ("8.8.8.8", 53),          // port-scoped deny
            ("8.8.8.8", 443),         // port mismatch -> allow
            ("other.test", 22),       // no match at all -> allow
        ];
        for (host, port) in queries {
            assert_eq!(
                net_decide(&rules, host, port),
                snapshot.decide(host, port),
                "reference and snapshot paths must agree for {host}:{port}"
            );
        }
    }
}
