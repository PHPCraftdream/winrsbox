use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetMode {
    Allow,
    Deny,
    Log,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetRule {
    pub id: String,
    pub host_pattern: String,
    pub port: Option<u16>,
    pub mode: NetMode,
}

pub fn match_host(pattern: &str, host: &str) -> bool {
    let p = pattern.to_lowercase();
    let h = host.to_lowercase();
    if p == h { return true; }
    if p == "*" { return true; }
    if let Some(suffix) = p.strip_prefix("*.") {
        let dot_suffix = format!(".{suffix}");
        return h.ends_with(&dot_suffix) || h == suffix;
    }
    crate::path::segment_match(&p, &h)
}

pub fn parse_cidr(cidr: &str) -> Option<(u32, u32)> {
    let (ip_str, bits_str) = cidr.split_once('/')?;
    let bits: u32 = bits_str.parse().ok()?;
    if bits > 32 { return None; }
    let ip = parse_ipv4(ip_str)?;
    let mask = if bits == 0 { 0 } else { !0u32 << (32 - bits) };
    Some((ip & mask, mask))
}

pub fn parse_ipv4(s: &str) -> Option<u32> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 { return None; }
    let a: u32 = parts[0].parse().ok()?;
    let b: u32 = parts[1].parse().ok()?;
    let c: u32 = parts[2].parse().ok()?;
    let d: u32 = parts[3].parse().ok()?;
    if a > 255 || b > 255 || c > 255 || d > 255 { return None; }
    Some((a << 24) | (b << 16) | (c << 8) | d)
}

pub fn ip_in_cidr(ip: u32, network: u32, mask: u32) -> bool {
    (ip & mask) == network
}

pub fn is_localhost(host: &str) -> bool {
    let h = host.to_lowercase();
    h == "localhost" || h == "127.0.0.1" || h == "::1" || h == "0.0.0.0"
}

// ── Versioned, immutable, pre-parsed net-rule snapshot ───────────────────────
//
// Every NetDecide IPC request used to trigger a full NET_RULES table scan +
// bincode decode of every rule per connect (db::net_rule_list in the
// launcher). Instead, rules are compiled ONCE per persisted generation
// (db::NET_RULES_GEN) into a `NetSnapshot` and decided against the compiled
// form. The persisted generation counter is the cross-process invalidation
// signal: net rules are ONLY written out-of-process (CLI
// `winrsbox netrule add/remove/clear` on the same policy.redb), so an
// in-memory-only cache would go stale forever — the counter must live in
// the DB and bump atomically with every rule write.

/// Host-matching strategy pre-parsed per rule. The classification mirrors
/// `match_host`'s branch ORDER exactly so compiled decisions are
/// observably identical to the legacy per-request matcher.
#[derive(Debug, Clone, PartialEq, Eq)]
enum HostKind {
    /// Pattern is "*": matches every host.
    Star,
    /// Pattern is "*.suffix": literal suffix matching — NO glob
    /// interpretation of `*`/`?` inside the suffix; segment_match is never
    /// reached for such patterns in match_host. Stores `.{suffix}`.
    Suffix { dot_suffix: Box<str> },
    /// Anything else: glob match via `crate::path::segment_match`.
    Glob { pattern: Box<str> },
}

/// One net rule with all pattern parsing hoisted out of the hot path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledNetRule {
    pub id: String,
    pub port: Option<u16>,
    /// `host_pattern.to_lowercase()` — match_host lowercases per call; we
    /// do it once at compile time.
    pub pattern_lower: Box<str>,
    pub mode: NetMode,
    kind: HostKind,
    /// `(network, mask)` when the pattern parses as a v4 CIDR. Parsed from
    /// the ORIGINAL (unlowered) pattern — this mirrors the launcher's
    /// net_host_matches, which calls parse_cidr on the raw pattern.
    cidr: Option<(u32, u32)>,
}

impl CompiledNetRule {
    fn compile(rule: &NetRule) -> Self {
        let pattern_lower: Box<str> = rule.host_pattern.to_lowercase().into();
        // Branch order mirrors match_host exactly: "*", then "*." prefix
        // (literal suffix), else glob.
        let kind = if &*pattern_lower == "*" {
            HostKind::Star
        } else if let Some(suffix) = pattern_lower.strip_prefix("*.") {
            HostKind::Suffix { dot_suffix: format!(".{suffix}").into() }
        } else {
            HostKind::Glob { pattern: pattern_lower.clone() }
        };
        let cidr = parse_cidr(&rule.host_pattern);
        Self {
            id: rule.id.clone(),
            port: rule.port,
            pattern_lower,
            mode: rule.mode,
            kind,
            cidr,
        }
    }

    /// Host match for an already-lowercased host. A faithful port of
    /// match_host + the launcher's CIDR fallback: the `p == h` exact
    /// branch applies to EVERY pattern shape (including a host that
    /// literally equals a "*.suffix" pattern), then the kind branch, then
    /// CIDR containment. Evaluating the string branches first and the
    /// CIDR last is observably identical to the legacy
    /// match_host-then-CIDR order because every branch is a pure
    /// OR-predicate.
    fn matches(&self, host_lower: &str) -> bool {
        if &*self.pattern_lower == host_lower {
            return true;
        }
        let kind_match = match &self.kind {
            HostKind::Star => true,
            HostKind::Suffix { dot_suffix } => {
                let dot: &str = dot_suffix; // deref-coerce &Box<str>
                host_lower == &dot[1..] || host_lower.ends_with(dot)
            }
            HostKind::Glob { pattern } => crate::path::segment_match(pattern, host_lower),
        };
        if kind_match {
            return true;
        }
        if let (Some((net, mask)), Some(ip)) = (self.cidr, parse_ipv4(host_lower)) {
            return (ip & mask) == net;
        }
        false
    }
}

/// An immutable, pre-parsed net-rules snapshot for one persisted
/// generation. Readers always decide against exactly one consistent
/// snapshot; rebuilds are published atomically via ArcSwap by
/// `Policy::net_rule_decide`.
pub struct NetSnapshot {
    /// Persisted generation (db::NET_RULES_GEN) this snapshot was compiled
    /// from; the rebuild check is `stored.gen != current gen`.
    pub gen: u64,
    rules: Vec<CompiledNetRule>,
}

impl NetSnapshot {
    /// Compile rules in stored order — ascending rule id, the same order
    /// db::net_rule_list's range scan yields. Order matters: it decides
    /// which matching deny/allow id is reported first.
    pub fn from_rules(gen: u64, rules: &[NetRule]) -> NetSnapshot {
        NetSnapshot { gen, rules: rules.iter().map(CompiledNetRule::compile).collect() }
    }

    /// Read every net rule and compile it at `gen`.
    pub fn load_from_db(db: &redb::Database, gen: u64) -> Result<NetSnapshot, crate::PolicyError> {
        let rules = crate::db::net_rule_list(db)?;
        Ok(Self::from_rules(gen, &rules))
    }

    /// Faithful port of the launcher's net_decide
    /// (crates/winrsbox-launcher/src/pipe_server/records.rs): lowercase the
    /// host once, iterate rules in stored order, skip port mismatches,
    /// first matching Deny wins over any matching Allow, Log rules never
    /// affect the outcome, no match (including no rules at all) allows.
    pub fn decide(&self, host: &str, port: u16) -> (bool, Option<String>) {
        let host_lower = host.to_lowercase();
        let mut deny_rule: Option<&str> = None;
        let mut allow_rule: Option<&str> = None;
        for r in &self.rules {
            if r.port.is_some() && r.port != Some(port) {
                continue;
            }
            if !r.matches(&host_lower) {
                continue;
            }
            match r.mode {
                NetMode::Deny => {
                    if deny_rule.is_none() {
                        deny_rule = Some(&r.id);
                    }
                }
                NetMode::Allow => {
                    if allow_rule.is_none() {
                        allow_rule = Some(&r.id);
                    }
                }
                NetMode::Log => {}
            }
        }
        match deny_rule {
            Some(id) => (false, Some(id.to_string())),
            None => (true, allow_rule.map(str::to_string)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn match_host_exact() {
        assert!(match_host("api.github.com", "api.github.com"));
        assert!(match_host("API.GitHub.COM", "api.github.com"));
        assert!(!match_host("api.github.com", "evil.com"));
    }

    #[test]
    fn match_host_wildcard_subdomain() {
        assert!(match_host("*.github.com", "api.github.com"));
        assert!(match_host("*.github.com", "raw.github.com"));
        assert!(!match_host("*.github.com", "github.io"));
        assert!(!match_host("*.github.com", "evil.github.com.evil.org"));
    }

    #[test]
    fn match_host_star_all() {
        assert!(match_host("*", "anything.com"));
        assert!(match_host("*", "127.0.0.1"));
    }

    #[test]
    fn parse_cidr_basic() {
        let (net, mask) = parse_cidr("10.0.0.0/8").unwrap();
        assert_eq!(net, 0x0A000000);
        assert_eq!(mask, 0xFF000000);
    }

    #[test]
    fn parse_cidr_24() {
        let (net, mask) = parse_cidr("192.168.1.0/24").unwrap();
        assert_eq!(net, 0xC0A80100);
        assert_eq!(mask, 0xFFFFFF00);
    }

    #[test]
    fn parse_cidr_32() {
        let (net, mask) = parse_cidr("1.2.3.4/32").unwrap();
        assert_eq!(net, 0x01020304);
        assert_eq!(mask, 0xFFFFFFFF);
    }

    #[test]
    fn parse_cidr_invalid() {
        assert!(parse_cidr("not_ip/8").is_none());
        assert!(parse_cidr("10.0.0.0/33").is_none());
        assert!(parse_cidr("10.0.0.0").is_none());
    }

    #[test]
    fn ip_in_cidr_works() {
        let (net, mask) = parse_cidr("10.0.0.0/8").unwrap();
        assert!(ip_in_cidr(parse_ipv4("10.1.2.3").unwrap(), net, mask));
        assert!(ip_in_cidr(parse_ipv4("10.255.255.255").unwrap(), net, mask));
        assert!(!ip_in_cidr(parse_ipv4("11.0.0.1").unwrap(), net, mask));
    }

    #[test]
    fn parse_ipv4_basic() {
        assert_eq!(parse_ipv4("192.168.1.1"), Some(0xC0A80101));
        assert_eq!(parse_ipv4("0.0.0.0"), Some(0));
        assert_eq!(parse_ipv4("255.255.255.255"), Some(0xFFFFFFFF));
    }

    #[test]
    fn parse_ipv4_invalid() {
        assert!(parse_ipv4("256.0.0.0").is_none());
        assert!(parse_ipv4("1.2.3").is_none());
        assert!(parse_ipv4("abc").is_none());
    }

    #[test]
    fn is_localhost_works() {
        assert!(is_localhost("localhost"));
        assert!(is_localhost("127.0.0.1"));
        assert!(is_localhost("::1"));
        assert!(is_localhost("0.0.0.0"));
        assert!(!is_localhost("10.0.0.1"));
        assert!(!is_localhost("google.com"));
    }

    #[test]
    fn match_host_no_false_suffix() {
        assert!(!match_host("*.github.com", "notgithub.com"));
    }

    // ── Versioned snapshot: classification ────────────────────────────────

    fn nrule(id: &str, pat: &str, port: Option<u16>, mode: NetMode) -> NetRule {
        NetRule { id: id.into(), host_pattern: pat.into(), port, mode }
    }

    #[test]
    fn snapshot_classification_star_suffix_glob_cidr() {
        let snap = NetSnapshot::from_rules(0, &[
            nrule("star", "*", None, NetMode::Allow),
            nrule("suffix", "*.Example.COM", None, NetMode::Allow),
            nrule("glob", "api?.github.com", None, NetMode::Allow),
            nrule("cidr", "10.0.0.0/8", None, NetMode::Deny),
        ]);
        assert!(matches!(snap.rules[0].kind, HostKind::Star));
        assert!(matches!(snap.rules[1].kind, HostKind::Suffix { .. }));
        assert_eq!(&*snap.rules[1].pattern_lower, "*.example.com");
        match &snap.rules[1].kind {
            HostKind::Suffix { dot_suffix } => assert_eq!(&**dot_suffix, ".example.com"),
            _ => unreachable!("suffix rule must classify as Suffix"),
        }
        assert!(matches!(snap.rules[2].kind, HostKind::Glob { .. }));
        // "10.0.0.0/8" is BOTH a valid glob string and a valid CIDR: the
        // cidr must be parsed AND the kind must be Glob (not "*", no "*."
        // prefix → glob branch, exactly like match_host).
        assert!(matches!(snap.rules[3].kind, HostKind::Glob { .. }));
        assert_eq!(snap.rules[3].cidr, Some((0x0A000000, 0xFF000000)));
        assert_eq!(snap.rules[0].cidr, None, "* never parses as CIDR");
        assert_eq!(snap.rules[1].cidr, None, "*.suffix never parses as CIDR");
    }

    #[test]
    fn snapshot_from_rules_preserves_order() {
        let snap = NetSnapshot::from_rules(7, &[
            nrule("b", "b.com", None, NetMode::Allow),
            nrule("a", "a.com", None, NetMode::Deny),
        ]);
        assert_eq!(snap.gen, 7);
        assert_eq!(snap.rules.len(), 2);
        assert_eq!(snap.rules[0].id, "b", "stored (ascending-id) order is preserved");
        assert_eq!(snap.rules[1].id, "a");
    }

    // ── Versioned snapshot: decide ────────────────────────────────────────

    #[test]
    fn snapshot_decide_exact_and_case_insensitive() {
        let snap = NetSnapshot::from_rules(0, &[nrule("a", "api.github.com", None, NetMode::Allow)]);
        assert_eq!(snap.decide("api.github.com", 443), (true, Some("a".into())));
        // Uppercase rule pattern vs lowercase host.
        let upper = NetSnapshot::from_rules(0, &[nrule("a", "API.GitHub.COM", None, NetMode::Allow)]);
        assert_eq!(upper.decide("api.github.com", 443), (true, Some("a".into())));
        // Lowercase rule pattern vs uppercase host.
        assert_eq!(upper.decide("API.GitHub.COM", 443), (true, Some("a".into())));
        assert_eq!(snap.decide("evil.com", 443), (true, None));
    }

    #[test]
    fn snapshot_decide_star() {
        let allow_all = NetSnapshot::from_rules(0, &[nrule("a", "*", None, NetMode::Allow)]);
        assert_eq!(allow_all.decide("anything.com", 80), (true, Some("a".into())));
        let deny_all = NetSnapshot::from_rules(0, &[nrule("d", "*", None, NetMode::Deny)]);
        assert_eq!(deny_all.decide("127.0.0.1", 80), (false, Some("d".into())));
    }

    #[test]
    fn snapshot_decide_suffix() {
        let snap = NetSnapshot::from_rules(0, &[nrule("a", "*.example.com", None, NetMode::Allow)]);
        assert_eq!(snap.decide("a.example.com", 443), (true, Some("a".into())));
        // Bare suffix also matches (h == suffix branch).
        assert_eq!(snap.decide("example.com", 443), (true, Some("a".into())));
        // NOT a false suffix match.
        assert_eq!(snap.decide("badexample.com", 443), (true, None));
        assert_eq!(snap.decide("evil.example.com.evil.org", 443), (true, None));
        // Degenerate p == h: a host that literally equals the "*.suffix"
        // pattern matches via the exact branch.
        assert_eq!(snap.decide("*.example.com", 443), (true, Some("a".into())));
    }

    #[test]
    fn snapshot_decide_cidr() {
        let snap = NetSnapshot::from_rules(0, &[nrule("d", "10.0.0.0/8", None, NetMode::Deny)]);
        assert_eq!(snap.decide("10.1.2.3", 80), (false, Some("d".into())));
        assert_eq!(snap.decide("11.0.0.1", 80), (true, None));
        // Exact /32 containment.
        let exact = NetSnapshot::from_rules(0, &[nrule("d", "1.2.3.4/32", None, NetMode::Deny)]);
        assert_eq!(exact.decide("1.2.3.4", 80), (false, Some("d".into())));
    }

    #[test]
    fn snapshot_decide_port_filter() {
        let snap = NetSnapshot::from_rules(0, &[nrule("d", "8.8.8.8", Some(443), NetMode::Deny)]);
        assert_eq!(snap.decide("8.8.8.8", 80), (true, None), "port-mismatched rule is skipped");
        assert_eq!(snap.decide("8.8.8.8", 443), (false, Some("d".into())));
    }

    #[test]
    fn snapshot_decide_deny_wins_log_neutral_and_empty() {
        // Deny wins over allow even when the allow rule comes first, and
        // the deny id is the one reported.
        let snap = NetSnapshot::from_rules(0, &[
            nrule("allow-1", "*.example.com", None, NetMode::Allow),
            nrule("deny-1", "specific.example.com", None, NetMode::Deny),
        ]);
        assert_eq!(snap.decide("specific.example.com", 443), (false, Some("deny-1".into())));
        assert_eq!(snap.decide("other.example.com", 443), (true, Some("allow-1".into())));

        // Log rules never affect the outcome.
        let logged = NetSnapshot::from_rules(0, &[
            nrule("log-1", "*.example.com", None, NetMode::Log),
            nrule("allow-2", "a.example.com", None, NetMode::Allow),
        ]);
        assert_eq!(logged.decide("a.example.com", 443), (true, Some("allow-2".into())));
        let log_only = NetSnapshot::from_rules(0, &[nrule("log-2", "*", None, NetMode::Log)]);
        assert_eq!(log_only.decide("anything.com", 80), (true, None));

        // No rules at all → allow with no matched id.
        let empty = NetSnapshot::from_rules(0, &[]);
        assert_eq!(empty.decide("example.com", 443), (true, None));
    }

    // ── Equivalence vs the CURRENT launcher decision core ─────────────────
    //
    // Verbatim copy (renamed) of
    // crates/winrsbox-launcher/src/pipe_server/records.rs `net_decide` +
    // `net_host_matches` as of this writing. The only textual difference is
    // the crate path (`policy::net::x` → the in-crate `super::` items);
    // every statement is otherwise byte-identical. If the launcher core
    // ever changes semantics, this test is the tripwire.

    fn legacy_net_decide(rules: &[NetRule], host: &str, port: u16) -> (bool, Option<String>) {
        let mut deny_rule: Option<&str> = None;
        let mut allow_rule: Option<&str> = None;
        for r in rules {
            if r.port.is_some() && r.port != Some(port) {
                continue;
            }
            if !legacy_host_matches(&r.host_pattern, host) {
                continue;
            }
            match r.mode {
                NetMode::Deny => {
                    if deny_rule.is_none() {
                        deny_rule = Some(&r.id);
                    }
                }
                NetMode::Allow => {
                    if allow_rule.is_none() {
                        allow_rule = Some(&r.id);
                    }
                }
                NetMode::Log => {}
            }
        }
        match deny_rule {
            Some(id) => (false, Some(id.to_string())),
            None => (true, allow_rule.map(str::to_string)),
        }
    }

    fn legacy_host_matches(pattern: &str, host: &str) -> bool {
        if match_host(pattern, host) {
            return true;
        }
        match (parse_cidr(pattern), parse_ipv4(host)) {
            (Some((net, mask)), Some(ip)) => ip_in_cidr(ip, net, mask),
            _ => false,
        }
    }

    #[test]
    fn snapshot_equivalence_with_launcher_net_decide() {
        type Case = (Vec<NetRule>, &'static str, u16, (bool, Option<String>));
        let cases: Vec<Case> = vec![
            // no rules at all
            (vec![], "example.com", 443, (true, None)),
            // star allow / star deny
            (vec![nrule("a", "*", None, NetMode::Allow)], "anything.com", 80, (true, Some("a".into()))),
            (vec![nrule("d", "*", None, NetMode::Deny)], "127.0.0.1", 80, (false, Some("d".into()))),
            // exact hit / miss
            (vec![nrule("a", "api.github.com", None, NetMode::Allow)], "api.github.com", 443, (true, Some("a".into()))),
            (vec![nrule("a", "api.github.com", None, NetMode::Allow)], "evil.com", 443, (true, None)),
            // port filter on an exact rule
            (vec![nrule("a", "api.github.com", Some(443), NetMode::Allow)], "api.github.com", 80, (true, None)),
            // case-insensitivity, both directions
            (vec![nrule("a", "API.GitHub.COM", None, NetMode::Allow)], "api.github.com", 443, (true, Some("a".into()))),
            (vec![nrule("a", "api.github.com", None, NetMode::Allow)], "API.GitHub.COM", 443, (true, Some("a".into()))),
            // "*.suffix": subdomain, bare suffix, false suffix, trailing junk
            (vec![nrule("a", "*.example.com", None, NetMode::Allow)], "a.example.com", 443, (true, Some("a".into()))),
            (vec![nrule("a", "*.example.com", None, NetMode::Allow)], "example.com", 443, (true, Some("a".into()))),
            (vec![nrule("a", "*.example.com", None, NetMode::Allow)], "badexample.com", 443, (true, None)),
            (vec![nrule("a", "*.example.com", None, NetMode::Allow)], "evil.example.com.evil.org", 443, (true, None)),
            // degenerate p == h (host literally equals the "*.suffix" pattern)
            (vec![nrule("a", "*.example.com", None, NetMode::Allow)], "*.example.com", 443, (true, Some("a".into()))),
            // CIDR containment / miss / port-filtered / exact /32
            (vec![nrule("d", "10.0.0.0/8", None, NetMode::Deny)], "10.1.2.3", 80, (false, Some("d".into()))),
            (vec![nrule("d", "10.0.0.0/8", None, NetMode::Deny)], "11.0.0.1", 80, (true, None)),
            (vec![nrule("d", "10.0.0.0/8", Some(443), NetMode::Deny)], "10.1.2.3", 80, (true, None)),
            (vec![nrule("d", "1.2.3.4/32", None, NetMode::Deny)], "1.2.3.4", 80, (false, Some("d".into()))),
            (vec![nrule("d", "1.2.3.4/32", None, NetMode::Deny)], "1.2.3.5", 80, (true, None)),
            // digits are unaffected by lowercasing — uppercase-ish IP host
            (vec![nrule("d", "10.0.0.0/8", None, NetMode::Deny)], "10.1.2.3", 443, (false, Some("d".into()))),
            // invalid CIDR (/33) → None → glob fallback (no wildcards → miss)
            (vec![nrule("d", "10.0.0.0/33", None, NetMode::Deny)], "10.1.2.3", 80, (true, None)),
            // glob `?` hit and miss
            (vec![nrule("a", "api?.github.com", None, NetMode::Allow)], "api1.github.com", 443, (true, Some("a".into()))),
            (vec![nrule("a", "api?.github.com", None, NetMode::Allow)], "api12.github.com", 443, (true, None)),
            // multi-label suffix
            (vec![nrule("a", "*.a.b", None, NetMode::Allow)], "x.a.b", 80, (true, Some("a".into()))),
            // degenerate "*." pattern
            (vec![nrule("a", "*.", None, NetMode::Allow)], "anything", 80, (true, None)),
            // empty pattern / empty host
            (vec![nrule("d", "", None, NetMode::Deny)], "", 80, (false, Some("d".into()))),
            (vec![nrule("d", "", None, NetMode::Deny)], "example.com", 80, (true, None)),
            // deny wins over allow regardless of stored order
            (vec![
                nrule("allow-1", "*.example.com", None, NetMode::Allow),
                nrule("deny-1", "specific.example.com", None, NetMode::Deny),
            ], "specific.example.com", 443, (false, Some("deny-1".into()))),
            (vec![
                nrule("deny-1", "*.example.com", None, NetMode::Deny),
                nrule("allow-1", "a.example.com", None, NetMode::Allow),
            ], "a.example.com", 443, (false, Some("deny-1".into()))),
            // mixed kinds: star allow vs CIDR deny → deny wins
            (vec![
                nrule("allow-1", "*", None, NetMode::Allow),
                nrule("deny-1", "10.0.0.0/8", None, NetMode::Deny),
            ], "10.1.2.3", 443, (false, Some("deny-1".into()))),
            // Log neutrality: log-only, and log + allow
            (vec![nrule("log-1", "*", None, NetMode::Log)], "anything.com", 80, (true, None)),
            (vec![
                nrule("log-1", "*.example.com", None, NetMode::Log),
                nrule("allow-1", "a.example.com", None, NetMode::Allow),
            ], "a.example.com", 443, (true, Some("allow-1".into()))),
            // quirky but well-defined: host literally equals a CIDR string
            (vec![nrule("d", "10.0.0.0/8", None, NetMode::Deny)], "10.0.0.0/8", 80, (false, Some("d".into()))),
        ];
        assert!(cases.len() >= 20, "equivalence table must stay diverse");
        for (rules, host, port, expected) in &cases {
            let compiled = NetSnapshot::from_rules(0, rules).decide(host, *port);
            let legacy = legacy_net_decide(rules, host, *port);
            assert_eq!(
                compiled, legacy,
                "compiled vs legacy diverged for {host}:{port} with rules {rules:?}"
            );
            assert_eq!(compiled, *expected, "unexpected outcome for {host}:{port}");
        }
    }
}
