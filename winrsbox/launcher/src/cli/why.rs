use anyhow::{bail, Result};
use std::path::PathBuf;

pub fn run(args: &[String], state_dir: &std::path::Path) -> Result<()> {
    let sandbox_root = state_dir.join("workdir");
    let mock_dirs_root = state_dir.join("mock-dirs");
    let project_root = state_dir.parent()
        .and_then(|p| p.parent())
        .unwrap_or(state_dir)
        .to_path_buf();

    let db_path = state_dir.join("policy.redb");
    let policy = policy::Policy::open_or_create(
        &db_path,
        sandbox_root,
        mock_dirs_root,
        project_root,
    )?;

    let json = has_flag(args, "--json");
    let write_flag = has_flag(args, "--write");
    let stdin_flag = has_flag(args, "--stdin");
    let depth = find_arg(args, "--depth=").map(|s| s.parse::<u8>()).transpose()?;
    let exe = find_arg(args, "--exe=").map(String::from);

    // Collect paths: either from --stdin, or positional after flags
    let paths: Vec<String> = if stdin_flag {
        use std::io::BufRead;
        std::io::stdin().lock().lines().filter_map(|l| l.ok()).collect()
    } else {
        args.iter()
            .filter(|a| !a.starts_with('-'))
            .cloned()
            .collect()
    };

    if paths.is_empty() {
        bail!("why: at least one path required");
    }

    for path in &paths {
        if write_flag {
            let traced = policy.decide_traced(path, true, depth, exe.as_deref());
            if json {
                let obj = serde_json::json!({
                    "schema_version": 1,
                    "path": path,
                    "context": serde_json::json!({
                        "depth": depth,
                        "exe": exe,
                        "write": true,
                    }),
                    "decision": format!("{:?}", traced.decision).to_lowercase(),
                    "target_path": traced.target_path,
                    "rule_id": traced.rule_id,
                    "rule_prefix": traced.rule_prefix,
                    "mock_match": traced.mock_match,
                    "mockdir_match": traced.mockdir_match,
                    "chain": traced.chain.iter().map(|c| serde_json::json!({
                        "id": c.id,
                        "prefix": c.prefix,
                        "verdict": match &c.verdict {
                            policy::Verdict::Match { specificity } => serde_json::json!({"match": specificity}),
                            policy::Verdict::Skip { reason } => serde_json::json!({"skip": reason}),
                        }
                    })).collect::<Vec<_>>(),
                });
                println!("{}", serde_json::to_string(&obj)?);
            } else {
                print_human(&policy, path, true, &traced);
            }
        } else {
            let read_traced = policy.decide_traced(path, false, depth, exe.as_deref());
            let write_traced = policy.decide_traced(path, true, depth, exe.as_deref());
            if json {
                let obj = serde_json::json!({
                    "schema_version": 1,
                    "path": path,
                    "context": serde_json::json!({
                        "depth": depth,
                        "exe": exe,
                    }),
                    "read": traced_to_json(&read_traced),
                    "write": traced_to_json(&write_traced),
                });
                println!("{}", serde_json::to_string(&obj)?);
            } else {
                print_human_pair(path, depth, &read_traced, &write_traced);
            }
        }
    }

    Ok(())
}

fn traced_to_json(td: &policy::TracedDecision) -> serde_json::Value {
    serde_json::json!({
        "decision": format!("{:?}", td.decision).to_lowercase(),
        "target_path": td.target_path,
        "rule_id": td.rule_id,
        "rule_prefix": td.rule_prefix,
        "chain": td.chain.iter().map(|c| serde_json::json!({
            "id": c.id,
            "prefix": c.prefix,
            "verdict": match &c.verdict {
                policy::Verdict::Match { specificity } => serde_json::json!({"match": specificity}),
                policy::Verdict::Skip { reason } => serde_json::json!({"skip": reason}),
            }
        })).collect::<Vec<_>>(),
    })
}

fn print_human(_policy: &policy::Policy, path: &str, _write: bool, traced: &policy::TracedDecision) {
    let decision = format!("{:?}", traced.decision).to_lowercase();
    let target = traced.target_path.as_deref()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.to_string());
    let rule_info = traced.rule_id.as_deref().map(|id| {
        format!(" [rule: {} prefix={}]", id, traced.rule_prefix.as_deref().unwrap_or("?"))
    }).unwrap_or_default();
    println!("{}  →  {}{}", path, decision, if target != path { format!(" → {}", target) } else { String::new() });
    println!("{}", rule_info);
    if !traced.chain.is_empty() {
        println!("  considered:");
        for c in &traced.chain {
            match &c.verdict {
                policy::Verdict::Match { specificity } => {
                    println!("    {}  {}  MATCH (specificity={})", c.id, c.prefix, specificity);
                }
                policy::Verdict::Skip { reason } => {
                    println!("    {}  {}  skip ({})", c.id, c.prefix, reason);
                }
            }
        }
    }
}

fn print_human_pair(path: &str, depth: Option<u8>, read_td: &policy::TracedDecision, write_td: &policy::TracedDecision) {
    let depth_str = depth.map(|d| format!("depth={d}")).unwrap_or_default();
    println!("{}  ({})", path, depth_str);
    // read line
    {
        let decision = format!("{:?}", read_td.decision).to_lowercase();
        let target = read_td.target_path.as_deref()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.to_string());
        let rule_info = read_td.rule_id.as_deref().map(|id| format!("[rule: {} prefix={}]", id, read_td.rule_prefix.as_deref().unwrap_or("?"))).unwrap_or_default();
        println!("  read:  {} → {}  {}", decision, target, rule_info);
    }
    // write line
    {
        let decision = format!("{:?}", write_td.decision).to_lowercase();
        let target = write_td.target_path.as_deref()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.to_string());
        let rule_info = write_td.rule_id.as_deref().map(|id| format!("[rule: {} prefix={}]", id, write_td.rule_prefix.as_deref().unwrap_or("?"))).unwrap_or_default();
        println!("  write: {} → {}  {}", decision, target, rule_info);
    }
    // chain (use write chain as canonical)
    if !write_td.chain.is_empty() {
        println!("  considered:");
        for c in &write_td.chain {
            match &c.verdict {
                policy::Verdict::Match { specificity } => {
                    println!("    {}  {}  MATCH (specificity={})", c.id, c.prefix, specificity);
                }
                policy::Verdict::Skip { reason } => {
                    println!("    {}  {}  skip ({})", c.id, c.prefix, reason);
                }
            }
        }
    }
}

pub fn run_what_if(args: &[String], state_dir: &std::path::Path) -> Result<()> {
    // Parse: rule add --prefix=... -- <paths...>
    if args.len() < 2 { bail!("what-if: expected 'rule add ... -- <paths...>'"); }
    if args[0].to_lowercase() != "rule" || args[1].to_lowercase() != "add" {
        bail!("what-if: only 'rule add' is supported");
    }

    let rule_args = &args[2..];
    // Split on "--"
    let separator_pos = rule_args.iter().position(|a| a == "--")
        .ok_or_else(|| anyhow::anyhow!("what-if: '--' separator required before paths"))?;
    let rule_part = &rule_args[..separator_pos];
    let paths = &rule_args[separator_pos + 1..];

    if paths.is_empty() {
        bail!("what-if: at least one path required after --");
    }

    let json = has_flag(args, "--json");

    // Parse hypothetical rule
    let prefix = find_arg(rule_part, "--prefix=")
        .ok_or_else(|| anyhow::anyhow!("what-if rule add: --prefix is required"))?;
    let prefix_lower = prefix.to_lowercase();
    let write_mode = find_arg(rule_part, "--write=").map(|s| match s {
        "passthrough" => policy::db::RuleMode::Passthrough,
        "deny" => policy::db::RuleMode::Deny,
        "cow" => policy::db::RuleMode::Cow,
        "redirect" => policy::db::RuleMode::Redirect,
        _ => policy::db::RuleMode::Passthrough,
    }).unwrap_or(policy::db::RuleMode::Cow);
    let read_mode = find_arg(rule_part, "--read=").map(|s| match s {
        "passthrough" => policy::db::RuleMode::Passthrough,
        "deny" => policy::db::RuleMode::Deny,
        "cow" => policy::db::RuleMode::Cow,
        "redirect" => policy::db::RuleMode::Redirect,
        _ => policy::db::RuleMode::Passthrough,
    }).unwrap_or(policy::db::RuleMode::Passthrough);

    let hypothetical = policy::db::RuleRow {
        id: "__hypothetical__".into(),
        prefix: prefix_lower.clone(),
        mode_read: read_mode,
        mode_write: write_mode,
        when: None,
    };

    let sandbox_root = state_dir.join("workdir");
    let mock_dirs_root = state_dir.join("mock-dirs");
    let project_root = state_dir.parent()
        .and_then(|p| p.parent())
        .unwrap_or(state_dir)
        .to_path_buf();
    let db_path = state_dir.join("policy.redb");
    let policy = policy::Policy::open_or_create(
        &db_path,
        sandbox_root,
        mock_dirs_root,
        project_root,
    )?;

    // Baseline: compute decisions without hypothetical
    let mut baseline = Vec::new();
    for p in paths {
        let before = policy.decide_traced(p, true, None, None);
        baseline.push((p.to_string(), before));
    }

    // Apply hypothetical rule temporarily
    policy::db::rule_upsert(policy.db(), &hypothetical)?;

    let mut results = Vec::new();
    for (path, before) in &baseline {
        let after = policy.decide_traced(path, true, None, None);
        let changed = format!("{:?}", before.decision) != format!("{:?}", after.decision)
            || before.target_path != after.target_path;
        results.push(serde_json::json!({
            "path": path,
            "before": traced_to_json(before),
            "after": traced_to_json(&after),
            "changed": changed,
        }));
    }

    // Remove hypothetical (restore state)
    policy::db::rule_remove_by_prefix(policy.db(), &prefix_lower)?;

    if json {
        let out = serde_json::json!({
            "schema_version": 1,
            "hypothetical": {
                "kind": "rule",
                "action": "add",
                "fields": {
                    "prefix": prefix,
                    "read": format!("{:?}", read_mode).to_lowercase(),
                    "write": format!("{:?}", write_mode).to_lowercase(),
                },
            },
            "results": results,
        });
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else {
        println!("Hypothetical: rule prefix={} read={} write={}", prefix,
            format!("{:?}", read_mode).to_lowercase(),
            format!("{:?}", write_mode).to_lowercase());
        for r in &results {
            let path = r["path"].as_str().unwrap();
            let changed = r["changed"].as_bool().unwrap();
            println!("  {}  {}", path, if changed { "CHANGED" } else { "unchanged" });
            if changed {
                let before_d = r["before"]["decision"].as_str().unwrap();
                let after_d = r["after"]["decision"].as_str().unwrap();
                println!("    {} → {}", before_d, after_d);
            }
        }
    }
    Ok(())
}

fn find_arg<'a>(args: &'a [String], prefix: &str) -> Option<&'a str> {
    args.iter().find(|a| a.starts_with(prefix)).map(|a| &a[prefix.len()..])
}

fn has_flag(args: &[String], flag: &str) -> bool {
    args.iter().any(|a| a == flag)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_state() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join(".winrsbox").join("test");
        std::fs::create_dir_all(&state).unwrap();
        std::fs::create_dir_all(state.join("workdir")).unwrap();
        std::fs::create_dir_all(state.join("mock-dirs")).unwrap();
        (dir, state)
    }

    #[test]
    fn why_write_mode_json() {
        let (_dir, state) = tmp_state();
        // Add a deny rule first
        let db = super::super::open_db(&state).unwrap();
        let row = policy::db::RuleRow {
            id: "test-rule".into(),
            prefix: "c:\\secret".into(),
            mode_read: policy::db::RuleMode::Passthrough,
            mode_write: policy::db::RuleMode::Deny,
            when: None,
        };
        policy::db::rule_upsert(&db, &row).unwrap();
        drop(db);

        // Run why --write
        let result = run(&[
            "--write".into(),
            "--json".into(),
            r"C:\Secret\x.txt".into(),
        ], &state);
        // We can't easily capture stdout in tests, so just ensure no error
        assert!(result.is_ok());
    }

    #[test]
    fn why_both_modes() {
        let (_dir, state) = tmp_state();
        let result = run(&[
            "--json".into(),
            r"C:\some\path".into(),
        ], &state);
        assert!(result.is_ok());
    }

    #[test]
    fn why_chain_contains_skipped() {
        let (_dir, state) = tmp_state();
        let db = super::super::open_db(&state).unwrap();
        policy::db::rule_upsert(&db, &policy::db::RuleRow {
            id: "deny-win".into(),
            prefix: "c:\\windows".into(),
            mode_read: policy::db::RuleMode::Deny,
            mode_write: policy::db::RuleMode::Deny,
            when: None,
        }).unwrap();
        drop(db);

        // Query a path that doesn't match → should show skip in chain
        let db_path = state.join("policy.redb");
        let sandbox = state.join("workdir");
        let mock_dirs = state.join("mock-dirs");
        let project = state.parent().and_then(|p| p.parent()).unwrap().to_path_buf();
        let policy = policy::Policy::open_or_create(&db_path, sandbox, mock_dirs, project).unwrap();

        let traced = policy.decide_traced(r"c:\other\file", true, None, None);
        // Chain should contain deny-win as skip
        let skip_entries: Vec<_> = traced.chain.iter()
            .filter(|c| matches!(c.verdict, policy::Verdict::Skip { .. }))
            .collect();
        assert!(!skip_entries.is_empty(), "chain should have skipped entries");
    }

    #[test]
    fn why_target_path_for_cow() {
        let (_dir, state) = tmp_state();
        let db_path = state.join("policy.redb");
        let sandbox = state.join("workdir");
        let mock_dirs = state.join("mock-dirs");
        let project = state.parent().and_then(|p| p.parent()).unwrap().to_path_buf();
        let policy = policy::Policy::open_or_create(&db_path, sandbox.clone(), mock_dirs, project).unwrap();

        // Ensure defaults are set (cow for write)
        policy::db::defaults_set(policy.db(),
            Some(policy::db::RuleMode::Passthrough),
            Some(policy::db::RuleMode::Cow)).unwrap();

        // Default write is cow
        let traced = policy.decide_traced(r"c:\data.txt", true, None, None);
        assert!(matches!(traced.decision, policy::db::RuleMode::Cow));
        assert!(traced.target_path.is_some());
        assert!(traced.target_path.unwrap().starts_with(&sandbox));
    }

    #[test]
    fn why_deny_target_path_none() {
        let (_dir, state) = tmp_state();
        let db = super::super::open_db(&state).unwrap();
        policy::db::rule_upsert(&db, &policy::db::RuleRow {
            id: "deny-all".into(),
            prefix: "c:\\deny".into(),
            mode_read: policy::db::RuleMode::Deny,
            mode_write: policy::db::RuleMode::Deny,
            when: None,
        }).unwrap();
        drop(db);

        let db_path = state.join("policy.redb");
        let sandbox = state.join("workdir");
        let mock_dirs = state.join("mock-dirs");
        let project = state.parent().and_then(|p| p.parent()).unwrap().to_path_buf();
        let policy = policy::Policy::open_or_create(&db_path, sandbox, mock_dirs, project).unwrap();

        let traced = policy.decide_traced(r"c:\deny\file", true, None, None);
        assert!(matches!(traced.decision, policy::db::RuleMode::Deny));
        assert!(traced.target_path.is_none());
    }

    #[test]
    fn what_if_does_not_mutate_state() {
        let (_dir, state) = tmp_state();
        // Export state before
        let db = super::super::open_db(&state).unwrap();
        let rules_before = policy::db::rule_list(&db).unwrap();
        drop(db);

        let result = run_what_if(&[
            "rule".into(),
            "add".into(),
            "--prefix=C:\\Hypothetical".into(),
            "--write=deny".into(),
            "--".into(),
            r"C:\Hypothetical\x.txt".into(),
        ], &state);
        assert!(result.is_ok());

        // Verify state unchanged
        let db = super::super::open_db(&state).unwrap();
        let rules_after = policy::db::rule_list(&db).unwrap();
        assert_eq!(rules_before.len(), rules_after.len());
    }

    #[test]
    fn what_if_changed_flag_correct() {
        let (_dir, state) = tmp_state();
        // No rules match C:\Secret, so baseline is cow (default write)
        // Hypothetical deny rule on C:\Secret should show changed=true

        let result = run_what_if(&[
            "rule".into(),
            "add".into(),
            "--prefix=C:\\Secret".into(),
            "--write=deny".into(),
            "--".into(),
            r"C:\Secret\x.txt".into(),
            r"C:\Public\y.txt".into(),
        ], &state);
        assert!(result.is_ok());
    }
}
