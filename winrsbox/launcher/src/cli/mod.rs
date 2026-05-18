pub mod id;
pub mod rule;
pub mod mock;
pub mod mockdir;
pub mod defaults;
pub mod r#why;
pub mod export;

use anyhow::Result;

/// Exit codes (structured, testable).
pub const EXIT_OK: i32 = 0;
pub const EXIT_USER_ERROR: i32 = 1;
pub const EXIT_SYSTEM_ERROR: i32 = 2;
pub const EXIT_CONFLICT: i32 = 3;

/// Known subcommands — used for back-compat dispatch.
pub const SUBCOMMANDS: &[&str] = &[
    "rule", "mock", "mockdir", "defaults", "why", "what-if", "export", "import",
];

/// Check if args represent a CLI subcommand (vs legacy sandbox run).
pub fn is_cli_command(args: &[String]) -> bool {
    if args.is_empty() { return false; }
    let first = args[0].to_lowercase();
    SUBCOMMANDS.contains(&first.as_str())
}

/// Dispatch CLI subcommand. `state_dir` is the `.winrsbox/<name>/` path.
pub fn run_cli(args: &[String], state_dir: &std::path::Path) -> Result<()> {
    if args.is_empty() {
        anyhow::bail!("no subcommand specified");
    }
    let cmd = args[0].to_lowercase();
    let rest = &args[1..];

    match cmd.as_str() {
        "rule" => rule::run(rest, state_dir),
        "mock" => mock::run(rest, state_dir),
        "mockdir" => mockdir::run(rest, state_dir),
        "defaults" => defaults::run(rest, state_dir),
        "why" => r#why::run(rest, state_dir),
        "what-if" => r#why::run_what_if(rest, state_dir),
        "export" => export::run_export(rest, state_dir),
        "import" => export::run_import(rest, state_dir),
        _ => anyhow::bail!("unknown subcommand: {}", cmd),
    }
}

/// Open the policy database (create if needed).
fn open_db(state_dir: &std::path::Path) -> Result<redb::Database> {
    let db_path = state_dir.join("policy.redb");
    let db = redb::Database::create(&db_path)?;
    // Ensure tables exist
    {
        let txn = db.begin_write()?;
        txn.open_table(policy::db::RULES)?;
        txn.open_table(policy::db::MOCKS)?;
        txn.open_table(policy::db::MOCK_DIRS)?;
        txn.open_table(policy::db::OVERLAY_IDX)?;
        txn.commit()?;
    }
    Ok(db)
}
