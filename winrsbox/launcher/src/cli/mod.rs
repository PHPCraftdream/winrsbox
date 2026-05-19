pub mod id;
pub mod rule;
pub mod mock;
pub mod mockdir;
pub mod defaults;
pub mod r#why;
pub mod export;
pub mod regrule;
pub mod regmock;
pub mod regdefaults;
pub mod regwhy;

use anyhow::Result;

/// Exit codes (structured, testable).
pub const EXIT_OK: i32 = 0;
pub const EXIT_USER_ERROR: i32 = 1;
pub const EXIT_SYSTEM_ERROR: i32 = 2;
pub const EXIT_CONFLICT: i32 = 3;

/// Known subcommands — used for back-compat dispatch.
pub const SUBCOMMANDS: &[&str] = &[
    "rule", "mock", "mockdir", "defaults", "why", "what-if", "export", "import",
    "regrule", "regmock", "regdefaults", "regwhy",
];

/// Check if args represent a CLI subcommand (vs legacy sandbox run).
pub fn is_cli_command(args: &[String]) -> bool {
    if args.is_empty() { return false; }
    let first = args[0].to_lowercase();
    SUBCOMMANDS.contains(&first.as_str())
}

pub const CLI_HELP: &str = "\
winrsbox — Windows filesystem sandbox CLI

SUBCOMMANDS:
  rule       Add, remove, list, show, or clear sandbox rules
  mock       Add, remove, list, or show file mocks
  mockdir    Add, remove, or list mocked directories
  defaults   Set or show default read/write policy modes
  why        Simulate a path lookup — show decision, target path, and rule chain
  what-if    Test a hypothetical rule change without mutating state
  export     Dump current state as JSON to stdout (filesystem + registry)
  import     Load state from JSON stdin (merge or --replace) or --ktav file

REGISTRY SANDBOX:
  regrule    Add, remove, list, or clear registry sandbox rules
  regmock    Add, remove, or list registry value mocks
  regdefaults Set or show default registry read/write policy modes
  regwhy     Simulate a registry key lookup — show decision and source

GLOBAL OPTIONS:
  --state-dir=PATH   Override state directory (default: auto-discover)
  WINRSBOX_STATE_DIR  env var — same as --state-dir

EXIT CODES:
  0  Success
  1  User error (bad args, invalid mode, unknown id)
  2  System error (IO, permissions, redb)

EXAMPLES:
  winrsbox rule add --prefix='C:\\Users\\*\\AppData' --write=deny
  winrsbox why 'C:\\Users\\alice\\doc.txt' --write --depth=1 --json
  winrsbox what-if rule add --prefix='C:\\Secret' --write=deny -- C:\\foo
  winrsbox export --json > backup.json
  winrsbox import --replace < backup.json
";

/// Dispatch CLI subcommand. `state_dir` is the `.winrsbox/<name>/` path.
pub fn run_cli(args: &[String], state_dir: &std::path::Path) -> Result<()> {
    if args.is_empty() || args.iter().any(|a| a == "--help" || a == "-h") {
        print!("{}", CLI_HELP);
        return Ok(());
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
        "regrule" => regrule::run(rest, state_dir),
        "regmock" => regmock::run(rest, state_dir),
        "regdefaults" => regdefaults::run(rest, state_dir),
        "regwhy" => regwhy::run(rest, state_dir),
        _ => anyhow::bail!("unknown subcommand '{}'. Run 'winrsbox --help' for usage.", cmd),
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
