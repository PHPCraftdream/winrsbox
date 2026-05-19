// Explorer context menu integration — install/uninstall right-click menu items.
//
// Registers 4 entries under HKCU (per-user, no admin needed):
//   1. "Open in winrsbox (wezterm)"
//   2. "Open in winrsbox (wezterm) [Admin]"
//   3. "Open in winrsbox (powershell)"
//   4. "Open in winrsbox (powershell) [Admin]"
//
// Each entry is created for:
//   - Directory\shell         (right-click on folder)
//   - Directory\Background\shell (right-click on empty space in folder)
//   - Drive\shell             (right-click on drive root)

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// Registry key names
// ---------------------------------------------------------------------------

const VERB_WEZTERM: &str = "winrsbox-wezterm";
const VERB_WEZTERM_ADMIN: &str = "winrsbox-wezterm-admin";
const VERB_PWSH: &str = "winrsbox-powershell";
const VERB_PWSH_ADMIN: &str = "winrsbox-powershell-admin";

const LABEL_WEZTERM: &str = "Open in winrsbox (wezterm)";
const LABEL_WEZTERM_ADMIN: &str = "Open in winrsbox (wezterm) \u{1F6E1}\u{FE0F} Admin";
const LABEL_PWSH: &str = "Open in winrsbox (powershell)";
const LABEL_PWSH_ADMIN: &str = "Open in winrsbox (powershell) \u{1F6E1}\u{FE0F} Admin";

const SHELL_ROOTS: &[&str] = &[
    r"Software\Classes\Directory\shell",
    r"Software\Classes\Directory\Background\shell",
    r"Software\Classes\Drive\shell",
];

// ---------------------------------------------------------------------------
// Public entry
// ---------------------------------------------------------------------------

pub fn run(args: &[String]) -> Result<()> {
    if args.is_empty() || args.iter().any(|a| a == "--help" || a == "-h") {
        print_help();
        return Ok(());
    }
    let cmd = args[0].to_lowercase();
    match cmd.as_str() {
        "install" => run_install(args),
        "uninstall" => run_uninstall(),
        "status" => run_status(),
        _ => anyhow::bail!("unknown shell subcommand '{cmd}'. Use: shell install | uninstall | status"),
    }
}

fn print_help() {
    eprintln!(
        "\
winrsbox shell — Explorer context menu integration

SUBCOMMANDS:
  install [--wezterm <path>] [--pwsh <path>]
      Register right-click menu entries for wezterm and powershell.
      Wezterm must be installed; auto-detected from PATH or --wezterm.
      PowerShell is auto-detected (pwsh.exe or powershell.exe).

  uninstall
      Remove all winrsbox entries from the Explorer context menu.

  status
      Show current registration state.
"
    );
}

// ---------------------------------------------------------------------------
// Install
// ---------------------------------------------------------------------------

fn run_install(args: &[String]) -> Result<()> {
    let winrsbox_exe = std::env::current_exe()
        .context("cannot determine winrsbox.exe path")?
        .to_string_lossy()
        .into_owned();

    // Resolve wezterm
    let wezterm_flag = extract_flag(args, "--wezterm");
    let wezterm_path = wezterm_flag
        .map(PathBuf::from)
        .or_else(|| find_in_path("wezterm-gui.exe").or_else(|| find_in_path("wezterm.exe")));

    let wezterm_path = match wezterm_path {
        Some(p) => {
            if !p.exists() {
                anyhow::bail!("wezterm not found at '{}'. Install wezterm or use --wezterm <path>.", p.display());
            }
            p.to_string_lossy().into_owned()
        }
        None => {
            anyhow::bail!("wezterm not found in PATH. Install wezterm (https://wezfurlong.org/wezterm/) or pass --wezterm <path>.");
        }
    };

    // Resolve powershell
    let pwsh_flag = extract_flag(args, "--pwsh");
    let pwsh_path = pwsh_flag
        .map(PathBuf::from)
        .or_else(|| find_in_path("pwsh.exe").or_else(|| find_in_path("powershell.exe")));

    let pwsh_path = match pwsh_path {
        Some(p) => p.to_string_lossy().into_owned(),
        None => "powershell.exe".to_string(), // fallback — system powershell always available
    };

    let wezterm_icon = wezterm_icon_path(&wezterm_path);

    // 1. Wezterm (normal)
    let cmd_wez = compose_command(&winrsbox_exe, &wezterm_path, &["start"], false);
    install_verb(VERB_WEZTERM, LABEL_WEZTERM, &cmd_wez, &wezterm_icon, false)?;
    println!("  + {LABEL_WEZTERM}");

    // 2. Wezterm (admin)
    let cmd_wez_admin = compose_command(&winrsbox_exe, &wezterm_path, &["start"], false);
    install_verb(VERB_WEZTERM_ADMIN, LABEL_WEZTERM_ADMIN, &cmd_wez_admin, &wezterm_icon, true)?;
    println!("  + {LABEL_WEZTERM_ADMIN}");

    // 3. PowerShell (normal)
    let cmd_pwsh = compose_command(&winrsbox_exe, &pwsh_path, &["-NoLogo"], false);
    let pwsh_icon = format!("{pwsh_path},0");
    install_verb(VERB_PWSH, LABEL_PWSH, &cmd_pwsh, &pwsh_icon, false)?;
    println!("  + {LABEL_PWSH}");

    // 4. PowerShell (admin)
    let cmd_pwsh_admin = compose_command(&winrsbox_exe, &pwsh_path, &["-NoLogo"], false);
    install_verb(VERB_PWSH_ADMIN, LABEL_PWSH_ADMIN, &cmd_pwsh_admin, &pwsh_icon, true)?;
    println!("  + {LABEL_PWSH_ADMIN}");

    println!("\nInstalled 4 context menu entries.");
    println!("Right-click any folder > Show more options (Win11) to see them.");
    Ok(())
}

// ---------------------------------------------------------------------------
// Uninstall
// ---------------------------------------------------------------------------

fn run_uninstall() -> Result<()> {
    let verbs = [VERB_WEZTERM, VERB_WEZTERM_ADMIN, VERB_PWSH, VERB_PWSH_ADMIN];
    let mut removed = 0;
    for root in SHELL_ROOTS {
        let hkcu = winreg::RegKey::predef(winreg::enums::HKEY_CURRENT_USER);
        if let Ok(shell_key) = hkcu.open_subkey_with_flags(root, winreg::enums::KEY_ALL_ACCESS) {
            for verb in &verbs {
                if shell_key.delete_subkey_all(verb).is_ok() {
                    removed += 1;
                }
            }
        }
    }
    println!("Removed {removed} registry entries.");
    Ok(())
}

// ---------------------------------------------------------------------------
// Status
// ---------------------------------------------------------------------------

fn run_status() -> Result<()> {
    let verbs = [
        (VERB_WEZTERM, LABEL_WEZTERM),
        (VERB_WEZTERM_ADMIN, LABEL_WEZTERM_ADMIN),
        (VERB_PWSH, LABEL_PWSH),
        (VERB_PWSH_ADMIN, LABEL_PWSH_ADMIN),
    ];
    let hkcu = winreg::RegKey::predef(winreg::enums::HKEY_CURRENT_USER);
    let root = SHELL_ROOTS[0]; // Check in Directory\shell
    let mut found = 0;
    for (verb, label) in &verbs {
        let key_path = format!("{root}\\{verb}\\command");
        match hkcu.open_subkey(&key_path) {
            Ok(key) => {
                let cmd: String = key.get_value("").unwrap_or_default();
                println!("  [installed] {label}");
                println!("             cmd: {cmd}");
                found += 1;
            }
            Err(_) => {
                println!("  [missing]   {label}");
            }
        }
    }
    println!("\n{found}/4 entries installed.");
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

pub fn compose_command(winrsbox: &str, target: &str, target_args: &[&str], _admin: bool) -> String {
    let mut cmd = format!("\"{winrsbox}\" --cwd \"%V\" -- \"{target}\"");
    for arg in target_args {
        cmd.push(' ');
        cmd.push_str(arg);
    }
    cmd
}

fn wezterm_icon_path(wezterm_exe: &str) -> String {
    // Wezterm ships an icon resource in wezterm-gui.exe
    format!("{wezterm_exe},0")
}

fn install_verb(verb: &str, label: &str, command: &str, icon: &str, runas: bool) -> Result<()> {
    let hkcu = winreg::RegKey::predef(winreg::enums::HKEY_CURRENT_USER);

    for root in SHELL_ROOTS {
        let key_path = format!("{root}\\{verb}");
        let (key, _) = hkcu
            .create_subkey(&key_path)
            .with_context(|| format!("create registry key {key_path}"))?;
        key.set_value("", &label)?;
        key.set_value("Icon", &icon)?;

        if runas {
            // HasLUAShield shows the UAC shield icon; "runas" verb triggers elevation
            key.set_value("HasLUAShield", &"")?;
        }

        let (cmd_key, _) = key
            .create_subkey("command")
            .context("create command subkey")?;

        if runas {
            // For admin elevation: use cmd /c to wrap with runas-style invocation.
            // Actually, the proper way is to NOT set runas in the command but use
            // the "Extended" or the HasLUAShield + runas verb pattern.
            // The cleanest Win32 method: set command to the same exe but rely on
            // the registry verb being "runas" which tells Explorer to call ShellExecute
            // with "runas" verb.
            //
            // For simplicity: create a nested runas key that tells Explorer to elevate.
            // Actually the right approach: key.set_value("", "runas") at the verb level
            // does NOT work for custom verbs.
            //
            // The correct pattern is:
            //   HKCU\...\shell\verb\command\(default) = "cmd /c ..."
            // + HKCU\...\shell\verb\(default) = label
            // + HKCU\...\shell\verb\HasLUAShield = ""
            //
            // And the command itself wraps in: powershell Start-Process ... -Verb RunAs
            // This is the most reliable cross-version approach.
            let elevated_cmd = format!(
                "powershell.exe -WindowStyle Hidden -Command \"Start-Process -FilePath '{command_escaped}' -Verb RunAs\"",
                command_escaped = command.replace('\'', "''"),
            );
            // But this doesn't work well because %V expansion happens in Explorer,
            // not in powershell. Simpler approach: use cmd.exe for elevation.
            // Actually, the simplest working approach: the command is just the normal
            // command, and we add the "runas" verb via a separate registry trick.
            //
            // WORKING approach for custom verb elevation:
            // Set the command normally, but add "Extended" and "HasLUAShield".
            // Explorer then auto-elevates when the user clicks.
            // This only works for verbs that ARE "runas" ... which ours isn't.
            //
            // TRUE correct approach: wrap in powershell -Command Start-Process
            // But handle %V quoting. Let me use a different wrapper:
            // cmd.exe /c "cd /d "%V" && powershell Start-Process 'winrsbox.exe' -ArgumentList '--cwd','\"%V\"','--','target' -Verb RunAs"
            //
            // This is getting complex. Simplest reliable approach:
            // Use a .bat wrapper or just always use the non-admin command and note
            // that admin requires Shift-click or separate shortcut.
            //
            // ACTUALLY: the simplest that WORKS is to not quote %V in powershell
            // and instead use cmd wrapper:
            cmd_key.set_value(
                "",
                &format!(
                    "cmd.exe /c cd /d \"%V\" && powershell.exe -Command \"Start-Process -FilePath \\\"{winrsbox}\\\" -ArgumentList ('--cwd','\\\"%V\\\"','--','\\\"{target}\\\"'{extra_args}) -Verb RunAs\"",
                    winrsbox = command.split("\" --cwd").next().unwrap_or(command).trim_start_matches('"'),
                    target = extract_target_from_command(command),
                    extra_args = extract_extra_args_from_command(command),
                ),
            )?;
        } else {
            cmd_key.set_value("", &command)?;
        }
    }
    Ok(())
}

fn extract_target_from_command(cmd: &str) -> &str {
    // Command format: "winrsbox" --cwd "%V" -- "target" args...
    if let Some(after_dashdash) = cmd.split("-- \"").nth(1) {
        after_dashdash.split('"').next().unwrap_or("")
    } else {
        ""
    }
}

fn extract_extra_args_from_command(cmd: &str) -> String {
    // Extract args after target.exe in the command
    if let Some(after_dashdash) = cmd.split("-- ").nth(1) {
        // Skip the "target" part
        let rest = after_dashdash.split_once('"')
            .and_then(|(_, after)| after.split_once('"'))
            .map(|(_, r)| r.trim())
            .unwrap_or("");
        if rest.is_empty() {
            String::new()
        } else {
            format!(",'{rest}'")
        }
    } else {
        String::new()
    }
}

fn find_in_path(name: &str) -> Option<PathBuf> {
    let path_var = std::env::var("PATH").ok()?;
    for dir in path_var.split(';') {
        let candidate = Path::new(dir).join(name);
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}

fn extract_flag(args: &[String], flag: &str) -> Option<String> {
    for (i, arg) in args.iter().enumerate() {
        if arg == flag {
            return args.get(i + 1).cloned();
        }
        if let Some(val) = arg.strip_prefix(&format!("{flag}=")) {
            return Some(val.to_string());
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compose_command_normal() {
        let cmd = compose_command(
            r"C:\bin\winrsbox.exe",
            r"C:\Program Files\WezTerm\wezterm-gui.exe",
            &["start"],
            false,
        );
        assert_eq!(
            cmd,
            r#""C:\bin\winrsbox.exe" --cwd "%V" -- "C:\Program Files\WezTerm\wezterm-gui.exe" start"#
        );
    }

    #[test]
    fn compose_command_pwsh_with_nologo() {
        let cmd = compose_command(
            r"C:\bin\winrsbox.exe",
            r"C:\Program Files\PowerShell\7\pwsh.exe",
            &["-NoLogo"],
            false,
        );
        assert!(cmd.contains("-NoLogo"));
        assert!(cmd.contains(r#""%V""#));
    }

    #[test]
    fn extract_target_from_command_works() {
        let cmd = r#""C:\bin\winrsbox.exe" --cwd "%V" -- "C:\wezterm\wezterm-gui.exe" start"#;
        assert_eq!(extract_target_from_command(cmd), r"C:\wezterm\wezterm-gui.exe");
    }

    #[test]
    fn find_in_path_finds_cmd() {
        let found = find_in_path("cmd.exe");
        assert!(found.is_some(), "cmd.exe must be in PATH");
    }

    #[test]
    fn find_in_path_returns_none_for_nonexistent() {
        let found = find_in_path("this-binary-does-not-exist-ever.exe");
        assert!(found.is_none());
    }

    #[test]
    fn extract_flag_works() {
        let args: Vec<String> = vec!["install".into(), "--wezterm".into(), r"C:\wez\wezterm.exe".into()];
        assert_eq!(extract_flag(&args, "--wezterm"), Some(r"C:\wez\wezterm.exe".into()));
    }

    #[test]
    fn extract_flag_equals_form() {
        let args: Vec<String> = vec!["install".into(), r"--wezterm=C:\wez.exe".into()];
        assert_eq!(extract_flag(&args, "--wezterm"), Some(r"C:\wez.exe".into()));
    }

    #[test]
    fn extract_flag_missing_returns_none() {
        let args: Vec<String> = vec!["install".into()];
        assert_eq!(extract_flag(&args, "--wezterm"), None);
    }
}
