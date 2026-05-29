// Environment variable sanitization — removes sensitive variables
// before spawning the sandboxed child process.
//
// Sensitive patterns: API keys, tokens, secrets, credentials, passwords.
// Whitelist: PATH, TEMP, HOME, USERPROFILE, SystemRoot, and FS_SANDBOX_* vars.

/// Remove sensitive environment variables from the current process.
/// Must be called BEFORE CreateProcessW (child inherits parent env).
/// Returns the count of removed variables.
pub fn sanitize() -> usize {
    let mut removed = 0;
    let vars: Vec<(String, String)> = std::env::vars().collect();
    for (key, _) in &vars {
        if is_sensitive(key) {
            std::env::remove_var(key);
            removed += 1;
        }
    }
    removed
}

fn is_sensitive(key: &str) -> bool {
    let upper = key.to_ascii_uppercase();
    !is_whitelisted(&upper)
}

fn is_whitelisted(upper: &str) -> bool {
    const WHITELIST: &[&str] = &[
        "PATH", "PATHEXT", "TEMP", "TMP",
        "HOME", "USERPROFILE", "HOMEDRIVE", "HOMEPATH",
        "SYSTEMROOT", "SYSTEMDRIVE", "WINDIR",
        "COMSPEC", "OS", "PROCESSOR_ARCHITECTURE",
        "NUMBER_OF_PROCESSORS", "COMPUTERNAME", "USERNAME",
        "APPDATA", "LOCALAPPDATA", "PROGRAMDATA",
        "PROGRAMFILES", "PROGRAMFILES(X86)", "COMMONPROGRAMFILES",
        "COMMONPROGRAMFILES(X86)",
        "LANG", "LC_ALL", "LC_CTYPE",
        "TERM", "SHELL", "EDITOR", "VISUAL",
        "RUST_BACKTRACE", "RUST_LOG", "CARGO_HOME", "RUSTUP_HOME",
        "NODE_PATH", "NODE_ENV", "NPM_CONFIG_PREFIX",
        "PYTHONPATH", "PYTHONHOME", "VIRTUAL_ENV",
        "GIT_EXEC_PATH", "GIT_TEMPLATE_DIR",
        "WEZTERM_EXECUTABLE", "WEZTERM_EXECUTABLE_ARGS_CWD",
        "COLORTERM", "TERM_PROGRAM",
        "AI_AGENT",
    ];
    // FS_SANDBOX_* vars always kept
    if upper.starts_with("FS_SANDBOX_") { return true; }
    // WINRSBOX_* vars always kept
    if upper.starts_with("WINRSBOX_") { return true; }
    WHITELIST.contains(&upper)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sensitive_api_keys() {
        assert!(is_sensitive("ANTHROPIC_API_KEY"));
        assert!(is_sensitive("OPENAI_API_KEY"));
        assert!(is_sensitive("GITHUB_TOKEN"));
        assert!(is_sensitive("AWS_SECRET_ACCESS_KEY"));
        assert!(is_sensitive("DATABASE_URL"));
        assert!(is_sensitive("npm_token"));
        assert!(is_sensitive("MY_APP_PASSWORD"));
    }

    #[test]
    fn safe_vars_kept() {
        assert!(!is_sensitive("PATH"));
        assert!(!is_sensitive("TEMP"));
        assert!(!is_sensitive("USERPROFILE"));
        assert!(!is_sensitive("SYSTEMROOT"));
        assert!(!is_sensitive("FS_SANDBOX_PIPE"));
        assert!(!is_sensitive("RUST_BACKTRACE"));
        assert!(!is_sensitive("CARGO_HOME"));
    }

    #[test]
    fn edge_cases() {
        assert!(!is_sensitive("COMPUTERNAME"));
        assert!(!is_sensitive("NUMBER_OF_PROCESSORS"));
        assert!(is_sensitive("STRIPE_SECRET_KEY"));
        assert!(is_sensitive("JWT_SECRET"));
    }
}
