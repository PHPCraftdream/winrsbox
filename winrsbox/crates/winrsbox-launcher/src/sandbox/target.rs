use anyhow::Result;

use windows::core::PCWSTR;

/// Default `PATHEXT` when the variable is absent from the environment, in
/// Windows' own order. Only the four forms `CreateProcessW` can actually
/// start are listed: `.COM`/`.EXE` are images, `.BAT`/`.CMD` are rewritten to
/// `%COMSPEC% /c` by kernel32 itself. The rest of Windows' stock list
/// (`.VBS`, `.JS`, `.WSF`, `.MSC`, …) is handled by ShellExecute's
/// association lookup, not by `CreateProcessW`, and running those through a
/// script host is not something the sandbox should do implicitly.
const LAUNCHABLE_EXTS: &[&str] = &[".COM", ".EXE", ".BAT", ".CMD"];

/// Resolve `arg0` to a full image path the way a shell would.
///
/// `CreateProcessW` performs its own search, but it only ever appends `.exe`
/// to an extensionless name — it does not expand `PATHEXT`. So `winrsbox cx`,
/// where `cx` is a `cx.bat` on `PATH`, failed with
/// `The system cannot find the file specified. (0x80070002)`.
///
/// The search itself is not reimplemented here: `SearchPathW` IS the
/// primitive `CreateProcessW` uses, with the same directory order (the
/// caller's image dir, the current directory, System32, System, Windows,
/// then `PATH`). The only thing added is the loop over `PATHEXT` entries,
/// which is precisely the step `CreateProcessW` omits and `cmd.exe` performs.
///
/// Resolving up front — always, not only as a fallback after a failed launch
/// — matters beyond `cx`. `target_args[0]` is consumed raw by
/// `trust::verify_signature`, `inject::pre_launch_scan`, the WFP
/// `app_id_from_path` and the root `ProcInfo` entry. With a bare name such as
/// `winrsbox node`, `app_id_from_path` cannot canonicalize it and
/// `wfp::add_filter` correctly refuses to install an unscoped filter — so the
/// RFC1918 egress block was silently never applied. One substitution fixes
/// all of them.
///
/// A name that already carries a launchable extension, or any path
/// containing a separator, is resolved in a single call with no extension
/// appended — mirroring `CreateProcessW`'s own rule. An extensionless name is
/// never resolved with `ext = NULL`: on this machine that would find the
/// extensionless `cx` shell script sitting next to `cx.bat`, which is not a
/// Windows executable at all.
pub(crate) fn resolve_target(arg0: &str) -> Result<String> {
    let has_launchable_ext = std::path::Path::new(arg0)
        .extension()
        .map(|e| {
            let dotted = format!(".{}", e.to_string_lossy());
            LAUNCHABLE_EXTS.iter().any(|x| x.eq_ignore_ascii_case(&dotted))
        })
        .unwrap_or(false);

    if has_launchable_ext {
        if let Some(found) = search_path(arg0, None) {
            return Ok(found);
        }
    } else {
        let pathext = std::env::var("PATHEXT").unwrap_or_default();
        let exts: Vec<String> = if pathext.trim().is_empty() {
            LAUNCHABLE_EXTS.iter().map(|s| s.to_string()).collect()
        } else {
            pathext
                .split(';')
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
                .collect()
        };
        for ext in &exts {
            if let Some(found) = search_path(arg0, Some(ext)) {
                return Ok(found);
            }
        }
    }

    // An explicit path that does not resolve is a different mistake from a
    // bare name that is not on PATH; say which one happened.
    let looks_like_path = arg0.contains('\\') || arg0.contains('/') || arg0.contains(':');
    if looks_like_path {
        anyhow::bail!("target '{arg0}' does not exist");
    }
    anyhow::bail!(
        "target '{arg0}' not found on PATH (searched PATHEXT: {})",
        std::env::var("PATHEXT").unwrap_or_else(|_| LAUNCHABLE_EXTS.join(";")),
    );
}

/// One `SearchPathW` probe. `ext` is appended only when the name has no
/// extension of its own (Windows' rule, enforced by the caller).
fn search_path(name: &str, ext: Option<&str>) -> Option<String> {
    use windows::Win32::Storage::FileSystem::SearchPathW;

    let name_w: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
    let ext_w: Option<Vec<u16>> = ext.map(|e| e.encode_utf16().chain(Some(0)).collect());

    // Query the required length first, then fill: a path may exceed MAX_PATH.
    // SAFETY: both strings are NUL-terminated UTF-16; a zero-length buffer
    //         with a null pointer is the documented "how much do I need" form.
    let needed = unsafe {
        SearchPathW(
            PCWSTR::null(),
            PCWSTR(name_w.as_ptr()),
            ext_w.as_ref().map(|e| PCWSTR(e.as_ptr())).unwrap_or(PCWSTR::null()),
            None,
            None,
        )
    };
    if needed == 0 {
        return None;
    }
    let mut buf = vec![0u16; needed as usize + 1];
    // SAFETY: buf is `needed + 1` UTF-16 units, at least what the call above
    //         asked for; the same NUL-terminated inputs are reused.
    let written = unsafe {
        SearchPathW(
            PCWSTR::null(),
            PCWSTR(name_w.as_ptr()),
            ext_w.as_ref().map(|e| PCWSTR(e.as_ptr())).unwrap_or(PCWSTR::null()),
            Some(&mut buf),
            None,
        )
    };
    if written == 0 || written as usize > buf.len() {
        return None;
    }
    Some(String::from_utf16_lossy(&buf[..written as usize]))
}

/// Build a Windows command line string from an argument list.
/// Follows Microsoft CommandLineToArgvW escaping rules.
/// Iterates chars, not bytes: the result is encoded to UTF-16 for
/// CreateProcessW, so non-ASCII arguments must survive untouched.
pub(crate) fn build_cmdline(args: &[String]) -> String {
    fn quote_arg(a: &str) -> String {
        if a.is_empty() {
            return "\"\"".to_string();
        }
        if !a.contains(' ') && !a.contains('\t') && !a.contains('"') {
            return a.to_string();
        }
        let mut out = String::with_capacity(a.len() + 4);
        out.push('"');
        let chars: Vec<char> = a.chars().collect();
        let mut i = 0;
        while i < chars.len() {
            let ch = chars[i];
            if ch == '\\' {
                let start = i;
                while i < chars.len() && chars[i] == '\\' { i += 1; }
                let n = i - start;
                if i == chars.len() {
                    // Trailing backslashes → double them before closing quote
                    for _ in 0..n * 2 { out.push('\\'); }
                } else if chars[i] == '"' {
                    // Backslashes before quote → double them + escape the quote
                    for _ in 0..n * 2 { out.push('\\'); }
                    out.push('\\');
                    out.push('"');
                    i += 1;
                } else {
                    // Backslashes not before quote → emit literally
                    for _ in 0..n { out.push('\\'); }
                }
            } else if ch == '"' {
                out.push('\\');
                out.push('"');
                i += 1;
            } else {
                out.push(ch);
                i += 1;
            }
        }
        out.push('"');
        out
    }
    args.iter().map(|a| quote_arg(a)).collect::<Vec<_>>().join(" ")
}

