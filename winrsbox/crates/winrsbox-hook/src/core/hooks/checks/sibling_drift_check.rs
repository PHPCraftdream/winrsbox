
// ---------------------------------------------------------------------------
// Sibling-drift check (audit 2026-09-19 High: "guarded API, unguarded
// sibling"). This is the mechanical net for the exact drift that left
// NtAllocateVirtualMemoryEx, NtAlpcConnectPortEx, NtSecureConnectPort,
// ShellExecuteA / ShellExecuteExA and win32u!NtUserSendInput wide open while
// their guarded twins carried all the enforcement.
//
// Each guard module keeps a `pub(crate) const HOOKED_EXPORTS` list naming the
// exports it actually installs detours on. Two layers, both cheap and hermetic:
//
//   1. family coverage — whenever a family's base export is guarded, every
//      listed sibling must be guarded too. Fails when someone removes a
//      sibling detour, or guards a new `Foo` while leaving `FooEx` open.
//   2. list-vs-source — every name in a module's list must appear in that
//      module body as a quote-anchored install literal (`"Name@Z@"` for the
//      str/byte-literal GetProcAddress names, `"Name"` for ui_guard's macro
//      form), so the lists cannot rot independently of the real detours. The
//      scan covers everything BEFORE the list itself — the module body where
//      install() lives — so a stale list entry can never satisfy its own
//      check, and export names merely mentioned in tests/comments do not
//      count.
//
// Extending: guard a new export family → add its name to the module's export
// list and add a row below. DllGetClassObject is deliberately NOT listed: it
// is a per-DLL COM export resolved per loaded module (hundreds of copies
// across loaded in-proc servers), not a single address one detour can cover —
// a check row for it could never go green, so it stays documented as out of
// scope for user-mode single-export detours (see com_guard.rs notes).
// ---------------------------------------------------------------------------
    use crate::alpc_guard::HOOKED_EXPORTS as ALPC_HOOKED;
    use crate::memory_guard::HOOKED_EXPORTS as MEM_HOOKED;
    use crate::shell_guard::HOOKED_EXPORTS as SHELL_HOOKED;
    use crate::ui_guard::HOOKED_EXPORTS as UI_HOOKED;

    /// (family, module file, that module's hooked-export list, base exports
    /// carrying the guard today, siblings that MUST be guarded alongside).
    const FAMILIES: &[(&str, &str, &[&str], &[&str], &[&str])] = &[
        (
            "memory-alloc",
            "memory_guard.rs",
            MEM_HOOKED,
            &["NtAllocateVirtualMemory"],
            &["NtAllocateVirtualMemoryEx"],
        ),
        (
            "alpc-connect",
            "alpc_guard.rs",
            ALPC_HOOKED,
            &["NtAlpcConnectPort"],
            &["NtAlpcConnectPortEx", "NtSecureConnectPort"],
        ),
        (
            "shell-execute",
            "shell_guard.rs",
            SHELL_HOOKED,
            &["ShellExecuteW", "ShellExecuteExW"],
            &["ShellExecuteA", "ShellExecuteExA"],
        ),
        (
            "ui-input-injection",
            "ui_guard.rs",
            UI_HOOKED,
            &["SendInput"],
            &["NtUserSendInput"],
        ),
    ];

    /// True when `src` contains the export name as a quote-anchored install
    /// literal. Left-quote anchoring means `Foo` can never be satisfied by a
    /// mention inside `FooEx` (e.g. `"SendInput"` does not match
    /// `"NtUserSendInput@Z@"`), and the `@Z@` suffix form distinguishes
    /// real GetProcAddress literals from prose.
    fn referenced_in_install_code(src: &str, name: &str) -> bool {
        // Look for the export name as a Rust string literal, in the two forms
        // the install sites use: NUL-terminated (`"Name\0"`, what the detour
        // macros pass to GetProcAddress) and plain (`"Name"`).
        //
        // The quote and backslash are built from chars rather than written
        // inline so that this predicate's own source cannot be mistaken for an
        // install site if hooks.rs ever gets scanned too.
        const Q: char = '"';
        const BS: char = '\\';
        let with_nul = format!("{Q}{name}{BS}0{Q}");
        let plain = format!("{Q}{name}{Q}");
        src.contains(&with_nul) || src.contains(&plain)
    }

    #[test]
    fn sibling_exports_guarded_when_base_is_guarded() {
        for (family, file, list, bases, siblings) in FAMILIES {
            for base in *bases {
                if !list.contains(base) {
                    // Base guard intentionally removed → the family is gone
                    // wholesale; siblings may go with it (and must, see the
                    // list-vs-source check).
                    continue;
                }
                for sibling in *siblings {
                    assert!(
                        list.contains(sibling),
                        "SIBLING DRIFT in family `{family}` ({file}): `{base}` is                          guarded but `{sibling}` is not — the guard is bypassable                          through the sibling export. Hook `{sibling}` in {file}, or                          delete the family row here if the whole family was                          intentionally unguarded."
                    );
                }
            }
        }
    }

    #[test]
    fn hooked_export_lists_match_installed_detours() {
        for (family, file, list, _, _) in FAMILIES {
            let src = crate::hooks::module_source(file);
            // Scan only the module body (everything before the list itself):
            // a stale list entry cannot satisfy its own install check.
            let src = src.as_str();
            let body = src.split("HOOKED_EXPORTS").next().unwrap_or(src);
            for name in *list {
                assert!(
                    referenced_in_install_code(body, name),
                    "family `{family}`: `{name}` is listed in {file} exports but no                      install literal for it exists in the module body — the detour                      was removed without updating the list (or was never written)."
                );
            }
        }
    }

    #[test]
    fn base_exports_of_every_family_are_actually_listed() {
        // Pins the bases: if a base name silently disappears from its list,
        // the family test above goes vacuously green and the drift net dies.
        // Removing a base must be a deliberate, reviewed act that deletes
        // the family row (with a justification) — never an accident.
        for (family, file, list, bases, _) in FAMILIES {
            for base in *bases {
                assert!(
                    list.contains(base),
                    "family `{family}` ({file}): base export `{base}` is missing                      from the module's export list — restore the guard or delete                      the family row and justify why the guard is gone."
                );
            }
        }
    }

    #[test]
    fn hooked_export_names_are_wellformed() {
        for (family, _, list, _, _) in FAMILIES {
            assert!(!list.is_empty(), "family `{family}` has an empty export list");
            for name in *list {
                assert!(
                    !name.is_empty() && name.is_ascii(),
                    "bad export name {name:?} in family {family}"
                );
            }
            let mut sorted: Vec<&str> = list.to_vec();
            sorted.sort_unstable();
            let count = sorted.len();
            sorted.dedup();
            assert_eq!(
                sorted.len(),
                count,
                "duplicate export names in family {family}"
            );
        }
    }
