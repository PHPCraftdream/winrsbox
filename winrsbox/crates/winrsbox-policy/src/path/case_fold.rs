//! S11 — canonical NTFS-identity case fold for policy path keys.
//!
//! Why the kernel table and not Rust casing: NTFS default-table name
//! identity is what the kernel enforces when it decides two path spellings
//! name the same object. Rust's `to_lowercase()`/`to_uppercase()` implement
//! Unicode locale-linguistic mappings (full-mapping expansions, locale
//! rules) that diverge from NTFS identity in both directions, and an
//! ASCII-only fold (`to_ascii_lowercase`) misses every non-ASCII case pair
//! entirely — Cyrillic `СЕКРЕТ` vs `секрет` or Greek `ΧΩΡΟΣ` vs `χωρος`
//! produced different policy keys although default NTFS treats them as the
//! same file (the S11 bypass).
//!
//! The fold primitive is per-UTF-16-code-unit
//! `F(c) = RtlDowncaseUnicodeChar(RtlUpcaseUnicodeChar(c))`, with both
//! functions resolved at RUNTIME from ntdll (`GetModuleHandleW` +
//! `GetProcAddress`, cached in a `OnceLock`). Down∘Up is the composition,
//! not plain downcase: it guarantees that F's equivalence classes equal the
//! kernel upcase-table classes BY CONSTRUCTION on any OS table version —
//! the class of `c` is everything that upcases to the same image, and all
//! class members share `D(U(c))`. Lowercase representatives keep persisted
//! keys stable.
//!
//! ASCII fast path: the kernel tables fold ASCII exactly like
//! `to_ascii_lowercase`, so `F(ASCII) == ASCII-downcase` for every ASCII
//! unit. That means all existing persisted lowercase-ASCII db keys stay
//! byte-identical under this fold — no db migration is needed.
//!
//! The kernel tables are MORE CONSERVATIVE than Unicode simple mappings.
//! Direct probe on this machine's ntdll (pinned by tests): U+0130 (İ),
//! U+0131 (ı), U+03C2 (ς), U+00DF (ß), U+1E9E (ẞ), U+212A (KELVIN) and
//! U+212B (ANGSTROM) are IDENTITY under F, and the surrogate range
//! D800–DFFF is identity too, so supplementary-plane characters pass
//! through UTF-16 folding unchanged.
//!
//! KNOWN GAP — case-sensitive directories: NTFS/ReFS per-directory case
//! sensitivity (Windows 10 1803+, `fsutil file setCaseSensitiveInfo` /
//! `FileCaseSensitiveInformation`) is NOT modeled — this fold treats every
//! path as case-insensitive by default-table semantics. Named follow-up: a
//! separate model must query `FILE_CS_FLAG_CASE_SENSITIVE_DIR` per parent
//! directory at decision points; the primary create/open decide path has no
//! handle in hand and the policy server receives only path strings over
//! IPC, so per-directory awareness needs its own design (S11 follow-up).

/// A per-UTF-16-unit case-mapping function from ntdll
/// (`RtlUpcaseUnicodeChar` / `RtlDowncaseUnicodeChar`): pure u16 → u16
/// table lookup, documented in the NT kernel's ntifs headers.
type RtlCaseFn = unsafe extern "system" fn(u16) -> u16;

static RTL_CASE_FNS: std::sync::OnceLock<Option<(RtlCaseFn, RtlCaseFn)>> =
    std::sync::OnceLock::new();

// The crate deliberately avoids winapi/windows crates (see the
// GetFileInformationByHandle declaration in decide/mod.rs); kernel32 is in
// the default import set of every *-pc-windows-msvc target, so a plain
// extern block links without a #[link] attribute.
unsafe extern "system" {
    fn GetModuleHandleW(module_name: *const u16) -> isize;
    fn GetProcAddress(module: isize, name: *const i8) -> *mut std::ffi::c_void;
}

/// Resolve `(RtlUpcaseUnicodeChar, RtlDowncaseUnicodeChar)` from ntdll
/// exactly once; a null anywhere (no ntdll in-process — practically
/// impossible on Windows — or missing exports) is cached as `None`.
fn rtl_case_fns() -> Option<(RtlCaseFn, RtlCaseFn)> {
    *RTL_CASE_FNS.get_or_init(|| {
        // NUL-terminated wide module name for GetModuleHandleW.
        let name: Vec<u16> = "ntdll.dll\0".encode_utf16().collect();
        // SAFETY: `name` is a live, NUL-terminated UTF-16 buffer for the
        // duration of the call; GetModuleHandleW only reads it.
        let module = unsafe { GetModuleHandleW(name.as_ptr()) };
        if module == 0 {
            return None;
        }
        // SAFETY: `module` is the handle GetModuleHandleW just returned and
        // the byte literals are NUL-terminated C strings for the duration
        // of the calls; GetProcAddress only reads them.
        let up = unsafe {
            GetProcAddress(module, b"RtlUpcaseUnicodeChar\0".as_ptr() as *const i8)
        };
        let down = unsafe {
            GetProcAddress(module, b"RtlDowncaseUnicodeChar\0".as_ptr() as *const i8)
        };
        if up.is_null() || down.is_null() {
            return None;
        }
        // SAFETY: both pointers came back non-null from GetProcAddress for
        // the documented ntdll exports whose signature is exactly
        // `USHORT NTAPI Rtl*UnicodeChar(USHORT)` — i.e. u16 → u16 — and the
        // functions are pure table lookups with no state or failure mode.
        Some(unsafe {
            (
                std::mem::transmute::<*mut std::ffi::c_void, RtlCaseFn>(up),
                std::mem::transmute::<*mut std::ffi::c_void, RtlCaseFn>(down),
            )
        })
    })
}

/// Canonical NTFS-identity fold of one UTF-16 code unit:
/// `RtlDowncaseUnicodeChar(RtlUpcaseUnicodeChar(c))`. Units in the
/// surrogate range D800–DFFF are returned unchanged (belt-and-braces: the
/// probe shows identity, and this also guarantees folding can never create
/// a lone surrogate from a well-formed pair).
///
/// If the ntdll resolution failed, the fallback composes Rust's
/// `char::to_uppercase().next()` then `to_lowercase().next()` mapped back
/// to u16, or returns the unit unchanged when it is not a valid scalar.
/// The fallback DIVERGES from the kernel fold (Rust's maps are
/// locale-linguistic: they would fold İ/ß/KELVIN that the kernel leaves
/// identity and can expand to multi-char sequences) — it is never taken on
/// real Windows, where RtlUpcaseUnicodeChar/RtlDowncaseUnicodeChar exist on
/// every supported OS.
pub fn fold_u16_unit(c: u16) -> u16 {
    if (0xD800..=0xDFFF).contains(&c) {
        return c;
    }
    match rtl_case_fns() {
        // SAFETY: both pointers are the ntdll exports resolved by
        // `rtl_case_fns` with the documented u16 → u16 signature; the calls
        // are pure table lookups with no aliasing or state.
        Some((up, down)) => unsafe { down(up(c)) },
        None => {
            let Some(ch) = char::from_u32(c as u32) else { return c };
            match ch.to_uppercase().next().and_then(|u| u.to_lowercase().next()) {
                Some(l) => u16::try_from(l as u32).unwrap_or(c),
                None => c,
            }
        }
    }
}

/// Canonical NTFS-identity fold of a DOS path string (the `ensure_lower`
/// primitive). ASCII input keeps the historic zero-alloc behavior: already
/// lowercase → `Cow::Borrowed`, otherwise an owned ASCII-downcase. Non-ASCII
/// input is encoded to UTF-16, folded per unit via [`fold_u16_unit`], and
/// decoded back.
pub fn nt_case_fold(s: &str) -> std::borrow::Cow<'_, str> {
    if s.is_ascii() {
        // Kernel F == ASCII-downcase exactly — fast path is byte-identical
        // to the pre-S11 fold, keeping every persisted key stable.
        if s.bytes().all(|b| !b.is_ascii_uppercase()) {
            return std::borrow::Cow::Borrowed(s);
        }
        return std::borrow::Cow::Owned(s.to_ascii_lowercase());
    }
    let folded: Vec<u16> = s.encode_utf16().map(fold_u16_unit).collect();
    // Lossy is lossless here: the input was valid UTF-8, so its UTF-16
    // encoding is well-formed; folding maps BMP↔BMP and passes surrogate
    // units through untouched, so the folded slice is well-formed UTF-16
    // too and `from_utf16_lossy` cannot hit a replacement character.
    std::borrow::Cow::Owned(String::from_utf16_lossy(&folded))
}

/// UTF-16 twin of [`nt_case_fold`]: per-unit fold over a UTF-16 slice, for
/// hook-side UTF-16 enumeration paths. Lone surrogates pass through
/// unchanged (folding never manufactures one), matching
/// `String::from_utf16_lossy`'s later replacement behavior.
pub fn nt_case_fold_utf16(units: &[u16]) -> Vec<u16> {
    units.iter().copied().map(fold_u16_unit).collect()
}
