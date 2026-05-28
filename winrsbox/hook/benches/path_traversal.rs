//! Adversarial bench for `check_path_traversal` (M-T4).
//!
//! `check_path_traversal` runs on every NtCreateFile / NtOpenFile, so its
//! cost shows up in every FS syscall the sandbox sees. The hottest sub-step
//! is `needs_short_name_resolve`, which scans the path byte-by-byte for the
//! 8.3 short-name marker (`~<digit>`). On a 32k-char path that's 64 KB of
//! comparisons per call.
//!
//! Inputs cover:
//!   - normal short path (baseline)
//!   - long deeply-nested path (~16k chars)
//!   - GLOBALROOT-prefix + long path (early-exit on contains check)
//!   - tilde near the end of an 8 KB path (worst-case for short-name scan)
//!   - path containing `.winrsbox` (sandbox-state hide branch)
//!
//! Visibility note: `check_path_traversal` and `needs_short_name_resolve`
//! are `pub(crate)` in `hook::hooks`. Rust forbids re-exporting `pub(crate)`
//! items as `pub`, so thin wrappers in `hook::bench_api` (lib.rs) expose
//! them for bench access only. Marked `#[doc(hidden)]`.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ntapi::winapi::shared::ntdef::{OBJECT_ATTRIBUTES, UNICODE_STRING};

/// Holds the UTF-16 buffer, the UNICODE_STRING, and the OBJECT_ATTRIBUTES
/// so they all share a single lifetime. The `_buf` field must outlive the
/// returned attrs pointer.
struct AttrsHolder {
    _buf: Vec<u16>,
    _ustr: Box<UNICODE_STRING>,
    attrs: Box<OBJECT_ATTRIBUTES>,
}

impl AttrsHolder {
    fn new(raw_nt_path: &str) -> Self {
        let buf: Vec<u16> = raw_nt_path.encode_utf16().collect();
        let char_count = buf.len();
        // SAFETY: We pin the buffer behind a Box so the Buffer pointer in
        // UNICODE_STRING stays valid as long as `self` lives.
        let buf_ptr = buf.as_ptr() as *mut u16;

        let mut ustr = Box::new(UNICODE_STRING {
            Length: (char_count * 2) as u16,
            MaximumLength: (char_count * 2) as u16,
            Buffer: buf_ptr,
        });

        let attrs = Box::new(OBJECT_ATTRIBUTES {
            Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: std::ptr::null_mut(),
            ObjectName: &mut *ustr as *mut UNICODE_STRING,
            Attributes: 0,
            SecurityDescriptor: std::ptr::null_mut(),
            SecurityQualityOfService: std::ptr::null_mut(),
        });

        AttrsHolder {
            _buf: buf,
            _ustr: ustr,
            attrs,
        }
    }

    fn ptr(&self) -> *const OBJECT_ATTRIBUTES {
        &*self.attrs as *const OBJECT_ATTRIBUTES
    }
}

fn bench_path_traversal_normal(c: &mut Criterion) {
    // Typical short path — represents the common case.
    let holder = AttrsHolder::new(r"\??\C:\Users\username\Documents\project\src\main.rs");
    c.bench_function("path_traversal_normal_path", |b| {
        b.iter(|| unsafe {
            black_box(hook::bench_api::check_path_traversal(black_box(holder.ptr()), 0))
        });
    });
}

fn bench_path_traversal_long_path(c: &mut Criterion) {
    // ~16 KB path. Worst case for the to_ascii_lowercase + contains scan.
    let p = format!(r"\??\C:\{}", "a\\".repeat(2000));
    let holder = AttrsHolder::new(&p);
    c.bench_function("path_traversal_long_path", |b| {
        b.iter(|| unsafe {
            black_box(hook::bench_api::check_path_traversal(black_box(holder.ptr()), 0))
        });
    });
}

fn bench_path_traversal_globalroot(c: &mut Criterion) {
    // GLOBALROOT match triggers an early-return after the `contains` check.
    let p = format!(
        r"\??\GLOBALROOT\Device\HarddiskVolume1\Windows\{}",
        "x\\".repeat(500)
    );
    let holder = AttrsHolder::new(&p);
    c.bench_function("path_traversal_globalroot_deep", |b| {
        b.iter(|| unsafe {
            black_box(hook::bench_api::check_path_traversal(black_box(holder.ptr()), 0))
        });
    });
}

fn bench_path_traversal_tilde_at_end(c: &mut Criterion) {
    // ~8 KB path with `~1` very close to the end — short-name scan must walk
    // nearly the whole buffer before hitting the marker.
    let p = format!(r"\??\C:\Users\{}~1\file.txt", "x".repeat(8000));
    let holder = AttrsHolder::new(&p);
    c.bench_function("path_traversal_tilde_late", |b| {
        b.iter(|| unsafe {
            black_box(hook::bench_api::check_path_traversal(black_box(holder.ptr()), 0))
        });
    });
}

fn bench_path_traversal_dotwinrsbox(c: &mut Criterion) {
    // .winrsbox-hide branch — full pipeline runs and returns
    // STATUS_OBJECT_NAME_NOT_FOUND.
    let holder = AttrsHolder::new(r"\??\C:\sandbox-root\.winrsbox\some\deep\overlay\path.txt");
    c.bench_function("path_traversal_winrsbox_match", |b| {
        b.iter(|| unsafe {
            black_box(hook::bench_api::check_path_traversal(black_box(holder.ptr()), 0))
        });
    });
}

fn bench_short_name_resolve_long_no_tilde(c: &mut Criterion) {
    // Direct hot-path bench: `needs_short_name_resolve` byte-scan on a
    // ~16 KB path with no tilde — walks the entire buffer to return false.
    let p: String = "c:\\".to_string() + &"a\\".repeat(8000) + "file.txt";
    c.bench_function("short_name_resolve_long_no_tilde", |b| {
        b.iter(|| black_box(hook::bench_api::needs_short_name_resolve(black_box(&p))));
    });
}

criterion_group!(
    benches,
    bench_path_traversal_normal,
    bench_path_traversal_long_path,
    bench_path_traversal_globalroot,
    bench_path_traversal_tilde_at_end,
    bench_path_traversal_dotwinrsbox,
    bench_short_name_resolve_long_no_tilde,
);
criterion_main!(benches);
