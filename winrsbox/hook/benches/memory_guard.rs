use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn bench_is_executable(c: &mut Criterion) {
    let mut group = c.benchmark_group("memory_guard");

    group.bench_function("is_executable_hit", |b| {
        b.iter(|| hook::memory_guard::is_executable(black_box(0x40))) // PAGE_EXECUTE_READWRITE
    });

    group.bench_function("is_executable_miss", |b| {
        b.iter(|| hook::memory_guard::is_executable(black_box(0x04))) // PAGE_READWRITE
    });

    group.finish();
}

fn bench_is_address_in_module(c: &mut Criterion) {
    let mut group = c.benchmark_group("memory_guard");

    // Get a known module address (ntdll)
    let ntdll_base = unsafe {
        let name: Vec<u16> = "ntdll.dll\0".encode_utf16().collect();
        winapi::um::libloaderapi::GetModuleHandleW(name.as_ptr())
    };

    group.bench_function("is_addr_in_module_hit", |b| {
        b.iter(|| {
            hook::memory_guard::is_address_in_module(
                black_box(ntdll_base as *const winapi::ctypes::c_void),
            )
        })
    });

    // Heap address — not in any module
    let heap_buf = vec![0u8; 64];
    let heap_ptr = heap_buf.as_ptr() as *const winapi::ctypes::c_void;

    group.bench_function("is_addr_in_module_miss", |b| {
        b.iter(|| hook::memory_guard::is_address_in_module(black_box(heap_ptr)))
    });

    group.finish();
}

fn bench_module_path_for_address(c: &mut Criterion) {
    let mut group = c.benchmark_group("memory_guard");

    let ntdll_base = unsafe {
        let name: Vec<u16> = "ntdll.dll\0".encode_utf16().collect();
        winapi::um::libloaderapi::GetModuleHandleW(name.as_ptr())
    };

    group.bench_function("module_path_hit", |b| {
        b.iter(|| {
            hook::memory_guard::module_path_for_address(
                black_box(ntdll_base as *const winapi::ctypes::c_void),
            )
        })
    });

    let heap_buf = vec![0u8; 64];
    let heap_ptr = heap_buf.as_ptr() as *const winapi::ctypes::c_void;

    group.bench_function("module_path_miss", |b| {
        b.iter(|| hook::memory_guard::module_path_for_address(black_box(heap_ptr)))
    });

    group.finish();
}

fn bench_protect_name(c: &mut Criterion) {
    let mut group = c.benchmark_group("memory_guard");

    group.bench_function("protect_name", |b| {
        b.iter(|| hook::memory_guard::protect_name(black_box(0x40)))
    });

    group.finish();
}

fn bench_content_scan_4kb(c: &mut Criterion) {
    let bytes = vec![0x90u8; 4096];
    let mut group = c.benchmark_group("memory_guard");
    group.bench_function("content_scan_4kb_clean", |b| {
        b.iter(|| policy::scan::find_direct_syscalls(black_box(&bytes), 0x10000))
    });
    group.finish();
}

fn bench_content_scan_64kb(c: &mut Criterion) {
    let bytes = vec![0x90u8; 65536];
    let mut group = c.benchmark_group("memory_guard");
    group.bench_function("content_scan_64kb_clean", |b| {
        b.iter(|| policy::scan::find_direct_syscalls(black_box(&bytes), 0x10000))
    });
    group.finish();
}

fn bench_content_scan_1mb(c: &mut Criterion) {
    let bytes = vec![0x90u8; 1024 * 1024];
    let mut group = c.benchmark_group("memory_guard");
    group.bench_function("content_scan_1mb_clean", |b| {
        b.iter(|| policy::scan::find_direct_syscalls(black_box(&bytes), 0x10000))
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_is_executable,
    bench_is_address_in_module,
    bench_module_path_for_address,
    bench_protect_name,
    bench_content_scan_4kb,
    bench_content_scan_64kb,
    bench_content_scan_1mb,
);
criterion_main!(benches);
