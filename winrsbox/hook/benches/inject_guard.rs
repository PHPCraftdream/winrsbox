use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ntapi::winapi::shared::ntdef::HANDLE;

fn bench_is_self_process(c: &mut Criterion) {
    let mut g = c.benchmark_group("inject_guard");
    g.bench_function("is_self_process_pseudo", |b| {
        b.iter(|| hook::inject_guard::is_self_process(black_box(-1isize as HANDLE)))
    });
    g.bench_function("is_self_process_null", |b| {
        b.iter(|| hook::inject_guard::is_self_process(black_box(std::ptr::null_mut())))
    });
    g.finish();
}

fn bench_is_system_pid(c: &mut Criterion) {
    let mut g = c.benchmark_group("inject_guard");
    g.bench_function("is_system_pid_hit", |b| {
        b.iter(|| hook::inject_guard::is_system_pid(black_box(64)))
    });
    g.bench_function("is_system_pid_miss", |b| {
        b.iter(|| hook::inject_guard::is_system_pid(black_box(12345)))
    });
    g.finish();
}

fn bench_is_system_caller(c: &mut Criterion) {
    let mut g = c.benchmark_group("inject_guard");
    g.bench_function("is_system_caller", |b| {
        b.iter(|| hook::inject_guard::is_system_caller())
    });
    g.finish();
}

fn bench_thread_owner_pid(c: &mut Criterion) {
    let mut g = c.benchmark_group("inject_guard");
    g.bench_function("thread_owner_pid_current", |b| {
        // NtCurrentThread pseudo-handle = (HANDLE)-2
        b.iter(|| hook::inject_guard::thread_owner_pid(black_box(-2isize as HANDLE)))
    });
    g.bench_function("thread_owner_pid_null", |b| {
        b.iter(|| hook::inject_guard::thread_owner_pid(black_box(std::ptr::null_mut())))
    });
    g.finish();
}

fn bench_read_ctx_rip(c: &mut Criterion) {
    let mut g = c.benchmark_group("inject_guard");
    let mut buf = vec![0u8; 1024];
    buf[0xF8..0x100].copy_from_slice(&0x7FF8A1234567u64.to_le_bytes());
    let ctx = buf.as_ptr() as *const winapi::ctypes::c_void;
    g.bench_function("read_ctx_rip", |b| {
        b.iter(|| unsafe { hook::inject_guard::read_ctx_u64(black_box(ctx), 0xF8) })
    });
    g.finish();
}

fn bench_read_ctx_dr7(c: &mut Criterion) {
    let mut g = c.benchmark_group("inject_guard");
    let mut buf = vec![0u8; 1024];
    buf[0x370..0x378].copy_from_slice(&0x01u64.to_le_bytes());
    let ctx = buf.as_ptr() as *const winapi::ctypes::c_void;
    g.bench_function("read_ctx_dr7", |b| {
        b.iter(|| unsafe { hook::inject_guard::read_ctx_u64(black_box(ctx), 0x370) })
    });
    g.finish();
}

fn bench_read_ctx_flags(c: &mut Criterion) {
    let mut g = c.benchmark_group("inject_guard");
    let mut buf = vec![0u8; 1024];
    buf[0x30..0x34].copy_from_slice(&0x10_0001u32.to_le_bytes());
    let ctx = buf.as_ptr() as *const winapi::ctypes::c_void;
    g.bench_function("read_ctx_flags", |b| {
        b.iter(|| unsafe { hook::inject_guard::read_ctx_u32(black_box(ctx), 0x30) })
    });
    g.finish();
}

criterion_group!(
    benches,
    bench_is_self_process,
    bench_is_system_pid,
    bench_is_system_caller,
    bench_thread_owner_pid,
    bench_read_ctx_rip,
    bench_read_ctx_dr7,
    bench_read_ctx_flags,
);
criterion_main!(benches);
