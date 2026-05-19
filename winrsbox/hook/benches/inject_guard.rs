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

criterion_group!(
    benches,
    bench_is_self_process,
    bench_is_system_pid,
    bench_is_system_caller,
    bench_thread_owner_pid,
);
criterion_main!(benches);
