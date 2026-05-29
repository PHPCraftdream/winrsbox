use criterion::{black_box, criterion_group, criterion_main, Criterion};
use hook::process_tracker;

fn bench_is_owned_child_hit(c: &mut Criterion) {
    let pid = 0xFF0001;
    process_tracker::mark_spawned(pid, 0xFF0000, "c:\\a.exe".into(), 0);
    c.bench_function("process_tracker/is_owned_child_hit", |b| {
        b.iter(|| process_tracker::is_owned_child(black_box(pid)))
    });
    process_tracker::untrack(pid);
}

fn bench_is_owned_child_miss(c: &mut Criterion) {
    c.bench_function("process_tracker/is_owned_child_miss", |b| {
        b.iter(|| process_tracker::is_owned_child(black_box(0xFFFFFFFE)))
    });
}

fn bench_mark_spawned(c: &mut Criterion) {
    let mut i = 0u32;
    c.bench_function("process_tracker/mark_spawned", |b| {
        b.iter(|| {
            i = i.wrapping_add(1);
            let pid = 0xFE000000 | (i & 0xFFFFF);
            process_tracker::mark_spawned(
                black_box(pid),
                black_box(0xFE000000),
                black_box("c:\\bench.exe".into()),
                black_box(0),
            );
        })
    });
    // Cleanup: untrack a wide range
    for k in 0..=0xFFFFFu32 {
        process_tracker::untrack(0xFE000000 | k);
    }
}

fn bench_parent_of(c: &mut Criterion) {
    let pid = 0xFF0002;
    process_tracker::mark_spawned(pid, 0xFF0000, "c:\\a.exe".into(), 0);
    c.bench_function("process_tracker/parent_of_hit", |b| {
        b.iter(|| process_tracker::parent_of(black_box(pid)))
    });
    process_tracker::untrack(pid);
}

criterion_group!(
    benches,
    bench_is_owned_child_hit,
    bench_is_owned_child_miss,
    bench_mark_spawned,
    bench_parent_of,
);
criterion_main!(benches);
