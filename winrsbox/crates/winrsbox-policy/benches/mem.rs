use criterion::{black_box, criterion_group, criterion_main, Criterion};
use policy::mem::{MemPolicy, MemMode};

fn bench_mem_decide(c: &mut Criterion) {
    let mut group = c.benchmark_group("mem");
    let deny = MemPolicy { cross_process: MemMode::Deny, allow_child_pids: true };
    let allow = MemPolicy { cross_process: MemMode::Allow, allow_child_pids: false };

    group.bench_function("decide_self", |b| {
        b.iter(|| deny.decide(black_box(true), black_box(false)))
    });
    group.bench_function("decide_child_allow", |b| {
        b.iter(|| deny.decide(black_box(false), black_box(true)))
    });
    group.bench_function("decide_foreign_deny", |b| {
        b.iter(|| deny.decide(black_box(false), black_box(false)))
    });
    group.bench_function("decide_foreign_allow", |b| {
        b.iter(|| allow.decide(black_box(false), black_box(false)))
    });
    group.finish();
}

criterion_group!(benches, bench_mem_decide);
criterion_main!(benches);
