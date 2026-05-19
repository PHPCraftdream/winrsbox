use criterion::{black_box, criterion_group, criterion_main, Criterion};
use winrsbox::mitigations::{self, Profile};

fn bench_compute_none(c: &mut Criterion) {
    c.bench_function("mitigations/compute_none", |b| {
        b.iter(|| mitigations::compute(black_box(Profile::None)))
    });
}

fn bench_compute_scan(c: &mut Criterion) {
    c.bench_function("mitigations/compute_scan", |b| {
        b.iter(|| mitigations::compute(black_box(Profile::Scan)))
    });
}

fn bench_compute_full(c: &mut Criterion) {
    c.bench_function("mitigations/compute_full", |b| {
        b.iter(|| mitigations::compute(black_box(Profile::Full)))
    });
}

fn bench_to_bytes(c: &mut Criterion) {
    let (m1, m2) = mitigations::compute(Profile::Full);
    c.bench_function("mitigations/to_bytes", |b| {
        b.iter(|| mitigations::to_bytes(black_box(m1), black_box(m2)))
    });
}

criterion_group!(benches, bench_compute_none, bench_compute_scan, bench_compute_full, bench_to_bytes);
criterion_main!(benches);
