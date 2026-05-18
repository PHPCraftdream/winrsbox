use criterion::{black_box, criterion_group, criterion_main, Criterion};
use hook::hooks::{
    is_write_access, GENERIC_WRITE, FILE_CREATE,
};

fn bench_is_write_generic(c: &mut Criterion) {
    let mut group = c.benchmark_group("is_write");
    group.bench_function("is_write_generic", |b| {
        b.iter(|| is_write_access(black_box(GENERIC_WRITE), black_box(0)))
    });
    group.finish();
}

fn bench_is_write_disposition(c: &mut Criterion) {
    let mut group = c.benchmark_group("is_write");
    group.bench_function("is_write_disposition", |b| {
        b.iter(|| is_write_access(black_box(0), black_box(FILE_CREATE)))
    });
    group.finish();
}

fn bench_is_write_false(c: &mut Criterion) {
    let mut group = c.benchmark_group("is_write");
    group.bench_function("is_write_false", |b| {
        b.iter(|| is_write_access(black_box(0), black_box(1)))
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_is_write_generic,
    bench_is_write_disposition,
    bench_is_write_false,
);
criterion_main!(benches);
