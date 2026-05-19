use criterion::{black_box, criterion_group, criterion_main, Criterion};
use winrsbox::wfp::CidrV4;

fn bench_cidr_parse(c: &mut Criterion) {
    c.bench_function("wfp/cidr_parse", |b| {
        b.iter(|| CidrV4::parse(black_box("192.168.0.0/16")))
    });
}

fn bench_cidr_contains(c: &mut Criterion) {
    let cidr = CidrV4::parse("10.0.0.0/8").unwrap();
    c.bench_function("wfp/cidr_contains_hit", |b| {
        b.iter(|| cidr.contains(black_box(0x0A010203)))
    });
    c.bench_function("wfp/cidr_contains_miss", |b| {
        b.iter(|| cidr.contains(black_box(0x0B010203)))
    });
}

criterion_group!(benches, bench_cidr_parse, bench_cidr_contains);
criterion_main!(benches);
