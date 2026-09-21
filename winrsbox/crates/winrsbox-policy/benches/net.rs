use criterion::{black_box, criterion_group, criterion_main, Criterion};
use policy::net;

fn bench_match_host(c: &mut Criterion) {
    let mut group = c.benchmark_group("net");
    group.bench_function("match_host_exact", |b| {
        b.iter(|| net::match_host(black_box("api.github.com"), black_box("api.github.com")))
    });
    group.bench_function("match_host_wildcard", |b| {
        b.iter(|| net::match_host(black_box("*.github.com"), black_box("api.github.com")))
    });
    group.bench_function("match_host_miss", |b| {
        b.iter(|| net::match_host(black_box("*.github.com"), black_box("evil.com")))
    });
    group.bench_function("match_host_star_all", |b| {
        b.iter(|| net::match_host(black_box("*"), black_box("anything.example.com")))
    });
    group.finish();
}

fn bench_cidr(c: &mut Criterion) {
    let mut group = c.benchmark_group("net");
    group.bench_function("parse_cidr", |b| {
        b.iter(|| net::parse_cidr(black_box("10.0.0.0/8")))
    });
    group.bench_function("parse_ipv4", |b| {
        b.iter(|| net::parse_ipv4(black_box("192.168.1.100")))
    });
    let (net_addr, mask) = net::parse_cidr("10.0.0.0/8").unwrap();
    group.bench_function("ip_in_cidr", |b| {
        b.iter(|| net::ip_in_cidr(black_box(0x0A010203), black_box(net_addr), black_box(mask)))
    });
    group.finish();
}

fn bench_is_localhost(c: &mut Criterion) {
    let mut group = c.benchmark_group("net");
    group.bench_function("is_localhost_true", |b| {
        b.iter(|| net::is_localhost(black_box("127.0.0.1")))
    });
    group.bench_function("is_localhost_false", |b| {
        b.iter(|| net::is_localhost(black_box("api.github.com")))
    });
    group.finish();
}

criterion_group!(benches, bench_match_host, bench_cidr, bench_is_localhost);
criterion_main!(benches);
