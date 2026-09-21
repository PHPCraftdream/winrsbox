use criterion::{black_box, criterion_group, criterion_main, Criterion};
use hook::net_hooks;
use winapi::ctypes::c_void;

fn bench_parse_sockaddr_ipv4(c: &mut Criterion) {
    let mut buf = vec![0u8; 16];
    buf[0..2].copy_from_slice(&2u16.to_le_bytes()); // AF_INET
    buf[2..4].copy_from_slice(&443u16.to_be_bytes());
    buf[4..8].copy_from_slice(&[1, 2, 3, 4]);
    let ptr = buf.as_ptr() as *const c_void;
    c.bench_function("net_hooks/parse_sockaddr_ipv4", |b| {
        b.iter(|| unsafe { net_hooks::parse_sockaddr(black_box(ptr), 16) })
    });
}

fn bench_parse_sockaddr_ipv6(c: &mut Criterion) {
    let mut buf = vec![0u8; 28];
    buf[0..2].copy_from_slice(&23u16.to_le_bytes()); // AF_INET6
    buf[2..4].copy_from_slice(&443u16.to_be_bytes());
    let ptr = buf.as_ptr() as *const c_void;
    c.bench_function("net_hooks/parse_sockaddr_ipv6", |b| {
        b.iter(|| unsafe { net_hooks::parse_sockaddr(black_box(ptr), 28) })
    });
}

fn bench_is_localhost_hit(c: &mut Criterion) {
    c.bench_function("net_hooks/is_localhost_hit", |b| {
        b.iter(|| net_hooks::is_localhost(black_box("127.0.0.1")))
    });
}

fn bench_is_localhost_miss(c: &mut Criterion) {
    c.bench_function("net_hooks/is_localhost_miss", |b| {
        b.iter(|| net_hooks::is_localhost(black_box("8.8.8.8")))
    });
}

criterion_group!(
    benches,
    bench_parse_sockaddr_ipv4,
    bench_parse_sockaddr_ipv6,
    bench_is_localhost_hit,
    bench_is_localhost_miss,
);
criterion_main!(benches);
