use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use policy::scan::{find_direct_syscalls, pe_text_section};

fn make_nop_buffer(size: usize) -> Vec<u8> {
    vec![0x90u8; size]
}

fn make_realistic_buffer(size: usize) -> Vec<u8> {
    // Repeating compiler-like prologue/epilogue patterns: push rbp; mov rbp,rsp; xor eax,eax; pop rbp; ret
    let pattern = [0x55, 0x48, 0x89, 0xE5, 0x31, 0xC0, 0x5D, 0xC3];
    pattern.iter().cycle().take(size).copied().collect()
}

fn bench_scan_clean_1kb(c: &mut Criterion) {
    let buf = make_nop_buffer(1024);
    let mut g = c.benchmark_group("scan");
    g.throughput(Throughput::Bytes(1024));
    g.bench_function("clean_1kb_nops", |b| {
        b.iter(|| find_direct_syscalls(black_box(&buf), 0))
    });
    g.finish();
}

fn bench_scan_clean_1mb(c: &mut Criterion) {
    let buf = make_nop_buffer(1024 * 1024);
    let mut g = c.benchmark_group("scan");
    g.throughput(Throughput::Bytes(1024 * 1024));
    g.bench_function("clean_1mb_nops", |b| {
        b.iter(|| find_direct_syscalls(black_box(&buf), 0))
    });
    g.finish();
}

fn bench_scan_clean_10mb(c: &mut Criterion) {
    let buf = make_nop_buffer(10 * 1024 * 1024);
    let mut g = c.benchmark_group("scan");
    g.throughput(Throughput::Bytes(10 * 1024 * 1024));
    g.sample_size(20);
    g.bench_function("clean_10mb_nops", |b| {
        b.iter(|| find_direct_syscalls(black_box(&buf), 0))
    });
    g.finish();
}

fn bench_scan_realistic_1mb(c: &mut Criterion) {
    let buf = make_realistic_buffer(1024 * 1024);
    let mut g = c.benchmark_group("scan");
    g.throughput(Throughput::Bytes(1024 * 1024));
    g.bench_function("realistic_1mb", |b| {
        b.iter(|| find_direct_syscalls(black_box(&buf), 0))
    });
    g.finish();
}

fn bench_scan_1_hit_at_start(c: &mut Criterion) {
    let mut buf = vec![0x0F, 0x05];
    buf.extend(vec![0x90u8; 1024 * 1024 - 2]);
    let mut g = c.benchmark_group("scan");
    g.throughput(Throughput::Bytes(buf.len() as u64));
    g.bench_function("1mb_hit_at_start", |b| {
        b.iter(|| find_direct_syscalls(black_box(&buf), 0))
    });
    g.finish();
}

fn bench_scan_1_hit_at_end(c: &mut Criterion) {
    let mut buf = vec![0x90u8; 1024 * 1024 - 2];
    buf.push(0x0F);
    buf.push(0x05);
    let mut g = c.benchmark_group("scan");
    g.throughput(Throughput::Bytes(buf.len() as u64));
    g.bench_function("1mb_hit_at_end", |b| {
        b.iter(|| find_direct_syscalls(black_box(&buf), 0))
    });
    g.finish();
}

fn bench_scan_100_hits_scattered(c: &mut Criterion) {
    // 1MB with 100 syscalls spread out
    let mut buf = vec![0x90u8; 1024 * 1024];
    let step = buf.len() / 100;
    for i in 0..100 {
        let pos = i * step;
        if pos + 1 < buf.len() {
            buf[pos] = 0x0F;
            buf[pos + 1] = 0x05;
        }
    }
    let mut g = c.benchmark_group("scan");
    g.throughput(Throughput::Bytes(buf.len() as u64));
    g.bench_function("1mb_100_hits", |b| {
        b.iter(|| find_direct_syscalls(black_box(&buf), 0))
    });
    g.finish();
}

fn bench_pe_parse(c: &mut Criterion) {
    // Build a minimal valid PE header
    let mut buf = vec![0u8; 4096];
    buf[0] = b'M';
    buf[1] = b'Z';
    buf[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    buf[0x80..0x84].copy_from_slice(&0x00004550u32.to_le_bytes());
    buf[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
    buf[0x94..0x96].copy_from_slice(&0xF0u16.to_le_bytes());
    let section = 0x188;
    buf[section..section + 8].copy_from_slice(b".text\0\0\0");
    buf[section + 8..section + 12].copy_from_slice(&0x1234u32.to_le_bytes());
    buf[section + 12..section + 16].copy_from_slice(&0x1000u32.to_le_bytes());

    let mut g = c.benchmark_group("scan");
    g.bench_function("pe_text_section_parse", |b| {
        b.iter(|| pe_text_section(black_box(&buf)))
    });
    g.finish();
}

criterion_group!(
    benches,
    bench_scan_clean_1kb,
    bench_scan_clean_1mb,
    bench_scan_clean_10mb,
    bench_scan_realistic_1mb,
    bench_scan_1_hit_at_start,
    bench_scan_1_hit_at_end,
    bench_scan_100_hits_scattered,
    bench_pe_parse,
);
criterion_main!(benches);
