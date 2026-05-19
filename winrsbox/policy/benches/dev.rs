use criterion::{black_box, criterion_group, criterion_main, Criterion};
use policy::dev;

fn bench_nt_to_device_path(c: &mut Criterion) {
    let mut group = c.benchmark_group("dev");
    let raw_device: Vec<u16> = r"\Device\CldFlt".encode_utf16().collect();
    let raw_globalroot: Vec<u16> = r"\??\GLOBALROOT\Device\HarddiskVolume3\foo".encode_utf16().collect();
    let raw_dos: Vec<u16> = r"\??\C:\foo".encode_utf16().collect();

    group.bench_function("nt_to_device_path_device", |b| {
        b.iter(|| dev::nt_to_device_path(black_box(&raw_device)))
    });
    group.bench_function("nt_to_device_path_globalroot", |b| {
        b.iter(|| dev::nt_to_device_path(black_box(&raw_globalroot)))
    });
    group.bench_function("nt_to_device_path_dos_none", |b| {
        b.iter(|| dev::nt_to_device_path(black_box(&raw_dos)))
    });
    group.finish();
}

fn bench_classify_device(c: &mut Criterion) {
    let mut group = c.benchmark_group("dev");
    group.bench_function("classify_harddisk", |b| {
        b.iter(|| dev::classify_device(black_box(r"\device\harddiskvolume3")))
    });
    group.bench_function("classify_unknown", |b| {
        b.iter(|| dev::classify_device(black_box(r"\device\cldflt")))
    });
    group.finish();
}

criterion_group!(benches, bench_nt_to_device_path, bench_classify_device);
criterion_main!(benches);
