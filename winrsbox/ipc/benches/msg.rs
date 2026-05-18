use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ipc::{write_msg, read_msg, Req, LogLevel};
use std::io::Cursor;

fn bench_encode_decide(c: &mut Criterion) {
    let mut group = c.benchmark_group("ipc_msg");
    let msg = Req::Decide {
        dos_path: r"C:\Users\alice\foo.txt".to_owned(),
        write: false,
    };
    let mut buf = Cursor::new(Vec::new());

    group.bench_function("encode_decide", |b| {
        b.iter(|| {
            buf.set_position(0);
            buf.get_mut().clear();
            write_msg(&mut buf, black_box(&msg)).unwrap();
        })
    });
    group.finish();
}

fn bench_decode_decide(c: &mut Criterion) {
    let mut group = c.benchmark_group("ipc_msg");
    let msg = Req::Decide {
        dos_path: r"C:\Users\alice\foo.txt".to_owned(),
        write: false,
    };
    let mut enc = Cursor::new(Vec::new());
    write_msg(&mut enc, &msg).unwrap();
    let encoded = enc.into_inner();

    group.bench_function("decode_decide", |b| {
        b.iter(|| {
            let mut cur = Cursor::new(black_box(&encoded[..]));
            let _: Req = read_msg(&mut cur).unwrap();
        })
    });
    group.finish();
}

fn bench_roundtrip_decide(c: &mut Criterion) {
    let mut group = c.benchmark_group("ipc_msg");
    let msg = Req::Decide {
        dos_path: r"C:\Users\alice\foo.txt".to_owned(),
        write: false,
    };

    group.bench_function("roundtrip_decide", |b| {
        b.iter(|| {
            let mut buf = Cursor::new(Vec::new());
            write_msg(&mut buf, black_box(&msg)).unwrap();
            buf.set_position(0);
            let _: Req = read_msg(&mut buf).unwrap();
        })
    });
    group.finish();
}

fn bench_encode_log_short(c: &mut Criterion) {
    let mut group = c.benchmark_group("ipc_msg");
    let msg = Req::Log {
        pid: 42,
        level: LogLevel::Info,
        msg: "hi".to_owned(),
    };
    let mut buf = Cursor::new(Vec::new());

    group.bench_function("encode_log_short", |b| {
        b.iter(|| {
            buf.set_position(0);
            buf.get_mut().clear();
            write_msg(&mut buf, black_box(&msg)).unwrap();
        })
    });
    group.finish();
}

fn bench_encode_log_long(c: &mut Criterion) {
    let mut group = c.benchmark_group("ipc_msg");
    let msg = Req::Log {
        pid: 42,
        level: LogLevel::Info,
        msg: "x".repeat(4096),
    };
    let mut buf = Cursor::new(Vec::new());

    group.bench_function("encode_log_long", |b| {
        b.iter(|| {
            buf.set_position(0);
            buf.get_mut().clear();
            write_msg(&mut buf, black_box(&msg)).unwrap();
        })
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_encode_decide,
    bench_decode_decide,
    bench_roundtrip_decide,
    bench_encode_log_short,
    bench_encode_log_long,
);
criterion_main!(benches);
