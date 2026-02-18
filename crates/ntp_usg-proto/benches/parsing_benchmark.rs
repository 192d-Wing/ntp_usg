// Benchmarks for NTP protocol parsing and serialization.

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use ntp_proto::protocol::{
    ConstPackedSizeBytes, FromBytes, LeapIndicator, Mode, Packet, PrimarySource,
    ReferenceIdentifier, ShortFormat, Stratum, TimestampFormat, ToBytes, Version,
};

fn make_test_packet() -> Packet {
    Packet {
        leap_indicator: LeapIndicator::NoWarning,
        version: Version::V4,
        mode: Mode::Server,
        stratum: Stratum::PRIMARY,
        poll: 6,
        precision: -20,
        root_delay: ShortFormat {
            seconds: 0,
            fraction: 256,
        },
        root_dispersion: ShortFormat {
            seconds: 0,
            fraction: 512,
        },
        reference_id: ReferenceIdentifier::PrimarySource(PrimarySource::Gps),
        reference_timestamp: TimestampFormat {
            seconds: 3_913_056_000,
            fraction: 0xABCD_1234,
        },
        origin_timestamp: TimestampFormat {
            seconds: 3_913_056_001,
            fraction: 0x1111_2222,
        },
        receive_timestamp: TimestampFormat {
            seconds: 3_913_056_002,
            fraction: 0x3333_4444,
        },
        transmit_timestamp: TimestampFormat {
            seconds: 3_913_056_003,
            fraction: 0x5555_6666,
        },
    }
}

fn bench_packet_from_bytes(c: &mut Criterion) {
    let pkt = make_test_packet();
    let mut buf = [0u8; Packet::PACKED_SIZE_BYTES];
    pkt.to_bytes(&mut buf).unwrap();

    c.bench_function("packet_from_bytes", |b| {
        b.iter(|| Packet::from_bytes(black_box(&buf)).unwrap())
    });
}

fn bench_packet_to_bytes(c: &mut Criterion) {
    let pkt = make_test_packet();
    let mut buf = [0u8; Packet::PACKED_SIZE_BYTES];

    c.bench_function("packet_to_bytes", |b| {
        b.iter(|| black_box(&pkt).to_bytes(&mut buf).unwrap())
    });
}

fn bench_timestamp_from_bytes(c: &mut Criterion) {
    let buf = [0xE9, 0x32, 0xB8, 0x00, 0xAB, 0xCD, 0x12, 0x34];

    c.bench_function("timestamp_from_bytes", |b| {
        b.iter(|| TimestampFormat::from_bytes(black_box(&buf)).unwrap())
    });
}

fn bench_timestamp_to_bytes(c: &mut Criterion) {
    let ts = TimestampFormat {
        seconds: 3_913_056_000,
        fraction: 0xABCD_1234,
    };
    let mut buf = [0u8; 8];

    c.bench_function("timestamp_to_bytes", |b| {
        b.iter(|| black_box(&ts).to_bytes(&mut buf).unwrap())
    });
}

fn bench_packet_roundtrip(c: &mut Criterion) {
    let pkt = make_test_packet();
    let mut buf = [0u8; Packet::PACKED_SIZE_BYTES];

    c.bench_function("packet_roundtrip", |b| {
        b.iter(|| {
            pkt.to_bytes(&mut buf).unwrap();
            Packet::from_bytes(black_box(&buf)).unwrap()
        })
    });
}

fn bench_extension_field_iter(c: &mut Criterion) {
    use ntp_proto::extension::{self, ExtensionField};

    let fields = vec![
        ExtensionField {
            field_type: 0x0104,
            value: vec![0u8; 32],
        },
        ExtensionField {
            field_type: 0x0204,
            value: vec![0u8; 100],
        },
        ExtensionField {
            field_type: 0x0404,
            value: vec![0u8; 48],
        },
    ];
    let ext_bytes = extension::write_extension_fields(&fields).unwrap();

    c.bench_function("extension_field_iter_3_fields", |b| {
        b.iter(|| {
            let mut count = 0;
            for result in extension::iter_extension_fields(black_box(&ext_bytes)) {
                let _ = result.unwrap();
                count += 1;
            }
            count
        })
    });
}

criterion_group!(
    benches,
    bench_packet_from_bytes,
    bench_packet_to_bytes,
    bench_timestamp_from_bytes,
    bench_timestamp_to_bytes,
    bench_packet_roundtrip,
    bench_extension_field_iter,
);
criterion_main!(benches);
