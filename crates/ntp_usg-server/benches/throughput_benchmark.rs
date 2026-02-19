// Benchmarks for NTP server request handling throughput.

use std::hint::black_box;
use std::net::IpAddr;

use criterion::{Criterion, criterion_group, criterion_main};
use ntp_proto::protocol::{
    ConstPackedSizeBytes, LeapIndicator, Mode, Packet, PrimarySource, ReferenceIdentifier,
    ShortFormat, Stratum, TimestampFormat, ToBytes, Version,
};
use ntp_server::server_common::{
    AccessControl, ClientTable, IpNet, RateLimitConfig, ServerMetrics, ServerSystemState,
    handle_request, serialize_response_with_t3,
};

fn make_client_request_buf() -> [u8; Packet::PACKED_SIZE_BYTES] {
    let pkt = Packet {
        leap_indicator: LeapIndicator::NoWarning,
        version: Version::V4,
        mode: Mode::Client,
        stratum: Stratum::UNSPECIFIED,
        poll: 6,
        precision: 0,
        root_delay: ShortFormat::default(),
        root_dispersion: ShortFormat::default(),
        reference_id: ReferenceIdentifier::default(),
        reference_timestamp: TimestampFormat::default(),
        origin_timestamp: TimestampFormat::default(),
        receive_timestamp: TimestampFormat::default(),
        transmit_timestamp: TimestampFormat {
            seconds: 3_913_056_000,
            fraction: 0xABCD_1234,
        },
    };
    let mut buf = [0u8; Packet::PACKED_SIZE_BYTES];
    pkt.to_bytes(&mut buf).unwrap();
    buf
}

fn bench_handle_request_basic(c: &mut Criterion) {
    let buf = make_client_request_buf();
    let state = ServerSystemState::default();
    let ac = AccessControl::default();
    let metrics = ServerMetrics::default();
    let src_ip: IpAddr = "192.168.1.100".parse().unwrap();

    c.bench_function("handle_request_basic", |b| {
        b.iter(|| {
            let mut table = ClientTable::new(1024);
            handle_request(
                black_box(&buf),
                buf.len(),
                black_box(src_ip),
                &state,
                &ac,
                None,
                &mut table,
                false,
                Some(&metrics),
            )
        })
    });
}

fn bench_handle_request_with_rate_limit(c: &mut Criterion) {
    let buf = make_client_request_buf();
    let state = ServerSystemState::default();
    let ac = AccessControl::default();
    let metrics = ServerMetrics::default();
    let rate_config = RateLimitConfig::default();
    let src_ip: IpAddr = "192.168.1.100".parse().unwrap();

    c.bench_function("handle_request_with_rate_limit", |b| {
        b.iter(|| {
            let mut table = ClientTable::new(1024);
            handle_request(
                black_box(&buf),
                buf.len(),
                black_box(src_ip),
                &state,
                &ac,
                Some(&rate_config),
                &mut table,
                false,
                Some(&metrics),
            )
        })
    });
}

fn bench_response_serialization(c: &mut Criterion) {
    let pkt = Packet {
        leap_indicator: LeapIndicator::NoWarning,
        version: Version::V4,
        mode: Mode::Server,
        stratum: Stratum::PRIMARY,
        poll: 6,
        precision: -20,
        root_delay: ShortFormat::default(),
        root_dispersion: ShortFormat::default(),
        reference_id: ReferenceIdentifier::PrimarySource(PrimarySource::Locl),
        reference_timestamp: TimestampFormat {
            seconds: 3_913_056_000,
            fraction: 0,
        },
        origin_timestamp: TimestampFormat {
            seconds: 3_913_056_001,
            fraction: 0x1234_5678,
        },
        receive_timestamp: TimestampFormat {
            seconds: 3_913_056_002,
            fraction: 0x9ABC_DEF0,
        },
        transmit_timestamp: TimestampFormat::default(),
    };

    c.bench_function("serialize_response_with_t3", |b| {
        b.iter(|| serialize_response_with_t3(black_box(&pkt)).unwrap())
    });
}

fn bench_access_control_large_acl(c: &mut Criterion) {
    let buf = make_client_request_buf();
    let state = ServerSystemState::default();
    let metrics = ServerMetrics::default();
    let src_ip: IpAddr = "172.16.50.1".parse().unwrap();

    // Build an allow list with 1000 /24 subnets.
    let allow_list: Vec<_> = (0..4u8)
        .flat_map(|b| (0..=255u8).map(move |c| IpNet::new(IpAddr::from([10, b, c, 0]), 24)))
        .take(1000)
        .collect();
    let ac = AccessControl::new(Some(allow_list), None);

    c.bench_function("handle_request_large_acl_1000", |b| {
        b.iter(|| {
            let mut table = ClientTable::new(1024);
            handle_request(
                black_box(&buf),
                buf.len(),
                black_box(src_ip),
                &state,
                &ac,
                None,
                &mut table,
                false,
                Some(&metrics),
            )
        })
    });
}

fn bench_rate_limit_full_table(c: &mut Criterion) {
    let buf = make_client_request_buf();
    let state = ServerSystemState::default();
    let ac = AccessControl::default();
    let metrics = ServerMetrics::default();
    let rate_config = RateLimitConfig::default();

    // Pre-fill the client table to capacity with unique IPs.
    let max_clients = 1024;
    let mut table = ClientTable::new(max_clients);
    for i in 0..max_clients as u32 {
        let ip: IpAddr = IpAddr::from([
            (i >> 24) as u8 | 10,
            (i >> 16) as u8,
            (i >> 8) as u8,
            i as u8,
        ]);
        handle_request(
            &buf,
            buf.len(),
            ip,
            &state,
            &ac,
            Some(&rate_config),
            &mut table,
            false,
            None,
        );
    }

    // Benchmark a new client hitting the full table.
    let new_ip: IpAddr = "192.168.1.1".parse().unwrap();
    c.bench_function("handle_request_full_table_1024", |b| {
        b.iter(|| {
            handle_request(
                black_box(&buf),
                buf.len(),
                black_box(new_ip),
                &state,
                &ac,
                Some(&rate_config),
                &mut table,
                false,
                Some(&metrics),
            )
        })
    });
}

criterion_group!(
    benches,
    bench_handle_request_basic,
    bench_handle_request_with_rate_limit,
    bench_response_serialization,
    bench_access_control_large_acl,
    bench_rate_limit_full_table,
);
criterion_main!(benches);
