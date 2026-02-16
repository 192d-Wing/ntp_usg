// Benchmarks for RFC 5905 selection, clustering, and combine algorithms

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use ntp_client::selection::{cluster_survivors, combine, select_truechimers, PeerCandidate};

fn create_peer_candidates(n: usize) -> Vec<PeerCandidate> {
    (0..n)
        .map(|i| PeerCandidate {
            peer_index: i,
            offset: 0.010 + (i as f64 * 0.001),
            root_delay: 0.020 + (i as f64 * 0.002),
            root_dispersion: 0.005 + (i as f64 * 0.0005),
            jitter: 0.001,
            stratum: 2,
        })
        .collect()
}

fn bench_select_truechimers(c: &mut Criterion) {
    let mut group = c.benchmark_group("select_truechimers");

    for peer_count in [3, 5, 10, 20].iter() {
        group.bench_with_input(
            BenchmarkId::from_parameter(peer_count),
            peer_count,
            |b, &count| {
                let candidates = create_peer_candidates(count);
                b.iter(|| {
                    let truechimers = select_truechimers(black_box(&candidates));
                    black_box(truechimers);
                });
            },
        );
    }

    group.finish();
}

fn bench_cluster_survivors(c: &mut Criterion) {
    let mut group = c.benchmark_group("cluster_survivors");

    for peer_count in [3, 5, 10, 15].iter() {
        group.bench_with_input(
            BenchmarkId::from_parameter(peer_count),
            peer_count,
            |b, &count| {
                b.iter_batched(
                    || create_peer_candidates(count),
                    |mut candidates| {
                        cluster_survivors(black_box(&mut candidates));
                        black_box(candidates);
                    },
                    criterion::BatchSize::SmallInput,
                );
            },
        );
    }

    group.finish();
}

fn bench_combine(c: &mut Criterion) {
    let mut group = c.benchmark_group("combine");

    for peer_count in [3, 5, 10].iter() {
        group.bench_with_input(
            BenchmarkId::from_parameter(peer_count),
            peer_count,
            |b, &count| {
                let candidates = create_peer_candidates(count);
                b.iter(|| {
                    let result = combine(black_box(&candidates));
                    black_box(result);
                });
            },
        );
    }

    group.finish();
}

fn bench_full_pipeline(c: &mut Criterion) {
    let mut group = c.benchmark_group("full_selection_pipeline");

    for peer_count in [5, 10, 20].iter() {
        group.bench_with_input(
            BenchmarkId::from_parameter(peer_count),
            peer_count,
            |b, &count| {
                b.iter_batched(
                    || create_peer_candidates(count),
                    |candidates| {
                        // Full pipeline: selection -> clustering -> combine
                        let truechimers = select_truechimers(black_box(&candidates));
                        let mut survivors: Vec<_> = truechimers
                            .iter()
                            .map(|&idx| candidates[idx].clone())
                            .collect();
                        cluster_survivors(&mut survivors);
                        let result = combine(&survivors);
                        black_box(result);
                    },
                    criterion::BatchSize::SmallInput,
                );
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_select_truechimers,
    bench_cluster_survivors,
    bench_combine,
    bench_full_pipeline
);
criterion_main!(benches);
