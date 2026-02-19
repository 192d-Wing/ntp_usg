// Benchmarks for NTS AEAD encrypt/decrypt operations.

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use ntp_proto::nts_common::{
    AEAD_AES_SIV_CMAC_256, AEAD_AES_SIV_CMAC_512, aead_decrypt, aead_encrypt,
};

fn bench_aead_encrypt_256(c: &mut Criterion) {
    let key = vec![0xABu8; 32]; // 256-bit key
    let aad = [0u8; 48]; // NTP header as AAD
    let plaintext = [0u8; 0]; // NTS typically encrypts empty plaintext

    c.bench_function("nts_aead_encrypt_cmac256", |b| {
        b.iter(|| {
            aead_encrypt(
                AEAD_AES_SIV_CMAC_256,
                black_box(&key),
                black_box(&aad),
                black_box(&plaintext),
            )
            .unwrap()
        })
    });
}

fn bench_aead_encrypt_512(c: &mut Criterion) {
    let key = vec![0xABu8; 64]; // 512-bit key
    let aad = [0u8; 48];
    let plaintext = [0u8; 0];

    c.bench_function("nts_aead_encrypt_cmac512", |b| {
        b.iter(|| {
            aead_encrypt(
                AEAD_AES_SIV_CMAC_512,
                black_box(&key),
                black_box(&aad),
                black_box(&plaintext),
            )
            .unwrap()
        })
    });
}

fn bench_aead_decrypt_256(c: &mut Criterion) {
    let key = vec![0xABu8; 32];
    let aad = [0u8; 48];
    let plaintext = [0u8; 0];
    let (nonce, ciphertext) = aead_encrypt(AEAD_AES_SIV_CMAC_256, &key, &aad, &plaintext).unwrap();

    c.bench_function("nts_aead_decrypt_cmac256", |b| {
        b.iter(|| {
            aead_decrypt(
                AEAD_AES_SIV_CMAC_256,
                black_box(&key),
                black_box(&aad),
                black_box(&nonce),
                black_box(&ciphertext),
            )
            .unwrap()
        })
    });
}

fn bench_aead_decrypt_512(c: &mut Criterion) {
    let key = vec![0xABu8; 64];
    let aad = [0u8; 48];
    let plaintext = [0u8; 0];
    let (nonce, ciphertext) = aead_encrypt(AEAD_AES_SIV_CMAC_512, &key, &aad, &plaintext).unwrap();

    c.bench_function("nts_aead_decrypt_cmac512", |b| {
        b.iter(|| {
            aead_decrypt(
                AEAD_AES_SIV_CMAC_512,
                black_box(&key),
                black_box(&aad),
                black_box(&nonce),
                black_box(&ciphertext),
            )
            .unwrap()
        })
    });
}

criterion_group!(
    benches,
    bench_aead_encrypt_256,
    bench_aead_encrypt_512,
    bench_aead_decrypt_256,
    bench_aead_decrypt_512,
);
criterion_main!(benches);
