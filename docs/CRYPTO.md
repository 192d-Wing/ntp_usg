# Cryptographic Architecture

This document describes the cryptographic algorithms and libraries used across
the `ntp_usg` workspace, their FIPS certification status, and known gaps.

## Overview

| Context | Algorithm | Library | FIPS Status |
|---------|-----------|---------|-------------|
| TLS 1.3 (NTS-KE) | AES-128/256-GCM, ChaCha20-Poly1305 | `aws-lc-rs` via rustls | **FIPS 140-3 validated** (cert #4856) |
| TLS 1.3 key exchange | X25519MLKEM768 (PQ hybrid) | `aws-lc-rs` via rustls | **FIPS 203** (ML-KEM) |
| NTS AEAD (cookies + packets) | AES-SIV-CMAC-512 (256-bit AES) | `aes-siv` (RustCrypto) | **Not FIPS certified** |
| NTPv5 MAC extension | AES-CMAC-128 | `cmac` + `aes` (RustCrypto) | **Not FIPS certified** |
| Roughtime signatures | Ed25519 | `ring` | Not FIPS certified (ring 0.17) |
| Roughtime Merkle proofs | SHA-512 | `ring` | Not FIPS certified (ring 0.17) |

## TLS Layer — FIPS Certified

All NTS-KE connections (RFC 8915 key establishment) use TLS 1.3 via rustls with
the `aws-lc-rs` cryptographic backend. AWS-LC is FIPS 140-3 validated
(certificate #4856).

The `pq-nts` feature (auto-enabled by `nts` and `nts-smol`) activates:
- `rustls/aws-lc-rs` — FIPS-validated crypto provider
- `rustls/prefer-post-quantum` — X25519MLKEM768 hybrid key exchange (FIPS 203)

This means all NTS deployments automatically use the FIPS-validated TLS backend.
There is no configuration needed to enable this — it is the default.

## NTS AEAD Layer — Not FIPS Certified

RFC 8915 mandates AES-SIV-CMAC for NTS packet authentication and cookie
encryption. This is implemented via the `aes-siv` crate from the RustCrypto
project. RustCrypto crates are **not FIPS 140-3 certified**.

### Why AES-SIV-CMAC?

AES-SIV-CMAC is the **only** AEAD algorithm defined for NTS by RFC 8915. The
IANA NTS AEAD Algorithm registry contains two entries:

| ID | Algorithm | Key Size | AES Key Bits |
|----|-----------|----------|--------------|
| 15 | AEAD_AES_SIV_CMAC_256 | 32 bytes | 128-bit AES |
| 17 | AEAD_AES_SIV_CMAC_512 | 64 bytes | 256-bit AES |

AES-GCM, while FIPS-approved, is **not** a valid NTS AEAD algorithm. The
protocol requires AES-SIV-CMAC specifically because it provides
misuse-resistant authenticated encryption (nonce reuse does not catastrophically
break security).

### 256-bit AES Preference

As of v4.5.0, this library **prefers AEAD_AES_SIV_CMAC_512** (256-bit AES)
over AEAD_AES_SIV_CMAC_256 (128-bit AES) in all negotiation:

- **Client**: Proposes CMAC-512 first, CMAC-256 as fallback
- **Server**: Selects CMAC-512 when the client supports it
- **Server cookies**: Encrypted with CMAC-512 (64-byte master key)

Both algorithms remain supported for interoperability with servers/clients that
only implement CMAC-256.

### FIPS Gap: `aes-siv` Crate

The `aes-siv` crate uses RustCrypto's `aes` and `cmac` implementations, which
are pure-Rust, constant-time, and well-audited — but not submitted for FIPS
140-3 validation. No Rust AES-SIV-CMAC library currently holds FIPS
certification.

**Mitigation**: `aws-lc-rs` (which *is* FIPS-validated) does not expose
AES-SIV-CMAC in its Rust API. Until either:
1. `aws-lc-rs` adds AES-SIV-CMAC support, or
2. A FIPS-validated Rust AES-SIV-CMAC library becomes available

the `aes-siv` RustCrypto crate is the best available option. The underlying
AES primitive is identical to the FIPS-validated one — only the CMAC/SIV
construction lacks the formal certification.

## NTPv5 MAC — Not FIPS Certified

The NTPv5 draft (`draft-ietf-ntp-ntpv5-07`) specifies AES-CMAC-128 for the
MAC extension field (type 0xF502). This is implemented via the `cmac` and `aes`
crates from RustCrypto. The same FIPS gap as NTS AEAD applies.

**Note**: AES-CMAC-128 uses 128-bit AES keys. This is mandated by the NTPv5
draft and cannot be changed to 256-bit without violating the specification.

## Roughtime — Not FIPS Certified

Roughtime uses Ed25519 signatures and SHA-512 Merkle proofs via the `ring`
crate (v0.17). The `ring` crate is not FIPS-certified, though `aws-lc-rs`
(which shares the underlying AWS-LC C library) is. Roughtime is a
coarse-time protocol used for bootstrapping and is not on the critical path
for NTS-secured time synchronization.

## Summary

| Layer | FIPS 140-3 | Action Required |
|-------|-----------|-----------------|
| TLS 1.3 transport | Yes (aws-lc-rs) | None — already certified |
| PQ key exchange | Yes (FIPS 203) | None — already compliant |
| NTS AEAD | **No** (aes-siv) | Awaiting FIPS-certified AES-SIV-CMAC |
| NTPv5 MAC | **No** (cmac+aes) | Awaiting FIPS-certified AES-CMAC |
| Roughtime | **No** (ring) | Low priority — not security-critical |

## FIPS Migration Path

As of v4.10.0, the NTS AEAD layer is abstracted behind the `NtsAead` trait in
`ntp_proto::nts_common`:

```rust
pub trait NtsAead: Send + Sync {
    fn encrypt(&self, aad: &[u8], plaintext: &[u8]) -> io::Result<(Vec<u8>, Vec<u8>)>;
    fn decrypt(&self, aad: &[u8], nonce: &[u8], ciphertext: &[u8]) -> io::Result<Vec<u8>>;
    fn algorithm_id(&self) -> u16;
    fn key_length(&self) -> usize;
}
```

The default implementation (`AesSivCmacAead`) delegates to the `aes-siv`
RustCrypto crate. The existing free functions `aead_encrypt()` and
`aead_decrypt()` are preserved — no callers need to change.

A `fips-aead` feature flag is defined in `ntp_usg-proto/Cargo.toml` but
currently produces a `compile_error!` since no FIPS-certified backend exists.
When one becomes available, the migration path is:

1. Add the FIPS AES-SIV-CMAC dependency behind `fips-aead`
2. Implement `NtsAead` for the FIPS backend
3. Remove the `compile_error!` gate
4. Conditionally use the FIPS backend when `fips-aead` is enabled

For deployments requiring full FIPS 140-3 compliance end-to-end, the NTS AEAD
layer is the primary gap. The TLS transport layer (which protects NTS-KE key
establishment) is fully FIPS-compliant.
