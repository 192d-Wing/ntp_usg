// TLS configuration for NTS key establishment.
//
// Selects the appropriate cryptographic provider based on feature flags:
// - `pq-nts` (default with NTS): aws-lc-rs with X25519MLKEM768 preferred
// - without `pq-nts`: ring with classical X25519 only

use std::sync::Arc;

/// Build the TLS crypto provider for the current feature configuration.
///
/// With `pq-nts`: returns the aws-lc-rs provider, which prefers the
/// X25519MLKEM768 hybrid post-quantum key exchange with automatic
/// fallback to classical X25519 during TLS 1.3 negotiation.
///
/// Without `pq-nts`: returns the ring provider (classical X25519 only).
fn crypto_provider() -> rustls::crypto::CryptoProvider {
    #[cfg(feature = "pq-nts")]
    {
        rustls::crypto::aws_lc_rs::default_provider()
    }
    #[cfg(not(feature = "pq-nts"))]
    {
        rustls::crypto::ring::default_provider()
    }
}

/// Build a TLS client configuration for NTS-KE (RFC 8915).
///
/// Configures TLS 1.3 with the WebPKI root certificates and the
/// crypto provider selected by the `pq-nts` feature flag.
pub(crate) fn nts_client_config() -> rustls::ClientConfig {
    let root_store =
        rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    rustls::ClientConfig::builder_with_provider(Arc::new(crypto_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3 configuration valid")
        .with_root_certificates(root_store)
        .with_no_client_auth()
}
