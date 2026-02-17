// TLS configuration for NTS-KE server.
//
// Selects the appropriate cryptographic provider based on feature flags:
// - `pq-nts` (default with NTS): aws-lc-rs with X25519MLKEM768 preferred
// - without `pq-nts`: ring with classical X25519 only

use std::io;
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};

/// Build the TLS crypto provider for the current feature configuration.
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

/// Build a TLS server configuration for NTS-KE (RFC 8915, TLS 1.3 only).
pub(crate) fn nts_server_config(
    cert_chain: Vec<CertificateDer<'static>>,
    private_key: PrivateKeyDer<'static>,
) -> io::Result<rustls::ServerConfig> {
    rustls::ServerConfig::builder_with_provider(Arc::new(crypto_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3 configuration valid")
        .with_no_client_auth()
        .with_single_cert(cert_chain, private_key)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("TLS config error: {e}")))
}
