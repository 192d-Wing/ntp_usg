# Build stage
FROM rust:1-slim AS builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && \
    apt-get install -y pkg-config libssl-dev && \
    rm -rf /var/lib/apt/lists/*

# Copy workspace files
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

# Build the NTS server
RUN cargo build --release -p ntp_usg-server --features nts

# Create minimal NTS server example
RUN mkdir -p examples && \
    cat > examples/docker_nts_server.rs <<'EOF'
use ntp_server::nts_ke_server::NtsKeServerConfig;
use ntp_server::protocol::Stratum;
use ntp_server::server::NtpServer;
use std::fs;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();

    println!("Loading TLS certificates from /etc/ntp/certs/");

    // Load certificates
    let cert_pem = fs::read("/etc/ntp/certs/server.crt")
        .expect("Failed to read server.crt");
    let key_pem = fs::read("/etc/ntp/certs/server.key")
        .expect("Failed to read server.key");

    let nts_config = NtsKeServerConfig::from_pem(&cert_pem, &key_pem)
        .expect("Failed to parse certificates");

    println!("Starting NTS-KE server on 0.0.0.0:4460");
    println!("Starting NTP server on 0.0.0.0:123");

    let server = NtpServer::builder()
        .listen("0.0.0.0:123")
        .nts_ke(nts_config, "0.0.0.0:4460")
        .stratum(Stratum(2))
        .build()
        .await?;

    println!("NTS server ready");
    server.run().await
}
EOF

# Build the docker NTS server example
RUN cargo build --release --example docker_nts_server --features ntp_usg-server/nts

# Runtime stage
FROM debian:trixie-slim

# Install runtime dependencies
RUN apt-get update && \
    apt-get install -y netcat-openbsd ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Copy the binary
COPY --from=builder /build/target/release/examples/docker_nts_server /usr/local/bin/nts-server

# Expose NTP and NTS-KE ports
EXPOSE 123/udp
EXPOSE 4460/tcp

# Run as non-root user (after binding privileged ports)
RUN useradd -r -s /bin/false ntpuser
USER ntpuser

CMD ["/usr/local/bin/nts-server"]
