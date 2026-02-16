# Build stage
FROM rust:1.93-slim as builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && \
    apt-get install -y pkg-config libssl-dev && \
    rm -rf /var/lib/apt/lists/*

# Copy workspace files
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

# Build the NTP server
RUN cargo build --release -p ntp_usg-server --features tokio

# Create minimal server example
RUN mkdir -p examples && \
    cat > examples/docker_server.rs <<'EOF'
use ntp_server::protocol::Stratum;
use ntp_server::server::NtpServer;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();

    println!("Starting NTP test server on 0.0.0.0:123");

    let server = NtpServer::builder()
        .listen("0.0.0.0:123")
        .stratum(Stratum(2))
        .build()
        .await?;

    println!("NTP server ready");
    server.run().await
}
EOF

# Build the docker server example
RUN cargo build --release --example docker_server --features ntp_usg-server/tokio

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && \
    apt-get install -y netcat-openbsd && \
    rm -rf /var/lib/apt/lists/*

# Copy the binary
COPY --from=builder /build/target/release/examples/docker_server /usr/local/bin/ntp-server

# Expose NTP port
EXPOSE 123/udp

# Run as non-root user
RUN useradd -r -s /bin/false ntpuser
USER ntpuser

CMD ["/usr/local/bin/ntp-server"]
