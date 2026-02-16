# Test runner container for integration tests
FROM rust:1.93-slim

WORKDIR /workspace

# Install dependencies
RUN apt-get update && \
    apt-get install -y pkg-config libssl-dev netcat-openbsd && \
    rm -rf /var/lib/apt/lists/*

# Copy workspace
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

# Pre-build dependencies (layer caching)
RUN cargo build --tests --features "ntp_usg-client/tokio ntp_usg-client/nts" && \
    rm -rf target/debug/deps/ntp_usg*

# Default command runs all tests
CMD ["cargo", "test", "--workspace", "--features", "ntp_usg-client/tokio ntp_usg-client/nts"]
