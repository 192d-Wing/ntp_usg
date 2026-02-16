FROM rust:1-trixie

# Keep OS packages current
RUN apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/*

# Toolchain components
RUN rustup component add clippy rustfmt llvm-tools-preview

# Pre-built tools via cargo-binstall (fast, no compilation)
RUN curl -L --proto '=https' --tlsv1.2 -sSf \
    https://raw.githubusercontent.com/cargo-bins/cargo-binstall/main/install-from-binstall-release.sh | bash \
    && cargo binstall --no-confirm cargo-nextest cargo-llvm-cov cargo-audit cargo-deny

# Verify all tools are available
RUN cargo nextest --version \
    && cargo llvm-cov --version \
    && cargo audit --version \
    && cargo deny --version \
    && cargo fmt --version \
    && cargo clippy --version

# Clean up caches to reduce image size
RUN rm -rf /usr/local/cargo/registry /usr/local/cargo/git /tmp/*
