# Layer 1: OS packages (changes least often)
FROM rust:1-trixie AS base
RUN apt-get update && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends \
       gh libudev-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Layer 2: Rust components (changes with Rust version bumps)
FROM base AS toolchain
RUN rustup component add clippy rustfmt llvm-tools-preview

# Layer 3: Cargo tools (changes when tool versions bump)
FROM toolchain AS tools
RUN curl -L --proto '=https' --tlsv1.2 -sSf \
    https://raw.githubusercontent.com/cargo-bins/cargo-binstall/main/install-from-binstall-release.sh | bash \
    && cargo binstall --no-confirm \
       cargo-nextest cargo-llvm-cov cargo-audit cargo-deny cargo-cyclonedx \
    && rm -rf /usr/local/cargo/registry /usr/local/cargo/git /tmp/*

# Verify all tools are available
RUN cargo nextest --version \
    && cargo llvm-cov --version \
    && cargo audit --version \
    && cargo deny --version \
    && cargo cyclonedx --version \
    && cargo fmt --version \
    && cargo clippy --version \
    && gh --version
