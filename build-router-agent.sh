#!/bin/sh

# Test token_issuer package
cargo test --manifest-path veronymous-token/Cargo.toml
cargo test --manifest-path veronymous-token/crypto/Cargo.toml
cargo test --manifest-path veronymous-token/crypto/bb-signatures/Cargo.toml
cargo test --manifest-path veronymous-token/crypto/commitments/Cargo.toml
cargo test --manifest-path veronymous-token/crypto/common/Cargo.toml
cargo test --manifest-path veronymous-token/crypto/common/Cargo.toml

# Test the router agent
cargo test --manifest-path veronymous-router-agent/Cargo.toml

# Build the binary
cargo build --release --manifest-path veronymous-router-agent/Cargo.toml

# Build the docker image
docker build -t veronymous-router-agent -f veronymous-router-agent.Dockerfile ./target/release
