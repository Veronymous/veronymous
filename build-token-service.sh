#!/bin/sh

# Test
cargo test --manifest-path veronymous-token/Cargo.toml
cargo test --manifest-path veronymous-token/crypto/Cargo.toml
cargo test --manifest-path veronymous-token/crypto/bb-signatures/Cargo.toml
cargo test --manifest-path veronymous-token/crypto/commitments/Cargo.toml
cargo test --manifest-path veronymous-token/crypto/common/Cargo.toml
cargo test --manifest-path veronymous-token/crypto/common/Cargo.toml
cargo test --manifest-path veronymous-token-service/Cargo.toml

# Build the binary
cargo build --release --manifest-path veronymous-token-service/Cargo.toml

# Build the docker image
docker build -t veronymous-token-service -f veronymous-token-service.Dockerfile ./target/release/
