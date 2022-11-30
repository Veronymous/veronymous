from ubuntu:22.04

WORKDIR /opt/veronymous-token-service

ADD veronymous-token-service ./veronymous-token-service
ADD veronymous-token ./veronymous-token

# Install some dependencies
RUN apt-get update -y
RUN apt-get install curl -y
RUN apt-get install build-essential -y
RUN apt-get install clang -y

# Install rust and cargo
RUN curl --proto '=https' --tlsv1.3 https://sh.rustup.rs -sSf | sh -s -- -y 

# Rust setup
RUN bash -c "source $HOME/.cargo/env"

# Install 1.65 rust toolchain
RUN $HOME/.cargo/bin/rustup toolchain install 1.65

RUN $HOME/.cargo/bin/cargo build --manifest-path ./veronymous-token-service/Cargo.toml --release

# Move the binary
RUN mkdir ./bin 
RUN mv ./veronymous-token-service/target/release/veronymous_token_service ./bin/

# Remove source code
RUN rm -rf ./veronymous-token-service
RUN rm -rf ./veronymous-token

ENTRYPOINT ["./bin/veronymous_token_service"]
