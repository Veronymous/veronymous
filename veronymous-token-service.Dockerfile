FROM ubuntu:22.04

WORKDIR /opt/veronymous-token-service

# Build context is target/release/
ADD ./veronymous_token_service ./bin/veronymous_token_service

ENTRYPOINT ["./bin/veronymous_token_service"]