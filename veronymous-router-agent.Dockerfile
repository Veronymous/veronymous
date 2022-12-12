FROM ubuntu:22.04

WORKDIR /opt/veronymous-router-agent

# Build context is target/release/
ADD ./veronymous_router_agent ./bin/veronymous_router_agent

ENTRYPOINT ["./bin/veronymous_router_agent"]
