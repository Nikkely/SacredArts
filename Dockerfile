# syntax=docker/dockerfile:1
#
# SacredArts sandbox image: supervisor + runner + strace on Ubuntu 24.04.
# Build:  docker build -t sacredarts-sandbox:0.1.0 .
# The image is started only by the SacredArts MCP server with a fixed,
# hardened set of `docker run` options (see docs/security.md).

FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked -p sacredarts-runner -p sacredarts-tracer \
 && mkdir -p /out \
 && install -m 0755 target/release/sacredarts-runner target/release/sacredarts-supervisor /out/

FROM ubuntu:24.04
RUN apt-get update \
 && apt-get install -y --no-install-recommends strace \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd -g 10001 sacred \
 && useradd -u 10001 -g 10001 -M -d /workspace -s /usr/sbin/nologin sacred
COPY --from=build /out/ /usr/local/bin/
LABEL org.opencontainers.image.title="sacredarts-sandbox" \
      org.opencontainers.image.description="SacredArts Linux syscall laboratory sandbox" \
      org.opencontainers.image.licenses="MIT OR Apache-2.0"
USER 10001:10001
WORKDIR /workspace
ENTRYPOINT ["/usr/local/bin/sacredarts-supervisor"]
