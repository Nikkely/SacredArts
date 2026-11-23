#!/usr/bin/env bash
# Run cargo commands for the Linux-only crates inside a Rust container.
# Usage: scripts/linux-test.sh [cargo args...]   (default: test for linux crates)
set -euo pipefail
cd "$(dirname "$0")/.."
RUST_IMAGE="${RUST_IMAGE:-rust:1-bookworm}"
if [ $# -eq 0 ]; then
  set -- test -p sacredarts-core -p sacredarts-policy -p sacredarts-runner -p sacredarts-tracer -p sacredarts-guide
fi
exec docker run --rm \
  -v "$PWD":/src:ro \
  -v sacredarts-cargo-registry:/usr/local/cargo/registry \
  -v sacredarts-target-linux:/target \
  -e CARGO_TARGET_DIR=/target \
  -w /src "$RUST_IMAGE" cargo "$@"
