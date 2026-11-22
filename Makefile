IMAGE ?= sacredarts-sandbox:0.1.0

.PHONY: image build lint test linux-test e2e demo clean

image:            ## build the sandbox image (runner + supervisor + strace)
	docker build -t $(IMAGE) .

build:            ## build the MCP server for the host
	cargo build --release -p sacredarts-mcp

lint:             ## formatting + clippy (warnings are errors)
	cargo fmt --all --check
	cargo clippy --workspace --all-targets -- -D warnings

test:             ## host unit tests
	cargo test --workspace

linux-test:       ## Linux-only tests (runner, seccomp, paths, handles) inside Docker
	scripts/linux-test.sh

e2e: image        ## acceptance tests against Docker Desktop (spec Test 1-10)
	cargo test -p sacredarts-mcp --test acceptance -- --ignored --test-threads=1

demo: image build ## run the example MCP session
	python3 examples/demo_client.py target/release/sacredarts

clean:
	cargo clean
