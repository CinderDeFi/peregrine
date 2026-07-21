# Convenience targets. Everything here is a plain cargo/npm command — nothing
# in the build depends on `make`, it just saves typing.
.PHONY: help build test lint fmt fmt-check ci ci-all sim bench node devnet demo clean js-test bls-test contracts-test fixture install

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

build: ## Build everything
	cargo build --workspace --all-targets

test: ## Run the Rust test suite
	cargo test --workspace

lint: ## Clippy, warnings denied (same as CI)
	cargo clippy --workspace --all-targets -- -D warnings

fmt: ## Format the workspace
	cargo fmt --all

fmt-check: ## Check formatting without writing (same as CI)
	cargo fmt --all -- --check

js-test: ## Run the TypeScript light-client tests
	cd sdk/js && npm install --no-audit --no-fund && npm test

fixture: ## Regenerate the cross-language proof fixture from Rust
	cargo run -p peregrine-node --example gen_js_fixture

ci: fmt-check lint test js-test ## Everything CI runs

demo: ## Run the full end-to-end tour (start here)
	cargo run --release -p peregrine-cli -- -q demo

devnet: ## Start a local devnet with a client RPC endpoint
	cargo run --release -p peregrine-cli -- devnet up

bls-test: ## Interop tests incl. real mainnet BLS + rotation
	cargo test -p peregrine-interop --features bls

contracts-test: ## EVM verifier tests (needs foundry)
	cd contracts && forge test

ci-all: ci bls-test contracts-test ## Everything, including feature-gated suites

sim: ## Run the local multi-validator demonstration
	cargo run --release -p peregrine-cli -- sim

bench: ## Run the throughput/latency harness
	cargo run --release -p peregrine-cli -- bench

node: ## Run a local node with a client RPC endpoint
	cargo run --release -p peregrine-cli -- node run

install: ## Install the `peregrine` binary into ~/.cargo/bin
	cargo install --path crates/peregrine-cli

clean: ## Remove build artifacts
	cargo clean
