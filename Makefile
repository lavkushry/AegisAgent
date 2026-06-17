.PHONY: setup test fmt lint check clean

# One-shot dev environment setup: installs pre-commit and registers its git
# hook, plus the Python SDK in editable/dev mode. Mirrors CONTRIBUTING.md.
setup:
	python3 -m pip install -e "sdk-python[dev]"
	python3 -m pip install pre-commit
	pre-commit install

# Runs every test suite CI runs, in one command.
test:
	cargo test --manifest-path gateway/Cargo.toml
	python3 -m unittest discover -s sdk-python/tests
	cd sdk-go && go test ./...
	cd sdk-typescript && npm ci && npx tsc --noEmit && npm test

# Auto-formats Rust and Python sources in place.
fmt:
	cargo fmt --manifest-path gateway/Cargo.toml
	python3 -m black sdk-python/ examples/

# Read-only: fails non-zero on any formatting or lint violation (what CI runs).
lint:
	cargo fmt --manifest-path gateway/Cargo.toml -- --check
	cargo clippy --manifest-path gateway/Cargo.toml -- -D warnings
	python3 -m black --check sdk-python/ examples/

# Everything CONTRIBUTING.md asks you to run before opening a PR.
check: lint test

clean:
	cargo clean --manifest-path gateway/Cargo.toml
	rm -rf sdk-typescript/node_modules sdk-typescript/dist
	find . -name "__pycache__" -not -path "./gateway/target/*" -exec rm -rf {} +
