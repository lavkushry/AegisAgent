PYTHON ?= python3
VENV ?= .venv
VENV_PYTHON := $(VENV)/bin/python
VENV_PRE_COMMIT := $(VENV)/bin/pre-commit
PYTHON_RUNTIME_DEPS := $(VENV)/.aegis-python-runtime-deps
PYTHON_DEPS := $(VENV)/.aegis-python-deps

.PHONY: setup doctor demo test rust-test python-test go-test ts-test fmt lint check clean docs-validate docs-serve docs-build

$(VENV_PYTHON):
	$(PYTHON) -m venv $(VENV)

$(PYTHON_RUNTIME_DEPS): $(VENV_PYTHON) sdk-python/pyproject.toml
	$(VENV_PYTHON) -m pip install -e "sdk-python"
	touch $(PYTHON_RUNTIME_DEPS)

$(PYTHON_DEPS): $(PYTHON_RUNTIME_DEPS)
	$(VENV_PYTHON) -m pip install -e "sdk-python[dev]"
	touch $(PYTHON_DEPS)

# Docs system (MkDocs Material; see docs/START_HERE.md and scripts/validate-docs.mjs)
docs-validate:
	node scripts/validate-docs.mjs

docs-serve:
	pip install -r requirements-docs.txt && mkdocs serve

docs-build:
	node scripts/validate-docs.mjs && mkdocs build

# One-shot dev environment setup: installs pre-commit and registers its git
# hook, plus the Python SDK in editable/dev mode. Mirrors CONTRIBUTING.md.
setup: $(PYTHON_DEPS)
	$(VENV_PYTHON) -m pip install pre-commit
	$(VENV_PRE_COMMIT) install

doctor:
	bash scripts/doctor.sh

demo: doctor $(PYTHON_RUNTIME_DEPS)
	PYTHON_BIN=$(VENV_PYTHON) bash scripts/run-killer-demo.sh

# Runs the core local Rust, Python, Go, and TypeScript suites.
rust-test:
	cargo test --workspace -- --test-threads=1

python-test: $(PYTHON_DEPS)
	$(VENV_PYTHON) -m unittest discover -s sdk-python/tests

go-test:
	cd sdk-go && go test ./...

ts-test:
	cd sdk-typescript && npm ci && npm run build && npm test

test: rust-test python-test go-test ts-test

# Auto-formats Rust and Python sources in place.
fmt: $(PYTHON_DEPS)
	cargo fmt --all
	$(VENV_PYTHON) -m black sdk-python/ examples/

# Read-only: fails non-zero on any formatting or lint violation (what CI runs).
lint: $(PYTHON_DEPS)
	cargo fmt --all -- --check
	cargo clippy --workspace --all-targets -- -D warnings
	$(VENV_PYTHON) -m black --check sdk-python/ examples/

# Everything CONTRIBUTING.md asks you to run before opening a PR.
check: lint test

clean:
	cargo clean
	rm -rf sdk-typescript/node_modules sdk-typescript/dist
	rm -rf $(VENV)
	find . -name "__pycache__" -not -path "./target/*" -exec rm -rf {} +
