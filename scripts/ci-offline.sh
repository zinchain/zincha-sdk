#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="${PYTHON_BIN:-python3}"

cd "$ROOT_DIR"

echo "==> cargo fmt --all --check"
cargo fmt --all --check

echo "==> cargo test --workspace --all-targets"
cargo test --workspace --all-targets

echo "==> cargo build -p zincha-cli"
cargo build -p zincha-cli

echo "==> Python SDK unittest"
(
    cd sdk/python
    PYTHONPATH=src "$PYTHON_BIN" -m unittest discover -s tests
)

echo "==> TypeScript SDK tests"
(
    cd sdk/typescript
    if ! node --experimental-strip-types -e "" >/dev/null 2>&1; then
        echo "Node.js 22.6+ is required for TypeScript SDK tests." >&2
        echo "The tests use node --experimental-strip-types to execute .ts files directly." >&2
        exit 1
    fi
    if command -v npm >/dev/null 2>&1; then
        npm test
    else
        node --experimental-strip-types --test test/*.test.ts
    fi
)

echo "==> Public artifact checks"
scripts/check-public-artifacts.sh

echo "==> Public boundary scan"
scripts/check-public-boundary.sh

echo "Offline SDK CI OK"
