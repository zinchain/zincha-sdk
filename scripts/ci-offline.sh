#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="${PYTHON_BIN:-python3}"
export RUST_TEST_THREADS=1

cd "$ROOT_DIR"

echo "==> cargo fmt --all --check"
cargo fmt --all --check

echo "==> cargo test --locked --workspace --all-targets"
cargo test --locked --workspace --all-targets

echo "==> cargo build --locked -p zincha-cli"
cargo build --locked -p zincha-cli

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
    if command -v pnpm >/dev/null 2>&1; then
        if [ ! -d node_modules ]; then
            pnpm install --frozen-lockfile
        fi
        pnpm exec node --experimental-strip-types --test --test-concurrency=1 test/*.test.ts
        pnpm typecheck
        pnpm build
    elif command -v npm >/dev/null 2>&1; then
        if [ ! -d node_modules ]; then
            npm install --no-audit --no-fund
        fi
        node --experimental-strip-types --test --test-concurrency=1 test/*.test.ts
        npm run typecheck
        npm run build
    else
        echo "pnpm or npm is required for TypeScript SDK tests." >&2
        exit 1
    fi
)

echo "==> Public artifact checks"
scripts/check-public-artifacts.sh

echo "==> Public boundary scan"
scripts/check-public-boundary.sh

echo "Offline SDK CI OK"
