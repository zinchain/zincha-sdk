#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

manifest_private_pattern='(^|[^[:alnum:]_-])(rocksdb|libp2p|wasmtime|zincha-chain|zincha-node|zincha-consensus|zincha-storage|zincha-mempool|zincha-p2p|zincha-execution|zincha-state|zincha-operator)([^[:alnum:]_-]|$)'
source_private_pattern='(zincha_chain::|zincha_node::|zincha_consensus::|zincha_storage::|zincha_mempool::|zincha_p2p::|zincha_execution::|zincha_state::|zincha_operator::)'

echo "Checking public SDK dependency boundary"

if git grep -n -E "$manifest_private_pattern" -- \
    Cargo.toml \
    'crates/*/Cargo.toml' \
    'sdk/*/package.json' \
    'sdk/*/pyproject.toml'
then
    echo "error: private runtime dependency found in public SDK manifest" >&2
    exit 1
fi

if git grep -n -E "$source_private_pattern" -- \
    'crates/**/*.rs' \
    'sdk/**/*.py' \
    'sdk/**/*.ts'
then
    echo "error: private internal crate reference found in public SDK source" >&2
    exit 1
fi

echo "Public SDK dependency boundary OK"
