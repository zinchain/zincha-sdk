#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ZINCHA_BIN="${ZINCHA_BIN:-$ROOT_DIR/target/debug/zincha}"
ZINCHA_LIVE_RELEASE="${ZINCHA_LIVE_RELEASE:-vega}"
ZINCHA_LIVE_API_URL="${ZINCHA_LIVE_API_URL:-}"
ZINCHA_LIVE_TIMEOUT_SECS="${ZINCHA_LIVE_TIMEOUT_SECS:-45}"
ZINCHA_LIVE_MUTATING="${ZINCHA_LIVE_MUTATING:-0}"

if [[ ! -x "$ZINCHA_BIN" ]]; then
    echo "error: zincha binary not found or not executable at $ZINCHA_BIN" >&2
    echo "build it first with: cargo build -p zincha-cli" >&2
    exit 1
fi

target_args=()
if [[ -n "$ZINCHA_LIVE_API_URL" ]]; then
    target_args=(--api-url "$ZINCHA_LIVE_API_URL")
else
    target_args=(--release "$ZINCHA_LIVE_RELEASE")
fi

run_with_timeout() {
    if command -v timeout >/dev/null 2>&1; then
        timeout "${ZINCHA_LIVE_TIMEOUT_SECS}s" "$@"
    else
        "$@"
    fi
}

run_json_check() {
    local expected_command="$1"
    shift
    local output
    local status

    set +e
    output="$(run_with_timeout "$@" 2>&1)"
    status=$?
    set -e

    if [[ "$status" -ne 0 ]]; then
        echo "error: command failed with status $status: $*" >&2
        echo "$output" >&2
        exit "$status"
    fi

    JSON_PAYLOAD="$output" EXPECTED_COMMAND="$expected_command" python3 - <<'PY'
import json
import os
import re
import sys

payload = json.loads(os.environ["JSON_PAYLOAD"])
expected = os.environ["EXPECTED_COMMAND"]
if payload.get("ok") is not True:
    raise SystemExit(f"expected ok=true, got {payload!r}")
if payload.get("command") != expected:
    raise SystemExit(f"expected command={expected!r}, got {payload.get('command')!r}")
data = payload.get("data")
if not isinstance(data, dict):
    raise SystemExit(f"expected object data, got {data!r}")
if data.get("chain_id") != "zincha-vega-1":
    raise SystemExit(f"expected zincha-vega-1, got {data.get('chain_id')!r}")
if not isinstance(data.get("block_height"), int):
    raise SystemExit(f"expected numeric block_height, got {data.get('block_height')!r}")
if not re.fullmatch(r"[0-9a-f]{64}", str(data.get("latest_block_hash", ""))):
    raise SystemExit(f"expected 64-hex latest_block_hash, got {data.get('latest_block_hash')!r}")
for key in (
    "transaction_ttl_blocks",
    "transaction_reference_block_height",
    "transaction_reference_block_hash",
):
    if key not in data:
        raise SystemExit(f"missing {key}")
print(f"{expected}: Vega chain info OK at height {data['block_height']}")
PY
}

echo "Running read-only Vega CLI smoke checks"
run_json_check info "$ZINCHA_BIN" --json "${target_args[@]}" info
run_json_check query "$ZINCHA_BIN" --json "${target_args[@]}" query /v1/chain/info

if [[ "$ZINCHA_LIVE_MUTATING" == "1" ]]; then
    echo "error: mutating live Vega smoke is intentionally not implemented yet" >&2
    echo "read-only live checks passed; add faucet/submit coverage when the faucet flow is stable" >&2
    exit 1
fi

echo "Live Vega smoke OK"
