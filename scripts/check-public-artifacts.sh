#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="${PYTHON_BIN:-python3}"

cd "$ROOT_DIR"

echo "Checking public SDK artifacts"

if [[ ! -f skill.md ]]; then
    echo "error: missing skill.md" >&2
    exit 1
fi

if [[ ! -f openapi/openapi.json ]]; then
    echo "error: missing openapi/openapi.json" >&2
    exit 1
fi

"$PYTHON_BIN" - <<'PY'
import json
from pathlib import Path

spec_path = Path("openapi/openapi.json")
spec = json.loads(spec_path.read_text())

if spec.get("openapi") != "3.1.0":
    raise SystemExit("error: openapi/openapi.json must be OpenAPI 3.1.0")

description = ((spec.get("info") or {}).get("description") or "")
for required in (
    "https://zincha.com/docs",
    "https://zincha.com/skill.md",
):
    if required not in description:
        raise SystemExit(f"error: OpenAPI description missing {required!r}")

print("openapi/openapi.json parsed OK")
PY

private_markers=(
    "zincha-dev"
    "zincha-node"
    "endpoint_manifest"
    "ENDPOINT_ACCESS_CONTROL"
    "PUBLIC_TESTNET_RUNBOOKS"
    "src/api/endpoint_manifest"
    "src/release.rs"
    "release.rs"
)

for marker in "${private_markers[@]}"; do
    if grep -nF -- "$marker" skill.md; then
        echo "error: skill.md mentions private marker: $marker" >&2
        exit 1
    fi
done

required_skill_markers=(
    "https://github.com/zinchain/zincha-sdk"
    "https://github.com/zinchain/zincha-releases/releases"
    "https://zincha.com/openapi.json"
    "https://zincha.com/docs"
    "zincha --release vega info"
    "provider-authenticated"
)

for marker in "${required_skill_markers[@]}"; do
    if ! grep -qF -- "$marker" skill.md; then
        echo "error: skill.md missing required public marker: $marker" >&2
        exit 1
    fi
done

echo "Public SDK artifacts OK"
