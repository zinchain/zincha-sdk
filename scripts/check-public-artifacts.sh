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
    "SDK-facing endpoints",
    "participant-authenticated reads",
):
    if required not in description:
        raise SystemExit(f"error: OpenAPI description missing {required!r}")

task_operation = (((spec.get("paths") or {}).get("/v1/tasks/{id}") or {}).get("get") or {})
if not task_operation:
    raise SystemExit("error: OpenAPI missing GET /v1/tasks/{id}")
if task_operation.get("operationId") != "get_task":
    raise SystemExit("error: GET /v1/tasks/{id} must use operationId get_task")
if task_operation.get("x-zincha-audience") != "participant":
    raise SystemExit("error: GET /v1/tasks/{id} must be participant audience")
if task_operation.get("x-zincha-auth") != "signed_address":
    raise SystemExit("error: GET /v1/tasks/{id} must require signed_address auth")
if not any((item or {}).get("signedAddress") == [] for item in task_operation.get("security") or []):
    raise SystemExit("error: GET /v1/tasks/{id} must declare signedAddress security")
task_parameter_refs = [parameter.get("$ref") for parameter in task_operation.get("parameters") or []]
if "#/components/parameters/IdParam" not in task_parameter_refs:
    raise SystemExit("error: GET /v1/tasks/{id} missing IdParam")
task_response_schema = (
    (((task_operation.get("responses") or {}).get("200") or {}).get("content") or {})
    .get("application/json", {})
    .get("schema", {})
)
if task_response_schema.get("$ref") != "#/components/schemas/ApiResponse_Task":
    raise SystemExit("error: GET /v1/tasks/{id} must return ApiResponse_Task")

history_paths = {
    "/v1/accounts/{address}/transactions": "TransactionList",
    "/v1/contracts/{address}/transactions": "TransactionList",
    "/v1/tokens/{id}/transactions": "TokenTransactionList",
}

history_item_schemas = {
    "TransactionList": "TransactionListItem",
    "TokenTransactionList": "TokenTransaction",
}

for path, data_schema_name in history_paths.items():
    operation = (((spec.get("paths") or {}).get(path) or {}).get("get") or {})
    if not operation:
        raise SystemExit(f"error: OpenAPI missing GET {path}")
    parameter_refs = [parameter.get("$ref") for parameter in operation.get("parameters") or []]
    if "#/components/parameters/PaginationLimit" not in parameter_refs:
        raise SystemExit(f"error: {path} missing PaginationLimit")
    if "#/components/parameters/PaginationCursor" not in parameter_refs:
        raise SystemExit(f"error: {path} missing PaginationCursor")
    if "#/components/parameters/PaginationOffset" in parameter_refs:
        raise SystemExit(f"error: {path} must not expose PaginationOffset")

    response_schema = (
        (((operation.get("responses") or {}).get("200") or {}).get("content") or {})
        .get("application/json", {})
        .get("schema", {})
    )
    envelope_ref = response_schema.get("$ref")
    if not envelope_ref:
        raise SystemExit(f"error: {path} 200 response must reference a response envelope")
    envelope = spec["components"]["schemas"][envelope_ref.rsplit("/", 1)[-1]]
    data_refs = [
        item.get("$ref")
        for item in (
            ((envelope.get("properties") or {}).get("data") or {}).get("oneOf") or []
        )
        if item.get("$ref")
    ]
    expected_data_ref = f"#/components/schemas/{data_schema_name}"
    if expected_data_ref not in data_refs:
        raise SystemExit(f"error: {path} response data must reference {data_schema_name}")
    data_schema = spec["components"]["schemas"][data_schema_name]
    pagination_ref = ((data_schema.get("properties") or {}).get("pagination") or {}).get("$ref")
    if pagination_ref != "#/components/schemas/CursorPagination":
        raise SystemExit(f"error: {path} must use CursorPagination")
    item_schema_ref = (
        (((data_schema.get("properties") or {}).get("items") or {}).get("items") or {}).get("$ref")
    )
    expected_item_schema = history_item_schemas[data_schema_name]
    if item_schema_ref != f"#/components/schemas/{expected_item_schema}":
        raise SystemExit(f"error: {path} items must reference {expected_item_schema}")
    item_schema = spec["components"]["schemas"][expected_item_schema]
    item_properties = item_schema.get("properties") or {}
    if "block_timestamp_ms" not in item_properties:
        raise SystemExit(f"error: {expected_item_schema} missing block_timestamp_ms")
    if "timestamp_ms" in item_properties:
        raise SystemExit(f"error: {expected_item_schema} must not expose timestamp_ms")

transaction_status = spec["components"]["schemas"]["TransactionStatus"]
transaction_status_properties = transaction_status.get("properties") or {}
if "block_timestamp_ms" not in transaction_status_properties:
    raise SystemExit("error: TransactionStatus missing block_timestamp_ms")
if "timestamp_ms" in transaction_status_properties:
    raise SystemExit("error: TransactionStatus must not expose timestamp_ms")

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
    "faucet zn1..."
    "query balance"
    "query nonce"
    "\`--network\` is an alias"
    "contract/address/token transaction history) only to"
    "covers every Public-audience"
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
    "zincha --release vega faucet --address zn1..."
    "zincha --release vega query account zn1..."
    "zincha --release vega query account-nonce zn1..."
    "GET /v1/tasks/:id"
    "requires signed address authentication"
    "SDK-facing API surface"
    "index-backed"
    "pagination.next_cursor"
    "agents must not retry with \`offset\`"
    "provider-authenticated"
)

for marker in "${required_skill_markers[@]}"; do
    if ! grep -qF -- "$marker" skill.md; then
        echo "error: skill.md missing required public marker: $marker" >&2
        exit 1
    fi
done

echo "Public SDK artifacts OK"
