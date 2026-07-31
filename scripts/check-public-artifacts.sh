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

capability_paths = {
    "/v1/capabilities": (
        "list_capabilities",
        "#/components/schemas/ApiResponse_CapabilityCatalogList",
    ),
    "/v1/capabilities/search": (
        "search_capabilities",
        "#/components/schemas/ApiResponse_CapabilitySuggestionList",
    ),
    "/v1/capabilities/categories": (
        "get_capability_categories",
        "#/components/schemas/ApiResponse_CapabilityCategoryList",
    ),
    "/v1/capabilities/{slug}": (
        "get_capability",
        "#/components/schemas/ApiResponse_CapabilityCatalogEntry",
    ),
}
for path, (operation_id, response_ref) in capability_paths.items():
    operation = (((spec.get("paths") or {}).get(path) or {}).get("get") or {})
    if not operation:
        raise SystemExit(f"error: OpenAPI missing GET {path}")
    if operation.get("operationId") != operation_id:
        raise SystemExit(f"error: GET {path} must use operationId {operation_id}")
    if operation.get("x-zincha-audience") != "public":
        raise SystemExit(f"error: GET {path} must be public audience")
    if operation.get("x-zincha-auth") != "bearer":
        raise SystemExit(f"error: GET {path} must use optional bearer/global auth")
    security = operation.get("security") or []
    if not any(item == {} for item in security):
        raise SystemExit(f"error: GET {path} must permit anonymous calls when deployment auth is disabled")
    if any((item or {}).get("signedAddress") == [] for item in security):
        raise SystemExit(f"error: GET {path} must not declare signedAddress security")
    schema = (
        (((operation.get("responses") or {}).get("200") or {}).get("content") or {})
        .get("application/json", {})
        .get("schema", {})
    )
    if schema.get("$ref") != response_ref:
        raise SystemExit(f"error: GET {path} must return {response_ref}")

capability_list = (((spec.get("paths") or {}).get("/v1/capabilities") or {}).get("get") or {})
capability_list_params = capability_list.get("parameters") or []
capability_param_refs = [param.get("$ref") for param in capability_list_params if param.get("$ref")]
if "#/components/parameters/PaginationLimit" not in capability_param_refs:
    raise SystemExit("error: GET /v1/capabilities must expose PaginationLimit")
if "#/components/parameters/PaginationCursor" not in capability_param_refs:
    raise SystemExit("error: GET /v1/capabilities must expose PaginationCursor")
if "#/components/parameters/PaginationOffset" in capability_param_refs:
    raise SystemExit("error: GET /v1/capabilities must not expose PaginationOffset")
capability_list_schema = spec["components"]["schemas"].get("CapabilityCatalogList")
if not capability_list_schema:
    raise SystemExit("error: OpenAPI missing CapabilityCatalogList schema")
capability_string_schema = spec["components"]["schemas"].get("CapabilityString")
if not capability_string_schema:
    raise SystemExit("error: OpenAPI missing CapabilityString schema")
if capability_string_schema.get("pattern") is not None:
    raise SystemExit("error: CapabilityString must stay open and must not inherit catalog slug pattern")
if capability_string_schema.get("maxLength") != 256:
    raise SystemExit("error: CapabilityString must document the protocol 256-byte capability limit")
capability_slug_schema = spec["components"]["schemas"].get("CapabilitySlug")
if not capability_slug_schema:
    raise SystemExit("error: OpenAPI missing CapabilitySlug schema")
if not capability_slug_schema.get("pattern"):
    raise SystemExit("error: CapabilitySlug must remain the strict catalog metadata schema")
capability_param = (spec["components"].get("parameters") or {}).get("CapabilityParam") or {}
if ((capability_param.get("schema") or {}).get("$ref")) != "#/components/schemas/CapabilityString":
    raise SystemExit("error: generic capability path parameter must use open CapabilityString")
capability_slug_param = (spec["components"].get("parameters") or {}).get("CapabilitySlugParam") or {}
if ((capability_slug_param.get("schema") or {}).get("$ref")) != "#/components/schemas/CapabilitySlug":
    raise SystemExit("error: catalog slug path parameter must use strict CapabilitySlug")
capability_pagination_ref = (
    (capability_list_schema.get("properties") or {}).get("pagination") or {}
).get("$ref")
if capability_pagination_ref != "#/components/schemas/CursorPagination":
    raise SystemExit("error: CapabilityCatalogList must use CursorPagination")

capability_entry_schema = spec["components"]["schemas"].get("CapabilityCatalogEntry")
if not capability_entry_schema:
    raise SystemExit("error: OpenAPI missing CapabilityCatalogEntry schema")
capability_entry_properties = capability_entry_schema.get("properties") or {}
for required in (
    "slug",
    "display_name",
    "description",
    "category",
    "status",
    "aliases",
    "keywords",
    "examples",
    "related",
    "source",
    "created_at_block",
    "updated_at_block",
    "usage",
):
    if required not in capability_entry_properties:
        raise SystemExit(f"error: CapabilityCatalogEntry missing {required}")

event_log_operation = (((spec.get("paths") or {}).get("/v1/events") or {}).get("get") or {})
if not event_log_operation:
    raise SystemExit("error: OpenAPI missing GET /v1/events")
event_log_params = {
    parameter.get("name"): parameter
    for parameter in event_log_operation.get("parameters") or []
    if parameter.get("name")
}
for required in (
    "type",
    "capability_proposer",
    "capability_category",
    "capability_status",
    "after_seq",
    "backfill",
    "limit",
):
    if required not in event_log_params:
        raise SystemExit(f"error: GET /v1/events missing {required} query parameter")
for stale in ("event_type", "since_ms", "until_ms", "offset"):
    if stale in event_log_params:
        raise SystemExit(f"error: GET /v1/events must not expose stale {stale} parameter")
status_enum = ((event_log_params.get("capability_status") or {}).get("schema") or {}).get("enum")
if status_enum != ["active", "pending", "rejected", "deprecated"]:
    raise SystemExit("error: GET /v1/events capability_status must document catalog status enum")

task_opportunity = (((spec.get("paths") or {}).get("/v1/tasks/{id}/opportunity") or {}).get("get") or {})
if not task_opportunity:
    raise SystemExit("error: OpenAPI missing GET /v1/tasks/{id}/opportunity")
if task_opportunity.get("operationId") != "get_task_opportunity":
    raise SystemExit("error: GET /v1/tasks/{id}/opportunity must use operationId get_task_opportunity")
if task_opportunity.get("x-zincha-audience") != "public":
    raise SystemExit("error: GET /v1/tasks/{id}/opportunity must be public audience")
if task_opportunity.get("x-zincha-auth") != "bearer":
    raise SystemExit("error: GET /v1/tasks/{id}/opportunity must use optional bearer/global auth")
if "elapsed deadline" not in (task_opportunity.get("description") or ""):
    raise SystemExit("error: GET /v1/tasks/{id}/opportunity must document deadline filtering")
opportunity_security = task_opportunity.get("security") or []
if not any(item == {} for item in opportunity_security):
    raise SystemExit("error: GET /v1/tasks/{id}/opportunity must permit anonymous calls when deployment auth is disabled")
if not any((item or {}).get("bearerAuth") == [] for item in opportunity_security):
    raise SystemExit("error: GET /v1/tasks/{id}/opportunity must document optional bearerAuth")
if any((item or {}).get("signedAddress") == [] for item in opportunity_security):
    raise SystemExit("error: GET /v1/tasks/{id}/opportunity must not declare signedAddress security")
opportunity_response_schema = (
    (((task_opportunity.get("responses") or {}).get("200") or {}).get("content") or {})
    .get("application/json", {})
    .get("schema", {})
)
if opportunity_response_schema.get("$ref") != "#/components/schemas/ApiResponse_TaskOpportunity":
    raise SystemExit("error: GET /v1/tasks/{id}/opportunity must return ApiResponse_TaskOpportunity")
opportunity_schema = spec["components"]["schemas"].get("TaskOpportunity")
if not opportunity_schema:
    raise SystemExit("error: OpenAPI missing TaskOpportunity schema")
opportunity_properties = opportunity_schema.get("properties") or {}
for required in (
    "task_id",
    "requester",
    "description",
    "description_len",
    "required_capabilities",
    "max_fee",
    "priority",
    "deadline",
    "submitted_at_block",
    "status",
    "matched_agent",
    "match_preferences",
    "requester_trust",
):
    if required not in opportunity_properties:
        raise SystemExit(f"error: TaskOpportunity missing {required}")
for private_field in (
    "parameters",
    "input_refs",
    "result_hash",
    "dispute_reason",
    "disputed_at",
    "arbitrator",
    "arbitrator_fee_bps",
    "arbitration_deadline_at",
    "arbitration_reassignments",
    "prior_arbitrators",
    "resolved_by",
    "resolution_agent_wins",
    "resolution_reason",
    "resolved_at",
    "tools_used",
    "verified_tools",
    "description_embedding",
    "neural_embedding",
    "submitted_at",
    "challenge_deadline",
    "challenge_window_ms",
    "agreed_fee",
    "subtask_ids",
    "parent_task",
    "dependencies",
    "rated",
    "requester_submission_neutralized",
    "storage_deposit",
):
    if private_field in opportunity_properties:
        raise SystemExit(f"error: TaskOpportunity must not expose {private_field}")
if (opportunity_properties.get("requester_trust") or {}).get("$ref") != "#/components/schemas/RequesterTrustSummary":
    raise SystemExit("error: TaskOpportunity requester_trust must reference RequesterTrustSummary")
trust_summary_schema = spec["components"]["schemas"].get("RequesterTrustSummary")
if not trust_summary_schema:
    raise SystemExit("error: OpenAPI missing RequesterTrustSummary schema")
trust_summary_properties = trust_summary_schema.get("properties") or {}
for required in (
    "trust_score",
    "fulfillment_rate",
    "cancellation_rate",
    "matched_agent_timeouts",
    "rating_fairness",
    "failed_reports_given",
    "reviewed_outcomes",
    "failed_report_rate",
    "dispute_rate",
    "economic_backing",
    "auto_match_bonded_amount",
    "tasks_submitted",
    "third_party_tasks_submitted",
    "same_entity_submission_units_neutralized",
    "ratings_given",
    "auto_match_policy",
):
    if required not in trust_summary_properties:
        raise SystemExit(f"error: RequesterTrustSummary missing {required}")
for full_reputation_field in (
    "address",
    "total_spent",
    "total_spent_zin",
    "total_escrowed",
    "total_escrowed_zin",
):
    if full_reputation_field in trust_summary_properties:
        raise SystemExit(
            f"error: RequesterTrustSummary must not document full reputation field {full_reputation_field}"
        )
if (trust_summary_properties.get("auto_match_policy") or {}).get("$ref") != "#/components/schemas/RequesterAutoMatchPolicy":
    raise SystemExit("error: RequesterTrustSummary auto_match_policy must reference RequesterAutoMatchPolicy")
policy_schema = spec["components"]["schemas"].get("RequesterAutoMatchPolicy")
if not policy_schema:
    raise SystemExit("error: OpenAPI missing RequesterAutoMatchPolicy schema")
policy_properties = policy_schema.get("properties") or {}
for required in (
    "eligible",
    "blocked_by_trust",
    "min_trust_score",
    "required_additional_backing",
    "max_dispute_rate",
):
    if required not in policy_properties:
        raise SystemExit(f"error: RequesterAutoMatchPolicy missing {required}")
pending_operation = (((spec.get("paths") or {}).get("/v1/tasks/pending") or {}).get("get") or {})
if "not past deadline" not in (pending_operation.get("description") or ""):
    raise SystemExit("error: GET /v1/tasks/pending must document deadline filtering")
pending_response_schema = (
    (((pending_operation.get("responses") or {}).get("200") or {}).get("content") or {})
    .get("application/json", {})
    .get("schema", {})
)
if pending_response_schema.get("$ref") != "#/components/schemas/ApiResponse_TaskOpportunityList":
    raise SystemExit("error: GET /v1/tasks/pending must return ApiResponse_TaskOpportunityList")
opportunity_list = spec["components"]["schemas"].get("TaskOpportunityList") or {}
item_ref = (((opportunity_list.get("properties") or {}).get("items") or {}).get("items") or {}).get("$ref")
if item_ref != "#/components/schemas/TaskOpportunity":
    raise SystemExit("error: TaskOpportunityList items must reference TaskOpportunity")

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

workflow_detail_paths = {
    "/v1/agreements/{id}": "ApiResponse_AgreementDetail",
    "/v1/tool-jobs/{id}": "ApiResponse_ToolJobDetail",
    "/v1/tool-usage-sessions/{id}": "ApiResponse_ToolUsageSessionDetail",
}
workflow_list_paths = {
    "/v1/agreements/party/{address}": "ApiResponse_AgreementList",
    "/v1/agreements/arbitrator/{address}": "ApiResponse_AgreementList",
    "/v1/tool-jobs/requester/{address}": "ApiResponse_ToolJobList",
    "/v1/tool-jobs/provider/{address}": "ApiResponse_ToolJobList",
    "/v1/tool-usage-sessions/requester/{address}": "ApiResponse_ToolUsageSessionList",
    "/v1/tool-usage-sessions/provider/{address}": "ApiResponse_ToolUsageSessionList",
}

for path, response_name in workflow_detail_paths.items():
    operation = (((spec.get("paths") or {}).get(path) or {}).get("get") or {})
    if not operation:
        raise SystemExit(f"error: OpenAPI missing GET {path}")
    if operation.get("x-zincha-audience") != "participant":
        raise SystemExit(f"error: {path} must be participant audience")
    if operation.get("x-zincha-auth") != "signed_address":
        raise SystemExit(f"error: {path} must require signed_address auth")
    if not any((item or {}).get("signedAddress") == [] for item in operation.get("security") or []):
        raise SystemExit(f"error: {path} must declare signedAddress security")
    response_schema = (
        (((operation.get("responses") or {}).get("200") or {}).get("content") or {})
        .get("application/json", {})
        .get("schema", {})
    )
    if response_schema.get("$ref") != f"#/components/schemas/{response_name}":
        raise SystemExit(f"error: {path} must return {response_name}")

for schema_name in [
    "AgreementTerminalSummary",
    "ToolJobTerminalSummary",
    "ToolUsageSessionTerminalSummary",
]:
    schema = (spec.get("components") or {}).get("schemas", {}).get(schema_name) or {}
    if not schema:
        raise SystemExit(f"error: OpenAPI missing {schema_name}")
    required = set(schema.get("required") or [])
    for field in ["terminal_summary", "final_action", "final_update_block", "final_update_timestamp_ms"]:
        if field not in required:
            raise SystemExit(f"error: {schema_name} missing required {field}")

agreement_summary = (spec.get("components") or {}).get("schemas", {}).get("AgreementTerminalSummary") or {}
agreement_required = set(agreement_summary.get("required") or [])
for field in ["created_at_block", "service_provider", "prior_arbitrators"]:
    if field not in agreement_required or field not in (agreement_summary.get("properties") or {}):
        raise SystemExit(f"error: AgreementTerminalSummary missing {field}")

for schema_name in ["ToolJobTerminalSummary", "ToolUsageSessionTerminalSummary"]:
    schema = (spec.get("components") or {}).get("schemas", {}).get(schema_name) or {}
    required = set(schema.get("required") or [])
    for field in ["opened_at_block", "prior_arbitrators"]:
        if field not in required or field not in (schema.get("properties") or {}):
            raise SystemExit(f"error: {schema_name} missing {field}")

for path, response_name in workflow_list_paths.items():
    operation = (((spec.get("paths") or {}).get(path) or {}).get("get") or {})
    if not operation:
        raise SystemExit(f"error: OpenAPI missing GET {path}")
    if operation.get("x-zincha-audience") != "participant":
        raise SystemExit(f"error: {path} must be participant audience")
    if operation.get("x-zincha-auth") != "signed_address":
        raise SystemExit(f"error: {path} must require signed_address auth")
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
    if response_schema.get("$ref") != f"#/components/schemas/{response_name}":
        raise SystemExit(f"error: {path} must return {response_name}")
    list_schema_name = response_name.removeprefix("ApiResponse_")
    list_schema = spec["components"]["schemas"].get(list_schema_name) or {}
    pagination_ref = ((list_schema.get("properties") or {}).get("pagination") or {}).get("$ref")
    if pagination_ref != "#/components/schemas/CursorPagination":
        raise SystemExit(f"error: {path} must use CursorPagination")

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

contract_runtime_status = spec["components"]["schemas"].get("ContractRuntimeProfileStatus") or {}
contract_runtime_cache = (contract_runtime_status.get("properties") or {}).get("cache") or {}
contract_runtime_cache_properties = contract_runtime_cache.get("properties") or {}
contract_runtime_cache_required = set(contract_runtime_cache.get("required") or [])
for field in (
    "compiled_module_cache_entries",
    "compiled_module_cache_bytes",
    "compiled_module_cache_hits",
    "compiled_module_cache_misses",
    "compiled_module_cache_evictions",
    "compiled_module_cache_oversized_bypasses",
    "compiled_module_compilations",
    "compiled_module_cache_max_entries",
    "compiled_module_cache_max_bytes",
    "compiled_module_compilations_inflight",
    "compiled_module_max_concurrent_compilations",
):
    if field not in contract_runtime_cache_properties or field not in contract_runtime_cache_required:
        raise SystemExit(f"error: ContractRuntimeProfileStatus.cache missing required {field}")

direct_finality_status = spec["components"]["schemas"].get("DirectFinalityValidationStatus") or {}
direct_finality_properties = direct_finality_status.get("properties") or {}
direct_finality_required = set(direct_finality_status.get("required") or [])
for field in (
    "current_parent_scratch_pool_peak_bytes",
    "current_parent_scratch_pool_max_entries",
    "current_parent_scratch_pool_max_bytes",
    "current_parent_scratch_pool_hits",
    "current_parent_scratch_pool_misses",
    "current_parent_scratch_pool_discards",
    "state_commitment_lane_cache_entries",
    "state_commitment_lane_cache_bytes",
    "state_commitment_lane_cache_cap_bytes",
    "state_commitment_lane_cache_hits",
    "state_commitment_lane_cache_misses",
    "state_commitment_lane_cache_evictions",
    "state_commitment_durable_loader_backed",
):
    if field not in direct_finality_properties or field not in direct_finality_required:
        raise SystemExit(f"error: DirectFinalityValidationStatus missing required {field}")

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
    "GET /v1/tasks/pending\` and \`GET /v1/tasks/:id/opportunity"
    "open-task marketplace discovery"
    "unmatched tasks that are not past deadline"
    "GET /v1/tasks/:id"
    "requires signed address authentication"
    "Signed participant workflow reads are available for agreements, tool jobs"
    "GET /v1/tool-jobs/:id"
    "GET /v1/capabilities/search"
    "curated capability discovery metadata"
    "custom capability strings that are not present"
    "pending entries are immediately visible"
    "resolve to canonical catalog slugs"
    "terminally removed"
    "created/opened block, final update block, final update timestamp"
    "/v1/tool-jobs/provider/:address"
    "/v1/tool-usage-sessions/requester/:address"
    "/v1/agreements/arbitrator/:address"
    "opaque \`cursor\` pagination only, never \`offset\`"
    "SDK-facing API surface"
    "open-task opportunity discovery and signed task detail by ID"
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
