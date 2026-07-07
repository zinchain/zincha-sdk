"""High-level transaction builders.

Each builder constructs the bincode data payload for one transaction type
and returns an unsigned :class:`~zincha.transaction.Transaction` that the
caller (or a :class:`~zincha.client.ZinchaClient` method) can sign and
submit.

The wire format here MUST match the Rust primitives byte-for-byte. Each
builder is covered by a golden vector test (see
``tests/test_sdk.py``) that pins it to a fixture produced by the Rust SDK.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import List, Mapping, Optional, Sequence, Tuple, Union

from .bincode import BigNumberish, BincodeWriter, as_u64
from .crypto import hex_to_bytes, normalize_address, raw_address_hex
from .transaction import Transaction, create_transaction

ZERO_HASH = "0000000000000000000000000000000000000000000000000000000000000000"
CAPABILITY_PARENT_UNSET = object()

Hex = str


# ─── Shared types ───────────────────────────────────────────────────


@dataclass(frozen=True)
class MatchPreferences:
    """Matching-engine preferences for a TaskSubmit.

    Mirrors the Rust ``MatchPreferences`` struct. Defaults match the
    on-chain ``MatchPreferences::default()``.
    """

    w_semantic: int = 30
    w_reputation: int = 30
    w_price: int = 20
    w_freshness: int = 10
    w_stake: int = 10
    min_reputation: float = 0.0
    max_price: int = 0
    discovery_threshold: int = 10
    discovery_boost: int = 15


# ─── Capability + Hash256 helpers ───────────────────────────────────


def _write_capability(w: BincodeWriter, capability: str) -> None:
    """bincode-encodes a ``Capability`` newtype struct (just the inner string)."""
    w.write_string(capability)


def _write_hash256(w: BincodeWriter, hash_hex: Hex) -> None:
    """bincode-encodes a ``Hash256`` through the Rust Hash256 serde string form."""
    w.write_string(hex_to_bytes(hash_hex, 32).hex())


def _write_address(w: BincodeWriter, address: str) -> None:
    """bincode-encodes an ``Address`` through the Rust raw-hex string serde form."""
    w.write_string(raw_address_hex(address))


def _write_public_key(w: BincodeWriter, public_key: Hex) -> None:
    """bincode-encodes a ``PublicKey`` through the Rust hex string serde form."""
    w.write_string(hex_to_bytes(public_key, 32).hex())


def _write_bool(w: BincodeWriter, value: bool) -> None:
    w.write_u8(1 if value else 0)


def _write_optional_bool(w: BincodeWriter, value: Optional[bool]) -> None:
    w.write_option(value, _write_bool)


def _write_embedding(w: BincodeWriter, values: Sequence[float]) -> None:
    w.write_vec(values, lambda writer, value: writer.write_f32(value))


def _write_optional_embedding(w: BincodeWriter, values: Optional[Sequence[float]]) -> None:
    w.write_option(list(values) if values is not None else None, _write_embedding)


def _write_capabilities(w: BincodeWriter, values: Sequence[str]) -> None:
    w.write_vec(values, _write_capability)


def _write_optional_capabilities(w: BincodeWriter, values: Optional[Sequence[str]]) -> None:
    w.write_option(list(values) if values is not None else None, _write_capabilities)


def _validate_capability_slug(slug: str) -> bool:
    import re

    return len(slug) <= 128 and bool(
        re.fullmatch(r"^[a-z][a-z0-9-]*(\.[a-z][a-z0-9-]*){1,7}$", slug)
    )


def _normalize_capability_slug(slug: str) -> str:
    normalized = slug.strip().lower()
    if not _validate_capability_slug(normalized):
        raise ValueError("invalid capability slug")
    return normalized


def _normalize_capability_slugs(values: Optional[Sequence[str]]) -> Optional[List[str]]:
    if values is None:
        return None
    return [_normalize_capability_slug(value) for value in values]


def _write_string_vec(w: BincodeWriter, values: Sequence[str]) -> None:
    w.write_vec(values, lambda writer, value: writer.write_string(value))


def _write_optional_string_vec(w: BincodeWriter, values: Optional[Sequence[str]]) -> None:
    w.write_option(list(values) if values is not None else None, _write_string_vec)


def _write_optional_optional_string(w: BincodeWriter, value: object) -> None:
    if value is CAPABILITY_PARENT_UNSET:
        w.write_u8(0)
        return
    w.write_u8(1)
    w.write_option(value, lambda writer, inner: writer.write_string(inner))  # type: ignore[arg-type]


def _write_fee_schedule(w: BincodeWriter, values: Sequence[Tuple[str, BigNumberish]]) -> None:
    w.write_vec(
        values,
        lambda writer, entry: (
            writer.write_string(entry[0]),
            writer.write_u64(entry[1]),
        ),
    )


def _write_optional_fee_schedule(
    w: BincodeWriter,
    values: Optional[Sequence[Tuple[str, BigNumberish]]],
) -> None:
    w.write_option(list(values) if values is not None else None, _write_fee_schedule)


_SETTLEMENT_MODE_CODES = {
    "prepaid_access": 0,
    "result_escrowed": 1,
    "metered_usage": 2,
    "milestone_escrowed": 3,
}


def _write_settlement_mode(w: BincodeWriter, value: str) -> None:
    try:
        code = _SETTLEMENT_MODE_CODES[value]
    except KeyError as error:
        raise ValueError("unsupported tool settlement mode: %s" % value) from error
    w.write_u32(code)


def _write_optional_settlement_mode(w: BincodeWriter, value: Optional[str]) -> None:
    w.write_option(value, _write_settlement_mode)


_ARBITRATION_POLICY_CODES = {
    "protocol": 0,
}


def _write_arbitration_policy(w: BincodeWriter, value: str) -> None:
    try:
        code = _ARBITRATION_POLICY_CODES[value]
    except KeyError as error:
        raise ValueError("unsupported tool arbitration policy: %s" % value) from error
    w.write_u32(code)


def _write_optional_arbitration_policy(w: BincodeWriter, value: Optional[str]) -> None:
    w.write_option(value, _write_arbitration_policy)


_SUBSCRIPTION_OVERAGE_POLICY_CODES = {
    "deny": 0,
    "pay_as_you_go": 1,
}


def _write_subscription_overage_policy(w: BincodeWriter, value: str) -> None:
    try:
        code = _SUBSCRIPTION_OVERAGE_POLICY_CODES[value]
    except KeyError as error:
        raise ValueError("unsupported subscription overage policy: %s" % value) from error
    w.write_u32(code)


def _write_optional_subscription_overage_policy(w: BincodeWriter, value: Optional[str]) -> None:
    w.write_option(value, _write_subscription_overage_policy)


def _write_match_preferences(w: BincodeWriter, prefs: MatchPreferences) -> None:
    w.write_u8(prefs.w_semantic)
    w.write_u8(prefs.w_reputation)
    w.write_u8(prefs.w_price)
    w.write_u8(prefs.w_freshness)
    w.write_u8(prefs.w_stake)
    w.write_f64(prefs.min_reputation)
    w.write_u64(prefs.max_price)
    if not isinstance(prefs.discovery_threshold, int) or prefs.discovery_threshold < 0 or prefs.discovery_threshold > 0xFFFF_FFFF:
        raise ValueError("discovery_threshold must fit in unsigned 32 bits")
    w.write_u32(prefs.discovery_threshold)
    w.write_u8(prefs.discovery_boost)


# ─── agent_register ─────────────────────────────────────────────────


def encode_agent_register_data(
    *,
    name: str,
    description: str,
    capabilities: Sequence[str],
    model_hash: Hex = ZERO_HASH,
    neural_embedding: Optional[Sequence[float]] = None,
    min_fee_micro_zin: BigNumberish = 0,
    fee_schedule: Optional[Sequence[Tuple[str, BigNumberish]]] = None,
    metadata: bytes = b"",
) -> bytes:
    """bincode-encode the ``AgentRegisterData`` payload."""
    w = BincodeWriter()
    w.write_string(name)
    w.write_string(description)
    w.write_option(
        list(neural_embedding) if neural_embedding is not None else None,
        lambda writer, values: writer.write_vec(
            values,
            lambda inner_writer, value: inner_writer.write_f32(value),
        ),
    )
    _write_hash256(w, model_hash)
    w.write_vec(capabilities, _write_capability)
    w.write_bytes(metadata)
    w.write_u64(min_fee_micro_zin)
    _write_fee_schedule(w, list(fee_schedule) if fee_schedule is not None else [])
    return w.finish()


# ─── agent lifecycle ────────────────────────────────────────────────


def encode_agent_update_data(
    *,
    name: Optional[str] = None,
    description: Optional[str] = None,
    neural_embedding: Optional[Sequence[float]] = None,
    model_hash: Optional[Hex] = None,
    capabilities: Optional[Sequence[str]] = None,
    metadata: Optional[bytes] = None,
    active: Optional[bool] = None,
    min_fee_micro_zin: Optional[BigNumberish] = None,
    fee_schedule: Optional[Sequence[Tuple[str, BigNumberish]]] = None,
) -> bytes:
    """bincode-encode the ``AgentUpdateData`` payload."""
    w = BincodeWriter()
    w.write_option(name, lambda writer, value: writer.write_string(value))
    w.write_option(description, lambda writer, value: writer.write_string(value))
    _write_optional_embedding(w, neural_embedding)
    w.write_option(model_hash, _write_hash256)
    _write_optional_capabilities(w, capabilities)
    w.write_option(metadata, lambda writer, value: writer.write_bytes(value))
    _write_optional_bool(w, active)
    w.write_option(min_fee_micro_zin, lambda writer, value: writer.write_u64(value))
    _write_optional_fee_schedule(w, fee_schedule)
    return w.finish()


def encode_agent_deregister_data() -> bytes:
    """Encode the ``AgentDeregister`` payload: empty bytes, matching the Rust handler."""
    return b""


# ─── task_submit ────────────────────────────────────────────────────


def encode_task_submit_data(
    *,
    description: str,
    required_capabilities: Sequence[str],
    max_fee_micro_zin: BigNumberish,
    priority: int = 0,
    deadline_ms: BigNumberish = 0,
    parameters: bytes = b"",
    match_preferences: Optional[MatchPreferences] = None,
    neural_embedding: Optional[Sequence[float]] = None,
) -> bytes:
    """bincode-encode the ``TaskSubmitData`` payload."""
    w = BincodeWriter()
    w.write_string(description)
    w.write_option(
        list(neural_embedding) if neural_embedding is not None else None,
        lambda writer, values: writer.write_vec(
            values,
            lambda inner_writer, value: inner_writer.write_f32(value),
        ),
    )
    w.write_vec(required_capabilities, _write_capability)
    w.write_u64(max_fee_micro_zin)
    w.write_u8(priority)
    w.write_u64(deadline_ms)
    w.write_bytes(parameters)
    _write_match_preferences(w, match_preferences or MatchPreferences())
    return w.finish()


# ─── task lifecycle ─────────────────────────────────────────────────


def _write_hash256_vec(w: BincodeWriter, values: Sequence[Hex]) -> None:
    w.write_vec(values, _write_hash256)


def _write_receipt_proof(w: BincodeWriter, proof: dict) -> None:
    receipt = proof["receipt"]
    _write_hash256(w, receipt["token_id"])
    _write_hash256(w, receipt["tool_id"])
    _write_address(w, receipt["invoker"])
    w.write_u64(receipt["amount_paid"])
    w.write_u64(receipt["issued_at"])
    w.write_u64(receipt["block_number"])
    w.write_u64(receipt["nonce"])
    w.write_vec(
        proof.get("proof_siblings", []),
        lambda writer, entry: (
            _write_hash256(writer, entry[0]),
            writer.write_u8(1 if entry[1] else 0),
        ),
    )
    _write_hash256(w, proof["receipt_root"])


def encode_task_fulfill_data(
    *,
    task_id: Hex,
    result_hash: Hex = ZERO_HASH,
    result_data: bytes = b"",
    tools_used: Optional[Sequence[Hex]] = None,
    input_refs: Optional[Sequence[Hex]] = None,
    receipt_proofs: Optional[Sequence[dict]] = None,
) -> bytes:
    """bincode-encode the ``TaskFulfillData`` payload."""
    w = BincodeWriter()
    _write_hash256(w, task_id)
    _write_hash256(w, result_hash)
    w.write_bytes(result_data)
    _write_hash256_vec(w, tools_used or [])
    _write_hash256_vec(w, input_refs or [])
    w.write_vec(receipt_proofs or [], _write_receipt_proof)
    return w.finish()


def encode_task_accept_data(*, task_id: Hex) -> bytes:
    """bincode-encode the ``TaskAcceptData`` payload."""
    w = BincodeWriter()
    _write_hash256(w, task_id)
    return w.finish()


def encode_task_dispute_data(*, task_id: Hex, reason: str) -> bytes:
    """bincode-encode the ``TaskDisputeData`` payload."""
    w = BincodeWriter()
    _write_hash256(w, task_id)
    w.write_string(reason)
    return w.finish()


def encode_task_resolve_data(*, task_id: Hex, agent_wins: bool, reason: str) -> bytes:
    """bincode-encode the ``TaskResolveData`` payload."""
    w = BincodeWriter()
    _write_hash256(w, task_id)
    w.write_u8(1 if agent_wins else 0)
    w.write_string(reason)
    return w.finish()


def encode_task_finalize_data(*, task_id: Hex) -> bytes:
    """bincode-encode the ``TaskFinalizeData`` payload."""
    w = BincodeWriter()
    _write_hash256(w, task_id)
    return w.finish()


def encode_task_cancel_data(*, task_id: Hex) -> bytes:
    """Encode the ``TaskCancel`` payload: raw 32-byte task id, matching the Rust handler."""
    return hex_to_bytes(task_id, 32)


def encode_reputation_update_data(
    *,
    task_id: Hex,
    quality_score: float,
    requester_accepted: bool,
    feedback: str = "",
) -> bytes:
    """bincode-encode the ``ReputationUpdateData`` payload."""
    if not math.isfinite(quality_score):
        raise ValueError("quality_score must be finite")
    if quality_score < 0 or quality_score > 10:
        raise ValueError("quality_score must be between 0 and 10")
    w = BincodeWriter()
    _write_hash256(w, task_id)
    w.write_f64(quality_score)
    w.write_u8(1 if requester_accepted else 0)
    w.write_string(feedback[:500])
    return w.finish()


# ─── token_create ───────────────────────────────────────────────────


def encode_token_create_data(
    *,
    name: str,
    symbol: str,
    decimals: int,
    initial_supply: BigNumberish,
    max_supply: BigNumberish = 0,
    burnable: bool = False,
    mint_authority: Optional[str] = None,
    metadata: bytes = b"",
) -> bytes:
    """bincode-encode the ``TokenCreateData`` payload."""
    w = BincodeWriter()
    w.write_string(name)
    w.write_string(symbol)
    w.write_u8(decimals)
    w.write_u64(initial_supply)
    w.write_u64(max_supply)
    w.write_u8(1 if burnable else 0)
    w.write_option(mint_authority, _write_address)
    w.write_bytes(metadata)
    return w.finish()


# ─── token_transfer ─────────────────────────────────────────────────


def encode_token_transfer_data(
    *,
    token_id: Hex,
    to: str,
    amount: BigNumberish,
) -> bytes:
    """bincode-encode the ``TokenTransferData`` payload."""
    w = BincodeWriter()
    _write_hash256(w, token_id)
    _write_address(w, to)
    w.write_u64(amount)
    return w.finish()


# ─── token_approve ──────────────────────────────────────────────────


def encode_token_approve_data(
    *,
    token_id: Hex,
    spender: str,
    amount: BigNumberish,
) -> bytes:
    """bincode-encode the ``TokenApproveData`` payload."""
    w = BincodeWriter()
    _write_hash256(w, token_id)
    _write_address(w, spender)
    w.write_u64(amount)
    return w.finish()


# ─── token_mint ─────────────────────────────────────────────────────


def encode_token_mint_data(
    *,
    token_id: Hex,
    to: str,
    amount: BigNumberish,
) -> bytes:
    """bincode-encode the ``TokenMintData`` payload."""
    w = BincodeWriter()
    _write_hash256(w, token_id)
    _write_address(w, to)
    w.write_u64(amount)
    return w.finish()


# ─── token_burn ─────────────────────────────────────────────────────


def encode_token_burn_data(
    *,
    token_id: Hex,
    amount: BigNumberish,
) -> bytes:
    """bincode-encode the ``TokenBurnData`` payload."""
    w = BincodeWriter()
    _write_hash256(w, token_id)
    w.write_u64(amount)
    return w.finish()


# ─── tool lifecycle ─────────────────────────────────────────────────


def encode_tool_register_data(
    *,
    name: str,
    description: str,
    endpoint: str,
    price_per_call: BigNumberish,
    capabilities: Sequence[str],
    settlement_mode: str = "prepaid_access",
    sla_ms: BigNumberish = 3_600_000,
    challenge_window_ms: BigNumberish = 900_000,
    max_result_metadata_bytes: int = 4_096,
    arbitration_policy: str = "protocol",
    match_enabled: bool = True,
    neural_embedding: Optional[Sequence[float]] = None,
    version: str = "1.0.0",
) -> bytes:
    """bincode-encode the ``ToolRegisterData`` payload."""
    w = BincodeWriter()
    w.write_string(name)
    w.write_string(description)
    w.write_string(endpoint)
    w.write_u64(price_per_call)
    _write_settlement_mode(w, settlement_mode)
    w.write_u64(sla_ms)
    w.write_u64(challenge_window_ms)
    w.write_u32(max_result_metadata_bytes)
    _write_arbitration_policy(w, arbitration_policy)
    _write_capabilities(w, capabilities)
    _write_bool(w, match_enabled)
    _write_optional_embedding(w, neural_embedding)
    w.write_string(version)
    return w.finish()


def encode_tool_update_data(
    *,
    tool_id: Hex,
    description: Optional[str] = None,
    endpoint: Optional[str] = None,
    price_per_call: Optional[BigNumberish] = None,
    settlement_mode: Optional[str] = None,
    sla_ms: Optional[BigNumberish] = None,
    challenge_window_ms: Optional[BigNumberish] = None,
    max_result_metadata_bytes: Optional[int] = None,
    arbitration_policy: Optional[str] = None,
    capabilities: Optional[Sequence[str]] = None,
    match_enabled: Optional[bool] = None,
    neural_embedding: Optional[Sequence[float]] = None,
    version: Optional[str] = None,
    active: Optional[bool] = None,
) -> bytes:
    """bincode-encode the ``ToolUpdateData`` payload."""
    w = BincodeWriter()
    _write_hash256(w, tool_id)
    w.write_option(description, lambda writer, value: writer.write_string(value))
    w.write_option(endpoint, lambda writer, value: writer.write_string(value))
    w.write_option(price_per_call, lambda writer, value: writer.write_u64(value))
    _write_optional_settlement_mode(w, settlement_mode)
    w.write_option(sla_ms, lambda writer, value: writer.write_u64(value))
    w.write_option(challenge_window_ms, lambda writer, value: writer.write_u64(value))
    w.write_option(max_result_metadata_bytes, lambda writer, value: writer.write_u32(value))
    _write_optional_arbitration_policy(w, arbitration_policy)
    _write_optional_capabilities(w, capabilities)
    _write_optional_bool(w, match_enabled)
    _write_optional_embedding(w, neural_embedding)
    w.write_option(version, lambda writer, value: writer.write_string(value))
    _write_optional_bool(w, active)
    return w.finish()


def _write_tool_milestone(w: BincodeWriter, value: Mapping[str, BigNumberish]) -> None:
    w.write_string(str(value["label"]))
    w.write_u64(value["amount"])


def encode_tool_invoke_data(
    *,
    tool_id: Hex,
    input_data: bytes = b"",
    max_metered_units: Optional[BigNumberish] = None,
    gas_limit: BigNumberish = 400_000,
    milestones: Optional[Sequence[Mapping[str, BigNumberish]]] = None,
) -> bytes:
    """bincode-encode the ``ToolInvokeData`` payload."""
    w = BincodeWriter()
    _write_hash256(w, tool_id)
    w.write_bytes(input_data)
    w.write_option(max_metered_units, lambda writer, value: writer.write_u64(value))
    w.write_u64(gas_limit)
    w.write_vec(milestones or [], _write_tool_milestone)
    return w.finish()


def encode_tool_deregister_data(*, tool_id: Hex) -> bytes:
    """Encode the ``ToolDeregister`` payload: raw 32-byte tool id, matching the Rust handler."""
    return hex_to_bytes(tool_id, 32)


def encode_tool_result_submit_data(
    *,
    job_id: Hex,
    result_hash: Hex,
    result_metadata: bytes = b"",
    milestone_index: Optional[int] = None,
) -> bytes:
    """bincode-encode the ``ToolResultSubmitData`` payload."""
    w = BincodeWriter()
    _write_hash256(w, job_id)
    _write_hash256(w, result_hash)
    w.write_bytes(result_metadata)
    w.write_option(milestone_index, lambda writer, value: writer.write_u32(value))
    return w.finish()


def encode_tool_result_accept_data(
    *,
    job_id: Hex,
    milestone_index: Optional[int] = None,
) -> bytes:
    """bincode-encode the ``ToolResultAcceptData`` payload."""
    w = BincodeWriter()
    _write_hash256(w, job_id)
    w.write_option(milestone_index, lambda writer, value: writer.write_u32(value))
    return w.finish()


def encode_tool_result_dispute_data(
    *,
    job_id: Hex,
    reason: str,
    milestone_index: Optional[int] = None,
) -> bytes:
    """bincode-encode the ``ToolResultDisputeData`` payload."""
    w = BincodeWriter()
    _write_hash256(w, job_id)
    w.write_string(reason)
    w.write_option(milestone_index, lambda writer, value: writer.write_u32(value))
    return w.finish()


def encode_tool_result_resolve_data(
    *,
    job_id: Hex,
    provider_wins: bool,
    reason: str,
    milestone_index: Optional[int] = None,
) -> bytes:
    """bincode-encode the ``ToolResultResolveData`` payload."""
    w = BincodeWriter()
    _write_hash256(w, job_id)
    _write_bool(w, provider_wins)
    w.write_string(reason)
    w.write_option(milestone_index, lambda writer, value: writer.write_u32(value))
    return w.finish()


def encode_tool_job_expire_data(*, job_id: Hex) -> bytes:
    """bincode-encode the ``ToolJobExpireData`` payload."""
    w = BincodeWriter()
    _write_hash256(w, job_id)
    return w.finish()


def encode_tool_usage_report_data(
    *,
    session_id: Hex,
    units_used: BigNumberish,
    result_hash: Hex,
    result_metadata: bytes = b"",
) -> bytes:
    """bincode-encode the ``ToolUsageReportData`` payload."""
    w = BincodeWriter()
    _write_hash256(w, session_id)
    w.write_u64(units_used)
    _write_hash256(w, result_hash)
    w.write_bytes(result_metadata)
    return w.finish()


def encode_tool_usage_accept_data(*, session_id: Hex) -> bytes:
    """bincode-encode the ``ToolUsageAcceptData`` payload."""
    w = BincodeWriter()
    _write_hash256(w, session_id)
    return w.finish()


def encode_tool_usage_dispute_data(*, session_id: Hex, reason: str) -> bytes:
    """bincode-encode the ``ToolUsageDisputeData`` payload."""
    w = BincodeWriter()
    _write_hash256(w, session_id)
    w.write_string(reason)
    return w.finish()


def encode_tool_usage_resolve_data(
    *,
    session_id: Hex,
    provider_wins: bool,
    reason: str,
) -> bytes:
    """bincode-encode the ``ToolUsageResolveData`` payload."""
    w = BincodeWriter()
    _write_hash256(w, session_id)
    _write_bool(w, provider_wins)
    w.write_string(reason)
    return w.finish()


def encode_tool_usage_expire_data(*, session_id: Hex) -> bytes:
    """bincode-encode the ``ToolUsageExpireData`` payload."""
    w = BincodeWriter()
    _write_hash256(w, session_id)
    return w.finish()


def encode_tool_subscription_plan_create_data(
    *,
    tool_id: Hex,
    name: str,
    price_per_period: BigNumberish,
    period_ms: BigNumberish = 2_592_000_000,
    included_calls: int = 0,
    included_credits: BigNumberish = 0,
    overage_policy: str = "deny",
) -> bytes:
    """bincode-encode the ``ToolSubscriptionPlanCreateData`` payload."""
    w = BincodeWriter()
    _write_hash256(w, tool_id)
    w.write_string(name)
    w.write_u64(price_per_period)
    w.write_u64(period_ms)
    w.write_u32(included_calls)
    w.write_u64(included_credits)
    _write_subscription_overage_policy(w, overage_policy)
    return w.finish()


def encode_tool_subscription_plan_update_data(
    *,
    plan_id: Hex,
    name: Optional[str] = None,
    price_per_period: Optional[BigNumberish] = None,
    period_ms: Optional[BigNumberish] = None,
    included_calls: Optional[int] = None,
    included_credits: Optional[BigNumberish] = None,
    overage_policy: Optional[str] = None,
    active: Optional[bool] = None,
) -> bytes:
    """bincode-encode the ``ToolSubscriptionPlanUpdateData`` payload."""
    w = BincodeWriter()
    _write_hash256(w, plan_id)
    w.write_option(name, lambda writer, value: writer.write_string(value))
    w.write_option(price_per_period, lambda writer, value: writer.write_u64(value))
    w.write_option(period_ms, lambda writer, value: writer.write_u64(value))
    w.write_option(included_calls, lambda writer, value: writer.write_u32(value))
    w.write_option(included_credits, lambda writer, value: writer.write_u64(value))
    _write_optional_subscription_overage_policy(w, overage_policy)
    _write_optional_bool(w, active)
    return w.finish()


def encode_tool_subscription_start_data(
    *,
    plan_id: Hex,
    reserve_amount: BigNumberish = 0,
    auto_renew: bool = True,
) -> bytes:
    """bincode-encode the ``ToolSubscriptionStartData`` payload."""
    w = BincodeWriter()
    _write_hash256(w, plan_id)
    w.write_u64(reserve_amount)
    _write_bool(w, auto_renew)
    return w.finish()


def encode_tool_subscription_top_up_data(*, subscription_id: Hex, amount: BigNumberish) -> bytes:
    """bincode-encode the ``ToolSubscriptionTopUpData`` payload."""
    w = BincodeWriter()
    _write_hash256(w, subscription_id)
    w.write_u64(amount)
    return w.finish()


def encode_tool_subscription_cancel_data(*, subscription_id: Hex) -> bytes:
    """bincode-encode the ``ToolSubscriptionCancelData`` payload."""
    w = BincodeWriter()
    _write_hash256(w, subscription_id)
    return w.finish()


def encode_tool_subscription_resume_data(
    *,
    subscription_id: Hex,
    reserve_amount: BigNumberish = 0,
) -> bytes:
    """bincode-encode the ``ToolSubscriptionResumeData`` payload."""
    w = BincodeWriter()
    _write_hash256(w, subscription_id)
    w.write_u64(reserve_amount)
    return w.finish()


def encode_tool_subscription_renew_data(*, subscription_id: Hex) -> bytes:
    """bincode-encode the ``ToolSubscriptionRenewData`` payload."""
    w = BincodeWriter()
    _write_hash256(w, subscription_id)
    return w.finish()


# ─── Contracts ─────────────────────────────────────────────────────


_CONTRACT_SOURCE_LANGUAGE_CODES = {
    "wat": 0,
    "rust": 1,
    "assemblyscript": 2,
}


def _write_contract_source_language(w: BincodeWriter, value: str) -> None:
    try:
        code = _CONTRACT_SOURCE_LANGUAGE_CODES[value]
    except KeyError as error:
        raise ValueError("unsupported contract source language: %s" % value) from error
    w.write_u32(code)


def _write_contract_source_proof(w: BincodeWriter, proof: Mapping[str, object]) -> None:
    _write_contract_source_language(w, str(proof["language"]))
    w.write_string(str(proof.get("compiler", "")))
    w.write_string(str(proof["source_code"]))
    witness = proof.get("bytecode_witness")
    w.write_option(None if witness is None else str(witness), lambda writer, value: writer.write_string(value))


def _write_contract_abi_param(w: BincodeWriter, param: Mapping[str, object]) -> None:
    w.write_string(str(param["name"]))
    w.write_string(str(param["ty"]))
    w.write_string(str(param.get("description", "")))


def _write_contract_function_signature(w: BincodeWriter, signature: Mapping[str, object]) -> None:
    w.write_string(str(signature["name"]))
    w.write_string(str(signature.get("description", "")))
    w.write_vec(signature.get("params", []) or [], _write_contract_abi_param)
    w.write_vec(signature.get("returns", []) or [], _write_contract_abi_param)
    _write_bool(w, bool(signature.get("mutates", False)))


def _write_contract_abi(w: BincodeWriter, abi: Mapping[str, object]) -> None:
    w.write_string(str(abi["name"]))
    w.write_string(str(abi["version"]))
    w.write_vec(abi["functions"], _write_contract_function_signature)


def encode_contract_deploy_data(*, bytecode: bytes) -> bytes:
    """bincode-encode the ``ContractDeployData`` payload."""
    w = BincodeWriter()
    w.write_bytes(bytes(bytecode))
    return w.finish()


def encode_contract_call_data(
    *,
    contract_address: str,
    function_name: str,
    args: bytes = b"",
    gas_limit: BigNumberish,
) -> bytes:
    """bincode-encode the ``ContractCallData`` payload."""
    w = BincodeWriter()
    _write_address(w, contract_address)
    w.write_string(function_name)
    w.write_bytes(bytes(args))
    w.write_u64(gas_limit)
    return w.finish()


def encode_contract_verify_data(*, contract_address: str, proof: Mapping[str, object]) -> bytes:
    """bincode-encode the ``ContractVerifyData`` payload."""
    w = BincodeWriter()
    _write_address(w, contract_address)
    _write_contract_source_proof(w, proof)
    return w.finish()


def encode_contract_publish_abi_data(*, contract_address: str, abi: Mapping[str, object]) -> bytes:
    """bincode-encode the ``ContractPublishAbiData`` payload."""
    w = BincodeWriter()
    _write_address(w, contract_address)
    _write_contract_abi(w, abi)
    return w.finish()


def encode_contract_route_update_data(
    *,
    route_name: str,
    target_contract_address: str,
) -> bytes:
    """bincode-encode the ``ContractRouteUpdateData`` payload."""
    w = BincodeWriter()
    w.write_string(route_name)
    _write_address(w, target_contract_address)
    return w.finish()


def encode_contract_route_call_data(
    *,
    deployer: str,
    route_name: str,
    function_name: str,
    args: bytes = b"",
    gas_limit: BigNumberish,
) -> bytes:
    """bincode-encode the ``ContractRouteCallData`` payload."""
    w = BincodeWriter()
    _write_address(w, deployer)
    w.write_string(route_name)
    w.write_string(function_name)
    w.write_bytes(bytes(args))
    w.write_u64(gas_limit)
    return w.finish()


def encode_contract_deactivate_data(*, contract_address: str) -> bytes:
    """Encode ``ContractDeactivate`` raw 20-byte address payload."""
    return bytes.fromhex(raw_address_hex(contract_address))


# ─── Staking + validator basics ────────────────────────────────────


def _write_validator_executor_service(w: BincodeWriter, service: Mapping[str, object]) -> None:
    w.write_u32(int(service["partition_id"]))
    w.write_string(str(service["rpc_endpoint"]))
    _write_public_key(w, str(service["executor_public_key"]))


def _encode_validator_update_payload(
    *,
    executor_services: Optional[Sequence[Mapping[str, object]]] = None,
    vrf_public_key: Optional[Hex] = None,
) -> bytes:
    w = BincodeWriter()
    w.write_vec(executor_services or [], _write_validator_executor_service)
    w.write_option(vrf_public_key, _write_public_key)
    return w.finish()


def encode_validator_register_data(
    *,
    vrf_public_key: Hex,
    executor_services: Optional[Sequence[Mapping[str, object]]] = None,
) -> bytes:
    """bincode-encode the ``ValidatorUpdateData`` payload used by validator registration."""
    return _encode_validator_update_payload(
        executor_services=executor_services,
        vrf_public_key=vrf_public_key,
    )


def encode_validator_update_data(
    *,
    executor_services: Optional[Sequence[Mapping[str, object]]] = None,
    vrf_public_key: Optional[Hex] = None,
) -> bytes:
    """bincode-encode the ``ValidatorUpdateData`` payload."""
    return _encode_validator_update_payload(
        executor_services=executor_services,
        vrf_public_key=vrf_public_key,
    )


def encode_validator_exit_data() -> bytes:
    """ValidatorExit has an empty payload."""
    return b""


def encode_validator_vrf_commit_data(
    *,
    target_epoch: BigNumberish,
    commitment: Hex,
) -> bytes:
    """bincode-encode the ``ValidatorVrfCommitData`` payload."""
    w = BincodeWriter()
    w.write_u64(target_epoch)
    _write_hash256(w, commitment)
    return w.finish()


def encode_validator_vrf_contribution_data(
    *,
    target_epoch: BigNumberish,
    vrf_output: bytes,
    vrf_proof: bytes,
) -> bytes:
    """bincode-encode the ``ValidatorVrfContributionData`` payload."""
    w = BincodeWriter()
    w.write_u64(target_epoch)
    w.write_bytes(bytes(vrf_output))
    w.write_bytes(bytes(vrf_proof))
    return w.finish()


_STAKE_TARGET_CODES = {
    "agent": 0,
    "validator": 1,
    "requester_auto_match": 2,
}


def _encode_stake_target(target: str) -> bytes:
    try:
        code = _STAKE_TARGET_CODES[target]
    except KeyError as error:
        raise ValueError("unsupported stake target: %s" % target) from error
    w = BincodeWriter()
    w.write_u32(code)
    return w.finish()


def encode_stake_data(*, target: str) -> bytes:
    """bincode-encode the ``StakeTarget`` payload for a ``stake`` transaction."""
    return _encode_stake_target(target)


def encode_unstake_data(*, target: str) -> bytes:
    """bincode-encode the ``StakeTarget`` payload for an ``unstake`` transaction."""
    return _encode_stake_target(target)


# ─── capability catalog ─────────────────────────────────────────────


def encode_capability_propose_data(
    *,
    slug: str,
    display_name: str,
    description: str,
    category: str,
    parent: Optional[str] = None,
    aliases: Optional[Sequence[str]] = None,
    keywords: Optional[Sequence[str]] = None,
    examples: Optional[Sequence[str]] = None,
    related: Optional[Sequence[str]] = None,
) -> bytes:
    """bincode-encode the ``CapabilityProposeData`` payload."""
    w = BincodeWriter()
    w.write_string(_normalize_capability_slug(slug))
    w.write_string(display_name)
    w.write_string(description)
    w.write_string(category.strip().lower())
    w.write_option(
        _normalize_capability_slug(parent) if parent is not None else None,
        lambda writer, value: writer.write_string(value),
    )
    _write_string_vec(w, _normalize_capability_slugs(aliases) or [])
    _write_string_vec(w, list(keywords or []))
    _write_string_vec(w, list(examples or []))
    _write_string_vec(w, _normalize_capability_slugs(related) or [])
    return w.finish()


def encode_capability_approve_data(
    *,
    slug: str,
    display_name: Optional[str] = None,
    description: Optional[str] = None,
    category: Optional[str] = None,
    parent: object = CAPABILITY_PARENT_UNSET,
    aliases: Optional[Sequence[str]] = None,
    keywords: Optional[Sequence[str]] = None,
    examples: Optional[Sequence[str]] = None,
    related: Optional[Sequence[str]] = None,
) -> bytes:
    """bincode-encode the ``CapabilityApproveData`` payload.

    ``parent`` uses ``CAPABILITY_PARENT_UNSET`` for no parent edit, ``None``
    to clear, and a string to set a new parent.
    """
    w = BincodeWriter()
    w.write_string(_normalize_capability_slug(slug))
    w.write_option(display_name, lambda writer, value: writer.write_string(value))
    w.write_option(description, lambda writer, value: writer.write_string(value))
    w.write_option(
        category.strip().lower() if category is not None else None,
        lambda writer, value: writer.write_string(value),
    )
    _write_optional_optional_string(
        w,
        CAPABILITY_PARENT_UNSET
        if parent is CAPABILITY_PARENT_UNSET
        else None
        if parent is None
        else _normalize_capability_slug(str(parent)),
    )
    _write_optional_string_vec(w, _normalize_capability_slugs(aliases))
    _write_optional_string_vec(w, list(keywords) if keywords is not None else None)
    _write_optional_string_vec(w, list(examples) if examples is not None else None)
    _write_optional_string_vec(w, _normalize_capability_slugs(related))
    return w.finish()


def encode_capability_reject_data(*, slug: str, reason: str = "") -> bytes:
    """bincode-encode the ``CapabilityRejectData`` payload."""
    w = BincodeWriter()
    w.write_string(_normalize_capability_slug(slug))
    w.write_string(reason)
    return w.finish()


def encode_capability_deprecate_data(
    *,
    slug: str,
    replacement: str,
    reason: str = "",
) -> bytes:
    """bincode-encode the ``CapabilityDeprecateData`` payload."""
    w = BincodeWriter()
    w.write_string(_normalize_capability_slug(slug))
    w.write_string(_normalize_capability_slug(replacement))
    w.write_string(reason)
    return w.finish()


# ─── Generic wrapper ────────────────────────────────────────────────


def create_signable_transaction(
    *,
    tx_type: str,
    sender: str,
    data: bytes,
    nonce: BigNumberish,
    chain_id: str,
    amount_micro_zin: BigNumberish = 0,
    fee_micro_zin: BigNumberish = 0,
    max_priority_fee_per_gas: BigNumberish = 0,
    timestamp_ms: Optional[BigNumberish] = None,
    reference_block_height: BigNumberish = 0,
    reference_block_hash: Hex = ZERO_HASH,
    max_valid_block_height: BigNumberish = 0,
) -> Transaction:
    """Build an unsigned Transaction with a pre-encoded data payload."""
    return create_transaction(
        tx_type=tx_type,
        sender=normalize_address(sender),
        nonce=as_u64(nonce, "nonce"),
        chain_id=chain_id,
        amount=amount_micro_zin,
        fee=fee_micro_zin,
        max_priority_fee_per_gas=max_priority_fee_per_gas,
        timestamp_ms=timestamp_ms,
        reference_block_height=reference_block_height,
        reference_block_hash=reference_block_hash,
        max_valid_block_height=max_valid_block_height,
        data=data,
    )
