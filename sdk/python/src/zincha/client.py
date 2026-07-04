"""Synchronous REST client for ZINCHA node APIs."""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Dict, Mapping, Optional, Sequence, Tuple

from .builders import (
    CAPABILITY_PARENT_UNSET,
    MatchPreferences,
    create_signable_transaction,
    encode_agent_deregister_data,
    encode_agent_register_data,
    encode_agent_update_data,
    encode_capability_approve_data,
    encode_capability_deprecate_data,
    encode_capability_propose_data,
    encode_capability_reject_data,
    encode_task_accept_data,
    encode_task_cancel_data,
    encode_task_dispute_data,
    encode_task_finalize_data,
    encode_task_fulfill_data,
    encode_task_resolve_data,
    encode_task_submit_data,
    encode_tool_deregister_data,
    encode_tool_invoke_data,
    encode_tool_job_expire_data,
    encode_tool_register_data,
    encode_tool_result_accept_data,
    encode_tool_result_dispute_data,
    encode_tool_result_resolve_data,
    encode_tool_result_submit_data,
    encode_tool_subscription_cancel_data,
    encode_tool_subscription_plan_create_data,
    encode_tool_subscription_plan_update_data,
    encode_tool_subscription_renew_data,
    encode_tool_subscription_resume_data,
    encode_tool_subscription_start_data,
    encode_tool_subscription_top_up_data,
    encode_tool_update_data,
    encode_tool_usage_accept_data,
    encode_tool_usage_dispute_data,
    encode_tool_usage_expire_data,
    encode_tool_usage_report_data,
    encode_tool_usage_resolve_data,
    encode_contract_call_data,
    encode_contract_deactivate_data,
    encode_contract_deploy_data,
    encode_contract_publish_abi_data,
    encode_contract_route_call_data,
    encode_contract_route_update_data,
    encode_contract_verify_data,
    encode_token_approve_data,
    encode_token_burn_data,
    encode_token_create_data,
    encode_token_mint_data,
    encode_token_transfer_data,
    encode_stake_data,
    encode_unstake_data,
    encode_validator_exit_data,
    encode_validator_register_data,
    encode_validator_update_data,
    encode_validator_vrf_commit_data,
    encode_validator_vrf_contribution_data,
)
from .crypto import Keypair, normalize_address, signed_request_headers
from .release import is_mainnet_release, parse_release_name, release_spec
from .transaction import (
    SignedTransaction,
    create_transfer_transaction,
    estimate_transfer_fee_micro_zin,
    sign_transaction,
    signed_transaction_hex,
    with_validity_window,
)

_CAPABILITY_SLUG_RE = re.compile(r"^[a-z][a-z0-9-]*(\.[a-z][a-z0-9-]*){1,7}$")


def validate_capability_slug(slug: str) -> bool:
    return len(slug) <= 128 and bool(_CAPABILITY_SLUG_RE.fullmatch(slug))


def normalize_capability_slug(slug: str) -> str:
    normalized = slug.strip().lower()
    if not validate_capability_slug(normalized):
        raise ValueError("invalid capability slug")
    return normalized


Transport = Callable[
    [str, str, Mapping[str, str], Optional[bytes], Optional[float]],
    Tuple[int, str],
]


class ZinchaApiError(Exception):
    def __init__(self, status: int, message: str, data: Any = None) -> None:
        super().__init__(message)
        self.status = status
        self.data = data


class ZinchaClient:
    def __init__(
        self,
        *,
        base_url: Optional[str] = None,
        faucet_url: Optional[str] = None,
        websocket_url: Optional[str] = None,
        release: Optional[str] = None,
        bearer_token: Optional[str] = None,
        signer: Optional[Keypair] = None,
        timeout: Optional[float] = 30.0,
        transport: Optional[Transport] = None,
    ) -> None:
        parsed_release = parse_release_name(release) if release is not None else None
        spec = release_spec(parsed_release) if parsed_release is not None else None
        self.release = parsed_release
        self.base_url = _trim_trailing_slash(
            base_url or (spec.canonical_rpc_url if spec is not None else "http://127.0.0.1:9944")
        )
        self.faucet_url = _trim_trailing_slash(
            faucet_url or (self.base_url if base_url is not None else None)
            or (spec.faucet_url if spec is not None else None)
            or self.base_url
        )
        self.websocket_url = websocket_url or (
            spec.canonical_websocket_url if spec is not None else None
        )
        self.bearer_token = bearer_token
        self.signer = signer
        self.timeout = timeout
        self._transport = transport or _urllib_transport

    @classmethod
    def for_release(cls, release: str, **options: Any) -> "ZinchaClient":
        return cls(release=release, **options)

    def request(
        self,
        method: str,
        path: str,
        *,
        query: Optional[Mapping[str, Any]] = None,
        body: Any = None,
        bearer_token: Optional[str] = None,
        signed: bool = False,
        timeout: Optional[float] = None,
    ) -> Any:
        return self._request_from_base_url(
            self.base_url,
            method,
            path,
            query=query,
            body=body,
            bearer_token=bearer_token,
            signed=signed,
            timeout=timeout,
        )

    def _request_from_base_url(
        self,
        base_url: str,
        method: str,
        path: str,
        *,
        query: Optional[Mapping[str, Any]] = None,
        body: Any = None,
        bearer_token: Optional[str] = None,
        signed: bool = False,
        timeout: Optional[float] = None,
    ) -> Any:
        request_target = _build_request_target(path, query)
        url = base_url + request_target
        encoded_body = None
        headers = {"accept": "application/json"}
        if body is not None:
            encoded_body = json.dumps(body, separators=(",", ":")).encode("utf-8")
            headers["content-type"] = "application/json"
        bearer = bearer_token if bearer_token is not None else self.bearer_token
        if bearer:
            headers["authorization"] = "Bearer %s" % bearer
        if signed:
            if self.signer is None:
                raise ValueError("signed request requires a client signer")
            headers.update(
                signed_request_headers(
                    self.signer,
                    method,
                    request_target,
                    encoded_body or b"",
                )
            )

        status, text = self._transport(
            method.upper(),
            url,
            headers,
            encoded_body,
            self.timeout if timeout is None else timeout,
        )
        try:
            parsed = json.loads(text) if text else None
        except ValueError as error:
            raise ZinchaApiError(status, "invalid JSON response: %s" % error, text)

        if status < 200 or status >= 300:
            api = parsed if isinstance(parsed, dict) else {}
            raise ZinchaApiError(status, api.get("error") or "HTTP %d" % status, api.get("data"))
        if not isinstance(parsed, dict) or parsed.get("success") is not True:
            message = parsed.get("error") if isinstance(parsed, dict) else None
            data = parsed.get("data") if isinstance(parsed, dict) else parsed
            raise ZinchaApiError(status, message or "ZINCHA API request failed", data)
        return parsed.get("data")

    def get(
        self,
        path: str,
        *,
        query: Optional[Mapping[str, Any]] = None,
        bearer_token: Optional[str] = None,
        signed: bool = False,
        timeout: Optional[float] = None,
    ) -> Any:
        return self.request(
            "GET",
            path,
            query=query,
            bearer_token=bearer_token,
            signed=signed,
            timeout=timeout,
        )

    def post(
        self,
        path: str,
        body: Any = None,
        *,
        query: Optional[Mapping[str, Any]] = None,
        bearer_token: Optional[str] = None,
        signed: bool = False,
        timeout: Optional[float] = None,
    ) -> Any:
        return self.request(
            "POST",
            path,
            query=query,
            body=body,
            bearer_token=bearer_token,
            signed=signed,
            timeout=timeout,
        )

    def chain_info(self) -> Dict[str, Any]:
        return self.get("/v1/chain/info")

    def chain_stats(self) -> Any:
        return self.get("/v1/chain/stats")

    def latest_block(self) -> Any:
        return self.get("/v1/blocks/latest")

    def block_by_number(self, number: int) -> Any:
        return self.get("/v1/blocks/%d" % number)

    def balance(self, address: str) -> Dict[str, Any]:
        return self.get("/v1/accounts/%s/balance" % normalize_address(address))

    def nonce(self, address: str) -> Dict[str, Any]:
        return self.get("/v1/accounts/%s/nonce" % normalize_address(address))

    def account_transactions(
        self,
        address: str,
        *,
        limit: Optional[int] = None,
        cursor: Optional[str] = None,
    ) -> Any:
        return self.get(
            "/v1/accounts/%s/transactions" % normalize_address(address),
            query={"limit": limit, "cursor": cursor},
        )

    def capabilities(
        self,
        *,
        limit: Optional[int] = None,
        cursor: Optional[str] = None,
        status: Optional[str] = None,
        category: Optional[str] = None,
        parent: Optional[str] = None,
    ) -> Any:
        return self.get(
            "/v1/capabilities",
            query={
                "limit": limit,
                "cursor": cursor,
                "status": status,
                "category": category,
                "parent": parent,
            },
        )

    def capability_search(
        self,
        q: str,
        *,
        limit: Optional[int] = None,
        status: Optional[str] = None,
        category: Optional[str] = None,
    ) -> Any:
        return self.get(
            "/v1/capabilities/search",
            query={
                "q": q,
                "limit": limit,
                "status": status,
                "category": category,
            },
        )

    def capability(self, slug: str) -> Any:
        return self.get(
            "/v1/capabilities/%s"
            % urllib.parse.quote(normalize_capability_slug(slug), safe="")
        )

    def capability_categories(self) -> Any:
        return self.get("/v1/capabilities/categories")

    def transaction(self, tx_hash: str) -> Dict[str, Any]:
        return self.get("/v1/tx/%s" % _normalize_hash(tx_hash))

    def submit_transaction_hex(self, signed_tx_hex: str) -> Dict[str, Any]:
        return self.post("/v1/tx/submit", {"signed_tx_hex": _normalize_hex_even(signed_tx_hex)})

    def submit_signed_transaction(self, tx: SignedTransaction) -> Dict[str, Any]:
        return self.submit_transaction_hex(signed_transaction_hex(tx))

    def submit_transaction_batch(self, signed_tx_hexes: list) -> Any:
        return self.post(
            "/v1/tx/submit/batch",
            {"signed_transactions_hex": [_normalize_hex_even(value) for value in signed_tx_hexes]},
        )

    def build_transfer(
        self,
        keypair: Keypair,
        *,
        recipient: str,
        amount_micro_zin: int,
        fee_micro_zin: Optional[int] = None,
        nonce: Optional[int] = None,
        chain_id: Optional[str] = None,
        timestamp_ms: Optional[int] = None,
        max_priority_fee_per_gas: int = 0,
        reference_block_height: Optional[int] = None,
        reference_block_hash: Optional[str] = None,
        max_valid_block_height: Optional[int] = None,
    ) -> SignedTransaction:
        validity_fields = sum(
            value is not None
            for value in (
                reference_block_height,
                reference_block_hash,
                max_valid_block_height,
            )
        )
        if validity_fields > 0 and validity_fields < 3:
            raise ValueError(
                "reference_block_height, reference_block_hash, and max_valid_block_height must be provided together"
            )
        needs_validity_window = validity_fields == 0
        needs_chain_info = chain_id is None or fee_micro_zin is None or needs_validity_window
        chain_info = self.chain_info() if needs_chain_info else None
        selected_nonce = nonce if nonce is not None else int(self.nonce(keypair.address())["next_nonce"])
        selected_chain_id = chain_id or (chain_info or {}).get("chain_id")
        if not selected_chain_id:
            raise ValueError("chain_id is required when chain info is not available")
        selected_fee = (
            int(fee_micro_zin)
            if fee_micro_zin is not None
            else estimate_transfer_fee_micro_zin(int((chain_info or {}).get("next_base_fee", 0)))
        )
        tx = create_transfer_transaction(
            keypair,
            recipient=recipient,
            amount_micro_zin=amount_micro_zin,
            fee_micro_zin=selected_fee,
            nonce=selected_nonce,
            chain_id=selected_chain_id,
            timestamp_ms=timestamp_ms,
            max_priority_fee_per_gas=max_priority_fee_per_gas,
            reference_block_height=reference_block_height or 0,
            reference_block_hash=reference_block_hash or "00" * 32,
            max_valid_block_height=max_valid_block_height or 0,
        )
        if needs_validity_window and chain_info is not None and chain_info.get("transaction_ttl_blocks") is not None:
            tx = with_validity_window(
                tx,
                int(chain_info["transaction_reference_block_height"]),
                str(chain_info["transaction_reference_block_hash"]),
                int(chain_info["transaction_ttl_blocks"]),
            )
        return sign_transaction(tx, keypair)

    def transfer_and_submit(self, keypair: Keypair, **input: Any) -> Dict[str, Any]:
        return self.submit_signed_transaction(self.build_transfer(keypair, **input))

    def build_register_agent(
        self,
        keypair: Keypair,
        *,
        name: str,
        description: str,
        capabilities: Sequence[str],
        model_hash: str = "00" * 32,
        neural_embedding: Optional[Sequence[float]] = None,
        min_fee_micro_zin: int = 0,
        fee_schedule: Optional[Sequence[tuple]] = None,
        metadata: bytes = b"",
        fee_micro_zin: int = 0,
        nonce: Optional[int] = None,
        chain_id: Optional[str] = None,
        timestamp_ms: Optional[int] = None,
        max_priority_fee_per_gas: int = 0,
        reference_block_height: Optional[int] = None,
        reference_block_hash: Optional[str] = None,
        max_valid_block_height: Optional[int] = None,
    ) -> SignedTransaction:
        """Build + sign an ``agent_register`` transaction.

        Auto-fetches ``chain_id`` and ``nonce`` when omitted, and pins the
        transaction's validity window to the chain's current reference
        block.
        """
        data = encode_agent_register_data(
            name=name,
            description=description,
            capabilities=capabilities,
            model_hash=model_hash,
            neural_embedding=neural_embedding,
            min_fee_micro_zin=min_fee_micro_zin,
            fee_schedule=fee_schedule,
            metadata=metadata,
        )
        return self._build_typed_transaction(
            keypair,
            tx_type="agent_register",
            data=data,
            nonce=nonce,
            fee_micro_zin=fee_micro_zin,
            max_priority_fee_per_gas=max_priority_fee_per_gas,
            chain_id=chain_id,
            timestamp_ms=timestamp_ms,
            reference_block_height=reference_block_height,
            reference_block_hash=reference_block_hash,
            max_valid_block_height=max_valid_block_height,
        )

    def register_agent_and_submit(self, keypair: Keypair, **input: Any) -> Dict[str, Any]:
        return self.submit_signed_transaction(self.build_register_agent(keypair, **input))

    def build_update_agent(
        self,
        keypair: Keypair,
        *,
        name: Optional[str] = None,
        description: Optional[str] = None,
        neural_embedding: Optional[Sequence[float]] = None,
        model_hash: Optional[str] = None,
        capabilities: Optional[Sequence[str]] = None,
        metadata: Optional[bytes] = None,
        active: Optional[bool] = None,
        min_fee_micro_zin: Optional[int] = None,
        fee_schedule: Optional[Sequence[tuple]] = None,
        fee_micro_zin: int = 0,
        nonce: Optional[int] = None,
        chain_id: Optional[str] = None,
        timestamp_ms: Optional[int] = None,
        max_priority_fee_per_gas: int = 0,
        reference_block_height: Optional[int] = None,
        reference_block_hash: Optional[str] = None,
        max_valid_block_height: Optional[int] = None,
    ) -> SignedTransaction:
        """Build + sign an ``agent_update`` transaction."""
        data = encode_agent_update_data(
            name=name,
            description=description,
            neural_embedding=neural_embedding,
            model_hash=model_hash,
            capabilities=capabilities,
            metadata=metadata,
            active=active,
            min_fee_micro_zin=min_fee_micro_zin,
            fee_schedule=fee_schedule,
        )
        return self._build_typed_transaction(
            keypair,
            tx_type="agent_update",
            data=data,
            nonce=nonce,
            fee_micro_zin=fee_micro_zin,
            max_priority_fee_per_gas=max_priority_fee_per_gas,
            chain_id=chain_id,
            timestamp_ms=timestamp_ms,
            reference_block_height=reference_block_height,
            reference_block_hash=reference_block_hash,
            max_valid_block_height=max_valid_block_height,
        )

    def update_agent_and_submit(self, keypair: Keypair, **input: Any) -> Dict[str, Any]:
        return self.submit_signed_transaction(self.build_update_agent(keypair, **input))

    def build_deregister_agent(
        self,
        keypair: Keypair,
        *,
        fee_micro_zin: int = 0,
        nonce: Optional[int] = None,
        chain_id: Optional[str] = None,
        timestamp_ms: Optional[int] = None,
        max_priority_fee_per_gas: int = 0,
        reference_block_height: Optional[int] = None,
        reference_block_hash: Optional[str] = None,
        max_valid_block_height: Optional[int] = None,
    ) -> SignedTransaction:
        """Build + sign an ``agent_deregister`` transaction."""
        return self._build_typed_transaction(
            keypair,
            tx_type="agent_deregister",
            data=encode_agent_deregister_data(),
            nonce=nonce,
            fee_micro_zin=fee_micro_zin,
            max_priority_fee_per_gas=max_priority_fee_per_gas,
            chain_id=chain_id,
            timestamp_ms=timestamp_ms,
            reference_block_height=reference_block_height,
            reference_block_hash=reference_block_hash,
            max_valid_block_height=max_valid_block_height,
        )

    def deregister_agent_and_submit(self, keypair: Keypair, **input: Any) -> Dict[str, Any]:
        return self.submit_signed_transaction(self.build_deregister_agent(keypair, **input))

    def build_propose_capability(
        self,
        keypair: Keypair,
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
        fee_micro_zin: int = 0,
        nonce: Optional[int] = None,
        chain_id: Optional[str] = None,
        timestamp_ms: Optional[int] = None,
        max_priority_fee_per_gas: int = 0,
        reference_block_height: Optional[int] = None,
        reference_block_hash: Optional[str] = None,
        max_valid_block_height: Optional[int] = None,
    ) -> SignedTransaction:
        """Build + sign a ``capability_propose`` transaction."""
        data = encode_capability_propose_data(
            slug=slug,
            display_name=display_name,
            description=description,
            category=category,
            parent=parent,
            aliases=aliases,
            keywords=keywords,
            examples=examples,
            related=related,
        )
        return self._build_typed_transaction(
            keypair,
            tx_type="capability_propose",
            data=data,
            nonce=nonce,
            fee_micro_zin=fee_micro_zin,
            max_priority_fee_per_gas=max_priority_fee_per_gas,
            chain_id=chain_id,
            timestamp_ms=timestamp_ms,
            reference_block_height=reference_block_height,
            reference_block_hash=reference_block_hash,
            max_valid_block_height=max_valid_block_height,
        )

    def propose_capability_and_submit(self, keypair: Keypair, **input: Any) -> Dict[str, Any]:
        return self.submit_signed_transaction(self.build_propose_capability(keypair, **input))

    def build_approve_capability(
        self,
        keypair: Keypair,
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
        fee_micro_zin: int = 0,
        nonce: Optional[int] = None,
        chain_id: Optional[str] = None,
        timestamp_ms: Optional[int] = None,
        max_priority_fee_per_gas: int = 0,
        reference_block_height: Optional[int] = None,
        reference_block_hash: Optional[str] = None,
        max_valid_block_height: Optional[int] = None,
    ) -> SignedTransaction:
        """Build + sign a curator-only ``capability_approve`` transaction.

        ``parent`` defaults to no edit. Pass ``None`` to clear the parent.
        """
        data = encode_capability_approve_data(
            slug=slug,
            display_name=display_name,
            description=description,
            category=category,
            parent=parent,
            aliases=aliases,
            keywords=keywords,
            examples=examples,
            related=related,
        )
        return self._build_typed_transaction(
            keypair,
            tx_type="capability_approve",
            data=data,
            nonce=nonce,
            fee_micro_zin=fee_micro_zin,
            max_priority_fee_per_gas=max_priority_fee_per_gas,
            chain_id=chain_id,
            timestamp_ms=timestamp_ms,
            reference_block_height=reference_block_height,
            reference_block_hash=reference_block_hash,
            max_valid_block_height=max_valid_block_height,
        )

    def approve_capability_and_submit(self, keypair: Keypair, **input: Any) -> Dict[str, Any]:
        return self.submit_signed_transaction(self.build_approve_capability(keypair, **input))

    def build_reject_capability(
        self,
        keypair: Keypair,
        *,
        slug: str,
        reason: str = "",
        fee_micro_zin: int = 0,
        nonce: Optional[int] = None,
        chain_id: Optional[str] = None,
        timestamp_ms: Optional[int] = None,
        max_priority_fee_per_gas: int = 0,
        reference_block_height: Optional[int] = None,
        reference_block_hash: Optional[str] = None,
        max_valid_block_height: Optional[int] = None,
    ) -> SignedTransaction:
        """Build + sign a curator-only ``capability_reject`` transaction."""
        return self._build_typed_transaction(
            keypair,
            tx_type="capability_reject",
            data=encode_capability_reject_data(slug=slug, reason=reason),
            nonce=nonce,
            fee_micro_zin=fee_micro_zin,
            max_priority_fee_per_gas=max_priority_fee_per_gas,
            chain_id=chain_id,
            timestamp_ms=timestamp_ms,
            reference_block_height=reference_block_height,
            reference_block_hash=reference_block_hash,
            max_valid_block_height=max_valid_block_height,
        )

    def reject_capability_and_submit(self, keypair: Keypair, **input: Any) -> Dict[str, Any]:
        return self.submit_signed_transaction(self.build_reject_capability(keypair, **input))

    def build_deprecate_capability(
        self,
        keypair: Keypair,
        *,
        slug: str,
        replacement: str,
        reason: str = "",
        fee_micro_zin: int = 0,
        nonce: Optional[int] = None,
        chain_id: Optional[str] = None,
        timestamp_ms: Optional[int] = None,
        max_priority_fee_per_gas: int = 0,
        reference_block_height: Optional[int] = None,
        reference_block_hash: Optional[str] = None,
        max_valid_block_height: Optional[int] = None,
    ) -> SignedTransaction:
        """Build + sign a curator-only ``capability_deprecate`` transaction."""
        return self._build_typed_transaction(
            keypair,
            tx_type="capability_deprecate",
            data=encode_capability_deprecate_data(slug=slug, replacement=replacement, reason=reason),
            nonce=nonce,
            fee_micro_zin=fee_micro_zin,
            max_priority_fee_per_gas=max_priority_fee_per_gas,
            chain_id=chain_id,
            timestamp_ms=timestamp_ms,
            reference_block_height=reference_block_height,
            reference_block_hash=reference_block_hash,
            max_valid_block_height=max_valid_block_height,
        )

    def deprecate_capability_and_submit(self, keypair: Keypair, **input: Any) -> Dict[str, Any]:
        return self.submit_signed_transaction(self.build_deprecate_capability(keypair, **input))

    def build_submit_task(
        self,
        keypair: Keypair,
        *,
        description: str,
        required_capabilities: Sequence[str],
        max_fee_micro_zin: int,
        priority: int = 0,
        deadline_ms: int = 0,
        parameters: bytes = b"",
        match_preferences: Optional[MatchPreferences] = None,
        neural_embedding: Optional[Sequence[float]] = None,
        fee_micro_zin: int = 0,
        nonce: Optional[int] = None,
        chain_id: Optional[str] = None,
        timestamp_ms: Optional[int] = None,
        max_priority_fee_per_gas: int = 0,
        reference_block_height: Optional[int] = None,
        reference_block_hash: Optional[str] = None,
        max_valid_block_height: Optional[int] = None,
    ) -> SignedTransaction:
        """Build + sign a ``task_submit`` transaction.

        Auto-fetches ``chain_id`` and ``nonce`` when omitted, and pins the
        transaction's validity window to the chain's current reference
        block.
        """
        data = encode_task_submit_data(
            description=description,
            required_capabilities=required_capabilities,
            max_fee_micro_zin=max_fee_micro_zin,
            priority=priority,
            deadline_ms=deadline_ms,
            parameters=parameters,
            match_preferences=match_preferences,
            neural_embedding=neural_embedding,
        )
        return self._build_typed_transaction(
            keypair,
            tx_type="task_submit",
            data=data,
            nonce=nonce,
            fee_micro_zin=fee_micro_zin,
            max_priority_fee_per_gas=max_priority_fee_per_gas,
            chain_id=chain_id,
            timestamp_ms=timestamp_ms,
            reference_block_height=reference_block_height,
            reference_block_hash=reference_block_hash,
            max_valid_block_height=max_valid_block_height,
        )

    def submit_task_and_submit(self, keypair: Keypair, **input: Any) -> Dict[str, Any]:
        return self.submit_signed_transaction(self.build_submit_task(keypair, **input))

    def build_fulfill_task(
        self,
        keypair: Keypair,
        *,
        task_id: str,
        result_hash: str = "00" * 32,
        result_data: bytes = b"",
        tools_used: Optional[Sequence[str]] = None,
        input_refs: Optional[Sequence[str]] = None,
        receipt_proofs: Optional[Sequence[dict]] = None,
        fee_micro_zin: int = 0,
        nonce: Optional[int] = None,
        chain_id: Optional[str] = None,
        timestamp_ms: Optional[int] = None,
        max_priority_fee_per_gas: int = 0,
        reference_block_height: Optional[int] = None,
        reference_block_hash: Optional[str] = None,
        max_valid_block_height: Optional[int] = None,
    ) -> SignedTransaction:
        """Build + sign a ``task_fulfill`` transaction."""
        data = encode_task_fulfill_data(
            task_id=task_id,
            result_hash=result_hash,
            result_data=result_data,
            tools_used=tools_used,
            input_refs=input_refs,
            receipt_proofs=receipt_proofs,
        )
        return self._build_typed_transaction(
            keypair,
            tx_type="task_fulfill",
            data=data,
            nonce=nonce,
            fee_micro_zin=fee_micro_zin,
            max_priority_fee_per_gas=max_priority_fee_per_gas,
            chain_id=chain_id,
            timestamp_ms=timestamp_ms,
            reference_block_height=reference_block_height,
            reference_block_hash=reference_block_hash,
            max_valid_block_height=max_valid_block_height,
        )

    def fulfill_task_and_submit(self, keypair: Keypair, **input: Any) -> Dict[str, Any]:
        return self.submit_signed_transaction(self.build_fulfill_task(keypair, **input))

    def build_accept_task(
        self,
        keypair: Keypair,
        *,
        task_id: str,
        fee_micro_zin: int = 0,
        nonce: Optional[int] = None,
        chain_id: Optional[str] = None,
        timestamp_ms: Optional[int] = None,
        max_priority_fee_per_gas: int = 0,
        reference_block_height: Optional[int] = None,
        reference_block_hash: Optional[str] = None,
        max_valid_block_height: Optional[int] = None,
    ) -> SignedTransaction:
        """Build + sign a ``task_accept`` transaction."""
        data = encode_task_accept_data(task_id=task_id)
        return self._build_typed_transaction(
            keypair,
            tx_type="task_accept",
            data=data,
            nonce=nonce,
            fee_micro_zin=fee_micro_zin,
            max_priority_fee_per_gas=max_priority_fee_per_gas,
            chain_id=chain_id,
            timestamp_ms=timestamp_ms,
            reference_block_height=reference_block_height,
            reference_block_hash=reference_block_hash,
            max_valid_block_height=max_valid_block_height,
        )

    def accept_task_and_submit(self, keypair: Keypair, **input: Any) -> Dict[str, Any]:
        return self.submit_signed_transaction(self.build_accept_task(keypair, **input))

    def build_dispute_task(
        self,
        keypair: Keypair,
        *,
        task_id: str,
        reason: str,
        fee_micro_zin: int = 0,
        nonce: Optional[int] = None,
        chain_id: Optional[str] = None,
        timestamp_ms: Optional[int] = None,
        max_priority_fee_per_gas: int = 0,
        reference_block_height: Optional[int] = None,
        reference_block_hash: Optional[str] = None,
        max_valid_block_height: Optional[int] = None,
    ) -> SignedTransaction:
        """Build + sign a ``task_dispute`` transaction."""
        data = encode_task_dispute_data(task_id=task_id, reason=reason)
        return self._build_typed_transaction(
            keypair,
            tx_type="task_dispute",
            data=data,
            nonce=nonce,
            fee_micro_zin=fee_micro_zin,
            max_priority_fee_per_gas=max_priority_fee_per_gas,
            chain_id=chain_id,
            timestamp_ms=timestamp_ms,
            reference_block_height=reference_block_height,
            reference_block_hash=reference_block_hash,
            max_valid_block_height=max_valid_block_height,
        )

    def dispute_task_and_submit(self, keypair: Keypair, **input: Any) -> Dict[str, Any]:
        return self.submit_signed_transaction(self.build_dispute_task(keypair, **input))

    def build_resolve_task(
        self,
        keypair: Keypair,
        *,
        task_id: str,
        agent_wins: bool,
        reason: str,
        fee_micro_zin: int = 0,
        nonce: Optional[int] = None,
        chain_id: Optional[str] = None,
        timestamp_ms: Optional[int] = None,
        max_priority_fee_per_gas: int = 0,
        reference_block_height: Optional[int] = None,
        reference_block_hash: Optional[str] = None,
        max_valid_block_height: Optional[int] = None,
    ) -> SignedTransaction:
        """Build + sign a ``task_resolve`` transaction."""
        data = encode_task_resolve_data(task_id=task_id, agent_wins=agent_wins, reason=reason)
        return self._build_typed_transaction(
            keypair,
            tx_type="task_resolve",
            data=data,
            nonce=nonce,
            fee_micro_zin=fee_micro_zin,
            max_priority_fee_per_gas=max_priority_fee_per_gas,
            chain_id=chain_id,
            timestamp_ms=timestamp_ms,
            reference_block_height=reference_block_height,
            reference_block_hash=reference_block_hash,
            max_valid_block_height=max_valid_block_height,
        )

    def resolve_task_and_submit(self, keypair: Keypair, **input: Any) -> Dict[str, Any]:
        return self.submit_signed_transaction(self.build_resolve_task(keypair, **input))

    def build_finalize_task(
        self,
        keypair: Keypair,
        *,
        task_id: str,
        fee_micro_zin: int = 0,
        nonce: Optional[int] = None,
        chain_id: Optional[str] = None,
        timestamp_ms: Optional[int] = None,
        max_priority_fee_per_gas: int = 0,
        reference_block_height: Optional[int] = None,
        reference_block_hash: Optional[str] = None,
        max_valid_block_height: Optional[int] = None,
    ) -> SignedTransaction:
        """Build + sign a ``task_finalize`` transaction."""
        data = encode_task_finalize_data(task_id=task_id)
        return self._build_typed_transaction(
            keypair,
            tx_type="task_finalize",
            data=data,
            nonce=nonce,
            fee_micro_zin=fee_micro_zin,
            max_priority_fee_per_gas=max_priority_fee_per_gas,
            chain_id=chain_id,
            timestamp_ms=timestamp_ms,
            reference_block_height=reference_block_height,
            reference_block_hash=reference_block_hash,
            max_valid_block_height=max_valid_block_height,
        )

    def finalize_task_and_submit(self, keypair: Keypair, **input: Any) -> Dict[str, Any]:
        return self.submit_signed_transaction(self.build_finalize_task(keypair, **input))

    def build_cancel_task(
        self,
        keypair: Keypair,
        *,
        task_id: str,
        fee_micro_zin: int = 0,
        nonce: Optional[int] = None,
        chain_id: Optional[str] = None,
        timestamp_ms: Optional[int] = None,
        max_priority_fee_per_gas: int = 0,
        reference_block_height: Optional[int] = None,
        reference_block_hash: Optional[str] = None,
        max_valid_block_height: Optional[int] = None,
    ) -> SignedTransaction:
        """Build + sign a ``task_cancel`` transaction."""
        data = encode_task_cancel_data(task_id=task_id)
        return self._build_typed_transaction(
            keypair,
            tx_type="task_cancel",
            data=data,
            nonce=nonce,
            fee_micro_zin=fee_micro_zin,
            max_priority_fee_per_gas=max_priority_fee_per_gas,
            chain_id=chain_id,
            timestamp_ms=timestamp_ms,
            reference_block_height=reference_block_height,
            reference_block_hash=reference_block_hash,
            max_valid_block_height=max_valid_block_height,
        )

    def cancel_task_and_submit(self, keypair: Keypair, **input: Any) -> Dict[str, Any]:
        return self.submit_signed_transaction(self.build_cancel_task(keypair, **input))

    def build_create_token(
        self,
        keypair: Keypair,
        *,
        name: str,
        symbol: str,
        decimals: int,
        initial_supply: int,
        max_supply: int = 0,
        burnable: bool = False,
        mint_authority: Optional[str] = None,
        metadata: bytes = b"",
        fee_micro_zin: int = 0,
        nonce: Optional[int] = None,
        chain_id: Optional[str] = None,
        timestamp_ms: Optional[int] = None,
        max_priority_fee_per_gas: int = 0,
        reference_block_height: Optional[int] = None,
        reference_block_hash: Optional[str] = None,
        max_valid_block_height: Optional[int] = None,
    ) -> SignedTransaction:
        """Build + sign a ``token_create`` transaction."""
        data = encode_token_create_data(
            name=name,
            symbol=symbol,
            decimals=decimals,
            initial_supply=initial_supply,
            max_supply=max_supply,
            burnable=burnable,
            mint_authority=mint_authority,
            metadata=metadata,
        )
        return self._build_typed_transaction(
            keypair,
            tx_type="token_create",
            data=data,
            nonce=nonce,
            fee_micro_zin=fee_micro_zin,
            max_priority_fee_per_gas=max_priority_fee_per_gas,
            chain_id=chain_id,
            timestamp_ms=timestamp_ms,
            reference_block_height=reference_block_height,
            reference_block_hash=reference_block_hash,
            max_valid_block_height=max_valid_block_height,
        )

    def create_token_and_submit(self, keypair: Keypair, **input: Any) -> Dict[str, Any]:
        return self.submit_signed_transaction(self.build_create_token(keypair, **input))

    def build_transfer_token(
        self,
        keypair: Keypair,
        *,
        token_id: str,
        to: str,
        amount: int,
        fee_micro_zin: int = 0,
        nonce: Optional[int] = None,
        chain_id: Optional[str] = None,
        timestamp_ms: Optional[int] = None,
        max_priority_fee_per_gas: int = 0,
        reference_block_height: Optional[int] = None,
        reference_block_hash: Optional[str] = None,
        max_valid_block_height: Optional[int] = None,
    ) -> SignedTransaction:
        """Build + sign a ``token_transfer`` transaction."""
        data = encode_token_transfer_data(token_id=token_id, to=to, amount=amount)
        return self._build_typed_transaction(
            keypair,
            tx_type="token_transfer",
            data=data,
            nonce=nonce,
            fee_micro_zin=fee_micro_zin,
            max_priority_fee_per_gas=max_priority_fee_per_gas,
            chain_id=chain_id,
            timestamp_ms=timestamp_ms,
            reference_block_height=reference_block_height,
            reference_block_hash=reference_block_hash,
            max_valid_block_height=max_valid_block_height,
        )

    def transfer_token_and_submit(self, keypair: Keypair, **input: Any) -> Dict[str, Any]:
        return self.submit_signed_transaction(self.build_transfer_token(keypair, **input))

    def build_approve_token(
        self,
        keypair: Keypair,
        *,
        token_id: str,
        spender: str,
        amount: int,
        fee_micro_zin: int = 0,
        nonce: Optional[int] = None,
        chain_id: Optional[str] = None,
        timestamp_ms: Optional[int] = None,
        max_priority_fee_per_gas: int = 0,
        reference_block_height: Optional[int] = None,
        reference_block_hash: Optional[str] = None,
        max_valid_block_height: Optional[int] = None,
    ) -> SignedTransaction:
        """Build + sign a ``token_approve`` transaction."""
        data = encode_token_approve_data(token_id=token_id, spender=spender, amount=amount)
        return self._build_typed_transaction(
            keypair,
            tx_type="token_approve",
            data=data,
            nonce=nonce,
            fee_micro_zin=fee_micro_zin,
            max_priority_fee_per_gas=max_priority_fee_per_gas,
            chain_id=chain_id,
            timestamp_ms=timestamp_ms,
            reference_block_height=reference_block_height,
            reference_block_hash=reference_block_hash,
            max_valid_block_height=max_valid_block_height,
        )

    def approve_token_and_submit(self, keypair: Keypair, **input: Any) -> Dict[str, Any]:
        return self.submit_signed_transaction(self.build_approve_token(keypair, **input))

    def build_mint_token(
        self,
        keypair: Keypair,
        *,
        token_id: str,
        to: str,
        amount: int,
        fee_micro_zin: int = 0,
        nonce: Optional[int] = None,
        chain_id: Optional[str] = None,
        timestamp_ms: Optional[int] = None,
        max_priority_fee_per_gas: int = 0,
        reference_block_height: Optional[int] = None,
        reference_block_hash: Optional[str] = None,
        max_valid_block_height: Optional[int] = None,
    ) -> SignedTransaction:
        """Build + sign a ``token_mint`` transaction."""
        data = encode_token_mint_data(token_id=token_id, to=to, amount=amount)
        return self._build_typed_transaction(
            keypair,
            tx_type="token_mint",
            data=data,
            nonce=nonce,
            fee_micro_zin=fee_micro_zin,
            max_priority_fee_per_gas=max_priority_fee_per_gas,
            chain_id=chain_id,
            timestamp_ms=timestamp_ms,
            reference_block_height=reference_block_height,
            reference_block_hash=reference_block_hash,
            max_valid_block_height=max_valid_block_height,
        )

    def mint_token_and_submit(self, keypair: Keypair, **input: Any) -> Dict[str, Any]:
        return self.submit_signed_transaction(self.build_mint_token(keypair, **input))

    def build_burn_token(
        self,
        keypair: Keypair,
        *,
        token_id: str,
        amount: int,
        fee_micro_zin: int = 0,
        nonce: Optional[int] = None,
        chain_id: Optional[str] = None,
        timestamp_ms: Optional[int] = None,
        max_priority_fee_per_gas: int = 0,
        reference_block_height: Optional[int] = None,
        reference_block_hash: Optional[str] = None,
        max_valid_block_height: Optional[int] = None,
    ) -> SignedTransaction:
        """Build + sign a ``token_burn`` transaction."""
        data = encode_token_burn_data(token_id=token_id, amount=amount)
        return self._build_typed_transaction(
            keypair,
            tx_type="token_burn",
            data=data,
            nonce=nonce,
            fee_micro_zin=fee_micro_zin,
            max_priority_fee_per_gas=max_priority_fee_per_gas,
            chain_id=chain_id,
            timestamp_ms=timestamp_ms,
            reference_block_height=reference_block_height,
            reference_block_hash=reference_block_hash,
            max_valid_block_height=max_valid_block_height,
        )

    def burn_token_and_submit(self, keypair: Keypair, **input: Any) -> Dict[str, Any]:
        return self.submit_signed_transaction(self.build_burn_token(keypair, **input))

    def build_register_tool(
        self,
        keypair: Keypair,
        *,
        name: str,
        description: str,
        endpoint: str,
        price_per_call: int,
        capabilities: Sequence[str],
        settlement_mode: str = "prepaid_access",
        sla_ms: int = 3_600_000,
        challenge_window_ms: int = 900_000,
        max_result_metadata_bytes: int = 4_096,
        arbitration_policy: str = "protocol",
        match_enabled: bool = True,
        neural_embedding: Optional[Sequence[float]] = None,
        version: str = "1.0.0",
        fee_micro_zin: int = 0,
        nonce: Optional[int] = None,
        chain_id: Optional[str] = None,
        timestamp_ms: Optional[int] = None,
        max_priority_fee_per_gas: int = 0,
        reference_block_height: Optional[int] = None,
        reference_block_hash: Optional[str] = None,
        max_valid_block_height: Optional[int] = None,
    ) -> SignedTransaction:
        """Build + sign a ``tool_register`` transaction."""
        data = encode_tool_register_data(
            name=name,
            description=description,
            endpoint=endpoint,
            price_per_call=price_per_call,
            capabilities=capabilities,
            settlement_mode=settlement_mode,
            sla_ms=sla_ms,
            challenge_window_ms=challenge_window_ms,
            max_result_metadata_bytes=max_result_metadata_bytes,
            arbitration_policy=arbitration_policy,
            match_enabled=match_enabled,
            neural_embedding=neural_embedding,
            version=version,
        )
        return self._build_typed_transaction(
            keypair,
            tx_type="tool_register",
            data=data,
            nonce=nonce,
            fee_micro_zin=fee_micro_zin,
            max_priority_fee_per_gas=max_priority_fee_per_gas,
            chain_id=chain_id,
            timestamp_ms=timestamp_ms,
            reference_block_height=reference_block_height,
            reference_block_hash=reference_block_hash,
            max_valid_block_height=max_valid_block_height,
        )

    def register_tool_and_submit(self, keypair: Keypair, **input: Any) -> Dict[str, Any]:
        return self.submit_signed_transaction(self.build_register_tool(keypair, **input))

    def build_update_tool(
        self,
        keypair: Keypair,
        *,
        tool_id: str,
        description: Optional[str] = None,
        endpoint: Optional[str] = None,
        price_per_call: Optional[int] = None,
        settlement_mode: Optional[str] = None,
        sla_ms: Optional[int] = None,
        challenge_window_ms: Optional[int] = None,
        max_result_metadata_bytes: Optional[int] = None,
        arbitration_policy: Optional[str] = None,
        capabilities: Optional[Sequence[str]] = None,
        match_enabled: Optional[bool] = None,
        neural_embedding: Optional[Sequence[float]] = None,
        version: Optional[str] = None,
        active: Optional[bool] = None,
        fee_micro_zin: int = 0,
        nonce: Optional[int] = None,
        chain_id: Optional[str] = None,
        timestamp_ms: Optional[int] = None,
        max_priority_fee_per_gas: int = 0,
        reference_block_height: Optional[int] = None,
        reference_block_hash: Optional[str] = None,
        max_valid_block_height: Optional[int] = None,
    ) -> SignedTransaction:
        """Build + sign a ``tool_update`` transaction."""
        data = encode_tool_update_data(
            tool_id=tool_id,
            description=description,
            endpoint=endpoint,
            price_per_call=price_per_call,
            settlement_mode=settlement_mode,
            sla_ms=sla_ms,
            challenge_window_ms=challenge_window_ms,
            max_result_metadata_bytes=max_result_metadata_bytes,
            arbitration_policy=arbitration_policy,
            capabilities=capabilities,
            match_enabled=match_enabled,
            neural_embedding=neural_embedding,
            version=version,
            active=active,
        )
        return self._build_typed_transaction(
            keypair,
            tx_type="tool_update",
            data=data,
            nonce=nonce,
            fee_micro_zin=fee_micro_zin,
            max_priority_fee_per_gas=max_priority_fee_per_gas,
            chain_id=chain_id,
            timestamp_ms=timestamp_ms,
            reference_block_height=reference_block_height,
            reference_block_hash=reference_block_hash,
            max_valid_block_height=max_valid_block_height,
        )

    def update_tool_and_submit(self, keypair: Keypair, **input: Any) -> Dict[str, Any]:
        return self.submit_signed_transaction(self.build_update_tool(keypair, **input))

    def build_invoke_tool(
        self,
        keypair: Keypair,
        *,
        tool_id: str,
        input_data: bytes = b"",
        max_metered_units: Optional[int] = None,
        gas_limit: int = 400_000,
        milestones: Optional[Sequence[Mapping[str, Any]]] = None,
        fee_micro_zin: int = 0,
        nonce: Optional[int] = None,
        chain_id: Optional[str] = None,
        timestamp_ms: Optional[int] = None,
        max_priority_fee_per_gas: int = 0,
        reference_block_height: Optional[int] = None,
        reference_block_hash: Optional[str] = None,
        max_valid_block_height: Optional[int] = None,
    ) -> SignedTransaction:
        """Build + sign a ``tool_invoke`` transaction."""
        data = encode_tool_invoke_data(
            tool_id=tool_id,
            input_data=input_data,
            max_metered_units=max_metered_units,
            gas_limit=gas_limit,
            milestones=milestones,
        )
        return self._build_typed_transaction(
            keypair,
            tx_type="tool_invoke",
            data=data,
            nonce=nonce,
            fee_micro_zin=fee_micro_zin,
            max_priority_fee_per_gas=max_priority_fee_per_gas,
            chain_id=chain_id,
            timestamp_ms=timestamp_ms,
            reference_block_height=reference_block_height,
            reference_block_hash=reference_block_hash,
            max_valid_block_height=max_valid_block_height,
        )

    def invoke_tool_and_submit(self, keypair: Keypair, **input: Any) -> Dict[str, Any]:
        return self.submit_signed_transaction(self.build_invoke_tool(keypair, **input))

    def build_deregister_tool(
        self,
        keypair: Keypair,
        *,
        tool_id: str,
        fee_micro_zin: int = 0,
        nonce: Optional[int] = None,
        chain_id: Optional[str] = None,
        timestamp_ms: Optional[int] = None,
        max_priority_fee_per_gas: int = 0,
        reference_block_height: Optional[int] = None,
        reference_block_hash: Optional[str] = None,
        max_valid_block_height: Optional[int] = None,
    ) -> SignedTransaction:
        """Build + sign a ``tool_deregister`` transaction."""
        return self._build_typed_transaction(
            keypair,
            tx_type="tool_deregister",
            data=encode_tool_deregister_data(tool_id=tool_id),
            nonce=nonce,
            fee_micro_zin=fee_micro_zin,
            max_priority_fee_per_gas=max_priority_fee_per_gas,
            chain_id=chain_id,
            timestamp_ms=timestamp_ms,
            reference_block_height=reference_block_height,
            reference_block_hash=reference_block_hash,
            max_valid_block_height=max_valid_block_height,
        )

    def deregister_tool_and_submit(self, keypair: Keypair, **input: Any) -> Dict[str, Any]:
        return self.submit_signed_transaction(self.build_deregister_tool(keypair, **input))

    def build_submit_tool_result(
        self,
        keypair: Keypair,
        *,
        job_id: str,
        result_hash: str,
        result_metadata: bytes = b"",
        milestone_index: Optional[int] = None,
        fee_micro_zin: int = 0,
        nonce: Optional[int] = None,
        chain_id: Optional[str] = None,
        timestamp_ms: Optional[int] = None,
        max_priority_fee_per_gas: int = 0,
        reference_block_height: Optional[int] = None,
        reference_block_hash: Optional[str] = None,
        max_valid_block_height: Optional[int] = None,
    ) -> SignedTransaction:
        data = encode_tool_result_submit_data(
            job_id=job_id,
            result_hash=result_hash,
            result_metadata=result_metadata,
            milestone_index=milestone_index,
        )
        return self._build_typed_transaction(
            keypair,
            tx_type="tool_result_submit",
            data=data,
            nonce=nonce,
            fee_micro_zin=fee_micro_zin,
            max_priority_fee_per_gas=max_priority_fee_per_gas,
            chain_id=chain_id,
            timestamp_ms=timestamp_ms,
            reference_block_height=reference_block_height,
            reference_block_hash=reference_block_hash,
            max_valid_block_height=max_valid_block_height,
        )

    def submit_tool_result_and_submit(self, keypair: Keypair, **input: Any) -> Dict[str, Any]:
        return self.submit_signed_transaction(self.build_submit_tool_result(keypair, **input))

    def build_accept_tool_result(
        self,
        keypair: Keypair,
        *,
        job_id: str,
        milestone_index: Optional[int] = None,
        **tx: Any,
    ) -> SignedTransaction:
        return self._build_typed_transaction(
            keypair,
            tx_type="tool_result_accept",
            data=encode_tool_result_accept_data(job_id=job_id, milestone_index=milestone_index),
            **_typed_transaction_options(tx),
        )

    def accept_tool_result_and_submit(self, keypair: Keypair, **input: Any) -> Dict[str, Any]:
        return self.submit_signed_transaction(self.build_accept_tool_result(keypair, **input))

    def build_dispute_tool_result(
        self,
        keypair: Keypair,
        *,
        job_id: str,
        reason: str,
        milestone_index: Optional[int] = None,
        **tx: Any,
    ) -> SignedTransaction:
        return self._build_typed_transaction(
            keypair,
            tx_type="tool_result_dispute",
            data=encode_tool_result_dispute_data(
                job_id=job_id,
                reason=reason,
                milestone_index=milestone_index,
            ),
            **_typed_transaction_options(tx),
        )

    def dispute_tool_result_and_submit(self, keypair: Keypair, **input: Any) -> Dict[str, Any]:
        return self.submit_signed_transaction(self.build_dispute_tool_result(keypair, **input))

    def build_resolve_tool_result(
        self,
        keypair: Keypair,
        *,
        job_id: str,
        provider_wins: bool,
        reason: str,
        milestone_index: Optional[int] = None,
        **tx: Any,
    ) -> SignedTransaction:
        return self._build_typed_transaction(
            keypair,
            tx_type="tool_result_resolve",
            data=encode_tool_result_resolve_data(
                job_id=job_id,
                provider_wins=provider_wins,
                reason=reason,
                milestone_index=milestone_index,
            ),
            **_typed_transaction_options(tx),
        )

    def resolve_tool_result_and_submit(self, keypair: Keypair, **input: Any) -> Dict[str, Any]:
        return self.submit_signed_transaction(self.build_resolve_tool_result(keypair, **input))

    def build_expire_tool_job(
        self,
        keypair: Keypair,
        *,
        job_id: str,
        **tx: Any,
    ) -> SignedTransaction:
        return self._build_typed_transaction(
            keypair,
            tx_type="tool_job_expire",
            data=encode_tool_job_expire_data(job_id=job_id),
            **_typed_transaction_options(tx),
        )

    def expire_tool_job_and_submit(self, keypair: Keypair, **input: Any) -> Dict[str, Any]:
        return self.submit_signed_transaction(self.build_expire_tool_job(keypair, **input))

    def build_report_tool_usage(
        self,
        keypair: Keypair,
        *,
        session_id: str,
        units_used: int,
        result_hash: str,
        result_metadata: bytes = b"",
        **tx: Any,
    ) -> SignedTransaction:
        return self._build_typed_transaction(
            keypair,
            tx_type="tool_usage_report",
            data=encode_tool_usage_report_data(
                session_id=session_id,
                units_used=units_used,
                result_hash=result_hash,
                result_metadata=result_metadata,
            ),
            **_typed_transaction_options(tx),
        )

    def report_tool_usage_and_submit(self, keypair: Keypair, **input: Any) -> Dict[str, Any]:
        return self.submit_signed_transaction(self.build_report_tool_usage(keypair, **input))

    def build_accept_tool_usage(
        self,
        keypair: Keypair,
        *,
        session_id: str,
        **tx: Any,
    ) -> SignedTransaction:
        return self._build_typed_transaction(
            keypair,
            tx_type="tool_usage_accept",
            data=encode_tool_usage_accept_data(session_id=session_id),
            **_typed_transaction_options(tx),
        )

    def accept_tool_usage_and_submit(self, keypair: Keypair, **input: Any) -> Dict[str, Any]:
        return self.submit_signed_transaction(self.build_accept_tool_usage(keypair, **input))

    def build_dispute_tool_usage(
        self,
        keypair: Keypair,
        *,
        session_id: str,
        reason: str,
        **tx: Any,
    ) -> SignedTransaction:
        return self._build_typed_transaction(
            keypair,
            tx_type="tool_usage_dispute",
            data=encode_tool_usage_dispute_data(session_id=session_id, reason=reason),
            **_typed_transaction_options(tx),
        )

    def dispute_tool_usage_and_submit(self, keypair: Keypair, **input: Any) -> Dict[str, Any]:
        return self.submit_signed_transaction(self.build_dispute_tool_usage(keypair, **input))

    def build_resolve_tool_usage(
        self,
        keypair: Keypair,
        *,
        session_id: str,
        provider_wins: bool,
        reason: str,
        **tx: Any,
    ) -> SignedTransaction:
        return self._build_typed_transaction(
            keypair,
            tx_type="tool_usage_resolve",
            data=encode_tool_usage_resolve_data(
                session_id=session_id,
                provider_wins=provider_wins,
                reason=reason,
            ),
            **_typed_transaction_options(tx),
        )

    def resolve_tool_usage_and_submit(self, keypair: Keypair, **input: Any) -> Dict[str, Any]:
        return self.submit_signed_transaction(self.build_resolve_tool_usage(keypair, **input))

    def build_expire_tool_usage(
        self,
        keypair: Keypair,
        *,
        session_id: str,
        **tx: Any,
    ) -> SignedTransaction:
        return self._build_typed_transaction(
            keypair,
            tx_type="tool_usage_expire",
            data=encode_tool_usage_expire_data(session_id=session_id),
            **_typed_transaction_options(tx),
        )

    def expire_tool_usage_and_submit(self, keypair: Keypair, **input: Any) -> Dict[str, Any]:
        return self.submit_signed_transaction(self.build_expire_tool_usage(keypair, **input))

    def build_create_tool_subscription_plan(
        self,
        keypair: Keypair,
        *,
        tool_id: str,
        name: str,
        price_per_period: int,
        period_ms: int = 2_592_000_000,
        included_calls: int = 0,
        included_credits: int = 0,
        overage_policy: str = "deny",
        **tx: Any,
    ) -> SignedTransaction:
        data = encode_tool_subscription_plan_create_data(
            tool_id=tool_id,
            name=name,
            price_per_period=price_per_period,
            period_ms=period_ms,
            included_calls=included_calls,
            included_credits=included_credits,
            overage_policy=overage_policy,
        )
        return self._build_typed_transaction(
            keypair,
            tx_type="tool_subscription_plan_create",
            data=data,
            **_typed_transaction_options(tx),
        )

    def create_tool_subscription_plan_and_submit(self, keypair: Keypair, **input: Any) -> Dict[str, Any]:
        return self.submit_signed_transaction(self.build_create_tool_subscription_plan(keypair, **input))

    def build_update_tool_subscription_plan(
        self,
        keypair: Keypair,
        *,
        plan_id: str,
        name: Optional[str] = None,
        price_per_period: Optional[int] = None,
        period_ms: Optional[int] = None,
        included_calls: Optional[int] = None,
        included_credits: Optional[int] = None,
        overage_policy: Optional[str] = None,
        active: Optional[bool] = None,
        **tx: Any,
    ) -> SignedTransaction:
        data = encode_tool_subscription_plan_update_data(
            plan_id=plan_id,
            name=name,
            price_per_period=price_per_period,
            period_ms=period_ms,
            included_calls=included_calls,
            included_credits=included_credits,
            overage_policy=overage_policy,
            active=active,
        )
        return self._build_typed_transaction(
            keypair,
            tx_type="tool_subscription_plan_update",
            data=data,
            **_typed_transaction_options(tx),
        )

    def update_tool_subscription_plan_and_submit(self, keypair: Keypair, **input: Any) -> Dict[str, Any]:
        return self.submit_signed_transaction(self.build_update_tool_subscription_plan(keypair, **input))

    def build_start_tool_subscription(
        self,
        keypair: Keypair,
        *,
        plan_id: str,
        reserve_amount: int = 0,
        auto_renew: bool = True,
        **tx: Any,
    ) -> SignedTransaction:
        data = encode_tool_subscription_start_data(
            plan_id=plan_id,
            reserve_amount=reserve_amount,
            auto_renew=auto_renew,
        )
        return self._build_typed_transaction(
            keypair,
            tx_type="tool_subscription_start",
            data=data,
            **_typed_transaction_options(tx),
        )

    def start_tool_subscription_and_submit(self, keypair: Keypair, **input: Any) -> Dict[str, Any]:
        return self.submit_signed_transaction(self.build_start_tool_subscription(keypair, **input))

    def build_top_up_tool_subscription(
        self,
        keypair: Keypair,
        *,
        subscription_id: str,
        amount: int,
        **tx: Any,
    ) -> SignedTransaction:
        data = encode_tool_subscription_top_up_data(subscription_id=subscription_id, amount=amount)
        return self._build_typed_transaction(
            keypair,
            tx_type="tool_subscription_top_up",
            data=data,
            **_typed_transaction_options(tx),
        )

    def top_up_tool_subscription_and_submit(self, keypair: Keypair, **input: Any) -> Dict[str, Any]:
        return self.submit_signed_transaction(self.build_top_up_tool_subscription(keypair, **input))

    def build_cancel_tool_subscription(
        self,
        keypair: Keypair,
        *,
        subscription_id: str,
        **tx: Any,
    ) -> SignedTransaction:
        return self._build_typed_transaction(
            keypair,
            tx_type="tool_subscription_cancel",
            data=encode_tool_subscription_cancel_data(subscription_id=subscription_id),
            **_typed_transaction_options(tx),
        )

    def cancel_tool_subscription_and_submit(self, keypair: Keypair, **input: Any) -> Dict[str, Any]:
        return self.submit_signed_transaction(self.build_cancel_tool_subscription(keypair, **input))

    def build_resume_tool_subscription(
        self,
        keypair: Keypair,
        *,
        subscription_id: str,
        reserve_amount: int = 0,
        **tx: Any,
    ) -> SignedTransaction:
        data = encode_tool_subscription_resume_data(
            subscription_id=subscription_id,
            reserve_amount=reserve_amount,
        )
        return self._build_typed_transaction(
            keypair,
            tx_type="tool_subscription_resume",
            data=data,
            **_typed_transaction_options(tx),
        )

    def resume_tool_subscription_and_submit(self, keypair: Keypair, **input: Any) -> Dict[str, Any]:
        return self.submit_signed_transaction(self.build_resume_tool_subscription(keypair, **input))

    def build_renew_tool_subscription(
        self,
        keypair: Keypair,
        *,
        subscription_id: str,
        **tx: Any,
    ) -> SignedTransaction:
        return self._build_typed_transaction(
            keypair,
            tx_type="tool_subscription_renew",
            data=encode_tool_subscription_renew_data(subscription_id=subscription_id),
            **_typed_transaction_options(tx),
        )

    def renew_tool_subscription_and_submit(self, keypair: Keypair, **input: Any) -> Dict[str, Any]:
        return self.submit_signed_transaction(self.build_renew_tool_subscription(keypair, **input))

    def build_deploy_contract(
        self,
        keypair: Keypair,
        *,
        bytecode: bytes,
        amount_micro_zin: int = 0,
        **tx: Any,
    ) -> SignedTransaction:
        """Build + sign a ``contract_deploy`` transaction."""
        return self._build_typed_transaction(
            keypair,
            tx_type="contract_deploy",
            data=encode_contract_deploy_data(bytecode=bytecode),
            amount_micro_zin=amount_micro_zin,
            **_typed_transaction_options(tx),
        )

    def deploy_contract_and_submit(self, keypair: Keypair, **input: Any) -> Dict[str, Any]:
        return self.submit_signed_transaction(self.build_deploy_contract(keypair, **input))

    def build_call_contract(
        self,
        keypair: Keypair,
        *,
        contract_address: str,
        function_name: str,
        args: bytes = b"",
        gas_limit: int,
        amount_micro_zin: int = 0,
        **tx: Any,
    ) -> SignedTransaction:
        """Build + sign a ``contract_call`` transaction."""
        data = encode_contract_call_data(
            contract_address=contract_address,
            function_name=function_name,
            args=args,
            gas_limit=gas_limit,
        )
        return self._build_typed_transaction(
            keypair,
            tx_type="contract_call",
            data=data,
            amount_micro_zin=amount_micro_zin,
            **_typed_transaction_options(tx),
        )

    def call_contract_and_submit(self, keypair: Keypair, **input: Any) -> Dict[str, Any]:
        return self.submit_signed_transaction(self.build_call_contract(keypair, **input))

    def build_verify_contract(
        self,
        keypair: Keypair,
        *,
        contract_address: str,
        proof: Mapping[str, object],
        **tx: Any,
    ) -> SignedTransaction:
        """Build + sign a ``contract_verify`` transaction."""
        return self._build_typed_transaction(
            keypair,
            tx_type="contract_verify",
            data=encode_contract_verify_data(contract_address=contract_address, proof=proof),
            **_typed_transaction_options(tx),
        )

    def verify_contract_and_submit(self, keypair: Keypair, **input: Any) -> Dict[str, Any]:
        return self.submit_signed_transaction(self.build_verify_contract(keypair, **input))

    def build_publish_contract_abi(
        self,
        keypair: Keypair,
        *,
        contract_address: str,
        abi: Mapping[str, object],
        **tx: Any,
    ) -> SignedTransaction:
        """Build + sign a ``contract_publish_abi`` transaction."""
        return self._build_typed_transaction(
            keypair,
            tx_type="contract_publish_abi",
            data=encode_contract_publish_abi_data(contract_address=contract_address, abi=abi),
            **_typed_transaction_options(tx),
        )

    def publish_contract_abi_and_submit(self, keypair: Keypair, **input: Any) -> Dict[str, Any]:
        return self.submit_signed_transaction(self.build_publish_contract_abi(keypair, **input))

    def build_update_contract_route(
        self,
        keypair: Keypair,
        *,
        route_name: str,
        target_contract_address: str,
        **tx: Any,
    ) -> SignedTransaction:
        """Build + sign a ``contract_route_update`` transaction."""
        data = encode_contract_route_update_data(
            route_name=route_name,
            target_contract_address=target_contract_address,
        )
        return self._build_typed_transaction(
            keypair,
            tx_type="contract_route_update",
            data=data,
            **_typed_transaction_options(tx),
        )

    def update_contract_route_and_submit(self, keypair: Keypair, **input: Any) -> Dict[str, Any]:
        return self.submit_signed_transaction(self.build_update_contract_route(keypair, **input))

    def build_call_contract_route(
        self,
        keypair: Keypair,
        *,
        deployer: str,
        route_name: str,
        function_name: str,
        args: bytes = b"",
        gas_limit: int,
        amount_micro_zin: int = 0,
        **tx: Any,
    ) -> SignedTransaction:
        """Build + sign a ``contract_route_call`` transaction."""
        data = encode_contract_route_call_data(
            deployer=deployer,
            route_name=route_name,
            function_name=function_name,
            args=args,
            gas_limit=gas_limit,
        )
        return self._build_typed_transaction(
            keypair,
            tx_type="contract_route_call",
            data=data,
            amount_micro_zin=amount_micro_zin,
            **_typed_transaction_options(tx),
        )

    def call_contract_route_and_submit(self, keypair: Keypair, **input: Any) -> Dict[str, Any]:
        return self.submit_signed_transaction(self.build_call_contract_route(keypair, **input))

    def build_deactivate_contract(
        self,
        keypair: Keypair,
        *,
        contract_address: str,
        **tx: Any,
    ) -> SignedTransaction:
        """Build + sign a ``contract_deactivate`` transaction."""
        return self._build_typed_transaction(
            keypair,
            tx_type="contract_deactivate",
            data=encode_contract_deactivate_data(contract_address=contract_address),
            **_typed_transaction_options(tx),
        )

    def deactivate_contract_and_submit(self, keypair: Keypair, **input: Any) -> Dict[str, Any]:
        return self.submit_signed_transaction(self.build_deactivate_contract(keypair, **input))

    def build_register_validator(
        self,
        keypair: Keypair,
        *,
        stake_micro_zin: int,
        executor_services: Optional[Sequence[Mapping[str, object]]] = None,
        vrf_public_key: Optional[str] = None,
        fee_micro_zin: int = 0,
        nonce: Optional[int] = None,
        chain_id: Optional[str] = None,
        timestamp_ms: Optional[int] = None,
        max_priority_fee_per_gas: int = 0,
        reference_block_height: Optional[int] = None,
        reference_block_hash: Optional[str] = None,
        max_valid_block_height: Optional[int] = None,
    ) -> SignedTransaction:
        """Build + sign a ``validator_register`` transaction."""
        data = encode_validator_register_data(
            executor_services=executor_services,
            vrf_public_key=vrf_public_key or keypair.public_key_hex(),
        )
        return self._build_typed_transaction(
            keypair,
            tx_type="validator_register",
            data=data,
            amount_micro_zin=stake_micro_zin,
            nonce=nonce,
            fee_micro_zin=fee_micro_zin,
            max_priority_fee_per_gas=max_priority_fee_per_gas,
            chain_id=chain_id,
            timestamp_ms=timestamp_ms,
            reference_block_height=reference_block_height,
            reference_block_hash=reference_block_hash,
            max_valid_block_height=max_valid_block_height,
        )

    def register_validator_and_submit(self, keypair: Keypair, **input: Any) -> Dict[str, Any]:
        return self.submit_signed_transaction(self.build_register_validator(keypair, **input))

    def build_update_validator(
        self,
        keypair: Keypair,
        *,
        executor_services: Optional[Sequence[Mapping[str, object]]] = None,
        vrf_public_key: Optional[str] = None,
        fee_micro_zin: int = 0,
        nonce: Optional[int] = None,
        chain_id: Optional[str] = None,
        timestamp_ms: Optional[int] = None,
        max_priority_fee_per_gas: int = 0,
        reference_block_height: Optional[int] = None,
        reference_block_hash: Optional[str] = None,
        max_valid_block_height: Optional[int] = None,
    ) -> SignedTransaction:
        """Build + sign a ``validator_update`` transaction."""
        data = encode_validator_update_data(
            executor_services=executor_services,
            vrf_public_key=vrf_public_key,
        )
        return self._build_typed_transaction(
            keypair,
            tx_type="validator_update",
            data=data,
            nonce=nonce,
            fee_micro_zin=fee_micro_zin,
            max_priority_fee_per_gas=max_priority_fee_per_gas,
            chain_id=chain_id,
            timestamp_ms=timestamp_ms,
            reference_block_height=reference_block_height,
            reference_block_hash=reference_block_hash,
            max_valid_block_height=max_valid_block_height,
        )

    def update_validator_and_submit(self, keypair: Keypair, **input: Any) -> Dict[str, Any]:
        return self.submit_signed_transaction(self.build_update_validator(keypair, **input))

    def build_exit_validator(
        self,
        keypair: Keypair,
        *,
        fee_micro_zin: int = 0,
        nonce: Optional[int] = None,
        chain_id: Optional[str] = None,
        timestamp_ms: Optional[int] = None,
        max_priority_fee_per_gas: int = 0,
        reference_block_height: Optional[int] = None,
        reference_block_hash: Optional[str] = None,
        max_valid_block_height: Optional[int] = None,
    ) -> SignedTransaction:
        """Build + sign a ``validator_exit`` transaction."""
        return self._build_typed_transaction(
            keypair,
            tx_type="validator_exit",
            data=encode_validator_exit_data(),
            nonce=nonce,
            fee_micro_zin=fee_micro_zin,
            max_priority_fee_per_gas=max_priority_fee_per_gas,
            chain_id=chain_id,
            timestamp_ms=timestamp_ms,
            reference_block_height=reference_block_height,
            reference_block_hash=reference_block_hash,
            max_valid_block_height=max_valid_block_height,
        )

    def exit_validator_and_submit(self, keypair: Keypair, **input: Any) -> Dict[str, Any]:
        return self.submit_signed_transaction(self.build_exit_validator(keypair, **input))

    def build_commit_validator_vrf(
        self,
        keypair: Keypair,
        *,
        target_epoch: int,
        commitment: str,
        fee_micro_zin: int = 0,
        nonce: Optional[int] = None,
        chain_id: Optional[str] = None,
        timestamp_ms: Optional[int] = None,
        max_priority_fee_per_gas: int = 0,
        reference_block_height: Optional[int] = None,
        reference_block_hash: Optional[str] = None,
        max_valid_block_height: Optional[int] = None,
    ) -> SignedTransaction:
        """Build + sign a ``validator_vrf_commit`` transaction."""
        data = encode_validator_vrf_commit_data(
            target_epoch=target_epoch,
            commitment=commitment,
        )
        return self._build_typed_transaction(
            keypair,
            tx_type="validator_vrf_commit",
            data=data,
            nonce=nonce,
            fee_micro_zin=fee_micro_zin,
            max_priority_fee_per_gas=max_priority_fee_per_gas,
            chain_id=chain_id,
            timestamp_ms=timestamp_ms,
            reference_block_height=reference_block_height,
            reference_block_hash=reference_block_hash,
            max_valid_block_height=max_valid_block_height,
        )

    def commit_validator_vrf_and_submit(self, keypair: Keypair, **input: Any) -> Dict[str, Any]:
        return self.submit_signed_transaction(self.build_commit_validator_vrf(keypair, **input))

    def build_contribute_validator_vrf(
        self,
        keypair: Keypair,
        *,
        target_epoch: int,
        vrf_output: bytes,
        vrf_proof: bytes,
        fee_micro_zin: int = 0,
        nonce: Optional[int] = None,
        chain_id: Optional[str] = None,
        timestamp_ms: Optional[int] = None,
        max_priority_fee_per_gas: int = 0,
        reference_block_height: Optional[int] = None,
        reference_block_hash: Optional[str] = None,
        max_valid_block_height: Optional[int] = None,
    ) -> SignedTransaction:
        """Build + sign a ``validator_vrf_contribution`` transaction."""
        data = encode_validator_vrf_contribution_data(
            target_epoch=target_epoch,
            vrf_output=vrf_output,
            vrf_proof=vrf_proof,
        )
        return self._build_typed_transaction(
            keypair,
            tx_type="validator_vrf_contribution",
            data=data,
            nonce=nonce,
            fee_micro_zin=fee_micro_zin,
            max_priority_fee_per_gas=max_priority_fee_per_gas,
            chain_id=chain_id,
            timestamp_ms=timestamp_ms,
            reference_block_height=reference_block_height,
            reference_block_hash=reference_block_hash,
            max_valid_block_height=max_valid_block_height,
        )

    def contribute_validator_vrf_and_submit(self, keypair: Keypair, **input: Any) -> Dict[str, Any]:
        return self.submit_signed_transaction(self.build_contribute_validator_vrf(keypair, **input))

    def build_stake(
        self,
        keypair: Keypair,
        *,
        target: str,
        amount_micro_zin: int,
        fee_micro_zin: int = 0,
        nonce: Optional[int] = None,
        chain_id: Optional[str] = None,
        timestamp_ms: Optional[int] = None,
        max_priority_fee_per_gas: int = 0,
        reference_block_height: Optional[int] = None,
        reference_block_hash: Optional[str] = None,
        max_valid_block_height: Optional[int] = None,
    ) -> SignedTransaction:
        """Build + sign a ``stake`` transaction."""
        return self._build_typed_transaction(
            keypair,
            tx_type="stake",
            data=encode_stake_data(target=target),
            amount_micro_zin=amount_micro_zin,
            nonce=nonce,
            fee_micro_zin=fee_micro_zin,
            max_priority_fee_per_gas=max_priority_fee_per_gas,
            chain_id=chain_id,
            timestamp_ms=timestamp_ms,
            reference_block_height=reference_block_height,
            reference_block_hash=reference_block_hash,
            max_valid_block_height=max_valid_block_height,
        )

    def stake_and_submit(self, keypair: Keypair, **input: Any) -> Dict[str, Any]:
        return self.submit_signed_transaction(self.build_stake(keypair, **input))

    def build_unstake(
        self,
        keypair: Keypair,
        *,
        target: str,
        amount_micro_zin: int,
        fee_micro_zin: int = 0,
        nonce: Optional[int] = None,
        chain_id: Optional[str] = None,
        timestamp_ms: Optional[int] = None,
        max_priority_fee_per_gas: int = 0,
        reference_block_height: Optional[int] = None,
        reference_block_hash: Optional[str] = None,
        max_valid_block_height: Optional[int] = None,
    ) -> SignedTransaction:
        """Build + sign an ``unstake`` transaction."""
        if target == "requester_auto_match":
            raise ValueError("requester_auto_match stake cannot be unstaked")
        return self._build_typed_transaction(
            keypair,
            tx_type="unstake",
            data=encode_unstake_data(target=target),
            amount_micro_zin=amount_micro_zin,
            nonce=nonce,
            fee_micro_zin=fee_micro_zin,
            max_priority_fee_per_gas=max_priority_fee_per_gas,
            chain_id=chain_id,
            timestamp_ms=timestamp_ms,
            reference_block_height=reference_block_height,
            reference_block_hash=reference_block_hash,
            max_valid_block_height=max_valid_block_height,
        )

    def unstake_and_submit(self, keypair: Keypair, **input: Any) -> Dict[str, Any]:
        return self.submit_signed_transaction(self.build_unstake(keypair, **input))

    def _build_typed_transaction(
        self,
        keypair: Keypair,
        *,
        tx_type: str,
        data: bytes,
        nonce: Optional[int],
        amount_micro_zin: int = 0,
        fee_micro_zin: int = 0,
        max_priority_fee_per_gas: int = 0,
        chain_id: Optional[str] = None,
        timestamp_ms: Optional[int] = None,
        reference_block_height: Optional[int] = None,
        reference_block_hash: Optional[str] = None,
        max_valid_block_height: Optional[int] = None,
    ) -> SignedTransaction:
        """Shared chain-aware assembly for typed (non-transfer) builders."""
        validity_fields = sum(
            value is not None
            for value in (
                reference_block_height,
                reference_block_hash,
                max_valid_block_height,
            )
        )
        if validity_fields > 0 and validity_fields < 3:
            raise ValueError(
                "reference_block_height, reference_block_hash, and max_valid_block_height must be provided together"
            )
        needs_validity_window = validity_fields == 0
        chain_info = self.chain_info() if chain_id is None or needs_validity_window else None
        selected_chain_id = chain_id or (chain_info or {}).get("chain_id")
        if not selected_chain_id:
            raise ValueError("chain_id is required when chain info is not available")
        selected_nonce = (
            nonce
            if nonce is not None
            else int(self.nonce(keypair.address())["next_nonce"])
        )
        tx = create_signable_transaction(
            tx_type=tx_type,
            sender=keypair.address(),
            data=data,
            nonce=selected_nonce,
            chain_id=selected_chain_id,
            amount_micro_zin=amount_micro_zin,
            fee_micro_zin=fee_micro_zin,
            max_priority_fee_per_gas=max_priority_fee_per_gas,
            timestamp_ms=timestamp_ms,
            reference_block_height=reference_block_height or 0,
            reference_block_hash=reference_block_hash or "00" * 32,
            max_valid_block_height=max_valid_block_height or 0,
        )
        if needs_validity_window and chain_info is not None and chain_info.get("transaction_ttl_blocks") is not None:
            tx = with_validity_window(
                tx,
                int(chain_info["transaction_reference_block_height"]),
                str(chain_info["transaction_reference_block_hash"]),
                int(chain_info["transaction_ttl_blocks"]),
            )
        return sign_transaction(tx, keypair)

    def request_faucet(
        self,
        *,
        address: str,
        amount_micro_zin: Optional[int] = None,
        amount_zin: Optional[int] = None,
    ) -> Dict[str, Any]:
        if self.release and is_mainnet_release(self.release):
            raise ValueError("faucet is unavailable for mainnet releases")
        body = {"address": normalize_address(address)}
        if amount_micro_zin is not None:
            body["amount_micro_zin"] = int(amount_micro_zin)
        if amount_zin is not None:
            body["amount_zin"] = int(amount_zin)
        return self._request_from_base_url(self.faucet_url, "POST", "/v1/faucet", body=body)

    def agents(self, **query: Any) -> Any:
        return self.get("/v1/agents", query=query)

    def agent(self, address: str) -> Any:
        return self.get("/v1/agents/%s" % normalize_address(address))

    def pending_tasks(self, **query: Any) -> Any:
        return self.get("/v1/tasks/pending", query=query)

    def task_opportunity(self, task_id: str) -> Any:
        return self.get("/v1/tasks/%s/opportunity" % _normalize_hash(task_id))

    def task(
        self,
        task_id: str,
        *,
        bearer_token: Optional[str] = None,
        timeout: Optional[float] = None,
    ) -> Any:
        return self.get(
            "/v1/tasks/%s" % _normalize_hash(task_id),
            bearer_token=bearer_token,
            signed=True,
            timeout=timeout,
        )

    def agreement(
        self,
        agreement_id: str,
        *,
        bearer_token: Optional[str] = None,
        timeout: Optional[float] = None,
    ) -> Any:
        return self.get(
            "/v1/agreements/%s" % _normalize_hash(agreement_id),
            bearer_token=bearer_token,
            signed=True,
            timeout=timeout,
        )

    def agreements_by_party(
        self,
        address: str,
        *,
        limit: Optional[int] = None,
        cursor: Optional[str] = None,
        bearer_token: Optional[str] = None,
        timeout: Optional[float] = None,
    ) -> Any:
        return self.get(
            "/v1/agreements/party/%s" % normalize_address(address),
            query={"limit": limit, "cursor": cursor},
            bearer_token=bearer_token,
            signed=True,
            timeout=timeout,
        )

    def agreements_by_arbitrator(
        self,
        address: str,
        *,
        limit: Optional[int] = None,
        cursor: Optional[str] = None,
        bearer_token: Optional[str] = None,
        timeout: Optional[float] = None,
    ) -> Any:
        return self.get(
            "/v1/agreements/arbitrator/%s" % normalize_address(address),
            query={"limit": limit, "cursor": cursor},
            bearer_token=bearer_token,
            signed=True,
            timeout=timeout,
        )

    def tool_job(
        self,
        job_id: str,
        *,
        bearer_token: Optional[str] = None,
        timeout: Optional[float] = None,
    ) -> Any:
        return self.get(
            "/v1/tool-jobs/%s" % _normalize_hash(job_id),
            bearer_token=bearer_token,
            signed=True,
            timeout=timeout,
        )

    def tool_jobs_by_requester(
        self,
        address: str,
        *,
        limit: Optional[int] = None,
        cursor: Optional[str] = None,
        bearer_token: Optional[str] = None,
        timeout: Optional[float] = None,
    ) -> Any:
        return self.get(
            "/v1/tool-jobs/requester/%s" % normalize_address(address),
            query={"limit": limit, "cursor": cursor},
            bearer_token=bearer_token,
            signed=True,
            timeout=timeout,
        )

    def tool_jobs_by_provider(
        self,
        address: str,
        *,
        limit: Optional[int] = None,
        cursor: Optional[str] = None,
        bearer_token: Optional[str] = None,
        timeout: Optional[float] = None,
    ) -> Any:
        return self.get(
            "/v1/tool-jobs/provider/%s" % normalize_address(address),
            query={"limit": limit, "cursor": cursor},
            bearer_token=bearer_token,
            signed=True,
            timeout=timeout,
        )

    def tool_usage_session(
        self,
        session_id: str,
        *,
        bearer_token: Optional[str] = None,
        timeout: Optional[float] = None,
    ) -> Any:
        return self.get(
            "/v1/tool-usage-sessions/%s" % _normalize_hash(session_id),
            bearer_token=bearer_token,
            signed=True,
            timeout=timeout,
        )

    def tool_usage_sessions_by_requester(
        self,
        address: str,
        *,
        limit: Optional[int] = None,
        cursor: Optional[str] = None,
        bearer_token: Optional[str] = None,
        timeout: Optional[float] = None,
    ) -> Any:
        return self.get(
            "/v1/tool-usage-sessions/requester/%s" % normalize_address(address),
            query={"limit": limit, "cursor": cursor},
            bearer_token=bearer_token,
            signed=True,
            timeout=timeout,
        )

    def tool_usage_sessions_by_provider(
        self,
        address: str,
        *,
        limit: Optional[int] = None,
        cursor: Optional[str] = None,
        bearer_token: Optional[str] = None,
        timeout: Optional[float] = None,
    ) -> Any:
        return self.get(
            "/v1/tool-usage-sessions/provider/%s" % normalize_address(address),
            query={"limit": limit, "cursor": cursor},
            bearer_token=bearer_token,
            signed=True,
            timeout=timeout,
        )

    def tools(self, **query: Any) -> Any:
        return self.get("/v1/tools", query=query)

    def contracts(self, **query: Any) -> Any:
        return self.get("/v1/contracts", query=query)

    def contract(self, address: str) -> Any:
        return self.get("/v1/contracts/%s" % normalize_address(address))

    def contract_transactions(
        self,
        address: str,
        *,
        limit: Optional[int] = None,
        cursor: Optional[str] = None,
    ) -> Any:
        return self.get(
            "/v1/contracts/%s/transactions" % normalize_address(address),
            query={"limit": limit, "cursor": cursor},
        )

    def contract_capabilities(self) -> Any:
        return self.get("/v1/contracts/capabilities")

    def tokens(self, **query: Any) -> Any:
        return self.get("/v1/tokens", query=query)

    def token(self, token_id: str) -> Any:
        return self.get("/v1/tokens/%s" % _normalize_hash(token_id))

    def token_transactions(
        self,
        token_id: str,
        *,
        limit: Optional[int] = None,
        cursor: Optional[str] = None,
    ) -> Any:
        return self.get(
            "/v1/tokens/%s/transactions" % _normalize_hash(token_id),
            query={"limit": limit, "cursor": cursor},
        )

    def validators(self) -> Any:
        return self.get("/v1/consensus/validators")

    def finality_stats(self) -> Any:
        return self.get("/v1/finality/stats")

    def network_summary(self) -> Any:
        return self.get("/v1/network/summary")

    def pipeline_status(self) -> Any:
        return self.get("/v1/pipeline/status")

    def events(self, **query: Any) -> Any:
        return self.get("/v1/events", query=query)

    def websocket_endpoint(self, path: str = "/ws") -> str:
        base = self.websocket_url or _http_to_websocket_url(self.base_url)
        return _trim_trailing_slash(base) + path

    def signed_request_headers(self, method: str, path: str, body: Any = None) -> Dict[str, str]:
        if self.signer is None:
            raise ValueError("signed request requires a client signer")
        payload = b"" if body is None else json.dumps(body, separators=(",", ":")).encode("utf-8")
        return signed_request_headers(self.signer, method, path, payload)


def _urllib_transport(
    method: str,
    url: str,
    headers: Mapping[str, str],
    body: Optional[bytes],
    timeout: Optional[float],
) -> Tuple[int, str]:
    request = urllib.request.Request(url, data=body, headers=dict(headers), method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return int(response.status), response.read().decode("utf-8")
    except urllib.error.HTTPError as error:
        return int(error.code), error.read().decode("utf-8")


def _trim_trailing_slash(value: str) -> str:
    return value.rstrip("/")


def _build_request_target(path: str, query: Optional[Mapping[str, Any]]) -> str:
    target = path if path.startswith("/") else "/" + path
    pairs = []
    for key, value in (query or {}).items():
        if value is not None:
            pairs.append((key, str(value)))
    encoded = urllib.parse.urlencode(pairs)
    return target + ("?" + encoded if encoded else "")


def _http_to_websocket_url(base_url: str) -> str:
    if base_url.startswith("https://"):
        return "wss://" + base_url[len("https://"):]
    if base_url.startswith("http://"):
        return "ws://" + base_url[len("http://"):]
    raise ValueError("cannot derive websocket URL from %s" % base_url)


def _normalize_hash(value: str) -> str:
    raw = value[2:] if value.startswith(("0x", "0X")) else value
    try:
        out = bytes.fromhex(raw)
    except ValueError as error:
        raise ValueError("invalid hex string") from error
    if len(out) != 32:
        raise ValueError("expected 32 bytes, got %d" % len(out))
    return out.hex()


def _normalize_hex_even(value: str) -> str:
    raw = value[2:] if value.startswith(("0x", "0X")) else value
    if len(raw) % 2 != 0:
        raise ValueError("invalid hex string")
    try:
        bytes.fromhex(raw)
    except ValueError as error:
        raise ValueError("invalid hex string") from error
    return raw.lower()


_TYPED_TRANSACTION_OPTION_KEYS = frozenset(
    (
        "nonce",
        "fee_micro_zin",
        "max_priority_fee_per_gas",
        "chain_id",
        "timestamp_ms",
        "reference_block_height",
        "reference_block_hash",
        "max_valid_block_height",
    )
)


def _typed_transaction_options(options: Mapping[str, Any]) -> Dict[str, Any]:
    unknown = sorted(set(options) - _TYPED_TRANSACTION_OPTION_KEYS)
    if unknown:
        raise TypeError("unexpected transaction option(s): %s" % ", ".join(unknown))
    return {
        "nonce": options.get("nonce"),
        "fee_micro_zin": options.get("fee_micro_zin", 0),
        "max_priority_fee_per_gas": options.get("max_priority_fee_per_gas", 0),
        "chain_id": options.get("chain_id"),
        "timestamp_ms": options.get("timestamp_ms"),
        "reference_block_height": options.get("reference_block_height"),
        "reference_block_hash": options.get("reference_block_hash"),
        "max_valid_block_height": options.get("max_valid_block_height"),
    }
