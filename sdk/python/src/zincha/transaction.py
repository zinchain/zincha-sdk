"""Transaction construction, bincode serialization, hashing, and signing."""

from __future__ import annotations

import time
from dataclasses import dataclass, replace
from typing import Dict, Optional, Union

from .bincode import BincodeWriter, as_u64
from .crypto import (
    Keypair,
    bytes_to_hex,
    hex_to_bytes,
    normalize_address,
    raw_address_hex,
    sha256,
)

BigNumberish = Union[int, str]

ZERO_HASH = "0000000000000000000000000000000000000000000000000000000000000000"
TRANSFER_GAS = 10

TX_TYPE_WIRE_CODES: Dict[str, int] = {
    "transfer": 0,
    "entity_link": 1,
    "agent_register": 2,
    "agent_update": 3,
    "task_submit": 4,
    "task_fulfill": 5,
    "task_cancel": 6,
    "reputation_update": 7,
    "tool_register": 8,
    "tool_invoke": 9,
    "tool_result_submit": 10,
    "tool_result_accept": 11,
    "tool_result_dispute": 12,
    "tool_result_resolve": 13,
    "tool_job_expire": 14,
    "tool_subscription_plan_create": 15,
    "tool_subscription_plan_update": 16,
    "tool_subscription_start": 17,
    "tool_subscription_top_up": 18,
    "tool_subscription_cancel": 19,
    "tool_subscription_resume": 20,
    "tool_subscription_renew": 21,
    "tool_update": 22,
    "agreement_create": 23,
    "agreement_accept": 24,
    "agreement_execute": 25,
    "agreement_dispute": 26,
    "agreement_resolve": 27,
    "agreement_cancel": 28,
    "arbitrator_register": 29,
    "validator_register": 30,
    "validator_exit": 31,
    "validator_vrf_commit": 32,
    "validator_vrf_contribution": 33,
    "stake": 34,
    "unstake": 35,
    "task_decompose": 36,
    "batch": 37,
    "contract_deploy": 38,
    "contract_call": 39,
    "token_create": 41,
    "token_transfer": 42,
    "token_approve": 43,
    "token_mint": 44,
    "token_update_authority": 45,
    "token_burn": 46,
    "agent_deregister": 47,
    "tool_deregister": 48,
    "arbitrator_deregister": 49,
    "contract_deactivate": 50,
    "token_destroy": 51,
    "tool_usage_report": 52,
    "tool_usage_accept": 53,
    "tool_usage_dispute": 54,
    "tool_usage_resolve": 55,
    "tool_usage_expire": 56,
    "validator_update": 57,
    "contract_verify": 58,
    "contract_publish_abi": 59,
    "contract_route_update": 60,
    "contract_route_call": 61,
    "protocol_params_update": 62,
    "task_accept": 63,
    "task_dispute": 64,
    "task_resolve": 65,
    "task_finalize": 66,
}


@dataclass(frozen=True)
class Transaction:
    tx_type: str
    sender: str
    recipient: str
    amount: int
    fee: int
    max_priority_fee_per_gas: int
    nonce: int
    timestamp: int
    reference_block_height: int
    reference_block_hash: str
    max_valid_block_height: int
    data: bytes
    chain_id: str


@dataclass(frozen=True)
class SignedTransaction:
    transaction: Transaction
    signature: str
    public_key: str
    hash: str


def create_transfer_transaction(
    keypair: Keypair,
    *,
    recipient: str,
    amount_micro_zin: BigNumberish,
    nonce: BigNumberish,
    chain_id: str,
    fee_micro_zin: BigNumberish = 0,
    timestamp_ms: Optional[BigNumberish] = None,
    max_priority_fee_per_gas: BigNumberish = 0,
    reference_block_height: BigNumberish = 0,
    reference_block_hash: str = ZERO_HASH,
    max_valid_block_height: BigNumberish = 0,
) -> Transaction:
    return Transaction(
        tx_type="transfer",
        sender=keypair.address(),
        recipient=normalize_address(recipient),
        amount=as_u64(amount_micro_zin, "amount_micro_zin"),
        fee=as_u64(fee_micro_zin, "fee_micro_zin"),
        max_priority_fee_per_gas=as_u64(
            max_priority_fee_per_gas,
            "max_priority_fee_per_gas",
        ),
        nonce=as_u64(nonce, "nonce"),
        timestamp=as_u64(
            int(timestamp_ms) if timestamp_ms is not None else int(time.time() * 1000),
            "timestamp_ms",
        ),
        reference_block_height=as_u64(reference_block_height, "reference_block_height"),
        reference_block_hash=_normalize_hash(reference_block_hash),
        max_valid_block_height=as_u64(max_valid_block_height, "max_valid_block_height"),
        data=b"",
        chain_id=chain_id,
    )


def create_transaction(
    *,
    tx_type: str,
    sender: str,
    nonce: BigNumberish,
    chain_id: str,
    recipient: Optional[str] = None,
    amount: BigNumberish = 0,
    fee: BigNumberish = 0,
    max_priority_fee_per_gas: BigNumberish = 0,
    timestamp_ms: Optional[BigNumberish] = None,
    reference_block_height: BigNumberish = 0,
    reference_block_hash: str = ZERO_HASH,
    max_valid_block_height: BigNumberish = 0,
    data: bytes = b"",
) -> Transaction:
    return Transaction(
        tx_type=tx_type,
        sender=normalize_address(sender),
        recipient=normalize_address(recipient or ("zn1" + ("0" * 40))),
        amount=as_u64(amount, "amount"),
        fee=as_u64(fee, "fee"),
        max_priority_fee_per_gas=as_u64(max_priority_fee_per_gas, "max_priority_fee_per_gas"),
        nonce=as_u64(nonce, "nonce"),
        timestamp=as_u64(
            int(timestamp_ms) if timestamp_ms is not None else int(time.time() * 1000),
            "timestamp_ms",
        ),
        reference_block_height=as_u64(reference_block_height, "reference_block_height"),
        reference_block_hash=_normalize_hash(reference_block_hash),
        max_valid_block_height=as_u64(max_valid_block_height, "max_valid_block_height"),
        data=bytes(data),
        chain_id=chain_id,
    )


def with_validity_window(
    tx: Transaction,
    reference_block_height: BigNumberish,
    reference_block_hash: str,
    ttl_blocks: BigNumberish,
) -> Transaction:
    height = as_u64(reference_block_height, "reference_block_height")
    ttl = as_u64(ttl_blocks, "ttl_blocks")
    return replace(
        tx,
        reference_block_height=height,
        reference_block_hash=_normalize_hash(reference_block_hash),
        max_valid_block_height=height + (ttl if ttl > 0 else 1),
    )


def serialize_transaction(tx: Transaction) -> bytes:
    writer = BincodeWriter()
    writer.write_u32(_tx_type_wire_code(tx.tx_type))
    writer.write_string(raw_address_hex(tx.sender))
    writer.write_string(raw_address_hex(tx.recipient))
    writer.write_u64(tx.amount)
    writer.write_u64(tx.fee)
    writer.write_u64(tx.max_priority_fee_per_gas)
    writer.write_u64(tx.nonce)
    writer.write_u64(tx.timestamp)
    writer.write_u64(tx.reference_block_height)
    writer.write_string(_normalize_hash(tx.reference_block_hash))
    writer.write_u64(tx.max_valid_block_height)
    writer.write_bytes(tx.data)
    writer.write_string(tx.chain_id)
    return writer.finish()


def hash_transaction(tx: Transaction) -> str:
    return bytes_to_hex(sha256(serialize_transaction(tx)))


def sign_transaction(tx: Transaction, keypair: Keypair) -> SignedTransaction:
    if normalize_address(tx.sender) != keypair.address():
        raise ValueError("transaction sender does not match signing key address")
    tx_hash = hash_transaction(tx)
    return SignedTransaction(
        transaction=tx,
        signature=keypair.sign(hex_to_bytes(tx_hash, 32)).hex(),
        public_key=keypair.public_key_hex(),
        hash=tx_hash,
    )


def serialize_signed_transaction(tx: SignedTransaction) -> bytes:
    writer = BincodeWriter()
    writer.write_raw(serialize_transaction(tx.transaction))
    writer.write_string(_normalize_hex(tx.signature, 64, "signature"))
    writer.write_string(_normalize_hex(tx.public_key, 32, "public_key"))
    writer.write_string(_normalize_hash(tx.hash))
    return writer.finish()


def signed_transaction_hex(tx: SignedTransaction) -> str:
    return serialize_signed_transaction(tx).hex()


def verify_signed_transaction(tx: SignedTransaction, keypair: Keypair) -> bool:
    if normalize_address(tx.transaction.sender) != keypair.address():
        return False
    if hash_transaction(tx.transaction) != _normalize_hash(tx.hash):
        return False
    return keypair.verify(hex_to_bytes(tx.hash, 32), hex_to_bytes(tx.signature, 64))


def estimate_transfer_fee_micro_zin(base_fee_per_gas: BigNumberish) -> int:
    return as_u64(base_fee_per_gas, "base_fee_per_gas") * TRANSFER_GAS


def _tx_type_wire_code(tx_type: str) -> int:
    try:
        return TX_TYPE_WIRE_CODES[tx_type]
    except KeyError as error:
        raise ValueError("unsupported transaction type %s" % tx_type) from error


def _normalize_hash(value: str) -> str:
    return _normalize_hex(value, 32, "hash")


def _normalize_hex(value: str, byte_count: int, field: str) -> str:
    return hex_to_bytes(value, byte_count).hex()
