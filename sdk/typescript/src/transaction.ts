import { BincodeWriter, asU64 } from "./bincode.ts";
import {
  bytesToHex,
  hexToBytes,
  normalizeAddress,
  rawAddressHex,
  sha256,
} from "./crypto.ts";
import type {
  AddressString,
  BigNumberish,
  Hex,
  SignedTransaction,
  Transaction,
  TransferInput,
  TxTypeName,
} from "./types.ts";
import { Keypair } from "./crypto.ts";

export const ZERO_HASH = "0000000000000000000000000000000000000000000000000000000000000000";
export const TRANSFER_GAS = 10n;

export const TX_TYPE_WIRE_CODES: Record<TxTypeName, number> = {
  transfer: 0,
  entity_link: 1,
  agent_register: 2,
  agent_update: 3,
  task_submit: 4,
  task_fulfill: 5,
  task_cancel: 6,
  reputation_update: 7,
  tool_register: 8,
  tool_invoke: 9,
  tool_result_submit: 10,
  tool_result_accept: 11,
  tool_result_dispute: 12,
  tool_result_resolve: 13,
  tool_job_expire: 14,
  tool_subscription_plan_create: 15,
  tool_subscription_plan_update: 16,
  tool_subscription_start: 17,
  tool_subscription_top_up: 18,
  tool_subscription_cancel: 19,
  tool_subscription_resume: 20,
  tool_subscription_renew: 21,
  tool_update: 22,
  agreement_create: 23,
  agreement_accept: 24,
  agreement_execute: 25,
  agreement_dispute: 26,
  agreement_resolve: 27,
  agreement_cancel: 28,
  arbitrator_register: 29,
  validator_register: 30,
  validator_exit: 31,
  validator_vrf_commit: 32,
  validator_vrf_contribution: 33,
  stake: 34,
  unstake: 35,
  task_decompose: 36,
  batch: 37,
  contract_deploy: 38,
  contract_call: 39,
  token_create: 41,
  token_transfer: 42,
  token_approve: 43,
  token_mint: 44,
  token_update_authority: 45,
  token_burn: 46,
  agent_deregister: 47,
  tool_deregister: 48,
  arbitrator_deregister: 49,
  contract_deactivate: 50,
  token_destroy: 51,
  tool_usage_report: 52,
  tool_usage_accept: 53,
  tool_usage_dispute: 54,
  tool_usage_resolve: 55,
  tool_usage_expire: 56,
  validator_update: 57,
  contract_verify: 58,
  contract_publish_abi: 59,
  contract_route_update: 60,
  contract_route_call: 61,
  protocol_params_update: 62,
  task_accept: 63,
  task_dispute: 64,
  task_resolve: 65,
  task_finalize: 66,
};

export function createTransferTransaction(
  keypair: Keypair,
  input: TransferInput & { chainId: string; nonce: BigNumberish },
): Transaction {
  return {
    txType: "transfer",
    sender: keypair.address(),
    recipient: normalizeAddress(input.recipient),
    amount: asU64(input.amountMicroZin, "amountMicroZin"),
    fee: asU64(input.feeMicroZin ?? 0n, "feeMicroZin"),
    maxPriorityFeePerGas: asU64(
      input.maxPriorityFeePerGas ?? 0n,
      "maxPriorityFeePerGas",
    ),
    nonce: asU64(input.nonce, "nonce"),
    timestamp: asU64(input.timestampMs ?? Date.now(), "timestampMs"),
    referenceBlockHeight: asU64(
      input.referenceBlockHeight ?? 0n,
      "referenceBlockHeight",
    ),
    referenceBlockHash: normalizeHash(input.referenceBlockHash ?? ZERO_HASH),
    maxValidBlockHeight: asU64(
      input.maxValidBlockHeight ?? 0n,
      "maxValidBlockHeight",
    ),
    data: new Uint8Array(),
    chainId: input.chainId,
  };
}

export function createTransaction(input: {
  txType: TxTypeName;
  sender: string;
  recipient?: string;
  amount?: BigNumberish;
  fee?: BigNumberish;
  maxPriorityFeePerGas?: BigNumberish;
  nonce: BigNumberish;
  timestampMs?: BigNumberish;
  referenceBlockHeight?: BigNumberish;
  referenceBlockHash?: Hex;
  maxValidBlockHeight?: BigNumberish;
  data?: Uint8Array;
  chainId: string;
}): Transaction {
  return {
    txType: input.txType,
    sender: normalizeAddress(input.sender),
    recipient: normalizeAddress(input.recipient ?? `zn1${"0".repeat(40)}`),
    amount: asU64(input.amount ?? 0n, "amount"),
    fee: asU64(input.fee ?? 0n, "fee"),
    maxPriorityFeePerGas: asU64(input.maxPriorityFeePerGas ?? 0n, "maxPriorityFeePerGas"),
    nonce: asU64(input.nonce, "nonce"),
    timestamp: asU64(input.timestampMs ?? Date.now(), "timestampMs"),
    referenceBlockHeight: asU64(input.referenceBlockHeight ?? 0n, "referenceBlockHeight"),
    referenceBlockHash: normalizeHash(input.referenceBlockHash ?? ZERO_HASH),
    maxValidBlockHeight: asU64(input.maxValidBlockHeight ?? 0n, "maxValidBlockHeight"),
    data: input.data ?? new Uint8Array(),
    chainId: input.chainId,
  };
}

export function withValidityWindow(
  tx: Transaction,
  referenceBlockHeight: BigNumberish,
  referenceBlockHash: Hex,
  ttlBlocks: BigNumberish,
): Transaction {
  const height = asU64(referenceBlockHeight, "referenceBlockHeight");
  const ttl = asU64(ttlBlocks, "ttlBlocks");
  return {
    ...tx,
    referenceBlockHeight: height,
    referenceBlockHash: normalizeHash(referenceBlockHash),
    maxValidBlockHeight: height + (ttl > 0n ? ttl : 1n),
  };
}

export function serializeTransaction(tx: Transaction): Uint8Array {
  const writer = new BincodeWriter();
  writer.writeU32(txTypeWireCode(tx.txType));
  writer.writeString(rawAddressHex(tx.sender));
  writer.writeString(rawAddressHex(tx.recipient));
  writer.writeU64(tx.amount);
  writer.writeU64(tx.fee);
  writer.writeU64(tx.maxPriorityFeePerGas);
  writer.writeU64(tx.nonce);
  writer.writeU64(tx.timestamp);
  writer.writeU64(tx.referenceBlockHeight);
  writer.writeString(normalizeHash(tx.referenceBlockHash));
  writer.writeU64(tx.maxValidBlockHeight);
  writer.writeBytes(tx.data);
  writer.writeString(tx.chainId);
  return writer.finish();
}

export function hashTransaction(tx: Transaction): Hex {
  return bytesToHex(sha256(serializeTransaction(tx)));
}

export function signTransaction(tx: Transaction, keypair: Keypair): SignedTransaction {
  if (tx.sender !== keypair.address()) {
    throw new Error("transaction sender does not match signing key address");
  }
  const hash = hashTransaction(tx);
  return {
    transaction: tx,
    signature: bytesToHex(keypair.sign(hexToBytes(hash, 32))),
    publicKey: keypair.publicKeyHex(),
    hash,
  };
}

export function serializeSignedTransaction(tx: SignedTransaction): Uint8Array {
  const writer = new BincodeWriter();
  writer.writeRaw(serializeTransaction(tx.transaction));
  writer.writeString(normalizeHex(tx.signature, 64, "signature"));
  writer.writeString(normalizeHex(tx.publicKey, 32, "publicKey"));
  writer.writeString(normalizeHash(tx.hash));
  return writer.finish();
}

export function signedTransactionHex(tx: SignedTransaction): Hex {
  return bytesToHex(serializeSignedTransaction(tx));
}

export function verifySignedTransaction(tx: SignedTransaction, keypair: Keypair): boolean {
  if (normalizeAddress(tx.transaction.sender) !== keypair.address()) {
    return false;
  }
  if (hashTransaction(tx.transaction) !== normalizeHash(tx.hash)) {
    return false;
  }
  return keypair.verify(hexToBytes(tx.hash, 32), hexToBytes(tx.signature, 64));
}

export function estimateTransferFeeMicroZin(baseFeePerGas: BigNumberish): bigint {
  return asU64(baseFeePerGas, "baseFeePerGas") * TRANSFER_GAS;
}

function txTypeWireCode(txType: TxTypeName): number {
  const code = TX_TYPE_WIRE_CODES[txType];
  if (code === undefined) {
    throw new Error(`unsupported transaction type ${txType}`);
  }
  return code;
}

function normalizeHash(hash: Hex): Hex {
  return normalizeHex(hash, 32, "hash");
}

function normalizeHex(value: Hex, bytes: number, field: string): Hex {
  return bytesToHex(hexToBytes(value, bytes));
}
