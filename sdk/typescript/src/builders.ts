// sdk/typescript/src/builders.ts
//
// Type-specific transaction builders. Each builder constructs the bincode
// data payload for one transaction type and returns an unsigned Transaction
// that the caller (or the higher-level ZinchaClient methods) can sign and
// submit.
//
// The wire format here MUST match the Rust primitives byte-for-byte. Each
// builder is covered by a golden vector test (see test/sdk.test.ts) that
// pins it to a fixture produced by the Rust SDK.

import { BincodeWriter, asU64 } from "./bincode.ts";
import { bytesToHex, hexToBytes, normalizeAddress, rawAddressHex } from "./crypto.ts";
import { createTransaction } from "./transaction.ts";
import type {
  AddressString,
  BigNumberish,
  Hex,
  Transaction,
  TxTypeName,
} from "./types.ts";

const ZERO_HASH = "0000000000000000000000000000000000000000000000000000000000000000";

/* ─── Shared types ──────────────────────────────────────────────── */

/**
 * Matching-engine preferences for a TaskSubmit. Mirrors the Rust
 * `MatchPreferences` struct. All fields are optional; omitted fields
 * fall back to the on-chain defaults (mirrored in
 * `DEFAULT_MATCH_PREFERENCES` below).
 */
export interface MatchPreferences {
  wSemantic?: number;
  wReputation?: number;
  wPrice?: number;
  wFreshness?: number;
  wStake?: number;
  /** Minimum reputation score to consider. f64. */
  minReputation?: number;
  /** Maximum acceptable fee in micro-ZIN (0 = no cap). */
  maxPrice?: BigNumberish;
  /**
   * Resolved-task threshold below which an agent gets a discovery bonus.
   * Default: 10. 0 disables discovery boost. u32.
   */
  discoveryThreshold?: number;
  /** Bonus score (0-50) added to below-threshold agents. */
  discoveryBoost?: number;
}

const DEFAULT_MATCH_PREFERENCES: Required<MatchPreferences> = {
  wSemantic: 30,
  wReputation: 30,
  wPrice: 20,
  wFreshness: 10,
  wStake: 10,
  minReputation: 0.0,
  maxPrice: 0n,
  discoveryThreshold: 10,
  discoveryBoost: 15,
};

export interface BaseTxOptions {
  /**
   * Sender nonce. If omitted, the caller is expected to either set it on
   * the returned Transaction or call the corresponding ZinchaClient
   * method, which fetches the nonce automatically.
   */
  nonce?: BigNumberish;
  /** Tx fee in micro-ZIN. */
  feeMicroZin?: BigNumberish;
  /** Optional priority fee. */
  maxPriorityFeePerGas?: BigNumberish;
  /** Chain id (e.g., "zincha-vega-1"). */
  chainId?: string;
  /** Optional explicit timestamp; defaults to Date.now(). */
  timestampMs?: BigNumberish;
  /** Explicit reference block height for transaction freshness. */
  referenceBlockHeight?: BigNumberish;
  /** Explicit 32-byte reference block hash for transaction freshness. */
  referenceBlockHash?: Hex;
  /** Explicit maximum valid block height. */
  maxValidBlockHeight?: BigNumberish;
}

/* ─── Capability + Hash256 helpers ───────────────────────────────── */

/** bincode-encodes a `Capability` newtype struct (just the inner string). */
function writeCapability(w: BincodeWriter, capability: string): void {
  w.writeString(capability);
}

/** bincode-encodes a `Hash256` through the Rust Hash256 serde string form. */
function writeHash256(w: BincodeWriter, hash: Hex): void {
  w.writeString(bytesToHex(hexToBytes(hash, 32)));
}

/** bincode-encodes an `Address` through the Rust raw-hex string serde form. */
function writeAddress(w: BincodeWriter, address: string): void {
  w.writeString(rawAddressHex(address));
}

function writePublicKey(w: BincodeWriter, publicKey: Hex): void {
  w.writeString(bytesToHex(hexToBytes(publicKey, 32)));
}

function writeOptionalBool(w: BincodeWriter, value: boolean | null | undefined): void {
  w.writeOption(value, (writer, bool) => writer.writeU8(bool ? 1 : 0));
}

function writeOptionalEmbedding(w: BincodeWriter, values: readonly number[] | null | undefined): void {
  w.writeOption(values, (writer, embedding) => {
    writer.writeVec(embedding, (innerWriter, value) => innerWriter.writeF32(value));
  });
}

function writeOptionalCapabilities(w: BincodeWriter, values: readonly string[] | null | undefined): void {
  w.writeOption(values, (writer, capabilities) => {
    writer.writeVec(capabilities, writeCapability);
  });
}

function writeFeeSchedule(w: BincodeWriter, values: ReadonlyArray<readonly [string, BigNumberish]>): void {
  w.writeVec(values, (writer, [name, fee]) => {
    writer.writeString(name);
    writer.writeU64(fee);
  });
}

function writeOptionalFeeSchedule(
  w: BincodeWriter,
  values: ReadonlyArray<readonly [string, BigNumberish]> | null | undefined,
): void {
  w.writeOption(values, writeFeeSchedule);
}

export type HttpToolSettlementMode =
  | "prepaid_access"
  | "result_escrowed"
  | "metered_usage"
  | "milestone_escrowed";

export type ToolArbitrationPolicy = "protocol";
export type SubscriptionOveragePolicy = "deny" | "pay_as_you_go";

function settlementModeCode(value: HttpToolSettlementMode): number {
  switch (value) {
    case "prepaid_access":
      return 0;
    case "result_escrowed":
      return 1;
    case "metered_usage":
      return 2;
    case "milestone_escrowed":
      return 3;
    default:
      throw new Error(`unsupported tool settlement mode: ${String(value)}`);
  }
}

function writeSettlementMode(w: BincodeWriter, value: HttpToolSettlementMode): void {
  w.writeU32(settlementModeCode(value));
}

function writeOptionalSettlementMode(
  w: BincodeWriter,
  value: HttpToolSettlementMode | null | undefined,
): void {
  w.writeOption(value, writeSettlementMode);
}

function arbitrationPolicyCode(value: ToolArbitrationPolicy): number {
  switch (value) {
    case "protocol":
      return 0;
    default:
      throw new Error(`unsupported tool arbitration policy: ${String(value)}`);
  }
}

function writeArbitrationPolicy(w: BincodeWriter, value: ToolArbitrationPolicy): void {
  w.writeU32(arbitrationPolicyCode(value));
}

function writeOptionalArbitrationPolicy(
  w: BincodeWriter,
  value: ToolArbitrationPolicy | null | undefined,
): void {
  w.writeOption(value, writeArbitrationPolicy);
}

function subscriptionOveragePolicyCode(value: SubscriptionOveragePolicy): number {
  switch (value) {
    case "deny":
      return 0;
    case "pay_as_you_go":
      return 1;
    default:
      throw new Error(`unsupported subscription overage policy: ${String(value)}`);
  }
}

function writeSubscriptionOveragePolicy(w: BincodeWriter, value: SubscriptionOveragePolicy): void {
  w.writeU32(subscriptionOveragePolicyCode(value));
}

function writeOptionalSubscriptionOveragePolicy(
  w: BincodeWriter,
  value: SubscriptionOveragePolicy | null | undefined,
): void {
  w.writeOption(value, writeSubscriptionOveragePolicy);
}

/* ─── agent_register ─────────────────────────────────────────────── */

export interface RegisterAgentInput extends BaseTxOptions {
  name: string;
  description: string;
  capabilities: readonly string[];
  /** Optional 32-byte hex hash of the underlying model. Defaults to zero hash. */
  modelHash?: Hex;
  /** Optional client-provided neural embedding (f32 vector). Defaults to none — the chain computes the base embedding on-chain. */
  neuralEmbedding?: readonly number[];
  /** Minimum fee the agent will accept in micro-ZIN. Default 0 (accept any). */
  minFeeMicroZin?: BigNumberish;
  /** Per-capability fee schedule, `[(capability, fee_micro_zin), ...]`. */
  feeSchedule?: ReadonlyArray<readonly [string, BigNumberish]>;
  /** Arbitrary metadata bytes. */
  metadata?: Uint8Array;
}

/** bincode-encode the `AgentRegisterData` payload. */
export function encodeAgentRegisterData(input: RegisterAgentInput): Uint8Array {
  const w = new BincodeWriter();
  w.writeString(input.name);
  w.writeString(input.description);
  w.writeOption(input.neuralEmbedding, (writer, values) => {
    writer.writeVec(values, (innerWriter, value) => innerWriter.writeF32(value));
  });
  writeHash256(w, input.modelHash ?? ZERO_HASH);
  w.writeVec(input.capabilities, writeCapability);
  w.writeBytes(input.metadata ?? new Uint8Array());
  w.writeU64(input.minFeeMicroZin ?? 0n);
  writeFeeSchedule(w, input.feeSchedule ?? []);
  return w.finish();
}

/* ─── agent lifecycle ────────────────────────────────────────────── */

export interface AgentUpdateInput extends BaseTxOptions {
  name?: string | null;
  description?: string | null;
  /** Some([]) clears the embedding on-chain; omit/null leaves it unchanged. */
  neuralEmbedding?: readonly number[] | null;
  modelHash?: Hex | null;
  capabilities?: readonly string[] | null;
  /** Some(empty bytes) clears metadata; omit/null leaves it unchanged. */
  metadata?: Uint8Array | null;
  active?: boolean | null;
  minFeeMicroZin?: BigNumberish | null;
  feeSchedule?: ReadonlyArray<readonly [string, BigNumberish]> | null;
}

/** bincode-encode the `AgentUpdateData` payload. */
export function encodeAgentUpdateData(input: AgentUpdateInput): Uint8Array {
  const w = new BincodeWriter();
  w.writeOption(input.name, (writer, value) => writer.writeString(value));
  w.writeOption(input.description, (writer, value) => writer.writeString(value));
  writeOptionalEmbedding(w, input.neuralEmbedding);
  w.writeOption(input.modelHash, writeHash256);
  writeOptionalCapabilities(w, input.capabilities);
  w.writeOption(input.metadata, (writer, value) => writer.writeBytes(value));
  writeOptionalBool(w, input.active);
  w.writeOption(input.minFeeMicroZin, (writer, value) => writer.writeU64(value));
  writeOptionalFeeSchedule(w, input.feeSchedule);
  return w.finish();
}

export type AgentDeregisterInput = BaseTxOptions;

/** Encode the `AgentDeregister` payload: empty bytes, matching the Rust handler. */
export function encodeAgentDeregisterData(_input: AgentDeregisterInput = {}): Uint8Array {
  return new Uint8Array();
}

/* ─── task_submit ────────────────────────────────────────────────── */

export interface SubmitTaskInput extends BaseTxOptions {
  description: string;
  requiredCapabilities: readonly string[];
  /** Maximum fee in micro-ZIN the requester will pay the matched agent. */
  maxFeeMicroZin: BigNumberish;
  /** Priority byte (0-255); higher = more eager matching. Default 0. */
  priority?: number;
  /**
   * Deadline in milliseconds. Interpreted by the chain; the SDK only
   * serializes the u64. Default 0 (no deadline).
   */
  deadlineMs?: BigNumberish;
  /** Arbitrary task input bytes; opaque to the chain. */
  parameters?: Uint8Array;
  /** Match-engine preferences. Defaults mirror Rust `MatchPreferences::default()`. */
  matchPreferences?: MatchPreferences;
  /** Optional client-provided neural embedding. Defaults to none. */
  neuralEmbedding?: readonly number[];
}

function writeMatchPreferences(w: BincodeWriter, prefs: MatchPreferences): void {
  const merged: Required<MatchPreferences> = {
    ...DEFAULT_MATCH_PREFERENCES,
    ...prefs,
  };
  w.writeU8(merged.wSemantic);
  w.writeU8(merged.wReputation);
  w.writeU8(merged.wPrice);
  w.writeU8(merged.wFreshness);
  w.writeU8(merged.wStake);
  w.writeF64(merged.minReputation);
  w.writeU64(merged.maxPrice);
  const dt = Number(merged.discoveryThreshold);
  if (!Number.isInteger(dt) || dt < 0 || dt > 0xffff_ffff) {
    throw new Error("discoveryThreshold must fit in unsigned 32 bits");
  }
  w.writeU32(dt);
  w.writeU8(merged.discoveryBoost);
}

/** bincode-encode the `TaskSubmitData` payload. */
export function encodeTaskSubmitData(input: SubmitTaskInput): Uint8Array {
  const w = new BincodeWriter();
  w.writeString(input.description);
  w.writeOption(input.neuralEmbedding, (writer, values) => {
    writer.writeVec(values, (innerWriter, value) => innerWriter.writeF32(value));
  });
  w.writeVec(input.requiredCapabilities, writeCapability);
  w.writeU64(input.maxFeeMicroZin);
  w.writeU8(input.priority ?? 0);
  w.writeU64(input.deadlineMs ?? 0n);
  w.writeBytes(input.parameters ?? new Uint8Array());
  writeMatchPreferences(w, input.matchPreferences ?? {});
  return w.finish();
}

/* ─── task lifecycle ─────────────────────────────────────────────── */

export interface ReceiptProofInput {
  receipt: {
    tokenId: Hex;
    toolId: Hex;
    invoker: AddressString | string;
    amountPaid: BigNumberish;
    issuedAt: BigNumberish;
    blockNumber: BigNumberish;
    nonce: BigNumberish;
  };
  proofSiblings: ReadonlyArray<readonly [Hex, boolean]>;
  receiptRoot: Hex;
}

export interface TaskFulfillInput extends BaseTxOptions {
  taskId: Hex;
  /** Zero hash signals work-started; nonzero hash submits completion. */
  resultHash?: Hex;
  resultData?: Uint8Array;
  toolsUsed?: readonly Hex[];
  inputRefs?: readonly Hex[];
  receiptProofs?: readonly ReceiptProofInput[];
}

function writeReceiptProof(w: BincodeWriter, proof: ReceiptProofInput): void {
  writeHash256(w, proof.receipt.tokenId);
  writeHash256(w, proof.receipt.toolId);
  writeAddress(w, proof.receipt.invoker);
  w.writeU64(proof.receipt.amountPaid);
  w.writeU64(proof.receipt.issuedAt);
  w.writeU64(proof.receipt.blockNumber);
  w.writeU64(proof.receipt.nonce);
  w.writeVec(proof.proofSiblings, (writer, [sibling, isRight]) => {
    writeHash256(writer, sibling);
    writer.writeU8(isRight ? 1 : 0);
  });
  writeHash256(w, proof.receiptRoot);
}

/** bincode-encode the `TaskFulfillData` payload. */
export function encodeTaskFulfillData(input: TaskFulfillInput): Uint8Array {
  const w = new BincodeWriter();
  writeHash256(w, input.taskId);
  writeHash256(w, input.resultHash ?? ZERO_HASH);
  w.writeBytes(input.resultData ?? new Uint8Array());
  w.writeVec(input.toolsUsed ?? [], writeHash256);
  w.writeVec(input.inputRefs ?? [], writeHash256);
  w.writeVec(input.receiptProofs ?? [], writeReceiptProof);
  return w.finish();
}

export interface TaskAcceptInput extends BaseTxOptions {
  taskId: Hex;
}

/** bincode-encode the `TaskAcceptData` payload. */
export function encodeTaskAcceptData(input: TaskAcceptInput): Uint8Array {
  const w = new BincodeWriter();
  writeHash256(w, input.taskId);
  return w.finish();
}

export interface TaskDisputeInput extends BaseTxOptions {
  taskId: Hex;
  reason: string;
}

/** bincode-encode the `TaskDisputeData` payload. */
export function encodeTaskDisputeData(input: TaskDisputeInput): Uint8Array {
  const w = new BincodeWriter();
  writeHash256(w, input.taskId);
  w.writeString(input.reason);
  return w.finish();
}

export interface TaskResolveInput extends BaseTxOptions {
  taskId: Hex;
  agentWins: boolean;
  reason: string;
}

/** bincode-encode the `TaskResolveData` payload. */
export function encodeTaskResolveData(input: TaskResolveInput): Uint8Array {
  const w = new BincodeWriter();
  writeHash256(w, input.taskId);
  w.writeU8(input.agentWins ? 1 : 0);
  w.writeString(input.reason);
  return w.finish();
}

export interface TaskFinalizeInput extends BaseTxOptions {
  taskId: Hex;
}

/** bincode-encode the `TaskFinalizeData` payload. */
export function encodeTaskFinalizeData(input: TaskFinalizeInput): Uint8Array {
  const w = new BincodeWriter();
  writeHash256(w, input.taskId);
  return w.finish();
}

export interface TaskCancelInput extends BaseTxOptions {
  taskId: Hex;
}

/** Encode the `TaskCancel` payload: raw 32-byte task id, matching the Rust handler. */
export function encodeTaskCancelData(input: TaskCancelInput): Uint8Array {
  return hexToBytes(input.taskId, 32);
}

/* ─── token_create ───────────────────────────────────────────────── */

export interface TokenCreateInput extends BaseTxOptions {
  name: string;
  /** Ticker symbol. The chain enforces canonical symbol validation. */
  symbol: string;
  decimals: number;
  initialSupply: BigNumberish;
  /** Maximum supply; 0 means unlimited. Default 0. */
  maxSupply?: BigNumberish;
  /** Whether holders may burn supply. Default false. */
  burnable?: boolean;
  /** Optional mint authority. Omit/null for fixed supply. */
  mintAuthority?: AddressString | string | null;
  /** Opaque token metadata bytes. */
  metadata?: Uint8Array;
}

/** bincode-encode the `TokenCreateData` payload. */
export function encodeTokenCreateData(input: TokenCreateInput): Uint8Array {
  const w = new BincodeWriter();
  w.writeString(input.name);
  w.writeString(input.symbol);
  w.writeU8(input.decimals);
  w.writeU64(input.initialSupply);
  w.writeU64(input.maxSupply ?? 0n);
  w.writeU8(input.burnable === true ? 1 : 0);
  w.writeOption(input.mintAuthority ?? null, writeAddress);
  w.writeBytes(input.metadata ?? new Uint8Array());
  return w.finish();
}

/* ─── token_transfer ─────────────────────────────────────────────── */

export interface TokenTransferInput extends BaseTxOptions {
  tokenId: Hex;
  to: AddressString | string;
  amount: BigNumberish;
}

/** bincode-encode the `TokenTransferData` payload. */
export function encodeTokenTransferData(input: TokenTransferInput): Uint8Array {
  const w = new BincodeWriter();
  writeHash256(w, input.tokenId);
  writeAddress(w, input.to);
  w.writeU64(input.amount);
  return w.finish();
}

/* ─── token_approve ──────────────────────────────────────────────── */

export interface TokenApproveInput extends BaseTxOptions {
  tokenId: Hex;
  spender: AddressString | string;
  amount: BigNumberish;
}

/** bincode-encode the `TokenApproveData` payload. */
export function encodeTokenApproveData(input: TokenApproveInput): Uint8Array {
  const w = new BincodeWriter();
  writeHash256(w, input.tokenId);
  writeAddress(w, input.spender);
  w.writeU64(input.amount);
  return w.finish();
}

/* ─── token_mint ─────────────────────────────────────────────────── */

export interface TokenMintInput extends BaseTxOptions {
  tokenId: Hex;
  to: AddressString | string;
  amount: BigNumberish;
}

/** bincode-encode the `TokenMintData` payload. */
export function encodeTokenMintData(input: TokenMintInput): Uint8Array {
  const w = new BincodeWriter();
  writeHash256(w, input.tokenId);
  writeAddress(w, input.to);
  w.writeU64(input.amount);
  return w.finish();
}

/* ─── token_burn ─────────────────────────────────────────────────── */

export interface TokenBurnInput extends BaseTxOptions {
  tokenId: Hex;
  amount: BigNumberish;
}

/** bincode-encode the `TokenBurnData` payload. */
export function encodeTokenBurnData(input: TokenBurnInput): Uint8Array {
  const w = new BincodeWriter();
  writeHash256(w, input.tokenId);
  w.writeU64(input.amount);
  return w.finish();
}

/* ─── tool lifecycle ─────────────────────────────────────────────── */

export interface ToolRegisterInput extends BaseTxOptions {
  name: string;
  description: string;
  endpoint: string;
  pricePerCall: BigNumberish;
  settlementMode?: HttpToolSettlementMode;
  slaMs?: BigNumberish;
  challengeWindowMs?: BigNumberish;
  maxResultMetadataBytes?: number;
  arbitrationPolicy?: ToolArbitrationPolicy;
  capabilities: readonly string[];
  matchEnabled?: boolean;
  neuralEmbedding?: readonly number[] | null;
  version?: string;
}

/** bincode-encode the `ToolRegisterData` payload. */
export function encodeToolRegisterData(input: ToolRegisterInput): Uint8Array {
  const w = new BincodeWriter();
  w.writeString(input.name);
  w.writeString(input.description);
  w.writeString(input.endpoint);
  w.writeU64(input.pricePerCall);
  writeSettlementMode(w, input.settlementMode ?? "prepaid_access");
  w.writeU64(input.slaMs ?? 3_600_000n);
  w.writeU64(input.challengeWindowMs ?? 900_000n);
  w.writeU32(input.maxResultMetadataBytes ?? 4_096);
  writeArbitrationPolicy(w, input.arbitrationPolicy ?? "protocol");
  w.writeVec(input.capabilities, writeCapability);
  w.writeU8(input.matchEnabled === false ? 0 : 1);
  writeOptionalEmbedding(w, input.neuralEmbedding);
  w.writeString(input.version ?? "1.0.0");
  return w.finish();
}

export interface ToolUpdateInput extends BaseTxOptions {
  toolId: Hex;
  description?: string | null;
  endpoint?: string | null;
  pricePerCall?: BigNumberish | null;
  settlementMode?: HttpToolSettlementMode | null;
  slaMs?: BigNumberish | null;
  challengeWindowMs?: BigNumberish | null;
  maxResultMetadataBytes?: number | null;
  arbitrationPolicy?: ToolArbitrationPolicy | null;
  capabilities?: readonly string[] | null;
  matchEnabled?: boolean | null;
  /** Some([]) clears the embedding on-chain; omit/null leaves it unchanged. */
  neuralEmbedding?: readonly number[] | null;
  version?: string | null;
  active?: boolean | null;
}

/** bincode-encode the `ToolUpdateData` payload. */
export function encodeToolUpdateData(input: ToolUpdateInput): Uint8Array {
  const w = new BincodeWriter();
  writeHash256(w, input.toolId);
  w.writeOption(input.description, (writer, value) => writer.writeString(value));
  w.writeOption(input.endpoint, (writer, value) => writer.writeString(value));
  w.writeOption(input.pricePerCall, (writer, value) => writer.writeU64(value));
  writeOptionalSettlementMode(w, input.settlementMode);
  w.writeOption(input.slaMs, (writer, value) => writer.writeU64(value));
  w.writeOption(input.challengeWindowMs, (writer, value) => writer.writeU64(value));
  w.writeOption(input.maxResultMetadataBytes, (writer, value) => writer.writeU32(value));
  writeOptionalArbitrationPolicy(w, input.arbitrationPolicy);
  writeOptionalCapabilities(w, input.capabilities);
  writeOptionalBool(w, input.matchEnabled);
  writeOptionalEmbedding(w, input.neuralEmbedding);
  w.writeOption(input.version, (writer, value) => writer.writeString(value));
  writeOptionalBool(w, input.active);
  return w.finish();
}

export interface ToolMilestoneInput {
  label: string;
  amount: BigNumberish;
}

function writeToolMilestone(w: BincodeWriter, value: ToolMilestoneInput): void {
  w.writeString(value.label);
  w.writeU64(value.amount);
}

export interface ToolInvokeInput extends BaseTxOptions {
  toolId: Hex;
  inputData?: Uint8Array;
  maxMeteredUnits?: BigNumberish | null;
  gasLimit?: BigNumberish;
  milestones?: readonly ToolMilestoneInput[];
}

/** bincode-encode the `ToolInvokeData` payload. */
export function encodeToolInvokeData(input: ToolInvokeInput): Uint8Array {
  const w = new BincodeWriter();
  writeHash256(w, input.toolId);
  w.writeBytes(input.inputData ?? new Uint8Array());
  w.writeOption(input.maxMeteredUnits, (writer, value) => writer.writeU64(value));
  w.writeU64(input.gasLimit ?? 400_000n);
  w.writeVec(input.milestones ?? [], writeToolMilestone);
  return w.finish();
}

export interface ToolDeregisterInput extends BaseTxOptions {
  toolId: Hex;
}

/** Encode the `ToolDeregister` payload: raw 32-byte tool id, matching the Rust handler. */
export function encodeToolDeregisterData(input: ToolDeregisterInput): Uint8Array {
  return hexToBytes(input.toolId, 32);
}

export interface ToolResultSubmitInput extends BaseTxOptions {
  jobId: Hex;
  resultHash: Hex;
  resultMetadata?: Uint8Array;
  milestoneIndex?: number | null;
}

/** bincode-encode the `ToolResultSubmitData` payload. */
export function encodeToolResultSubmitData(input: ToolResultSubmitInput): Uint8Array {
  const w = new BincodeWriter();
  writeHash256(w, input.jobId);
  writeHash256(w, input.resultHash);
  w.writeBytes(input.resultMetadata ?? new Uint8Array());
  w.writeOption(input.milestoneIndex, (writer, value) => writer.writeU32(value));
  return w.finish();
}

export interface ToolResultAcceptInput extends BaseTxOptions {
  jobId: Hex;
  milestoneIndex?: number | null;
}

/** bincode-encode the `ToolResultAcceptData` payload. */
export function encodeToolResultAcceptData(input: ToolResultAcceptInput): Uint8Array {
  const w = new BincodeWriter();
  writeHash256(w, input.jobId);
  w.writeOption(input.milestoneIndex, (writer, value) => writer.writeU32(value));
  return w.finish();
}

export interface ToolResultDisputeInput extends BaseTxOptions {
  jobId: Hex;
  reason: string;
  milestoneIndex?: number | null;
}

/** bincode-encode the `ToolResultDisputeData` payload. */
export function encodeToolResultDisputeData(input: ToolResultDisputeInput): Uint8Array {
  const w = new BincodeWriter();
  writeHash256(w, input.jobId);
  w.writeString(input.reason);
  w.writeOption(input.milestoneIndex, (writer, value) => writer.writeU32(value));
  return w.finish();
}

export interface ToolResultResolveInput extends BaseTxOptions {
  jobId: Hex;
  providerWins: boolean;
  reason: string;
  milestoneIndex?: number | null;
}

/** bincode-encode the `ToolResultResolveData` payload. */
export function encodeToolResultResolveData(input: ToolResultResolveInput): Uint8Array {
  const w = new BincodeWriter();
  writeHash256(w, input.jobId);
  w.writeU8(input.providerWins ? 1 : 0);
  w.writeString(input.reason);
  w.writeOption(input.milestoneIndex, (writer, value) => writer.writeU32(value));
  return w.finish();
}

export interface ToolJobExpireInput extends BaseTxOptions {
  jobId: Hex;
}

/** bincode-encode the `ToolJobExpireData` payload. */
export function encodeToolJobExpireData(input: ToolJobExpireInput): Uint8Array {
  const w = new BincodeWriter();
  writeHash256(w, input.jobId);
  return w.finish();
}

export interface ToolUsageReportInput extends BaseTxOptions {
  sessionId: Hex;
  unitsUsed: BigNumberish;
  resultHash: Hex;
  resultMetadata?: Uint8Array;
}

/** bincode-encode the `ToolUsageReportData` payload. */
export function encodeToolUsageReportData(input: ToolUsageReportInput): Uint8Array {
  const w = new BincodeWriter();
  writeHash256(w, input.sessionId);
  w.writeU64(input.unitsUsed);
  writeHash256(w, input.resultHash);
  w.writeBytes(input.resultMetadata ?? new Uint8Array());
  return w.finish();
}

export interface ToolUsageAcceptInput extends BaseTxOptions {
  sessionId: Hex;
}

/** bincode-encode the `ToolUsageAcceptData` payload. */
export function encodeToolUsageAcceptData(input: ToolUsageAcceptInput): Uint8Array {
  const w = new BincodeWriter();
  writeHash256(w, input.sessionId);
  return w.finish();
}

export interface ToolUsageDisputeInput extends BaseTxOptions {
  sessionId: Hex;
  reason: string;
}

/** bincode-encode the `ToolUsageDisputeData` payload. */
export function encodeToolUsageDisputeData(input: ToolUsageDisputeInput): Uint8Array {
  const w = new BincodeWriter();
  writeHash256(w, input.sessionId);
  w.writeString(input.reason);
  return w.finish();
}

export interface ToolUsageResolveInput extends BaseTxOptions {
  sessionId: Hex;
  providerWins: boolean;
  reason: string;
}

/** bincode-encode the `ToolUsageResolveData` payload. */
export function encodeToolUsageResolveData(input: ToolUsageResolveInput): Uint8Array {
  const w = new BincodeWriter();
  writeHash256(w, input.sessionId);
  w.writeU8(input.providerWins ? 1 : 0);
  w.writeString(input.reason);
  return w.finish();
}

export interface ToolUsageExpireInput extends BaseTxOptions {
  sessionId: Hex;
}

/** bincode-encode the `ToolUsageExpireData` payload. */
export function encodeToolUsageExpireData(input: ToolUsageExpireInput): Uint8Array {
  const w = new BincodeWriter();
  writeHash256(w, input.sessionId);
  return w.finish();
}

export interface ToolSubscriptionPlanCreateInput extends BaseTxOptions {
  toolId: Hex;
  name: string;
  pricePerPeriod: BigNumberish;
  periodMs?: BigNumberish;
  includedCalls?: number;
  includedCredits?: BigNumberish;
  overagePolicy?: SubscriptionOveragePolicy;
}

/** bincode-encode the `ToolSubscriptionPlanCreateData` payload. */
export function encodeToolSubscriptionPlanCreateData(input: ToolSubscriptionPlanCreateInput): Uint8Array {
  const w = new BincodeWriter();
  writeHash256(w, input.toolId);
  w.writeString(input.name);
  w.writeU64(input.pricePerPeriod);
  w.writeU64(input.periodMs ?? 2_592_000_000n);
  w.writeU32(input.includedCalls ?? 0);
  w.writeU64(input.includedCredits ?? 0n);
  writeSubscriptionOveragePolicy(w, input.overagePolicy ?? "deny");
  return w.finish();
}

export interface ToolSubscriptionPlanUpdateInput extends BaseTxOptions {
  planId: Hex;
  name?: string | null;
  pricePerPeriod?: BigNumberish | null;
  periodMs?: BigNumberish | null;
  includedCalls?: number | null;
  includedCredits?: BigNumberish | null;
  overagePolicy?: SubscriptionOveragePolicy | null;
  active?: boolean | null;
}

/** bincode-encode the `ToolSubscriptionPlanUpdateData` payload. */
export function encodeToolSubscriptionPlanUpdateData(input: ToolSubscriptionPlanUpdateInput): Uint8Array {
  const w = new BincodeWriter();
  writeHash256(w, input.planId);
  w.writeOption(input.name, (writer, value) => writer.writeString(value));
  w.writeOption(input.pricePerPeriod, (writer, value) => writer.writeU64(value));
  w.writeOption(input.periodMs, (writer, value) => writer.writeU64(value));
  w.writeOption(input.includedCalls, (writer, value) => writer.writeU32(value));
  w.writeOption(input.includedCredits, (writer, value) => writer.writeU64(value));
  writeOptionalSubscriptionOveragePolicy(w, input.overagePolicy);
  writeOptionalBool(w, input.active);
  return w.finish();
}

export interface ToolSubscriptionStartInput extends BaseTxOptions {
  planId: Hex;
  reserveAmount?: BigNumberish;
  autoRenew?: boolean;
}

/** bincode-encode the `ToolSubscriptionStartData` payload. */
export function encodeToolSubscriptionStartData(input: ToolSubscriptionStartInput): Uint8Array {
  const w = new BincodeWriter();
  writeHash256(w, input.planId);
  w.writeU64(input.reserveAmount ?? 0n);
  w.writeU8(input.autoRenew === false ? 0 : 1);
  return w.finish();
}

export interface ToolSubscriptionTopUpInput extends BaseTxOptions {
  subscriptionId: Hex;
  amount: BigNumberish;
}

/** bincode-encode the `ToolSubscriptionTopUpData` payload. */
export function encodeToolSubscriptionTopUpData(input: ToolSubscriptionTopUpInput): Uint8Array {
  const w = new BincodeWriter();
  writeHash256(w, input.subscriptionId);
  w.writeU64(input.amount);
  return w.finish();
}

export interface ToolSubscriptionCancelInput extends BaseTxOptions {
  subscriptionId: Hex;
}

/** bincode-encode the `ToolSubscriptionCancelData` payload. */
export function encodeToolSubscriptionCancelData(input: ToolSubscriptionCancelInput): Uint8Array {
  const w = new BincodeWriter();
  writeHash256(w, input.subscriptionId);
  return w.finish();
}

export interface ToolSubscriptionResumeInput extends BaseTxOptions {
  subscriptionId: Hex;
  reserveAmount?: BigNumberish;
}

/** bincode-encode the `ToolSubscriptionResumeData` payload. */
export function encodeToolSubscriptionResumeData(input: ToolSubscriptionResumeInput): Uint8Array {
  const w = new BincodeWriter();
  writeHash256(w, input.subscriptionId);
  w.writeU64(input.reserveAmount ?? 0n);
  return w.finish();
}

export interface ToolSubscriptionRenewInput extends BaseTxOptions {
  subscriptionId: Hex;
}

/** bincode-encode the `ToolSubscriptionRenewData` payload. */
export function encodeToolSubscriptionRenewData(input: ToolSubscriptionRenewInput): Uint8Array {
  const w = new BincodeWriter();
  writeHash256(w, input.subscriptionId);
  return w.finish();
}

/* ─── contracts ─────────────────────────────────────────────────── */

export type ContractSourceLanguage = "wat" | "rust" | "assemblyscript";

export interface ContractSourceProofInput {
  language: ContractSourceLanguage;
  compiler?: string;
  sourceCode: string;
  bytecodeWitness?: string | null;
}

export interface ContractAbiParamInput {
  name: string;
  ty: string;
  description?: string;
}

export interface ContractFunctionSignatureInput {
  name: string;
  description?: string;
  params?: readonly ContractAbiParamInput[];
  returns?: readonly ContractAbiParamInput[];
  mutates?: boolean;
}

export interface ContractAbiInput {
  name: string;
  version: string;
  functions: readonly ContractFunctionSignatureInput[];
}

export interface ContractDeployInput extends BaseTxOptions {
  bytecode: Uint8Array;
  /** Optional initial ZIN transferred to the deployed contract account. */
  amountMicroZin?: BigNumberish;
}

export interface ContractCallInput extends BaseTxOptions {
  contractAddress: AddressString | string;
  function: string;
  args?: Uint8Array;
  gasLimit: BigNumberish;
  /** Optional ZIN attached to the contract call. */
  amountMicroZin?: BigNumberish;
}

export interface ContractVerifyInput extends BaseTxOptions {
  contractAddress: AddressString | string;
  proof: ContractSourceProofInput;
}

export interface ContractPublishAbiInput extends BaseTxOptions {
  contractAddress: AddressString | string;
  abi: ContractAbiInput;
}

export interface ContractRouteUpdateInput extends BaseTxOptions {
  routeName: string;
  targetContractAddress: AddressString | string;
}

export interface ContractRouteCallInput extends BaseTxOptions {
  deployer: AddressString | string;
  routeName: string;
  function: string;
  args?: Uint8Array;
  gasLimit: BigNumberish;
  /** Optional ZIN attached to the routed contract call. */
  amountMicroZin?: BigNumberish;
}

export interface ContractDeactivateInput extends BaseTxOptions {
  contractAddress: AddressString | string;
}

function contractSourceLanguageCode(value: ContractSourceLanguage): number {
  switch (value) {
    case "wat":
      return 0;
    case "rust":
      return 1;
    case "assemblyscript":
      return 2;
    default:
      throw new Error(`unsupported contract source language: ${String(value)}`);
  }
}

function writeContractSourceLanguage(w: BincodeWriter, value: ContractSourceLanguage): void {
  w.writeU32(contractSourceLanguageCode(value));
}

function writeContractSourceProof(w: BincodeWriter, proof: ContractSourceProofInput): void {
  writeContractSourceLanguage(w, proof.language);
  w.writeString(proof.compiler ?? "");
  w.writeString(proof.sourceCode);
  w.writeOption(proof.bytecodeWitness, (writer, witness) => writer.writeString(witness));
}

function writeContractAbiParam(w: BincodeWriter, param: ContractAbiParamInput): void {
  w.writeString(param.name);
  w.writeString(param.ty);
  w.writeString(param.description ?? "");
}

function writeContractFunctionSignature(w: BincodeWriter, signature: ContractFunctionSignatureInput): void {
  w.writeString(signature.name);
  w.writeString(signature.description ?? "");
  w.writeVec(signature.params ?? [], writeContractAbiParam);
  w.writeVec(signature.returns ?? [], writeContractAbiParam);
  w.writeU8(signature.mutates ? 1 : 0);
}

function writeContractAbi(w: BincodeWriter, abi: ContractAbiInput): void {
  w.writeString(abi.name);
  w.writeString(abi.version);
  w.writeVec(abi.functions, writeContractFunctionSignature);
}

/** bincode-encode the `ContractDeployData` payload. */
export function encodeContractDeployData(input: ContractDeployInput): Uint8Array {
  const w = new BincodeWriter();
  w.writeBytes(input.bytecode);
  return w.finish();
}

/** bincode-encode the `ContractCallData` payload. */
export function encodeContractCallData(input: ContractCallInput): Uint8Array {
  const w = new BincodeWriter();
  writeAddress(w, input.contractAddress);
  w.writeString(input.function);
  w.writeBytes(input.args ?? new Uint8Array());
  w.writeU64(input.gasLimit);
  return w.finish();
}

/** bincode-encode the `ContractVerifyData` payload. */
export function encodeContractVerifyData(input: ContractVerifyInput): Uint8Array {
  const w = new BincodeWriter();
  writeAddress(w, input.contractAddress);
  writeContractSourceProof(w, input.proof);
  return w.finish();
}

/** bincode-encode the `ContractPublishAbiData` payload. */
export function encodeContractPublishAbiData(input: ContractPublishAbiInput): Uint8Array {
  const w = new BincodeWriter();
  writeAddress(w, input.contractAddress);
  writeContractAbi(w, input.abi);
  return w.finish();
}

/** bincode-encode the `ContractRouteUpdateData` payload. */
export function encodeContractRouteUpdateData(input: ContractRouteUpdateInput): Uint8Array {
  const w = new BincodeWriter();
  w.writeString(input.routeName);
  writeAddress(w, input.targetContractAddress);
  return w.finish();
}

/** bincode-encode the `ContractRouteCallData` payload. */
export function encodeContractRouteCallData(input: ContractRouteCallInput): Uint8Array {
  const w = new BincodeWriter();
  writeAddress(w, input.deployer);
  w.writeString(input.routeName);
  w.writeString(input.function);
  w.writeBytes(input.args ?? new Uint8Array());
  w.writeU64(input.gasLimit);
  return w.finish();
}

/**
 * Encode the `ContractDeactivate` payload. This transaction is intentionally
 * raw 20-byte address data on-chain rather than a bincode wrapper struct.
 */
export function encodeContractDeactivateData(input: ContractDeactivateInput): Uint8Array {
  return hexToBytes(rawAddressHex(input.contractAddress), 20);
}

/* ─── staking + validator basics ───────────────────────────────── */

export interface ValidatorExecutorServiceInput {
  partitionId: number;
  rpcEndpoint: string;
  executorPublicKey: Hex;
}

export interface ValidatorRegisterInput extends BaseTxOptions {
  stakeMicroZin: BigNumberish;
  executorServices?: readonly ValidatorExecutorServiceInput[];
  /** Defaults to the signing key's public key in ZinchaClient builders. */
  vrfPublicKey?: Hex | null;
}

export interface ValidatorUpdateInput extends BaseTxOptions {
  executorServices?: readonly ValidatorExecutorServiceInput[];
  vrfPublicKey?: Hex | null;
}

export interface ValidatorExitInput extends BaseTxOptions {}

export interface ValidatorVrfCommitInput extends BaseTxOptions {
  targetEpoch: BigNumberish;
  commitment: Hex;
}

export interface ValidatorVrfContributionInput extends BaseTxOptions {
  targetEpoch: BigNumberish;
  vrfOutput: Uint8Array;
  vrfProof: Uint8Array;
}

export type StakeTarget = "agent" | "validator" | "requester_auto_match";

export interface StakeInput extends BaseTxOptions {
  target: StakeTarget;
  amountMicroZin: BigNumberish;
}

export interface UnstakeInput extends BaseTxOptions {
  target: StakeTarget;
  amountMicroZin: BigNumberish;
}

function writeValidatorExecutorService(
  w: BincodeWriter,
  service: ValidatorExecutorServiceInput,
): void {
  w.writeU32(service.partitionId);
  w.writeString(service.rpcEndpoint);
  writePublicKey(w, service.executorPublicKey);
}

function encodeValidatorUpdatePayload(input: {
  executorServices?: readonly ValidatorExecutorServiceInput[];
  vrfPublicKey?: Hex | null;
}): Uint8Array {
  const w = new BincodeWriter();
  w.writeVec(input.executorServices ?? [], writeValidatorExecutorService);
  w.writeOption(input.vrfPublicKey, writePublicKey);
  return w.finish();
}

/** bincode-encode the `ValidatorUpdateData` payload used by validator registration. */
export function encodeValidatorRegisterData(
  input: Omit<ValidatorRegisterInput, "stakeMicroZin"> & { vrfPublicKey: Hex },
): Uint8Array {
  return encodeValidatorUpdatePayload(input);
}

/** bincode-encode the `ValidatorUpdateData` payload. */
export function encodeValidatorUpdateData(input: ValidatorUpdateInput): Uint8Array {
  return encodeValidatorUpdatePayload(input);
}

/** ValidatorExit has an empty payload. */
export function encodeValidatorExitData(_input: ValidatorExitInput = {}): Uint8Array {
  return new Uint8Array();
}

/** bincode-encode the `ValidatorVrfCommitData` payload. */
export function encodeValidatorVrfCommitData(input: ValidatorVrfCommitInput): Uint8Array {
  const w = new BincodeWriter();
  w.writeU64(input.targetEpoch);
  writeHash256(w, input.commitment);
  return w.finish();
}

/** bincode-encode the `ValidatorVrfContributionData` payload. */
export function encodeValidatorVrfContributionData(input: ValidatorVrfContributionInput): Uint8Array {
  const w = new BincodeWriter();
  w.writeU64(input.targetEpoch);
  w.writeBytes(input.vrfOutput);
  w.writeBytes(input.vrfProof);
  return w.finish();
}

function stakeTargetCode(target: StakeTarget): number {
  switch (target) {
    case "agent":
      return 0;
    case "validator":
      return 1;
    case "requester_auto_match":
      return 2;
    default:
      throw new Error(`unsupported stake target: ${String(target)}`);
  }
}

function encodeStakeTarget(target: StakeTarget): Uint8Array {
  const w = new BincodeWriter();
  w.writeU32(stakeTargetCode(target));
  return w.finish();
}

/** bincode-encode the `StakeTarget` payload for a `stake` transaction. */
export function encodeStakeData(input: Pick<StakeInput, "target">): Uint8Array {
  return encodeStakeTarget(input.target);
}

/** bincode-encode the `StakeTarget` payload for an `unstake` transaction. */
export function encodeUnstakeData(input: Pick<UnstakeInput, "target">): Uint8Array {
  return encodeStakeTarget(input.target);
}

/* ─── Generic wrapper ────────────────────────────────────────────── */

/**
 * Build an unsigned Transaction for a given tx type with a pre-encoded
 * data payload. Convenience around `createTransaction` for the typed
 * builders above.
 */
export function createSignableTransaction(input: {
  txType: TxTypeName;
  sender: AddressString | string;
  data: Uint8Array;
  nonce: BigNumberish;
  chainId: string;
  amountMicroZin?: BigNumberish;
  feeMicroZin?: BigNumberish;
  maxPriorityFeePerGas?: BigNumberish;
  timestampMs?: BigNumberish;
  referenceBlockHeight?: BigNumberish;
  referenceBlockHash?: Hex;
  maxValidBlockHeight?: BigNumberish;
}): Transaction {
  return createTransaction({
    txType: input.txType,
    sender: normalizeAddress(input.sender),
    nonce: asU64(input.nonce, "nonce"),
    chainId: input.chainId,
    amount: input.amountMicroZin,
    fee: input.feeMicroZin,
    maxPriorityFeePerGas: input.maxPriorityFeePerGas,
    timestampMs: input.timestampMs,
    data: input.data,
    referenceBlockHeight: input.referenceBlockHeight,
    referenceBlockHash: input.referenceBlockHash,
    maxValidBlockHeight: input.maxValidBlockHeight,
  });
}
