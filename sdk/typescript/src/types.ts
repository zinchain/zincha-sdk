export type Hex = string;
export type AddressString = `zn1${string}`;
export type ReleaseName = "polaris" | "vega" | "sirius" | "altair" | "lyra";
export type ReleaseStage =
  | "devnet"
  | "public-testnet"
  | "incentivized-testnet"
  | "mainnet"
  | "mainnet-upgrade";

export type BigNumberish = bigint | number | string;

export interface ApiResponse<T> {
  success: boolean;
  data: T | null;
  error: string | null;
}

export interface ReleaseSpec {
  name: ReleaseName;
  slug: ReleaseName;
  displayName: string;
  stage: ReleaseStage;
  chainId: string;
  canonicalRpcUrl: string;
  canonicalWebsocketUrl: string;
  bootNodes: readonly string[];
  explorerUrl?: string;
  faucetUrl?: string;
}

export interface ChainInfo {
  chain_id: string;
  release?: ReleaseName;
  release_name?: string;
  release_stage?: ReleaseStage;
  canonical_rpc_url?: string;
  canonical_websocket_url?: string;
  explorer_url?: string;
  faucet_url?: string;
  version: string;
  block_height: number;
  latest_block_hash: Hex;
  target_block_time_ms: number;
  transaction_ttl_blocks: number;
  transaction_reference_block_height: number;
  transaction_reference_block_hash: Hex;
  base_fee_per_gas: number;
  next_base_fee: number;
  contract_platform_profile_version: number;
  contract_platform_profile_id: Hex;
}

export interface BalanceResponse {
  address: AddressString;
  balance_micro_zin: number;
  balance_zin: number;
}

export interface NonceResponse {
  address: AddressString;
  nonce: number;
  next_nonce: number;
}

export interface TransactionHistoryQuery {
  limit?: number;
  cursor?: string;
}

export interface ParticipantWorkflowQuery {
  limit?: number;
  cursor?: string;
}

export interface CapabilityListQuery {
  limit?: number;
  cursor?: string;
  status?: "active" | "pending" | "deprecated" | "all" | string;
  category?: string;
  parent?: string;
}

export interface CapabilitySearchQuery {
  limit?: number;
  status?: "active" | "pending" | "deprecated" | "all" | string;
  category?: string;
}

export interface CapabilityUsageSummary {
  agent_count: number;
  tool_count: number;
  open_task_count: number;
  market_sample_count: number;
}

export interface CapabilityCatalogEntry {
  slug: string;
  display_name: string;
  description: string;
  category: string;
  parent?: string | null;
  status: "active" | "pending" | "rejected" | "deprecated" | string;
  aliases: string[];
  keywords: string[];
  examples: string[];
  related: string[];
  proposer?: AddressString | string | null;
  source: "seed" | "user_proposed" | "curated" | string;
  created_at_block: number;
  updated_at_block: number;
  usage: CapabilityUsageSummary;
}

export interface SubmitTransactionResponse {
  tx_hash: Hex;
  status: string;
}

export interface FaucetRequest {
  address: AddressString | string;
  amount_micro_zin?: number;
  amount_zin?: number;
}

export interface FaucetResponse extends SubmitTransactionResponse {
  recipient: AddressString;
  amount_micro_zin: number;
  fee_micro_zin: number;
  faucet_address: AddressString;
  address_claimed_today_micro_zin: number;
  global_distributed_today_micro_zin: number;
  global_reserved_cost_today_micro_zin?: number;
  global_reserve_balance_micro_zin?: number;
  limits: {
    address_cooldown_secs: number;
    address_daily_limit_micro_zin: number;
    global_daily_limit_micro_zin: number;
  };
}

export interface TransactionStatus {
  tx_hash: Hex;
  status: string;
  source: string;
  terminal: boolean;
  known: boolean;
  mempool_stage?: string | null;
  block_number?: number | null;
  block_hash?: Hex | null;
  block_timestamp_ms?: number | null;
  tx_index?: number | null;
  sender?: AddressString;
  tx_type?: string;
  nonce?: number;
  fee?: number;
  amount?: number;
  recipient?: AddressString;
  chain_id?: string;
  gas_used?: number;
  fee_charged?: number;
  error?: string | null;
}

export interface RequestOptions {
  query?: Record<string, string | number | boolean | undefined | null>;
  body?: unknown;
  bearerToken?: string;
  signed?: boolean;
  signal?: AbortSignal;
}

export interface SignedRequestSigner {
  address(): AddressString;
  publicKeyHex(): Hex;
  sign(message: Uint8Array): Uint8Array;
}

export interface ZinchaClientOptions {
  baseUrl?: string;
  faucetUrl?: string;
  websocketUrl?: string;
  release?: ReleaseName | string;
  bearerToken?: string;
  signer?: SignedRequestSigner;
  fetch?: typeof fetch;
}

export interface TransferInput {
  recipient: AddressString | string;
  amountMicroZin: BigNumberish;
  feeMicroZin?: BigNumberish;
  nonce?: BigNumberish;
  chainId?: string;
  timestampMs?: BigNumberish;
  maxPriorityFeePerGas?: BigNumberish;
  referenceBlockHeight?: BigNumberish;
  referenceBlockHash?: Hex;
  maxValidBlockHeight?: BigNumberish;
}

export interface Transaction {
  txType: TxTypeName;
  sender: AddressString;
  recipient: AddressString;
  amount: bigint;
  fee: bigint;
  maxPriorityFeePerGas: bigint;
  nonce: bigint;
  timestamp: bigint;
  referenceBlockHeight: bigint;
  referenceBlockHash: Hex;
  maxValidBlockHeight: bigint;
  data: Uint8Array;
  chainId: string;
}

export interface SignedTransaction {
  transaction: Transaction;
  signature: Hex;
  publicKey: Hex;
  hash: Hex;
}

export type TxTypeName =
  | "transfer"
  | "entity_link"
  | "agent_register"
  | "agent_update"
  | "task_submit"
  | "task_fulfill"
  | "task_cancel"
  | "reputation_update"
  | "task_accept"
  | "task_dispute"
  | "task_resolve"
  | "task_finalize"
  | "tool_register"
  | "tool_invoke"
  | "tool_result_submit"
  | "tool_result_accept"
  | "tool_result_dispute"
  | "tool_result_resolve"
  | "tool_job_expire"
  | "tool_subscription_plan_create"
  | "tool_subscription_plan_update"
  | "tool_subscription_start"
  | "tool_subscription_top_up"
  | "tool_subscription_cancel"
  | "tool_subscription_resume"
  | "tool_subscription_renew"
  | "tool_update"
  | "agreement_create"
  | "agreement_accept"
  | "agreement_execute"
  | "agreement_dispute"
  | "agreement_resolve"
  | "agreement_cancel"
  | "arbitrator_register"
  | "validator_register"
  | "validator_exit"
  | "validator_vrf_commit"
  | "validator_vrf_contribution"
  | "stake"
  | "unstake"
  | "task_decompose"
  | "batch"
  | "contract_deploy"
  | "contract_call"
  | "token_create"
  | "token_transfer"
  | "token_approve"
  | "token_mint"
  | "token_update_authority"
  | "token_burn"
  | "agent_deregister"
  | "tool_deregister"
  | "arbitrator_deregister"
  | "contract_deactivate"
  | "token_destroy"
  | "tool_usage_report"
  | "tool_usage_accept"
  | "tool_usage_dispute"
  | "tool_usage_resolve"
  | "tool_usage_expire"
  | "validator_update"
  | "contract_verify"
  | "contract_publish_abi"
  | "contract_route_update"
  | "contract_route_call"
  | "protocol_params_update"
  | "capability_propose"
  | "capability_approve"
  | "capability_reject"
  | "capability_deprecate";
