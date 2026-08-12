import assert from "node:assert/strict";
import { test } from "node:test";

import type {
  BalanceResponse,
  ChainInfo,
  FaucetResponse,
  MarketRate,
  NonceResponse,
  SubmitBatchResult,
  TransactionStatus,
} from "../src/types.ts";

const hash = "00".repeat(32);
const address = `zn1${"11".repeat(20)}` as `zn1${string}`;

const chainInfo = {
  chain_id: "zincha-vega-1",
  version: "0.1.0",
  block_height: 42,
  latest_block_hash: hash,
  target_block_time_ms: 1_000,
  transaction_ttl_blocks: 100,
  transaction_reference_block_height: 42,
  transaction_reference_block_hash: hash,
  base_fee_per_gas: 1,
  next_base_fee: 1,
  contract_platform_profile_version: 1,
  contract_platform_profile_id: hash,
  storage_mode: "archive",
  archive_mode: true,
  historical_reads_available: true,
  history_available_from: 0,
  history_available_to: 42,
  archive_backfill_complete: true,
} satisfies ChainInfo;

const balance = {
  address,
  balance_micro_zin: 1_000_000,
  balance_zin: 1,
  state_height: 42,
  state_hash: hash,
  state_root: hash,
  consistency: "committed",
} satisfies BalanceResponse;

const nonce = {
  address,
  committed_nonce: 3,
  nonce: 3,
  next_nonce: 4,
  state_height: 42,
  state_hash: hash,
  state_root: hash,
  consistency: "committed",
} satisfies NonceResponse;

const marketRate = {
  capability: "data.extraction",
  total_fulfilled: 10,
  avg_fee: 100,
  avg_fee_zin: 0.0001,
  median_fee: 90,
  median_fee_zin: 0.00009,
  min_fee: 50,
  max_fee: 150,
} satisfies MarketRate;

const faucet = {
  tx_hash: hash,
  status: "pending",
  recipient: address,
  amount_micro_zin: 1_000_000,
  fee_micro_zin: 1,
  faucet_address: address,
  address_claimed_today_micro_zin: 1_000_000,
  global_distributed_today_micro_zin: 2_000_000,
  global_reserved_cost_today_micro_zin: 2,
  global_reserve_balance_micro_zin: 1_000_000_000,
  limits: {
    address_cooldown_secs: 60,
    address_daily_limit_micro_zin: 10_000_000,
    global_daily_limit_micro_zin: 1_000_000_000,
  },
} satisfies FaucetResponse;

const transaction = {
  tx_hash: hash,
  status: "confirmed",
  source: "canonical_chain",
  terminal: true,
  known: true,
  mempool_stage: null,
  block_number: 42,
  block_hash: hash,
  block_timestamp_ms: 1_700_000_000_000,
  tx_index: 0,
  sender: address,
  tx_type: "Transfer",
  nonce: 3,
  fee: 100,
  amount: 1_000,
  recipient: address,
  chain_id: "zincha-vega-1",
  tx_data: { memo: "public" },
  gas_used: 21_000,
  gas_limit: 30_000,
  effective_gas_price: 2,
  base_fee_per_gas: 1,
  fee_charged: 42_000,
  fee_base_fee_total: 21_000,
  fee_burned: 10_500,
  fee_treasury: 5_250,
  fee_validator_base_fee: 5_250,
  fee_validator_tip: 21_000,
  fee_refunded: 58_000,
  rejection_reason: "not applicable",
  rejection_stage: "admission",
  rejected_at_ms: 1_700_000_000_000,
  rejected_at_block: 42,
  prepare_buffer_position: 0,
  prepare_buffer_size: 1,
  prepared_at_ms: 1_700_000_000_000,
  prepare_target_block_number: 43,
  prepare_target_timestamp_ms: 1_700_000_001_000,
  prepare_target_base_fee_per_gas: 1,
  private_orderflow: true,
  redacted: true,
} satisfies TransactionStatus;

const batch = {
  status: "batch-processed",
  accepted_count: 1,
  rejected_count: 1,
  tx_hashes: [hash],
  results: [
    { index: 0, status: "pending", tx_hash: hash, error: null },
    { index: 1, status: "rejected", tx_hash: null, error: "invalid" },
  ],
} satisfies SubmitBatchResult;

test("public response fixtures satisfy the current API types", () => {
  assert.equal(chainInfo.storage_mode, "archive");
  assert.equal(balance.consistency, "committed");
  assert.equal(nonce.committed_nonce, 3);
  assert.equal(marketRate.avg_fee_zin, 0.0001);
  assert.equal(faucet.global_reserve_balance_micro_zin, 1_000_000_000);
  assert.equal(transaction.source, "canonical_chain");
  assert.equal(batch.results.length, 2);
});
