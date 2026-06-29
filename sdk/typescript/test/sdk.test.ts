import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import {
  BincodeWriter,
  Keypair,
  ZinchaApiError,
  ZinchaClient,
  bytesToHex,
  createTransferTransaction,
  encodeAgentDeregisterData,
  encodeAgentRegisterData,
  encodeAgentUpdateData,
  encodeTaskAcceptData,
  encodeTaskCancelData,
  encodeTaskDisputeData,
  encodeTaskFinalizeData,
  encodeTaskFulfillData,
  encodeTaskResolveData,
  encodeTaskSubmitData,
  encodeToolDeregisterData,
  encodeToolInvokeData,
  encodeToolJobExpireData,
  encodeToolRegisterData,
  encodeToolResultAcceptData,
  encodeToolResultDisputeData,
  encodeToolResultResolveData,
  encodeToolResultSubmitData,
  encodeToolSubscriptionCancelData,
  encodeToolSubscriptionPlanCreateData,
  encodeToolSubscriptionPlanUpdateData,
  encodeToolSubscriptionRenewData,
  encodeToolSubscriptionResumeData,
  encodeToolSubscriptionStartData,
  encodeToolSubscriptionTopUpData,
  encodeToolUpdateData,
  encodeToolUsageAcceptData,
  encodeToolUsageDisputeData,
  encodeToolUsageExpireData,
  encodeToolUsageReportData,
  encodeToolUsageResolveData,
  encodeContractCallData,
  encodeContractDeactivateData,
  encodeContractDeployData,
  encodeContractPublishAbiData,
  encodeContractRouteCallData,
  encodeContractRouteUpdateData,
  encodeContractVerifyData,
  encodeTokenApproveData,
  encodeTokenBurnData,
  encodeTokenCreateData,
  encodeTokenMintData,
  encodeTokenTransferData,
  encodeStakeData,
  encodeUnstakeData,
  encodeValidatorExitData,
  encodeValidatorRegisterData,
  encodeValidatorUpdateData,
  encodeValidatorVrfCommitData,
  encodeValidatorVrfContributionData,
  releaseSpec,
  signedRequestHeaders,
  signedTransactionHex,
  signTransaction,
  withValidityWindow,
} from "../src/index.ts";

const golden = JSON.parse(
  readFileSync(new URL("../../testdata/golden-transfer.json", import.meta.url), "utf8"),
);

test("release catalog mirrors Rust release endpoints", () => {
  assert.equal(releaseSpec("vega").chainId, "zincha-vega-1");
  assert.equal(releaseSpec("vega").canonicalRpcUrl, "https://vega.zincha.com");
  assert.equal(releaseSpec("vega").faucetUrl, "https://faucet.vega.zincha.com");
  assert.equal(releaseSpec("vega").explorerUrl, "https://vega.zinscan.com");
  assert.equal(releaseSpec("testnet").slug, "vega");
  assert.equal(releaseSpec("sirius").canonicalWebsocketUrl, "wss://sirius.zincha.com");
  assert.equal(releaseSpec("mainnet").slug, "altair");
});

test("keypair derives Rust-compatible public key and address", () => {
  const keypair = Keypair.fromSecretHex(golden.secret_hex);
  assert.equal(keypair.publicKeyHex(), golden.public_key_hex);
  assert.equal(keypair.address(), golden.sender);
});

test("transfer serialization, hash, signature, and signed bytes match Rust golden vector", () => {
  const keypair = Keypair.fromSecretHex(golden.secret_hex);
  let tx = createTransferTransaction(keypair, {
    recipient: golden.recipient,
    amountMicroZin: golden.unsigned_transaction.amount,
    feeMicroZin: golden.unsigned_transaction.fee,
    nonce: golden.unsigned_transaction.nonce,
    chainId: golden.unsigned_transaction.chain_id,
    timestampMs: golden.unsigned_transaction.timestamp,
    maxPriorityFeePerGas: golden.unsigned_transaction.max_priority_fee_per_gas,
  });
  tx = withValidityWindow(
    tx,
    golden.unsigned_transaction.reference_block_height,
    golden.unsigned_transaction.reference_block_hash,
    100,
  );
  const signed = signTransaction(tx, keypair);
  assert.equal(signed.hash, golden.transaction_hash);
  assert.equal(signed.signature, golden.signature_hex);
  assert.equal(signed.publicKey, golden.public_key_hex);
  assert.equal(signedTransactionHex(signed), golden.signed_tx_hex);
});

test("signed request headers match Rust request-auth message shape", () => {
  const keypair = Keypair.fromSecretHex(golden.secret_hex);
  const body = JSON.stringify({ hello: "zincha" });
  const headers = signedRequestHeaders(keypair, {
    method: "POST",
    requestTarget: "/v1/tasks/estimate-fee?x=1",
    body,
    nonce: "nonce-1",
    timestampMs: 1_700_000_000_000,
  });
  assert.equal(headers["x-zincha-address"], golden.sender);
  assert.equal(headers["x-zincha-public-key"], golden.public_key_hex);
  assert.equal(headers["x-zincha-timestamp-ms"], "1700000000000");
  assert.equal(headers["x-zincha-nonce"], "nonce-1");
  assert.match(headers["x-zincha-body-sha256"], /^[0-9a-f]{64}$/);
  assert.match(headers["x-zincha-signature"], /^[0-9a-f]{128}$/);
  assert.equal(bytesToHex(keypair.sign(new TextEncoder().encode("hello"))).length, 128);
});

test("client unwraps API responses and surfaces API errors", async () => {
  const calls: Array<{ url: string; init: RequestInit }> = [];
  const client = new ZinchaClient({
    baseUrl: "http://node.test/",
    fetch: async (url, init = {}) => {
      calls.push({ url: String(url), init });
      if (String(url).endsWith("/v1/chain/info")) {
        return jsonResponse(200, {
          success: true,
          data: {
            chain_id: "zincha-vega-1",
            version: "0.1.0",
            block_height: 1,
            latest_block_hash: "00".repeat(32),
            target_block_time_ms: 1000,
            transaction_ttl_blocks: 100,
            transaction_reference_block_height: 1,
            transaction_reference_block_hash: "00".repeat(32),
            base_fee_per_gas: 1,
            next_base_fee: 1,
            contract_platform_profile_version: 1,
            contract_platform_profile_id: "11".repeat(32),
          },
          error: null,
        });
      }
      return jsonResponse(429, {
        success: false,
        data: { retry_after_secs: 10 },
        error: "rate limited",
      });
    },
  });

  const info = await client.chainInfo();
  assert.equal(info.chain_id, "zincha-vega-1");
  assert.equal(calls[0].url, "http://node.test/v1/chain/info");

  await assert.rejects(
    () => client.requestFaucet({ address: golden.sender }),
    (error: unknown) => {
      assert.ok(error instanceof ZinchaApiError);
      assert.equal(error.status, 429);
      assert.deepEqual(error.data, { retry_after_secs: 10 });
      return true;
    },
  );
});

test("release faucet helper uses release faucet API while normal calls use canonical RPC", async () => {
  const calls: Array<{ url: string; init: RequestInit }> = [];
  const client = ZinchaClient.forRelease("vega", {
    fetch: async (url, init = {}) => {
      calls.push({ url: String(url), init });
      if (String(url).endsWith("/v1/chain/info")) {
        return jsonResponse(200, {
          success: true,
          data: {
            chain_id: "zincha-vega-1",
            version: "0.1.0",
            block_height: 1,
            latest_block_hash: "00".repeat(32),
            target_block_time_ms: 1000,
            transaction_ttl_blocks: 100,
            transaction_reference_block_height: 1,
            transaction_reference_block_hash: "00".repeat(32),
            base_fee_per_gas: 1,
            next_base_fee: 1,
            contract_platform_profile_version: 1,
            contract_platform_profile_id: "11".repeat(32),
          },
          error: null,
        });
      }
      return jsonResponse(200, {
        success: true,
        data: {
          hash: "22".repeat(32),
          accepted: true,
          amount_micro_zin: "10000000",
          faucet_address: golden.recipient,
        },
        error: null,
      });
    },
  });

  await client.chainInfo();
  await client.requestFaucet({ address: golden.sender });

  assert.equal(calls[0].url, "https://vega.zincha.com/v1/chain/info");
  assert.equal(calls[1].url, "https://faucet.vega.zincha.com/v1/faucet");
});

test("faucet helper fails closed on mainnet releases", async () => {
  const client = ZinchaClient.forRelease("altair", {
    fetch: async () => jsonResponse(200, { success: true, data: {}, error: null }),
  });
  assert.throws(
    () => client.requestFaucet({ address: golden.sender }),
    /faucet is unavailable for mainnet releases/,
  );
});

test("typed builders pin validity window even when chainId is provided", async () => {
  const keypair = Keypair.fromSecretHex(golden.secret_hex);
  const calls: string[] = [];
  const client = new ZinchaClient({
    baseUrl: "http://node.test/",
    fetch: async (url) => {
      calls.push(String(url));
      if (String(url).endsWith("/v1/chain/info")) {
        return jsonResponse(200, {
          success: true,
          data: {
            chain_id: "zincha-vega-1",
            version: "0.1.0",
            block_height: 42,
            latest_block_hash: "22".repeat(32),
            target_block_time_ms: 1000,
            transaction_ttl_blocks: 100,
            transaction_reference_block_height: 42,
            transaction_reference_block_hash: "11".repeat(32),
            base_fee_per_gas: 1,
            next_base_fee: 1,
            contract_platform_profile_version: 1,
            contract_platform_profile_id: "33".repeat(32),
          },
          error: null,
        });
      }
      if (String(url).endsWith("/nonce")) {
        return jsonResponse(200, {
          success: true,
          data: { address: keypair.address(), nonce: 3, next_nonce: 4 },
          error: null,
        });
      }
      throw new Error(`unexpected URL ${url}`);
    },
  });

  const signed = await client.buildRegisterAgent(keypair, {
    name: "DataAnalyst",
    description: "High-performance financial analysis agent",
    capabilities: ["data.analysis"],
    chainId: "zincha-vega-1",
    feeMicroZin: 1_000n,
    timestampMs: 1_700_000_000_456n,
  });

  assert.ok(calls.some((url) => url.endsWith("/v1/chain/info")));
  assert.equal(signed.transaction.referenceBlockHeight, 42n);
  assert.equal(signed.transaction.referenceBlockHash, "11".repeat(32));
  assert.equal(signed.transaction.maxValidBlockHeight, 142n);
});

test("typed builders reject partial validity windows", async () => {
  const keypair = Keypair.fromSecretHex(golden.secret_hex);
  const client = new ZinchaClient({
    baseUrl: "http://node.test/",
    fetch: async () => {
      throw new Error("network should not be used for partial validity input");
    },
  });

  await assert.rejects(
    () => client.buildSubmitTask(keypair, {
      description: "Summarize Q4 trends in financial markets",
      requiredCapabilities: ["data.analysis"],
      maxFeeMicroZin: 50_000_000n,
      chainId: "zincha-vega-1",
      nonce: 5n,
      referenceBlockHeight: 42n,
    }),
    /referenceBlockHeight, referenceBlockHash, and maxValidBlockHeight must be provided together/,
  );
});

function jsonResponse(status: number, payload: unknown): Response {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { "content-type": "application/json" },
  });
}

/* ─── BincodeWriter primitive tests ───────────────────────────── */

test("BincodeWriter emits little-endian primitives matching bincode v1 wire format", () => {
  const w = new BincodeWriter();
  w.writeU8(1);
  w.writeU32(0x12345678);
  w.writeU64(0x0102030405060708n);
  assert.equal(
    bytesToHex(w.finish()),
    "0178563412" + "0807060504030201",
  );
});

test("BincodeWriter encodes Option<T>: None = 00, Some = 01 + payload", () => {
  const none = new BincodeWriter();
  none.writeOption<number>(null, (writer, value) => writer.writeU32(value));
  assert.equal(bytesToHex(none.finish()), "00");

  const some = new BincodeWriter();
  some.writeOption<number>(42, (writer, value) => writer.writeU32(value));
  assert.equal(bytesToHex(some.finish()), "01" + "2a000000");
});

test("BincodeWriter encodes Vec<T> as u64 length + each element", () => {
  const w = new BincodeWriter();
  w.writeVec(["a", "bc"], (writer, value) => writer.writeString(value));
  // len=2 (u64 LE), "a" (len=1 + 0x61), "bc" (len=2 + 0x6263)
  assert.equal(
    bytesToHex(w.finish()),
    "0200000000000000" + "0100000000000000" + "61" + "0200000000000000" + "6263",
  );
});

test("BincodeWriter writeF32 / writeF64 use little-endian IEEE 754", () => {
  const f32 = new BincodeWriter();
  f32.writeF32(1.0);
  assert.equal(bytesToHex(f32.finish()), "0000803f");

  const f64 = new BincodeWriter();
  f64.writeF64(2.5);
  assert.equal(bytesToHex(f64.finish()), "0000000000000440");
});

/* ─── encodeAgentRegisterData unit test ───────────────────────── */

test("encodeAgentRegisterData zero-filled fields produce the bincode wire layout", () => {
  // Empty strings, no embedding, zero hash, no caps, no metadata, zero min_fee,
  // empty fee schedule. Hash256 follows the Rust serde hex-string form.
  const bytes = encodeAgentRegisterData({
    name: "",
    description: "",
    capabilities: [],
  });
  const expected =
    "0000000000000000" +              // name ""
    "0000000000000000" +              // description ""
    "00" +                             // neural_embedding None
    "4000000000000000" +              // model_hash string length 64
    "30".repeat(64) +                 // model_hash zero hex string
    "0000000000000000" +              // capabilities
    "0000000000000000" +              // metadata
    "0000000000000000" +              // min_fee
    "0000000000000000";               // fee_schedule
  assert.equal(bytes.length, 121);
  assert.equal(bytesToHex(bytes), expected);
});

test("encodeAgentRegisterData emits expected bytes for a small input", () => {
  // name="ab", desc="", neural_embedding=None, model_hash=[0;32], caps=["x"],
  // metadata=[], min_fee=0, fee_schedule=[]
  const bytes = encodeAgentRegisterData({
    name: "ab",
    description: "",
    capabilities: ["x"],
  });
  const expected =
    "0200000000000000" + "6162" +     // name "ab"
    "0000000000000000" +               // description ""
    "00" +                              // neural_embedding None
    "4000000000000000" +               // model_hash string length 64
    "30".repeat(64) +                  // model_hash zero hex string
    "0100000000000000" +               // capabilities Vec len 1
    "0100000000000000" + "78" +       // Capability("x")
    "0000000000000000" +               // metadata Vec len 0
    "0000000000000000" +               // min_fee 0
    "0000000000000000";                // fee_schedule Vec len 0
  assert.equal(bytesToHex(bytes), expected);
});

test("encodeAgentRegisterData encodes Some(neural_embedding) Vec<f32>", () => {
  const bytes = encodeAgentRegisterData({
    name: "",
    description: "",
    capabilities: [],
    neuralEmbedding: [1.0, 2.0],
  });
  const expected =
    "0000000000000000" +              // name ""
    "0000000000000000" +              // description ""
    "01" +                             // neural_embedding Some tag
    "0200000000000000" +              // Vec<f32> len 2
    "0000803f" + "00000040" +        // f32 1.0, f32 2.0
    "4000000000000000" +              // model_hash string length 64
    "30".repeat(64) +                 // model_hash zero hex string
    "0000000000000000" +              // capabilities
    "0000000000000000" +              // metadata
    "0000000000000000" +              // min_fee
    "0000000000000000";               // fee_schedule
  assert.equal(bytesToHex(bytes), expected);
});

/* ─── encodeTaskSubmitData unit test ──────────────────────────── */

test("encodeTaskSubmitData with defaults emits MatchPreferences::default()", () => {
  const bytes = encodeTaskSubmitData({
    description: "x",
    requiredCapabilities: [],
    maxFeeMicroZin: 0n,
  });
  // description "x": 8 + 1
  // neural_embedding: 1 (None)
  // required_capabilities: 8 (empty Vec)
  // max_fee: 8 (0)
  // priority: 1 (0)
  // deadline: 8 (0)
  // parameters: 8 (empty Vec)
  // MatchPreferences defaults:
  //   w_semantic 30, w_reputation 30, w_price 20, w_freshness 10, w_stake 10 (5x u8 = 5)
  //   min_reputation 0.0 (f64 = 8)
  //   max_price 0 (u64 = 8)
  //   discovery_threshold 10 (u32 = 4)
  //   discovery_boost 15 (u8 = 1)
  // Total: 9 + 1 + 8 + 8 + 1 + 8 + 8 + 5 + 8 + 8 + 4 + 1 = 69
  assert.equal(bytes.length, 69);

  const expected =
    "0100000000000000" + "78" +       // description "x"
    "00" +                              // neural_embedding None
    "0000000000000000" +               // required_capabilities Vec len 0
    "0000000000000000" +               // max_fee 0
    "00" +                              // priority 0
    "0000000000000000" +               // deadline 0
    "0000000000000000" +               // parameters Vec len 0
    "1e" + "1e" + "14" + "0a" + "0a" + // weights
    "0000000000000000" +               // min_reputation 0.0
    "0000000000000000" +               // max_price 0
    "0a000000" +                       // discovery_threshold 10
    "0f";                               // discovery_boost 15
  assert.equal(bytesToHex(bytes), expected);
});

/* ─── Golden vector tests ─────────────────────────────────────── */
//
// The fixture files are generated by the Rust test
// `cargo test --test sdk_vectors` with `ZINCHA_WRITE_SDK_GOLDEN=1`.
// They are checked in and must be present.

test("encodeAgentRegisterData matches Rust golden vector", () => {
  const path = new URL("../../testdata/golden-agent-register.json", import.meta.url);
  const golden = JSON.parse(readFileSync(path, "utf8"));
  const input = golden.input;

  const data = encodeAgentRegisterData({
    name: input.name,
    description: input.description,
    capabilities: input.capabilities,
    minFeeMicroZin: input.min_fee_micro_zin,
    feeSchedule: input.fee_schedule,
  });
  assert.equal(bytesToHex(data), golden.data_hex);
});

test("encodeTaskSubmitData matches Rust golden vector", () => {
  const path = new URL("../../testdata/golden-task-submit.json", import.meta.url);
  const golden = JSON.parse(readFileSync(path, "utf8"));
  const input = golden.input;
  const prefs = input.match_preferences;

  const data = encodeTaskSubmitData({
    description: input.description,
    requiredCapabilities: input.required_capabilities,
    maxFeeMicroZin: input.max_fee_micro_zin,
    priority: input.priority,
    deadlineMs: input.deadline_ms,
    matchPreferences: {
      wSemantic: prefs.w_semantic,
      wReputation: prefs.w_reputation,
      wPrice: prefs.w_price,
      wFreshness: prefs.w_freshness,
      wStake: prefs.w_stake,
      minReputation: prefs.min_reputation,
      maxPrice: prefs.max_price,
      discoveryThreshold: prefs.discovery_threshold,
      discoveryBoost: prefs.discovery_boost,
    },
  });
  assert.equal(bytesToHex(data), golden.data_hex);
});

test("task lifecycle encoders match Rust golden vector", () => {
  const path = new URL("../../testdata/golden-task-lifecycle.json", import.meta.url);
  const golden = JSON.parse(readFileSync(path, "utf8"));

  const fulfill = encodeTaskFulfillData({
    taskId: golden.fulfill.input.task_id,
    resultHash: golden.fulfill.input.result_hash,
    resultData: Uint8Array.from(Buffer.from(golden.fulfill.input.result_data_hex, "hex")),
    toolsUsed: golden.fulfill.input.tools_used,
    inputRefs: golden.fulfill.input.input_refs,
    receiptProofs: golden.fulfill.input.receipt_proofs.map((proof: any) => ({
      receipt: {
        tokenId: proof.receipt.token_id,
        toolId: proof.receipt.tool_id,
        invoker: proof.receipt.invoker,
        amountPaid: proof.receipt.amount_paid,
        issuedAt: proof.receipt.issued_at,
        blockNumber: proof.receipt.block_number,
        nonce: proof.receipt.nonce,
      },
      proofSiblings: proof.proof_siblings,
      receiptRoot: proof.receipt_root,
    })),
  });
  assert.equal(bytesToHex(fulfill), golden.fulfill.data_hex);

  const accept = encodeTaskAcceptData({ taskId: golden.accept.input.task_id });
  assert.equal(bytesToHex(accept), golden.accept.data_hex);

  const dispute = encodeTaskDisputeData({
    taskId: golden.dispute.input.task_id,
    reason: golden.dispute.input.reason,
  });
  assert.equal(bytesToHex(dispute), golden.dispute.data_hex);

  const resolve = encodeTaskResolveData({
    taskId: golden.resolve.input.task_id,
    agentWins: golden.resolve.input.agent_wins,
    reason: golden.resolve.input.reason,
  });
  assert.equal(bytesToHex(resolve), golden.resolve.data_hex);

  const finalize = encodeTaskFinalizeData({ taskId: golden.finalize.input.task_id });
  assert.equal(bytesToHex(finalize), golden.finalize.data_hex);

  const cancel = encodeTaskCancelData({ taskId: golden.cancel.input.task_id });
  assert.equal(bytesToHex(cancel), golden.cancel.data_hex);
});

test("task lifecycle builders produce Rust-compatible signed transactions", async () => {
  const path = new URL("../../testdata/golden-task-lifecycle.json", import.meta.url);
  const golden = JSON.parse(readFileSync(path, "utf8"));
  const keypair = Keypair.fromSecretHex(golden.secret_hex);
  const client = new ZinchaClient({
    baseUrl: "http://node.test/",
    fetch: async () => {
      throw new Error("network should not be used when chain, nonce, and validity are explicit");
    },
  });

  const common = (transaction: typeof golden.fulfill.transaction) => ({
    feeMicroZin: transaction.fee_micro_zin,
    nonce: transaction.nonce,
    chainId: transaction.chain_id,
    timestampMs: transaction.timestamp,
    referenceBlockHeight: transaction.reference_block_height,
    referenceBlockHash: transaction.reference_block_hash,
    maxValidBlockHeight: transaction.max_valid_block_height,
  });

  const fulfill = await client.buildFulfillTask(keypair, {
    ...common(golden.fulfill.transaction),
    taskId: golden.fulfill.input.task_id,
    resultHash: golden.fulfill.input.result_hash,
    resultData: Uint8Array.from(Buffer.from(golden.fulfill.input.result_data_hex, "hex")),
    toolsUsed: golden.fulfill.input.tools_used,
    inputRefs: golden.fulfill.input.input_refs,
    receiptProofs: golden.fulfill.input.receipt_proofs.map((proof: any) => ({
      receipt: {
        tokenId: proof.receipt.token_id,
        toolId: proof.receipt.tool_id,
        invoker: proof.receipt.invoker,
        amountPaid: proof.receipt.amount_paid,
        issuedAt: proof.receipt.issued_at,
        blockNumber: proof.receipt.block_number,
        nonce: proof.receipt.nonce,
      },
      proofSiblings: proof.proof_siblings,
      receiptRoot: proof.receipt_root,
    })),
  });
  assert.equal(signedTransactionHex(fulfill), golden.fulfill.transaction.signed_tx_hex);

  const accept = await client.buildAcceptTask(keypair, {
    ...common(golden.accept.transaction),
    taskId: golden.accept.input.task_id,
  });
  assert.equal(signedTransactionHex(accept), golden.accept.transaction.signed_tx_hex);

  const dispute = await client.buildDisputeTask(keypair, {
    ...common(golden.dispute.transaction),
    taskId: golden.dispute.input.task_id,
    reason: golden.dispute.input.reason,
  });
  assert.equal(signedTransactionHex(dispute), golden.dispute.transaction.signed_tx_hex);

  const resolve = await client.buildResolveTask(keypair, {
    ...common(golden.resolve.transaction),
    taskId: golden.resolve.input.task_id,
    agentWins: golden.resolve.input.agent_wins,
    reason: golden.resolve.input.reason,
  });
  assert.equal(signedTransactionHex(resolve), golden.resolve.transaction.signed_tx_hex);

  const finalize = await client.buildFinalizeTask(keypair, {
    ...common(golden.finalize.transaction),
    taskId: golden.finalize.input.task_id,
  });
  assert.equal(signedTransactionHex(finalize), golden.finalize.transaction.signed_tx_hex);

  const cancel = await client.buildCancelTask(keypair, {
    ...common(golden.cancel.transaction),
    taskId: golden.cancel.input.task_id,
  });
  assert.equal(signedTransactionHex(cancel), golden.cancel.transaction.signed_tx_hex);
});

test("agent/tool lifecycle encoders match Rust golden vector", () => {
  const path = new URL("../../testdata/golden-agent-tool-lifecycle.json", import.meta.url);
  const golden = JSON.parse(readFileSync(path, "utf8"));

  const agentUpdate = encodeAgentUpdateData({
    name: golden.agent_update.input.name,
    description: golden.agent_update.input.description,
    neuralEmbedding: golden.agent_update.input.neural_embedding,
    modelHash: golden.agent_update.input.model_hash,
    capabilities: golden.agent_update.input.capabilities,
    metadata: Uint8Array.from(Buffer.from(golden.agent_update.input.metadata_hex, "hex")),
    active: golden.agent_update.input.active,
    minFeeMicroZin: golden.agent_update.input.min_fee_micro_zin,
    feeSchedule: golden.agent_update.input.fee_schedule,
  });
  assert.equal(bytesToHex(agentUpdate), golden.agent_update.data_hex);

  const agentDeregister = encodeAgentDeregisterData();
  assert.equal(bytesToHex(agentDeregister), golden.agent_deregister.data_hex);

  const toolRegister = encodeToolRegisterData({
    name: golden.tool_register.input.name,
    description: golden.tool_register.input.description,
    endpoint: golden.tool_register.input.endpoint,
    pricePerCall: golden.tool_register.input.price_per_call,
    settlementMode: golden.tool_register.input.settlement_mode,
    slaMs: golden.tool_register.input.sla_ms,
    challengeWindowMs: golden.tool_register.input.challenge_window_ms,
    maxResultMetadataBytes: golden.tool_register.input.max_result_metadata_bytes,
    arbitrationPolicy: golden.tool_register.input.arbitration_policy,
    capabilities: golden.tool_register.input.capabilities,
    matchEnabled: golden.tool_register.input.match_enabled,
    neuralEmbedding: golden.tool_register.input.neural_embedding,
    version: golden.tool_register.input.version,
  });
  assert.equal(bytesToHex(toolRegister), golden.tool_register.data_hex);

  const toolInvoke = encodeToolInvokeData({
    toolId: golden.tool_invoke.input.tool_id,
    inputData: Uint8Array.from(Buffer.from(golden.tool_invoke.input.input_data_hex, "hex")),
    maxMeteredUnits: golden.tool_invoke.input.max_metered_units,
    gasLimit: golden.tool_invoke.input.gas_limit,
    milestones: golden.tool_invoke.input.milestones,
  });
  assert.equal(bytesToHex(toolInvoke), golden.tool_invoke.data_hex);

  const toolUpdate = encodeToolUpdateData({
    toolId: golden.tool_update.input.tool_id,
    description: golden.tool_update.input.description,
    endpoint: golden.tool_update.input.endpoint,
    pricePerCall: golden.tool_update.input.price_per_call,
    settlementMode: golden.tool_update.input.settlement_mode,
    slaMs: golden.tool_update.input.sla_ms,
    challengeWindowMs: golden.tool_update.input.challenge_window_ms,
    maxResultMetadataBytes: golden.tool_update.input.max_result_metadata_bytes,
    arbitrationPolicy: golden.tool_update.input.arbitration_policy,
    capabilities: golden.tool_update.input.capabilities,
    matchEnabled: golden.tool_update.input.match_enabled,
    neuralEmbedding: golden.tool_update.input.neural_embedding,
    version: golden.tool_update.input.version,
    active: golden.tool_update.input.active,
  });
  assert.equal(bytesToHex(toolUpdate), golden.tool_update.data_hex);

  const toolDeregister = encodeToolDeregisterData({
    toolId: golden.tool_deregister.input.tool_id,
  });
  assert.equal(bytesToHex(toolDeregister), golden.tool_deregister.data_hex);

  assert.equal(bytesToHex(encodeToolResultSubmitData({
    jobId: golden.tool_result_submit.input.job_id,
    resultHash: golden.tool_result_submit.input.result_hash,
    resultMetadata: Uint8Array.from(Buffer.from(golden.tool_result_submit.input.result_metadata_hex, "hex")),
    milestoneIndex: golden.tool_result_submit.input.milestone_index,
  })), golden.tool_result_submit.data_hex);
  assert.equal(bytesToHex(encodeToolResultAcceptData({
    jobId: golden.tool_result_accept.input.job_id,
    milestoneIndex: golden.tool_result_accept.input.milestone_index,
  })), golden.tool_result_accept.data_hex);
  assert.equal(bytesToHex(encodeToolResultDisputeData({
    jobId: golden.tool_result_dispute.input.job_id,
    reason: golden.tool_result_dispute.input.reason,
    milestoneIndex: golden.tool_result_dispute.input.milestone_index,
  })), golden.tool_result_dispute.data_hex);
  assert.equal(bytesToHex(encodeToolResultResolveData({
    jobId: golden.tool_result_resolve.input.job_id,
    providerWins: golden.tool_result_resolve.input.provider_wins,
    reason: golden.tool_result_resolve.input.reason,
    milestoneIndex: golden.tool_result_resolve.input.milestone_index,
  })), golden.tool_result_resolve.data_hex);
  assert.equal(bytesToHex(encodeToolJobExpireData({
    jobId: golden.tool_job_expire.input.job_id,
  })), golden.tool_job_expire.data_hex);
  assert.equal(bytesToHex(encodeToolUsageReportData({
    sessionId: golden.tool_usage_report.input.session_id,
    unitsUsed: golden.tool_usage_report.input.units_used,
    resultHash: golden.tool_usage_report.input.result_hash,
    resultMetadata: Uint8Array.from(Buffer.from(golden.tool_usage_report.input.result_metadata_hex, "hex")),
  })), golden.tool_usage_report.data_hex);
  assert.equal(bytesToHex(encodeToolUsageAcceptData({
    sessionId: golden.tool_usage_accept.input.session_id,
  })), golden.tool_usage_accept.data_hex);
  assert.equal(bytesToHex(encodeToolUsageDisputeData({
    sessionId: golden.tool_usage_dispute.input.session_id,
    reason: golden.tool_usage_dispute.input.reason,
  })), golden.tool_usage_dispute.data_hex);
  assert.equal(bytesToHex(encodeToolUsageResolveData({
    sessionId: golden.tool_usage_resolve.input.session_id,
    providerWins: golden.tool_usage_resolve.input.provider_wins,
    reason: golden.tool_usage_resolve.input.reason,
  })), golden.tool_usage_resolve.data_hex);
  assert.equal(bytesToHex(encodeToolUsageExpireData({
    sessionId: golden.tool_usage_expire.input.session_id,
  })), golden.tool_usage_expire.data_hex);
  assert.equal(bytesToHex(encodeToolSubscriptionPlanCreateData({
    toolId: golden.tool_subscription_plan_create.input.tool_id,
    name: golden.tool_subscription_plan_create.input.name,
    pricePerPeriod: golden.tool_subscription_plan_create.input.price_per_period,
    periodMs: golden.tool_subscription_plan_create.input.period_ms,
    includedCalls: golden.tool_subscription_plan_create.input.included_calls,
    includedCredits: golden.tool_subscription_plan_create.input.included_credits,
    overagePolicy: golden.tool_subscription_plan_create.input.overage_policy,
  })), golden.tool_subscription_plan_create.data_hex);
  assert.equal(bytesToHex(encodeToolSubscriptionPlanUpdateData({
    planId: golden.tool_subscription_plan_update.input.plan_id,
    name: golden.tool_subscription_plan_update.input.name,
    pricePerPeriod: golden.tool_subscription_plan_update.input.price_per_period,
    periodMs: golden.tool_subscription_plan_update.input.period_ms,
    includedCalls: golden.tool_subscription_plan_update.input.included_calls,
    includedCredits: golden.tool_subscription_plan_update.input.included_credits,
    overagePolicy: golden.tool_subscription_plan_update.input.overage_policy,
    active: golden.tool_subscription_plan_update.input.active,
  })), golden.tool_subscription_plan_update.data_hex);
  assert.equal(bytesToHex(encodeToolSubscriptionStartData({
    planId: golden.tool_subscription_start.input.plan_id,
    reserveAmount: golden.tool_subscription_start.input.reserve_amount,
    autoRenew: golden.tool_subscription_start.input.auto_renew,
  })), golden.tool_subscription_start.data_hex);
  assert.equal(bytesToHex(encodeToolSubscriptionTopUpData({
    subscriptionId: golden.tool_subscription_top_up.input.subscription_id,
    amount: golden.tool_subscription_top_up.input.amount,
  })), golden.tool_subscription_top_up.data_hex);
  assert.equal(bytesToHex(encodeToolSubscriptionCancelData({
    subscriptionId: golden.tool_subscription_cancel.input.subscription_id,
  })), golden.tool_subscription_cancel.data_hex);
  assert.equal(bytesToHex(encodeToolSubscriptionResumeData({
    subscriptionId: golden.tool_subscription_resume.input.subscription_id,
    reserveAmount: golden.tool_subscription_resume.input.reserve_amount,
  })), golden.tool_subscription_resume.data_hex);
  assert.equal(bytesToHex(encodeToolSubscriptionRenewData({
    subscriptionId: golden.tool_subscription_renew.input.subscription_id,
  })), golden.tool_subscription_renew.data_hex);
});

test("agent/tool lifecycle builders produce Rust-compatible signed transactions", async () => {
  const path = new URL("../../testdata/golden-agent-tool-lifecycle.json", import.meta.url);
  const golden = JSON.parse(readFileSync(path, "utf8"));
  const keypair = Keypair.fromSecretHex(golden.secret_hex);
  const client = new ZinchaClient({
    baseUrl: "http://node.test/",
    fetch: async () => {
      throw new Error("network should not be used when chain, nonce, and validity are explicit");
    },
  });

  const common = (transaction: typeof golden.agent_update.transaction) => ({
    feeMicroZin: transaction.fee_micro_zin,
    nonce: transaction.nonce,
    chainId: transaction.chain_id,
    timestampMs: transaction.timestamp,
    referenceBlockHeight: transaction.reference_block_height,
    referenceBlockHash: transaction.reference_block_hash,
    maxValidBlockHeight: transaction.max_valid_block_height,
  });

  const agentUpdate = await client.buildUpdateAgent(keypair, {
    ...common(golden.agent_update.transaction),
    name: golden.agent_update.input.name,
    description: golden.agent_update.input.description,
    neuralEmbedding: golden.agent_update.input.neural_embedding,
    modelHash: golden.agent_update.input.model_hash,
    capabilities: golden.agent_update.input.capabilities,
    metadata: Uint8Array.from(Buffer.from(golden.agent_update.input.metadata_hex, "hex")),
    active: golden.agent_update.input.active,
    minFeeMicroZin: golden.agent_update.input.min_fee_micro_zin,
    feeSchedule: golden.agent_update.input.fee_schedule,
  });
  assert.equal(signedTransactionHex(agentUpdate), golden.agent_update.transaction.signed_tx_hex);

  const agentDeregister = await client.buildDeregisterAgent(keypair, {
    ...common(golden.agent_deregister.transaction),
  });
  assert.equal(signedTransactionHex(agentDeregister), golden.agent_deregister.transaction.signed_tx_hex);

  const toolRegister = await client.buildRegisterTool(keypair, {
    ...common(golden.tool_register.transaction),
    name: golden.tool_register.input.name,
    description: golden.tool_register.input.description,
    endpoint: golden.tool_register.input.endpoint,
    pricePerCall: golden.tool_register.input.price_per_call,
    settlementMode: golden.tool_register.input.settlement_mode,
    slaMs: golden.tool_register.input.sla_ms,
    challengeWindowMs: golden.tool_register.input.challenge_window_ms,
    maxResultMetadataBytes: golden.tool_register.input.max_result_metadata_bytes,
    arbitrationPolicy: golden.tool_register.input.arbitration_policy,
    capabilities: golden.tool_register.input.capabilities,
    matchEnabled: golden.tool_register.input.match_enabled,
    neuralEmbedding: golden.tool_register.input.neural_embedding,
    version: golden.tool_register.input.version,
  });
  assert.equal(signedTransactionHex(toolRegister), golden.tool_register.transaction.signed_tx_hex);

  const toolInvoke = await client.buildInvokeTool(keypair, {
    ...common(golden.tool_invoke.transaction),
    toolId: golden.tool_invoke.input.tool_id,
    inputData: Uint8Array.from(Buffer.from(golden.tool_invoke.input.input_data_hex, "hex")),
    maxMeteredUnits: golden.tool_invoke.input.max_metered_units,
    gasLimit: golden.tool_invoke.input.gas_limit,
    milestones: golden.tool_invoke.input.milestones,
  });
  assert.equal(signedTransactionHex(toolInvoke), golden.tool_invoke.transaction.signed_tx_hex);

  const toolUpdate = await client.buildUpdateTool(keypair, {
    ...common(golden.tool_update.transaction),
    toolId: golden.tool_update.input.tool_id,
    description: golden.tool_update.input.description,
    endpoint: golden.tool_update.input.endpoint,
    pricePerCall: golden.tool_update.input.price_per_call,
    settlementMode: golden.tool_update.input.settlement_mode,
    slaMs: golden.tool_update.input.sla_ms,
    challengeWindowMs: golden.tool_update.input.challenge_window_ms,
    maxResultMetadataBytes: golden.tool_update.input.max_result_metadata_bytes,
    arbitrationPolicy: golden.tool_update.input.arbitration_policy,
    capabilities: golden.tool_update.input.capabilities,
    matchEnabled: golden.tool_update.input.match_enabled,
    neuralEmbedding: golden.tool_update.input.neural_embedding,
    version: golden.tool_update.input.version,
    active: golden.tool_update.input.active,
  });
  assert.equal(signedTransactionHex(toolUpdate), golden.tool_update.transaction.signed_tx_hex);

  const toolDeregister = await client.buildDeregisterTool(keypair, {
    ...common(golden.tool_deregister.transaction),
    toolId: golden.tool_deregister.input.tool_id,
  });
  assert.equal(signedTransactionHex(toolDeregister), golden.tool_deregister.transaction.signed_tx_hex);

  const resultSubmit = await client.buildSubmitToolResult(keypair, {
    ...common(golden.tool_result_submit.transaction),
    jobId: golden.tool_result_submit.input.job_id,
    resultHash: golden.tool_result_submit.input.result_hash,
    resultMetadata: Uint8Array.from(Buffer.from(golden.tool_result_submit.input.result_metadata_hex, "hex")),
    milestoneIndex: golden.tool_result_submit.input.milestone_index,
  });
  assert.equal(signedTransactionHex(resultSubmit), golden.tool_result_submit.transaction.signed_tx_hex);

  const resultAccept = await client.buildAcceptToolResult(keypair, {
    ...common(golden.tool_result_accept.transaction),
    jobId: golden.tool_result_accept.input.job_id,
    milestoneIndex: golden.tool_result_accept.input.milestone_index,
  });
  assert.equal(signedTransactionHex(resultAccept), golden.tool_result_accept.transaction.signed_tx_hex);

  const resultDispute = await client.buildDisputeToolResult(keypair, {
    ...common(golden.tool_result_dispute.transaction),
    jobId: golden.tool_result_dispute.input.job_id,
    reason: golden.tool_result_dispute.input.reason,
    milestoneIndex: golden.tool_result_dispute.input.milestone_index,
  });
  assert.equal(signedTransactionHex(resultDispute), golden.tool_result_dispute.transaction.signed_tx_hex);

  const resultResolve = await client.buildResolveToolResult(keypair, {
    ...common(golden.tool_result_resolve.transaction),
    jobId: golden.tool_result_resolve.input.job_id,
    providerWins: golden.tool_result_resolve.input.provider_wins,
    reason: golden.tool_result_resolve.input.reason,
    milestoneIndex: golden.tool_result_resolve.input.milestone_index,
  });
  assert.equal(signedTransactionHex(resultResolve), golden.tool_result_resolve.transaction.signed_tx_hex);

  const jobExpire = await client.buildExpireToolJob(keypair, {
    ...common(golden.tool_job_expire.transaction),
    jobId: golden.tool_job_expire.input.job_id,
  });
  assert.equal(signedTransactionHex(jobExpire), golden.tool_job_expire.transaction.signed_tx_hex);

  const usageReport = await client.buildReportToolUsage(keypair, {
    ...common(golden.tool_usage_report.transaction),
    sessionId: golden.tool_usage_report.input.session_id,
    unitsUsed: golden.tool_usage_report.input.units_used,
    resultHash: golden.tool_usage_report.input.result_hash,
    resultMetadata: Uint8Array.from(Buffer.from(golden.tool_usage_report.input.result_metadata_hex, "hex")),
  });
  assert.equal(signedTransactionHex(usageReport), golden.tool_usage_report.transaction.signed_tx_hex);

  const usageAccept = await client.buildAcceptToolUsage(keypair, {
    ...common(golden.tool_usage_accept.transaction),
    sessionId: golden.tool_usage_accept.input.session_id,
  });
  assert.equal(signedTransactionHex(usageAccept), golden.tool_usage_accept.transaction.signed_tx_hex);

  const usageDispute = await client.buildDisputeToolUsage(keypair, {
    ...common(golden.tool_usage_dispute.transaction),
    sessionId: golden.tool_usage_dispute.input.session_id,
    reason: golden.tool_usage_dispute.input.reason,
  });
  assert.equal(signedTransactionHex(usageDispute), golden.tool_usage_dispute.transaction.signed_tx_hex);

  const usageResolve = await client.buildResolveToolUsage(keypair, {
    ...common(golden.tool_usage_resolve.transaction),
    sessionId: golden.tool_usage_resolve.input.session_id,
    providerWins: golden.tool_usage_resolve.input.provider_wins,
    reason: golden.tool_usage_resolve.input.reason,
  });
  assert.equal(signedTransactionHex(usageResolve), golden.tool_usage_resolve.transaction.signed_tx_hex);

  const usageExpire = await client.buildExpireToolUsage(keypair, {
    ...common(golden.tool_usage_expire.transaction),
    sessionId: golden.tool_usage_expire.input.session_id,
  });
  assert.equal(signedTransactionHex(usageExpire), golden.tool_usage_expire.transaction.signed_tx_hex);

  const planCreate = await client.buildCreateToolSubscriptionPlan(keypair, {
    ...common(golden.tool_subscription_plan_create.transaction),
    toolId: golden.tool_subscription_plan_create.input.tool_id,
    name: golden.tool_subscription_plan_create.input.name,
    pricePerPeriod: golden.tool_subscription_plan_create.input.price_per_period,
    periodMs: golden.tool_subscription_plan_create.input.period_ms,
    includedCalls: golden.tool_subscription_plan_create.input.included_calls,
    includedCredits: golden.tool_subscription_plan_create.input.included_credits,
    overagePolicy: golden.tool_subscription_plan_create.input.overage_policy,
  });
  assert.equal(signedTransactionHex(planCreate), golden.tool_subscription_plan_create.transaction.signed_tx_hex);

  const planUpdate = await client.buildUpdateToolSubscriptionPlan(keypair, {
    ...common(golden.tool_subscription_plan_update.transaction),
    planId: golden.tool_subscription_plan_update.input.plan_id,
    name: golden.tool_subscription_plan_update.input.name,
    pricePerPeriod: golden.tool_subscription_plan_update.input.price_per_period,
    periodMs: golden.tool_subscription_plan_update.input.period_ms,
    includedCalls: golden.tool_subscription_plan_update.input.included_calls,
    includedCredits: golden.tool_subscription_plan_update.input.included_credits,
    overagePolicy: golden.tool_subscription_plan_update.input.overage_policy,
    active: golden.tool_subscription_plan_update.input.active,
  });
  assert.equal(signedTransactionHex(planUpdate), golden.tool_subscription_plan_update.transaction.signed_tx_hex);

  const subscriptionStart = await client.buildStartToolSubscription(keypair, {
    ...common(golden.tool_subscription_start.transaction),
    planId: golden.tool_subscription_start.input.plan_id,
    reserveAmount: golden.tool_subscription_start.input.reserve_amount,
    autoRenew: golden.tool_subscription_start.input.auto_renew,
  });
  assert.equal(signedTransactionHex(subscriptionStart), golden.tool_subscription_start.transaction.signed_tx_hex);

  const subscriptionTopUp = await client.buildTopUpToolSubscription(keypair, {
    ...common(golden.tool_subscription_top_up.transaction),
    subscriptionId: golden.tool_subscription_top_up.input.subscription_id,
    amount: golden.tool_subscription_top_up.input.amount,
  });
  assert.equal(signedTransactionHex(subscriptionTopUp), golden.tool_subscription_top_up.transaction.signed_tx_hex);

  const subscriptionCancel = await client.buildCancelToolSubscription(keypair, {
    ...common(golden.tool_subscription_cancel.transaction),
    subscriptionId: golden.tool_subscription_cancel.input.subscription_id,
  });
  assert.equal(signedTransactionHex(subscriptionCancel), golden.tool_subscription_cancel.transaction.signed_tx_hex);

  const subscriptionResume = await client.buildResumeToolSubscription(keypair, {
    ...common(golden.tool_subscription_resume.transaction),
    subscriptionId: golden.tool_subscription_resume.input.subscription_id,
    reserveAmount: golden.tool_subscription_resume.input.reserve_amount,
  });
  assert.equal(signedTransactionHex(subscriptionResume), golden.tool_subscription_resume.transaction.signed_tx_hex);

  const subscriptionRenew = await client.buildRenewToolSubscription(keypair, {
    ...common(golden.tool_subscription_renew.transaction),
    subscriptionId: golden.tool_subscription_renew.input.subscription_id,
  });
  assert.equal(signedTransactionHex(subscriptionRenew), golden.tool_subscription_renew.transaction.signed_tx_hex);
});

test("token operation encoders match Rust golden vector", () => {
  const path = new URL("../../testdata/golden-token-operations.json", import.meta.url);
  const golden = JSON.parse(readFileSync(path, "utf8"));

  const create = encodeTokenCreateData({
    name: golden.create.input.name,
    symbol: golden.create.input.symbol,
    decimals: golden.create.input.decimals,
    initialSupply: golden.create.input.initial_supply,
    maxSupply: golden.create.input.max_supply,
    burnable: golden.create.input.burnable,
    mintAuthority: golden.create.input.mint_authority,
    metadata: Uint8Array.from(Buffer.from(golden.create.input.metadata_hex, "hex")),
  });
  assert.equal(bytesToHex(create), golden.create.data_hex);

  const transfer = encodeTokenTransferData({
    tokenId: golden.transfer.input.token_id,
    to: golden.transfer.input.to,
    amount: golden.transfer.input.amount,
  });
  assert.equal(bytesToHex(transfer), golden.transfer.data_hex);

  const approve = encodeTokenApproveData({
    tokenId: golden.approve.input.token_id,
    spender: golden.approve.input.spender,
    amount: golden.approve.input.amount,
  });
  assert.equal(bytesToHex(approve), golden.approve.data_hex);

  const mint = encodeTokenMintData({
    tokenId: golden.mint.input.token_id,
    to: golden.mint.input.to,
    amount: golden.mint.input.amount,
  });
  assert.equal(bytesToHex(mint), golden.mint.data_hex);

  const burn = encodeTokenBurnData({
    tokenId: golden.burn.input.token_id,
    amount: golden.burn.input.amount,
  });
  assert.equal(bytesToHex(burn), golden.burn.data_hex);
});

test("token builders produce Rust-compatible signed transactions", async () => {
  const path = new URL("../../testdata/golden-token-operations.json", import.meta.url);
  const golden = JSON.parse(readFileSync(path, "utf8"));
  const keypair = Keypair.fromSecretHex(golden.secret_hex);
  const client = new ZinchaClient({
    baseUrl: "http://node.test/",
    fetch: async () => {
      throw new Error("network should not be used when chain, nonce, and validity are explicit");
    },
  });

  const common = (transaction: typeof golden.create.transaction) => ({
    feeMicroZin: transaction.fee_micro_zin,
    nonce: transaction.nonce,
    chainId: transaction.chain_id,
    timestampMs: transaction.timestamp,
    referenceBlockHeight: transaction.reference_block_height,
    referenceBlockHash: transaction.reference_block_hash,
    maxValidBlockHeight: transaction.max_valid_block_height,
  });

  const create = await client.buildCreateToken(keypair, {
    ...common(golden.create.transaction),
    name: golden.create.input.name,
    symbol: golden.create.input.symbol,
    decimals: golden.create.input.decimals,
    initialSupply: golden.create.input.initial_supply,
    maxSupply: golden.create.input.max_supply,
    burnable: golden.create.input.burnable,
    mintAuthority: golden.create.input.mint_authority,
    metadata: Uint8Array.from(Buffer.from(golden.create.input.metadata_hex, "hex")),
  });
  assert.equal(signedTransactionHex(create), golden.create.transaction.signed_tx_hex);

  const transfer = await client.buildTransferToken(keypair, {
    ...common(golden.transfer.transaction),
    tokenId: golden.transfer.input.token_id,
    to: golden.transfer.input.to,
    amount: golden.transfer.input.amount,
  });
  assert.equal(signedTransactionHex(transfer), golden.transfer.transaction.signed_tx_hex);

  const approve = await client.buildApproveToken(keypair, {
    ...common(golden.approve.transaction),
    tokenId: golden.approve.input.token_id,
    spender: golden.approve.input.spender,
    amount: golden.approve.input.amount,
  });
  assert.equal(signedTransactionHex(approve), golden.approve.transaction.signed_tx_hex);

  const mint = await client.buildMintToken(keypair, {
    ...common(golden.mint.transaction),
    tokenId: golden.mint.input.token_id,
    to: golden.mint.input.to,
    amount: golden.mint.input.amount,
  });
  assert.equal(signedTransactionHex(mint), golden.mint.transaction.signed_tx_hex);

  const burn = await client.buildBurnToken(keypair, {
    ...common(golden.burn.transaction),
    tokenId: golden.burn.input.token_id,
    amount: golden.burn.input.amount,
  });
  assert.equal(signedTransactionHex(burn), golden.burn.transaction.signed_tx_hex);
});

test("contract encoders match Rust golden vector", () => {
  const path = new URL("../../testdata/golden-contract-operations.json", import.meta.url);
  const golden = JSON.parse(readFileSync(path, "utf8"));
  const proof = {
    language: golden.contract_verify.input.proof.language,
    compiler: golden.contract_verify.input.proof.compiler,
    sourceCode: golden.contract_verify.input.proof.source_code,
    bytecodeWitness: golden.contract_verify.input.proof.bytecode_witness,
  };

  assert.equal(bytesToHex(encodeContractDeployData({
    bytecode: Uint8Array.from(Buffer.from(golden.contract_deploy.input.bytecode_hex, "hex")),
  })), golden.contract_deploy.data_hex);

  assert.equal(bytesToHex(encodeContractCallData({
    contractAddress: golden.contract_call.input.contract_address,
    function: golden.contract_call.input.function,
    args: Uint8Array.from(Buffer.from(golden.contract_call.input.args_hex, "hex")),
    gasLimit: golden.contract_call.input.gas_limit,
  })), golden.contract_call.data_hex);

  assert.equal(bytesToHex(encodeContractVerifyData({
    contractAddress: golden.contract_verify.input.contract_address,
    proof,
  })), golden.contract_verify.data_hex);

  assert.equal(bytesToHex(encodeContractPublishAbiData({
    contractAddress: golden.contract_publish_abi.input.contract_address,
    abi: golden.contract_publish_abi.input.abi,
  })), golden.contract_publish_abi.data_hex);

  assert.equal(bytesToHex(encodeContractRouteUpdateData({
    routeName: golden.contract_route_update.input.route_name,
    targetContractAddress: golden.contract_route_update.input.target_contract_address,
  })), golden.contract_route_update.data_hex);

  assert.equal(bytesToHex(encodeContractRouteCallData({
    deployer: golden.contract_route_call.input.deployer,
    routeName: golden.contract_route_call.input.route_name,
    function: golden.contract_route_call.input.function,
    args: Uint8Array.from(Buffer.from(golden.contract_route_call.input.args_hex, "hex")),
    gasLimit: golden.contract_route_call.input.gas_limit,
  })), golden.contract_route_call.data_hex);

  assert.equal(bytesToHex(encodeContractDeactivateData({
    contractAddress: golden.contract_deactivate.input.contract_address,
  })), golden.contract_deactivate.data_hex);
});

test("contract builders produce Rust-compatible signed transactions", async () => {
  const path = new URL("../../testdata/golden-contract-operations.json", import.meta.url);
  const golden = JSON.parse(readFileSync(path, "utf8"));
  const keypair = Keypair.fromSecretHex(golden.secret_hex);
  const proof = {
    language: golden.contract_verify.input.proof.language,
    compiler: golden.contract_verify.input.proof.compiler,
    sourceCode: golden.contract_verify.input.proof.source_code,
    bytecodeWitness: golden.contract_verify.input.proof.bytecode_witness,
  };
  const client = new ZinchaClient({
    baseUrl: "http://node.test/",
    fetch: async () => {
      throw new Error("network should not be used when chain, nonce, and validity are explicit");
    },
  });

  const common = (transaction: typeof golden.contract_deploy.transaction) => ({
    feeMicroZin: transaction.fee_micro_zin,
    nonce: transaction.nonce,
    chainId: transaction.chain_id,
    timestampMs: transaction.timestamp,
    referenceBlockHeight: transaction.reference_block_height,
    referenceBlockHash: transaction.reference_block_hash,
    maxValidBlockHeight: transaction.max_valid_block_height,
  });

  const deploy = await client.buildDeployContract(keypair, {
    ...common(golden.contract_deploy.transaction),
    bytecode: Uint8Array.from(Buffer.from(golden.contract_deploy.input.bytecode_hex, "hex")),
    amountMicroZin: golden.contract_deploy.input.amount_micro_zin,
  });
  assert.equal(signedTransactionHex(deploy), golden.contract_deploy.transaction.signed_tx_hex);

  const call = await client.buildCallContract(keypair, {
    ...common(golden.contract_call.transaction),
    contractAddress: golden.contract_call.input.contract_address,
    function: golden.contract_call.input.function,
    args: Uint8Array.from(Buffer.from(golden.contract_call.input.args_hex, "hex")),
    gasLimit: golden.contract_call.input.gas_limit,
    amountMicroZin: golden.contract_call.input.amount_micro_zin,
  });
  assert.equal(signedTransactionHex(call), golden.contract_call.transaction.signed_tx_hex);

  const verify = await client.buildVerifyContract(keypair, {
    ...common(golden.contract_verify.transaction),
    contractAddress: golden.contract_verify.input.contract_address,
    proof,
  });
  assert.equal(signedTransactionHex(verify), golden.contract_verify.transaction.signed_tx_hex);

  const publishAbi = await client.buildPublishContractAbi(keypair, {
    ...common(golden.contract_publish_abi.transaction),
    contractAddress: golden.contract_publish_abi.input.contract_address,
    abi: golden.contract_publish_abi.input.abi,
  });
  assert.equal(signedTransactionHex(publishAbi), golden.contract_publish_abi.transaction.signed_tx_hex);

  const routeUpdate = await client.buildUpdateContractRoute(keypair, {
    ...common(golden.contract_route_update.transaction),
    routeName: golden.contract_route_update.input.route_name,
    targetContractAddress: golden.contract_route_update.input.target_contract_address,
  });
  assert.equal(signedTransactionHex(routeUpdate), golden.contract_route_update.transaction.signed_tx_hex);

  const routeCall = await client.buildCallContractRoute(keypair, {
    ...common(golden.contract_route_call.transaction),
    deployer: golden.contract_route_call.input.deployer,
    routeName: golden.contract_route_call.input.route_name,
    function: golden.contract_route_call.input.function,
    args: Uint8Array.from(Buffer.from(golden.contract_route_call.input.args_hex, "hex")),
    gasLimit: golden.contract_route_call.input.gas_limit,
    amountMicroZin: golden.contract_route_call.input.amount_micro_zin,
  });
  assert.equal(signedTransactionHex(routeCall), golden.contract_route_call.transaction.signed_tx_hex);

  const deactivate = await client.buildDeactivateContract(keypair, {
    ...common(golden.contract_deactivate.transaction),
    contractAddress: golden.contract_deactivate.input.contract_address,
  });
  assert.equal(signedTransactionHex(deactivate), golden.contract_deactivate.transaction.signed_tx_hex);
});

test("staking/validator encoders match Rust golden vector", () => {
  const path = new URL("../../testdata/golden-staking-validator.json", import.meta.url);
  const golden = JSON.parse(readFileSync(path, "utf8"));

  const validatorRegister = encodeValidatorRegisterData({
    executorServices: golden.validator_register.input.executor_services.map((service: any) => ({
      partitionId: service.partition_id,
      rpcEndpoint: service.rpc_endpoint,
      executorPublicKey: service.executor_public_key,
    })),
    vrfPublicKey: golden.validator_register.input.vrf_public_key,
  });
  assert.equal(bytesToHex(validatorRegister), golden.validator_register.data_hex);

  const validatorUpdate = encodeValidatorUpdateData({
    executorServices: golden.validator_update.input.executor_services.map((service: any) => ({
      partitionId: service.partition_id,
      rpcEndpoint: service.rpc_endpoint,
      executorPublicKey: service.executor_public_key,
    })),
    vrfPublicKey: golden.validator_update.input.vrf_public_key,
  });
  assert.equal(bytesToHex(validatorUpdate), golden.validator_update.data_hex);

  assert.equal(bytesToHex(encodeValidatorExitData()), golden.validator_exit.data_hex);

  const vrfCommit = encodeValidatorVrfCommitData({
    targetEpoch: golden.validator_vrf_commit.input.target_epoch,
    commitment: golden.validator_vrf_commit.input.commitment,
  });
  assert.equal(bytesToHex(vrfCommit), golden.validator_vrf_commit.data_hex);

  const vrfContribution = encodeValidatorVrfContributionData({
    targetEpoch: golden.validator_vrf_contribution.input.target_epoch,
    vrfOutput: Uint8Array.from(Buffer.from(golden.validator_vrf_contribution.input.vrf_output_hex, "hex")),
    vrfProof: Uint8Array.from(Buffer.from(golden.validator_vrf_contribution.input.vrf_proof_hex, "hex")),
  });
  assert.equal(bytesToHex(vrfContribution), golden.validator_vrf_contribution.data_hex);

  assert.equal(bytesToHex(encodeStakeData({
    target: golden.stake_agent.input.target,
  })), golden.stake_agent.data_hex);
  assert.equal(bytesToHex(encodeStakeData({
    target: golden.stake_validator.input.target,
  })), golden.stake_validator.data_hex);
  assert.equal(bytesToHex(encodeStakeData({
    target: golden.stake_requester_auto_match.input.target,
  })), golden.stake_requester_auto_match.data_hex);
  assert.equal(bytesToHex(encodeUnstakeData({
    target: golden.unstake_agent.input.target,
  })), golden.unstake_agent.data_hex);
  assert.equal(bytesToHex(encodeUnstakeData({
    target: golden.unstake_validator.input.target,
  })), golden.unstake_validator.data_hex);
});

test("staking/validator builders produce Rust-compatible signed transactions", async () => {
  const path = new URL("../../testdata/golden-staking-validator.json", import.meta.url);
  const golden = JSON.parse(readFileSync(path, "utf8"));
  const keypair = Keypair.fromSecretHex(golden.secret_hex);
  const client = new ZinchaClient({
    baseUrl: "http://node.test/",
    fetch: async () => {
      throw new Error("network should not be used when chain, nonce, and validity are explicit");
    },
  });

  const common = (transaction: typeof golden.validator_register.transaction) => ({
    feeMicroZin: transaction.fee_micro_zin,
    nonce: transaction.nonce,
    chainId: transaction.chain_id,
    timestampMs: transaction.timestamp,
    referenceBlockHeight: transaction.reference_block_height,
    referenceBlockHash: transaction.reference_block_hash,
    maxValidBlockHeight: transaction.max_valid_block_height,
  });

  const validatorRegister = await client.buildRegisterValidator(keypair, {
    ...common(golden.validator_register.transaction),
    stakeMicroZin: golden.validator_register.input.stake_micro_zin,
    executorServices: golden.validator_register.input.executor_services.map((service: any) => ({
      partitionId: service.partition_id,
      rpcEndpoint: service.rpc_endpoint,
      executorPublicKey: service.executor_public_key,
    })),
    vrfPublicKey: golden.validator_register.input.vrf_public_key,
  });
  assert.equal(signedTransactionHex(validatorRegister), golden.validator_register.transaction.signed_tx_hex);

  const validatorUpdate = await client.buildUpdateValidator(keypair, {
    ...common(golden.validator_update.transaction),
    executorServices: golden.validator_update.input.executor_services.map((service: any) => ({
      partitionId: service.partition_id,
      rpcEndpoint: service.rpc_endpoint,
      executorPublicKey: service.executor_public_key,
    })),
    vrfPublicKey: golden.validator_update.input.vrf_public_key,
  });
  assert.equal(signedTransactionHex(validatorUpdate), golden.validator_update.transaction.signed_tx_hex);

  const validatorExit = await client.buildExitValidator(keypair, {
    ...common(golden.validator_exit.transaction),
  });
  assert.equal(signedTransactionHex(validatorExit), golden.validator_exit.transaction.signed_tx_hex);

  const vrfCommit = await client.buildCommitValidatorVrf(keypair, {
    ...common(golden.validator_vrf_commit.transaction),
    targetEpoch: golden.validator_vrf_commit.input.target_epoch,
    commitment: golden.validator_vrf_commit.input.commitment,
  });
  assert.equal(signedTransactionHex(vrfCommit), golden.validator_vrf_commit.transaction.signed_tx_hex);

  const vrfContribution = await client.buildContributeValidatorVrf(keypair, {
    ...common(golden.validator_vrf_contribution.transaction),
    targetEpoch: golden.validator_vrf_contribution.input.target_epoch,
    vrfOutput: Uint8Array.from(Buffer.from(golden.validator_vrf_contribution.input.vrf_output_hex, "hex")),
    vrfProof: Uint8Array.from(Buffer.from(golden.validator_vrf_contribution.input.vrf_proof_hex, "hex")),
  });
  assert.equal(signedTransactionHex(vrfContribution), golden.validator_vrf_contribution.transaction.signed_tx_hex);

  const stakeAgent = await client.buildStake(keypair, {
    ...common(golden.stake_agent.transaction),
    target: golden.stake_agent.input.target,
    amountMicroZin: golden.stake_agent.input.amount_micro_zin,
  });
  assert.equal(signedTransactionHex(stakeAgent), golden.stake_agent.transaction.signed_tx_hex);

  const stakeValidator = await client.buildStake(keypair, {
    ...common(golden.stake_validator.transaction),
    target: golden.stake_validator.input.target,
    amountMicroZin: golden.stake_validator.input.amount_micro_zin,
  });
  assert.equal(signedTransactionHex(stakeValidator), golden.stake_validator.transaction.signed_tx_hex);

  const stakeRequester = await client.buildStake(keypair, {
    ...common(golden.stake_requester_auto_match.transaction),
    target: golden.stake_requester_auto_match.input.target,
    amountMicroZin: golden.stake_requester_auto_match.input.amount_micro_zin,
  });
  assert.equal(signedTransactionHex(stakeRequester), golden.stake_requester_auto_match.transaction.signed_tx_hex);

  const unstakeAgent = await client.buildUnstake(keypair, {
    ...common(golden.unstake_agent.transaction),
    target: golden.unstake_agent.input.target,
    amountMicroZin: golden.unstake_agent.input.amount_micro_zin,
  });
  assert.equal(signedTransactionHex(unstakeAgent), golden.unstake_agent.transaction.signed_tx_hex);

  const unstakeValidator = await client.buildUnstake(keypair, {
    ...common(golden.unstake_validator.transaction),
    target: golden.unstake_validator.input.target,
    amountMicroZin: golden.unstake_validator.input.amount_micro_zin,
  });
  assert.equal(signedTransactionHex(unstakeValidator), golden.unstake_validator.transaction.signed_tx_hex);

  await assert.rejects(() => client.buildUnstake(keypair, {
    target: "requester_auto_match",
    amountMicroZin: 1,
    chainId: "zincha-vega-1",
    nonce: 99,
    referenceBlockHeight: 42,
    referenceBlockHash: "11".repeat(32),
    maxValidBlockHeight: 100,
  }));
});
