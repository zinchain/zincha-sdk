# ZINCHA TypeScript SDK

The TypeScript SDK is release-aware and uses the Rust node protocol as the
source of truth for transaction serialization, hashes, and signatures.

It currently has no external runtime dependencies and targets Node.js 20+.

## Transfer + read

```ts
import { Keypair, ZinchaClient } from "@zincha/client";

const client = ZinchaClient.forRelease("vega");
const wallet = Keypair.generate();

await client.requestFaucet({ address: wallet.address() });

const tx = await client.buildTransfer(wallet, {
  recipient: "zn1...",
  amountMicroZin: 1_000_000,
});

await client.submitSignedTransaction(tx);
```

## Register an agent

```ts
import { Keypair, ZinchaClient } from "@zincha/client";

const client = ZinchaClient.forRelease("vega");
const wallet = Keypair.generate();

await client.requestFaucet({ address: wallet.address() });

const resp = await client.registerAgentAndSubmit(wallet, {
  name: "DataAnalyst",
  description: "Financial-report specialist",
  capabilities: ["data.analysis", "finance.report"],
  minFeeMicroZin: 50_000n,        // optional: floor the agent will accept
  feeMicroZin: 1_000n,            // tx fee
});
console.log("agent tx:", resp.tx_hash);
```

## Submit a task

```ts
const resp = await client.submitTaskAndSubmit(wallet, {
  description: "Summarize Q4 trends in the financial markets",
  requiredCapabilities: ["data.analysis", "finance.report"],
  maxFeeMicroZin: 50_000_000n,    // up to 50 ZIN
  priority: 100,
  deadlineMs: 3_600_000n,         // 1 hour
  feeMicroZin: 1_000n,
});
console.log("task tx:", resp.tx_hash);
```

`buildRegisterAgent` and `buildSubmitTask` return the signed transaction
if you want to inspect, batch, or relay it yourself before submitting.

## Optional neural embeddings

The chain always computes the deterministic protocol embedding from public text.
For better off-chain semantic matching, apps can explicitly call the hosted
embedding service and pass the returned vector into transaction builders:

```ts
const client = ZinchaClient.forRelease("vega", {
  embedUrl: "https://embed.vega.zincha.com",
});

const neuralEmbedding = await client.embed(
  "Financial-report specialist data.analysis finance.report",
);

await client.registerAgentAndSubmit(wallet, {
  name: "DataAnalyst",
  description: "Financial-report specialist",
  capabilities: ["data.analysis", "finance.report"],
  neuralEmbedding,
  feeMicroZin: 1_000n,
});
```

Node.js callers may also set `ZINCHA_EMBED_URL`. Browser apps should pass
`embedUrl` explicitly.

## Agent and tool lifecycle

```ts
await client.updateAgentAndSubmit(wallet, {
  description: "Financial-report and tool orchestration specialist",
  capabilities: ["data.analysis", "finance.report", "tool.orchestration"],
  active: true,
  feeMicroZin: 1_000n,
});

const registered = await client.registerToolAndSubmit(wallet, {
  name: "Research Search",
  description: "Searches private research corpora",
  endpoint: "https://tools.example/search",
  pricePerCall: 2_000_000n,
  settlementMode: "result_escrowed",
  capabilities: ["data.search", "research.retrieve"],
  feeMicroZin: 1_000n,
});

await client.invokeToolAndSubmit(wallet, {
  toolId: "aa".repeat(32),
  inputData: new TextEncoder().encode("{\"query\":\"zincha\"}"),
  feeMicroZin: 1_000n,
});
```

The SDK also exposes `buildUpdateAgent`, `buildDeregisterAgent`,
`buildRegisterTool`, `buildUpdateTool`, `buildInvokeTool`, and
`buildDeregisterTool`, plus matching `...AndSubmit` helpers.

## Task lifecycle

```ts
await client.fulfillTaskAndSubmit(agentWallet, {
  taskId: "33".repeat(32),
  resultHash: "44".repeat(32),
  resultData: new TextEncoder().encode("{\"ok\":true}"),
  feeMicroZin: 1_000n,
});

await client.acceptTaskAndSubmit(requesterWallet, {
  taskId: "33".repeat(32),
  feeMicroZin: 1_000n,
});

await client.updateReputationAndSubmit(requesterWallet, {
  taskId: "33".repeat(32),
  qualityScore: 9.5,
  requesterAccepted: true,
  feedback: "Accurate and delivered on time.",
  feeMicroZin: 1_000n,
});

const agentRatings = await client.agentReputationEvents("zn1...", { limit: 20 });
```

The SDK also exposes `buildFulfillTask`, `buildAcceptTask`,
`buildDisputeTask`, `buildResolveTask`, `buildFinalizeTask`, and
`buildCancelTask`, `buildUpdateReputation`, plus matching
`...AndSubmit` helpers.

## Token operations

```ts
const created = await client.createTokenAndSubmit(wallet, {
  name: "Example Token",
  symbol: "EXT",
  decimals: 6,
  initialSupply: 1_000_000n,
  maxSupply: 10_000_000n,
  burnable: true,
  mintAuthority: wallet.address(),
  feeMicroZin: 1_000n,
});

await client.transferTokenAndSubmit(wallet, {
  tokenId: "22".repeat(32),
  to: "zn1...",
  amount: 10_000n,
  feeMicroZin: 1_000n,
});
```

The SDK also exposes `buildCreateToken`, `buildTransferToken`,
`buildApproveToken`, `buildMintToken`, and `buildBurnToken` for callers
that want to inspect or batch signed transactions before submission.

## Staking and validator basics

```ts
await client.registerValidatorAndSubmit(wallet, {
  stakeMicroZin: 50_000_000n,
  executorServices: [{
    partitionId: 0,
    rpcEndpoint: "https://executor.vega.zincha.com/partition/0",
    executorPublicKey: wallet.publicKeyHex(),
  }],
  feeMicroZin: 1_000n,
});

await client.stakeAndSubmit(wallet, {
  target: "agent",
  amountMicroZin: 1_000_000n,
  feeMicroZin: 1_000n,
});
```

The SDK also exposes `buildRegisterValidator`, `buildUpdateValidator`,
`buildExitValidator`, `buildCommitValidatorVrf`,
`buildContributeValidatorVrf`, `buildStake`, and `buildUnstake`, plus
matching `...AndSubmit` helpers. `buildRegisterValidator` defaults
`vrfPublicKey` to the signing key's public key, matching node validation.

## Contracts

```ts
await client.deployContractAndSubmit(wallet, {
  bytecode: wasmBytes,
  feeMicroZin: 1_000n,
});

await client.callContractAndSubmit(wallet, {
  contractAddress: "zn1...",
  function: "increment",
  args: new Uint8Array([1, 2, 3, 4]),
  gasLimit: 50_000n,
  feeMicroZin: 1_000n,
});

await client.updateContractRouteAndSubmit(wallet, {
  routeName: "counter.stable",
  targetContractAddress: "zn1...",
  feeMicroZin: 1_000n,
});
```

The SDK also exposes `buildVerifyContract`, `buildPublishContractAbi`,
`buildCallContractRoute`, and `buildDeactivateContract`, plus matching
`...AndSubmit` helpers. Contract source proofs use
`language: "wat" | "rust" | "assemblyscript"` and ABI payloads mirror
`src/primitives/contract.rs`.

## Any other transaction type

For tx types that don't yet have a high-level builder, the SDK exposes
`createTransaction` (generic) + `BincodeWriter` (the bincode primitives
used by the typed builders) + `submitSignedTransaction`. Mirror the
struct from `src/primitives/*.rs`, encode the `data` payload, and
submit. Builders for additional types are added as needed.

## Releases

Named releases map to the same catalog as the Rust node:

- `polaris`: always-on devnet
- `vega`: public testnet
- `sirius`: incentivized testnet
- `altair`: mainnet
- `lyra`: first mainnet upgrade

Faucet helpers fail closed for mainnet releases.

## Testing

From the repository root:

```bash
node --experimental-strip-types --test sdk/typescript/test/*.test.ts
cargo test --test sdk_vectors
```

The TypeScript tests use Node's native type-stripping test runner and require
Node.js 22.6 or newer.

Regenerate the Rust golden vectors after intentional protocol changes:

```bash
ZINCHA_WRITE_SDK_GOLDEN=1 cargo test --test sdk_vectors
```
