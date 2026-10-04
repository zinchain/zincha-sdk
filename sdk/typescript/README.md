# ZINCHA TypeScript SDK

The TypeScript SDK is release-aware and uses the Rust node protocol as the
source of truth for transaction serialization, hashes, and signatures.

It is isomorphic — the same code runs in Node.js 22.6+, browsers, and the
MetaMask Snaps sandbox — with two audited pure-JS runtime dependencies
(`@noble/curves`, `@noble/hashes`, and `@noble/ciphers`). Any `TransactionSigner` (an in-process
`Keypair`, or an external wallet such as the Zincha MetaMask Snap) can sign.
The current serializer writes addresses, hashes, and public keys in the
fixed-width binary form required by protocol/storage format 58.

`client.transaction(hash)` receives the runtime's complete transaction-status
JSON. Confirmed nodes now return receipt `events`, `state_changes`, and
`contract_context`, including decoded protocol-authored contract operations.
The `TransactionStatus` interface and generated OpenAPI schema expose those
fields with typed receipt events, state changes, contract context, and operation
variants.

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

## Agreements

```ts
const created = await client.createAgreementAndSubmit(requesterWallet, {
  parties: [requesterWallet.address(), providerWallet.address()],
  terms: new TextEncoder().encode("Deliver the audited model"),
  escrowAmount: 1_000_000n,
  expiresAt: Date.now() + 86_400_000,
  serviceProvider: providerWallet.address(),
  milestones: [
    { description: "Prototype", amount: 400_000n },
    { description: "Production", amount: 600_000n },
  ],
  feeMicroZin: 1_000n,
});

await client.acceptAgreementAndSubmit(providerWallet, {
  agreementId: created.tx_hash,
  feeMicroZin: 1_000n,
});
```

The full lifecycle is typed: `buildCreateAgreement`,
`buildAcceptAgreement`, `buildExecuteAgreement`, `buildDisputeAgreement`,
`buildResolveAgreement`, and `buildCancelAgreement`, with matching
`...AndSubmit` helpers. Empty milestones produce the protocol's canonical
single-payment milestone. Create transactions automatically set the
transaction amount to `escrowAmount`.

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

## Participant conversations

`ConversationClient` talks to the workflow provider's separately advertised
conversation service. `createConversationDelegation` lets the account key
authorize a short-lived operational key, while `signConversationMessage` signs
each idempotent message without reopening the wallet. `ConversationOutbox`
persists signed messages through an injected store; `LocalStorageOutboxStore`
is provided for browser applications, and production platforms can use the same
interface with IndexedDB or their database.

The default outbox bounds are 1,000 entries and 64 MiB of serialized data.
`LocalStorageOutboxStore` is suitable only for a trusted, single-tab browser
origin: local storage is plaintext and its read/modify/write cycle is not
transactional across tabs or workers. Production browser platforms should use
an IndexedDB implementation, encrypt sensitive platform-readable drafts with
an application-held key, and elect one sender lease per account/conversation.

```ts
// Browser: selects the first HTTPS interface and verifies /v1/profile before
// any access token or workflow identifier is sent.
const conversation = await ConversationClient.fromProfile(profile);
const challenge = await conversation.issueChallenge(account.address(), subject);
const delegation = await createConversationDelegation({
  account,
  operational,
  encryptionPublicKey,
  subject,
  homeServiceId: profile.service_id,
  notBeforeMs: Date.now() - 1_000,
  expiresAtMs: Date.now() + 86_400_000,
});
const session = await conversation.createSession(challenge, delegation, operational);
conversation.setAccessToken(session.access_token);
```

Node applications can also use pinned TLS 1.3 without placing Node modules in
browser bundles:

```ts
import { createNodeConversationClient } from "@zincha/client/conversation-node";
const conversation = await createNodeConversationClient(profile, { policy: "auto" });
```

Policies are `auto`, `https_only`, and `zincha_tls_only`. `auto` follows
provider preference and advances only when a TCP endpoint is unreachable. A
TLS, pin, live-profile, or service-identity failure is terminal.
The Node export reuses pinned transports, evicts least-recently-used pools
above 256 services, and closes the old pool whenever a service's endpoint or
pin set changes.

`encryptConversationE2e` and `decryptConversationE2e` implement the versioned
X25519/HKDF-SHA256/XChaCha20-Poly1305 envelope. The service sees only opaque
ciphertext in `end_to_end` mode. Non-contributory X25519 keys and malformed
typed plaintext parts are rejected before signing or after decryption.
`events()` follows authenticated SSE and
resumes from the highest durable message sequence, performs bounded paged
catch-up after `resync_required`, and throws
`ConversationAuthorizationRequiredError` instead of retrying an expired or
revoked session. Persist a fully signed message with `ConversationOutbox`
before submission and use `flush()` for capped idempotent retries.

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
pnpm --dir sdk/typescript run typecheck
cargo test --test sdk_vectors
```

The runtime tests use Node's native type-stripping test runner and require
Node.js 22.6 or newer. The separate TypeScript compiler gate validates the
exported response and builder contracts under strict mode.

Regenerate the Rust golden vectors after intentional protocol changes:

```bash
ZINCHA_WRITE_SDK_GOLDEN=1 cargo test --test sdk_vectors
```

## 0.2.0 — isomorphic build and external signers

- `crypto.ts` no longer depends on `node:crypto`/`Buffer`; Ed25519 and SHA-256
  come from `@noble/curves` and `@noble/hashes`, so the same code runs in Node,
  browsers, and the MetaMask Snaps sandbox. Output is byte-identical (golden
  vectors unchanged).
- New `TransactionSigner` interface (async `sign`, optional `signTransaction`).
  Every `build*`/`*AndSubmit` method now accepts any `TransactionSigner`;
  `Keypair` still works unchanged.
- `signTransactionWith(tx, signer)` routes through a wallet's `signTransaction`
  when present (so the wallet can display the transaction) and verifies the
  returned signature, hash, and canonical bytes.
- `verifySignedTransactionSignature`, `transactionToJson`/`transactionFromJson`,
  `signedRequestMessage`/`parseSignedRequestMessage`, and
  `signedRequestHeadersAsync` support external wallets.
- `ZinchaClient#signedRequestHeaders` is now async.
- The package ships compiled ESM + type declarations from `dist/` (`npm run build`).
