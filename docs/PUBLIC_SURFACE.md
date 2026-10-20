# Public Surface Boundary

The SDK repository exposes client-side APIs only:

- Address, key, hash, signature, and transaction primitives.
- Client-safe protocol payloads used to construct and sign transactions.
- HTTP/WebSocket client helpers for public node APIs.
- Profile-driven provider conversation clients for Web-PKI HTTPS and pinned
  `zincha-tls-v1`; the Node-specific transport is isolated from browser bundles.
- Public CLI commands for key generation, wallet inspection, transaction
  construction/submission, faucet, info, query, watch, and participant
  conversation workflows.
- TypeScript and Python SDKs with golden-vector parity tests.
- The generated public OpenAPI artifact.

The scoped delegation work is on `main`, promoted on 2026-10-19 at SDK source
`75a55450b815368413f5ee4843928b5f08b2c597`. The reviewed upstream chain source is
`zinchain/zincha-dev@57a7c33f6c966cdac1e9178bc4df913dcaa8bed7`. It includes
scoped read grants/revocation, validator reactivation, task lifecycle APIs,
conversation clients/CLI, and transaction-history readiness diagnostics.
OpenAPI and onboarding artifacts are synchronized with that source.
Golden-vector and artifact-contract checks cover wire and response shapes.
Source promotion is separate from package publication, live deployment, and
performance qualification.

The SDK repository does not expose:

- Node startup/runtime code.
- Consensus, finality voting, or PoUC internals.
- Execution engine, state manager, storage DB, mempool, sync, or P2P internals.
- Operator, genesis, node-identity, internal worker, and e2e cluster tooling.
