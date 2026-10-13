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

The scoped delegation branch is aligned to
`zinchain/zincha-dev@8c3e801b9f78232c2a902269c3cf373acde326cb` as reviewed on
2026-10-13. It includes scoped read grants/revocation, validator reactivation,
task lifecycle APIs, and conversation clients. Its OpenAPI and onboarding
artifacts match that chain revision. Golden-vector and artifact-contract tests
check the wire and response shapes. These branch updates are not a promotion
to public `main` or a package release.

The SDK repository does not expose:

- Node startup/runtime code.
- Consensus, finality voting, or PoUC internals.
- Execution engine, state manager, storage DB, mempool, sync, or P2P internals.
- Operator, genesis, node-identity, internal worker, and e2e cluster tooling.
