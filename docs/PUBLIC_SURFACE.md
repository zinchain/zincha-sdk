# Public Surface Boundary

The SDK repository exposes client-side APIs only:

- Address, key, hash, signature, and transaction primitives.
- Client-safe protocol payloads used to construct and sign transactions.
- HTTP/WebSocket client helpers for public node APIs.
- Public CLI commands for key generation, wallet inspection, transaction
  construction/submission, faucet, info, query, and watch workflows.
- TypeScript and Python SDKs with golden-vector parity tests.
- The generated public OpenAPI artifact.

The SDK repository does not expose:

- Node startup/runtime code.
- Consensus, finality voting, or PoUC internals.
- Execution engine, state manager, storage DB, mempool, sync, or P2P internals.
- Operator, genesis, node-identity, internal worker, and e2e cluster tooling.

