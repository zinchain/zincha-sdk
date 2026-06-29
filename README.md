# Zincha Developer SDK

Public developer surface for Zincha.

This repository contains client-safe SDKs, transaction primitives, the public
`zincha` CLI, golden serialization vectors, and the public OpenAPI artifact.
It intentionally does not contain node, consensus, execution, storage, peer
networking, genesis, operator, or e2e cluster internals.

## Layout

- `crates/zincha-primitives` - Rust crypto, addresses, transactions, wallet-safe types, and client-safe protocol data.
- `crates/zincha-client` - Rust HTTP client helpers for public node APIs.
- `crates/zincha-cli-core` - Shared public CLI command implementation.
- `crates/zincha-cli` - Public `zincha` binary.
- `sdk/typescript` - TypeScript SDK package.
- `sdk/python` - Python SDK package.
- `sdk/testdata` - Golden vectors shared by SDK implementations.
- `openapi/openapi.json` - Public API specification artifact.

## Rust

```bash
cargo test --workspace
cargo run -p zincha-cli -- keygen --unsafe-print-secret
cargo run -p zincha-cli -- info --api-url http://127.0.0.1:9944
```

## TypeScript

```bash
cd sdk/typescript
npm test
```

## Python

```bash
cd sdk/python
PYTHONPATH=src python -m unittest discover -s tests
```

## Test Suite

Run the deterministic offline suite before opening a pull request:

```bash
scripts/ci-offline.sh
```

This formats and tests the Rust workspace, builds the `zincha` CLI, runs the
Python and TypeScript SDK tests, parses the public OpenAPI artifact, and checks
that private runtime dependencies have not leaked into the public SDK surface.

Live public-chain smoke tests are separate from required PR CI:

```bash
cargo build -p zincha-cli
scripts/live-vega-smoke.sh
```

The live smoke uses read-only `zincha --release vega` commands by default.
Mutating faucet/submit coverage must remain opt-in.

## CLI

```bash
zincha keygen --out wallet.key
zincha wallet address --secret-key wallet.key
zincha info --api-url http://127.0.0.1:9944
zincha query /v1/chain/info --api-url http://127.0.0.1:9944
zincha faucet --address zn1... --api-url http://127.0.0.1:9944
zincha tx transfer --secret-key wallet.key --to zn1... --amount 1000 --fee 1000 --nonce 0
```

## Repository Boundary

High-churn private development happens in
<https://github.com/zinchain/zincha-dev>. Release-ready core code is promoted
to the hardened <https://github.com/zinchain/zincha> repository. This public SDK
repository is updated from that hardened release source by explicit promotion,
not by automatic sync from `zincha-dev`.

Release binaries for the `zincha` CLI are built by GitHub Actions on version
tags and attached to GitHub Releases with SHA256 checksums. Generated binaries
are not committed to this repository.
