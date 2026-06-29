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
python -m pytest
```

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

The full private development surface lives in
<https://github.com/zinchain/zincha-dev>. This public SDK repository is the
canonical developer-facing surface for application builders.

