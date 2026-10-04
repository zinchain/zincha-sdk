# Zincha Developer SDK

Public developer surface for Zincha.

This repository contains client-safe SDKs, transaction primitives, the public
`zincha` CLI, golden serialization vectors, the public OpenAPI artifact, and
the public agent onboarding skill.
It intentionally does not contain node, consensus, execution, storage, peer
networking, genesis, operator, or e2e cluster internals.

## Layout

- `crates/zincha-primitives` - Rust crypto, addresses, transactions, wallet-safe types, and client-safe protocol data.
- `crates/zincha-client` - Rust HTTP helpers for public node APIs and provider-hosted conversations.
- `crates/zincha-cli-core` - Shared public CLI command implementation.
- `crates/zincha-cli` - Public `zincha` binary.
- `sdk/typescript` - TypeScript SDK package.
- `sdk/python` - Python SDK package.
- `sdk/testdata` - Signing and encrypted-envelope golden vectors shared by SDK implementations.
- `skill.md` - Public AI-agent onboarding and safety contract.
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
npm install     # audited crypto packages plus Node's pinned-TLS transport
npm test
npm run build   # compiled ESM + types in dist/
```

## Python

```bash
cd sdk/python
PYTHONPATH=src python -m unittest discover -s tests
```

All three SDKs implement the versioned provider-hosted conversation protocol:
account-authorized operational keys, exact message signing, resumable SSE,
durable idempotent outboxes, profile discovery, and optional X25519/HKDF/
XChaCha20-Poly1305 end-to-end encryption. Conversation traffic remains off
chain; the node's existing participant-protected workflow reads remain the
authorization source. All implementations reject non-contributory X25519 keys
and validate the complete typed plaintext schema before signing or after
decryption.

`ConversationProfileV2` advertises ordered Web-PKI HTTPS and/or
`zincha-tls-v1` interfaces. The Rust, Node, and Python clients support direct
TLS 1.3 leaf-certificate pinning from authenticated on-chain metadata; browser
TypeScript selects HTTPS and reports a precise unsupported-runtime error for a
pinned-only profile. Every profile-driven constructor verifies `/v1/profile`
before attaching a bearer token or sending workflow data.
`auto` classifies the real profile request and advances only for explicit
refusal, timeout, address, host, or network-unreachable failures. It does not
open a separate probe socket, and TLS, pin, HTTP, and identity failures remain
terminal.
Client pools retain at most 256 idle connections per endpoint. The Node pinned
transport also caps its process cache at 256 service pools and discards a
service's old pool and TLS resumption state when its endpoint or pin set changes.

Outboxes are deliberately bounded. The Rust file implementation defaults to
1,000 messages/64 MiB and uses private, atomically replaced files within one
process; a multi-process Rust platform should use its transactional database
instead. Python uses a private WAL-backed SQLite file with the same logical limits. The TypeScript
store serializes mutations within one SDK instance. Its `localStorage` adapter
is a browser convenience and provides neither confidentiality nor cross-tab
transactions; production browser platforms should supply an IndexedDB-backed
store and coordinate a single sender lease across tabs/workers.

## Test Suite

Run the deterministic offline suite before opening a pull request:

```bash
scripts/ci-offline.sh
```

This formats and tests the Rust workspace, builds the `zincha` CLI, runs the
Python and TypeScript SDK tests, validates the public `skill.md` and OpenAPI
artifacts, and checks that private runtime dependencies have not leaked into
the public SDK surface.

Live public-chain smoke tests are separate from required PR CI:

```bash
cargo build -p zincha-cli
scripts/live-vega-smoke.sh
```

The live smoke uses read-only `zincha --release vega` commands by default.
Mutating faucet/submit coverage must remain opt-in.

## Protocol alignment

This revision was promoted from `zinchain/zincha-dev` commit `61445bb` on
2026-09-28. Rust, TypeScript, and Python transaction serializers use the same
fixed-width binary representation for addresses, hashes, public keys, and
signatures, while human-readable JSON retains canonical hexadecimal strings.
The promoted OpenAPI and `skill.md` artifacts describe the same chain revision,
including complete transaction receipt events, state changes, contract context,
and typed token/native contract-operation journals.

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

Private development and release hardening happen outside this public SDK
repository. This public SDK repository is updated from hardened release
sources by explicit promotion, not by automatic sync from private working
repos.

Release binaries for the `zincha` CLI are built by GitHub Actions on version
tags and uploaded to <https://github.com/zinchain/zincha-releases>. Generated
binaries are not committed to this repository. The source workflow requires a
`ZINCHA_RELEASES_TOKEN` secret with `contents: write` access to the release hub.

To dry-run local packaging after building the CLI:

```bash
cargo build --release -p zincha-cli
scripts/package-cli-binary.sh v0.1.0 "$(rustc -vV | sed -n 's/^host: //p')" local target/release/zincha
```
