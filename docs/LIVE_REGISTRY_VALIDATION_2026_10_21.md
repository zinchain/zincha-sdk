# Published-package live Vega validation — October 21, 2026

This is the initial validation record, including the original failures. The
subsequent package releases and their fresh registry-install results are recorded
in [the patch-release validation](LIVE_REGISTRY_PATCH_RELEASE_2026_10_21.md).

Registry installs successfully signed, submitted and confirmed native transfers
through the Rust client, Cargo CLI, npm client and Python client. However,
**the published defaults did not all pass**. The CLI needed explicit faucet and
validity settings, and npm/Python needed an explicit correct fee. The fixes in
this change passed live tests using their normal defaults.

At this initial validation stage, the registry versions were unchanged and a
new release was required. The fixed npm archive and Python wheel tested here are local,
unpublished builds with unchanged version fields; their different hashes are
recorded in the [evidence manifest](evidence/LIVE_REGISTRY_VALIDATION_2026_10_21.json).

## Installation and scope

- Cargo: installed `zincha-cli=0.1.0` from crates.io with `--locked` into an
  isolated prefix. This installed the published primitives, client and CLI-core
  dependencies. Separately built an external Rust application using exact
  `zincha-client=0.1.0` and `zincha-primitives=0.1.0` registry dependencies.
- npm: installed `@zincha/client=0.2.1` from the public npm registry using pnpm
  into an external Node consumer, with lifecycle scripts disabled.
- PyPI: installed `zincha==0.1.0` from public PyPI in a fresh virtual environment.
  Live scripts used isolated Python mode and loaded the installed package.
- Environment: macOS; Rust 1.94.0, Node 24.19.0, Python 3.12.13.
- Endpoint: `https://vega.zincha.com`, chain `zincha-vega-1`, node version `0.1.0`.
  Faucet funds came from `https://faucet.vega.zincha.com` into disposable wallets.
- Every installation/test stage was run sequentially. Rust test threads and Node
  test concurrency were both set to one. No tester instance or validator was changed.

The Cargo package supplies the shared `zincha` CLI. The npm and Python packages
are libraries; they do not ship additional independent CLI executables.

Each successful test transferred **1,000 micro-ZIN**, verified the signed/submitted
hash, checked a terminal canonical receipt and finalized block, and reconciled
nonce advancement and both account balances. Actual charged fees were **30
micro-ZIN**. These are functionality checks, not throughput benchmarks or
qualification of every RPC endpoint, contract operation or conversation flow.

## Live results

| Client/build | Defaults and result | Finalized block | Transfer hash prefix |
| --- | --- | ---: | --- |
| Published Cargo CLI `0.1.0` | Default faucet failed with 404; default transfer failed with TTL 128. Explicit faucet URL and advertised anchor/TTL 64 succeeded. | 1,100,478 | `11b5efdba8abae73` |
| Published Rust client `0.1.0` | Public reads, manual transaction signing, submission and confirmation succeeded. The application supplied the advertised validity window and a 500,000-micro-ZIN fee cap. | 1,101,415 | `b973357ddb2f7a80` |
| Published npm `0.2.1` | Automatic fee 10 rejected; explicit fee 30 succeeded. | 1,101,548 | `55279c004f61095e` |
| Published PyPI `0.1.0` | Automatic fee 10 rejected; explicit fee 30 succeeded. | 1,101,614 | `d95251d74b62b628` |
| Corrected CLI build | Default release faucet, validity window, submission and wait all passed. | 1,101,859 | `f49b225cd54cbf04` |
| Corrected npm archive, separately installed | Automatic fee and validity, submission and finality all passed, without overrides. | 1,102,014 | `68a6f0468c07f60c` |
| Corrected Python wheel, separately installed | Automatic fee and validity, submission and finality all passed, without overrides. | 1,102,088 | `386971421f91eb83` |

The manifest contains full hashes, receipts, finalized-header proofs, registry
archive checksums, CLI binary hashes, local archive hashes and tested source
hashes. The original control installations were preserved while testing fixed
artifacts in separate consumer environments. No registry version was replaced.

## Defects and fixes

### Release-selected faucet routing

[`ZinchaClientBuilder::build`](../crates/zincha-client/src/lib.rs) populated the
release RPC and WebSocket endpoints but omitted the release faucet endpoint.
Consequently, `zincha --release vega faucet` posted to the node RPC host and
received HTTP 404. The explicit faucet host succeeded.

The builder now derives the default faucet from the same release specification.
Explicit RPC and faucet overrides retain their existing behavior. Regression
tests cover release aliases, mainnet, custom endpoints and the outgoing request.

### CLI validity defaults and missing metadata

[`resolve_wallet` / `apply_validity_window`](../crates/zincha-cli-core/src/tx.rs)
used a hardcoded 128-block TTL and generic chain-tip fields. Live Vega advertised
and enforced 64 blocks. It rejected the default transaction before admission.
The CLI also silently discarded chain-info errors and could guess a chain ID.

Online construction now uses `transaction_reference_block_height`,
`transaction_reference_block_hash` and `transaction_ttl_blocks`. Explicit TTLs
must be positive and within the advertised limit; partial anchors, missing
metadata and height overflow fail before signing. Offline construction requires
explicit chain ID and nonce; an explicit offline anchor also requires its TTL.
No extra RPC round trip was added.

An existing build-only test depended on swallowing a refused local connection
and guessing the chain ID. It now explicitly supplies `--offline` and
`--chain-id`. The failure was retained and investigated, not skipped. Tests also
verify that the advertised transaction anchor can differ from the latest block.

### Transfer fee estimation in npm and Python

[`transaction.ts`](../sdk/typescript/src/transaction.ts) and
[`transaction.py`](../sdk/python/src/zincha/transaction.py) defined transfer gas
as 10. The node's `GasSchedule::calculate_gas` charges the transaction base cost
(20) plus the transfer operation (10): **30 total** for an empty-data transfer.
Both published packages reproduced HTTP 422:

```text
Fee 10 below base fee requirement 30 (gas=30 × base_fee=1)
```

Both helpers now use the complete 30-gas cost and preserve caller-specified fee
caps. Regression tests cover multiple base fees and default builder output.
This adds no network request or per-transaction allocation. The explicit fee 30
used in the controls was correct for the observed base fee of 1; it is not a
universal fee recommendation for arbitrary network conditions.

### Premature Rust confirmation

[`wait_for_transaction`](../crates/zincha-client/src/lib.rs) classified pending
states with a list that omitted `prepared`. It could return before completion.
This was found during source review; the successfully recorded published live
transfers did not demonstrate a premature `prepared` return.

Polling now stops only for an explicit terminal `confirmed` or `rejected`
outcome. Missing evidence and unknown statuses continue waiting within the
existing timeout. A CLI regression test serves `prepared` and then `confirmed`
and verifies that the client consumes both responses.

### Confirmation and finality are separate observations

The initial Rust test observed a confirmed transaction at block 1,101,415 while
the finalized tip was still 1,101,413. Its immediate finality assertion failed.
This was a harness assumption, not a failed transfer or an SDK submission bug.
The same transaction was reconciled without resubmission.

The checks now wait for the finalized floor, then verify the receipt's exact
height/hash anchor through the bounded canonical-header endpoint. The original
published CLI observation already matched the exact finalized tip and block
hash. This prevents a merely confirmed or obsolete-fork receipt from counting
as finalized success.

## Regression checks

- Rust: `cargo test --locked --workspace --all-targets`, `RUST_TEST_THREADS=1`:
  **205 passed, zero failed or ignored**.
- TypeScript: **76 passed**, concurrency one; type checking and compilation passed.
- Python: **61 passed**, sequential unittest execution.
- Formatting, public OpenAPI/skill artifact validation, package fixture
  synchronization, dependency-boundary checks and smoke-script syntax: passed.
- **Strict Clippy is not green**: `cargo clippy --locked --workspace --all-targets
  -- -D warnings` stopped on 30 pre-existing warnings in unchanged
  `zincha-primitives`. An untouched archive of parent commit `0379723` reproduced
  exactly the same 30 diagnostics. They include existing argument-count,
  derivable-default and integer-helper style warnings. This change does not
  suppress them or claim strict-lint qualification.

A local packaging attempt initially invoked an unavailable `npm` executable
from pnpm's prepack hook. TypeScript had already been compiled successfully;
packing with pnpm's explicit `--config.ignore-scripts=true` then succeeded. This
was a local tool configuration issue, not a package runtime failure.

The fixes change client defaults and validation only. They change neither node
consensus, wire encoding nor API schemas. No OpenAPI or `skill.md` regeneration
is required. No TPS, CPU or RSS benchmark claim is made from these checks.

## Repeat the CLI check

```bash
cargo build --locked -p zincha-cli
ZINCHA_LIVE_MUTATING=1 ZINCHA_LIVE_TIMEOUT_SECS=120 scripts/live-vega-smoke.sh
```

The new opt-in helper creates disposable keys, funds them with 5 test ZIN,
transfers 1,000 micro-ZIN using defaults, checks finality and balances, and
removes its temporary keys. Scheduled smoke runs remain read-only. To save
individual responses, invoke `scripts/live-vega-transfer.py` directly with
`--binary`, `--timeout` and `--evidence-dir`.

After publishing new package versions, repeat the registry installations and
live checks against those versions. Passing local fixed builds does not change
the behavior of the currently published releases.
