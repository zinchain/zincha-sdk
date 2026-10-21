# Published SDK patch releases — October 21, 2026

**The published Cargo CLI, Rust client, npm client and PyPI client all passed
fresh-install live Vega reads, transfer submission, confirmation, finality,
nonce and balance checks.** npm's `latest` and `vega` tags now both select `0.2.2`;
a fresh, unversioned `npm install @zincha/client` installed that exact artifact.

These are functional native-transfer checks. They do not establish TPS/RSS
performance, endurance, or coverage of every endpoint and conversation flow.
No node binary or validator deployment changed.

## Published artifacts and source

| Registry | Current version | Package source | Successful publication |
| --- | --- | --- | --- |
| crates.io: primitives, client, CLI core and CLI | `0.1.2` | `4badcd430558aca3a89d10008e6c11d4bcbc9247` | [Cargo publication](https://github.com/zinchain/zincha-sdk/actions/runs/39686098496) |
| npm: `@zincha/client` | `0.2.2` | `7bf8ee8ece4fc7b87b52327a417efbe2d24b3380` | [Registry publication](https://github.com/zinchain/zincha-sdk/actions/runs/39683122678) |
| PyPI: `zincha` | `0.1.1` | `7bf8ee8ece4fc7b87b52327a417efbe2d24b3380` | [Registry publication](https://github.com/zinchain/zincha-sdk/actions/runs/39683122678) |

All uploads used trusted publishing. Public archive downloads match the sealed
manifest from their respective publishing run. npm signatures and attestations
passed, as did cryptographic verification of both PyPI attestations. The
[evidence manifest](evidence/LIVE_REGISTRY_PATCH_RELEASE_2026_10_21.json) records
full archive hashes, source revisions, installed binary hashes and receipts.

The first patch upload also published Cargo `0.1.1`. Installing it revealed a
hardcoded `zincha 0.1.0` CLI banner. Commit `4badcd4` derives the banner from Cargo
package metadata and makes the regression test compare the exact package
version. Cargo `0.1.2` includes that correction and all transaction fixes;
`zincha --version` from its public install reports `zincha 0.1.2`.

## Live results

Tests ran sequentially on macOS using isolated public-registry installations,
Rust 1.94.0, Node 24.19.0 and Python 3.12.13. The Rust processes used the existing
`x86_64-apple-darwin` toolchain; this is compatibility evidence, not a speed test.
The endpoint was `https://vega.zincha.com`, chain `zincha-vega-1`.

Each test transferred **1,000 micro-ZIN** from a disposable faucet-funded wallet
and paid **30 micro-ZIN**. Checks matched the signed/submitted hash, terminal
canonical receipt, exact finalized block anchor, nonce advancement and both
account balances. Disposable private keys were removed after validation.

| Consumer | Result and settings | Finalized block | Transaction hash prefix |
| --- | --- | ---: | --- |
| Cargo CLI `0.1.2` | Passed with default release faucet, fee and advertised validity; no overrides | 1,105,634 | `47a123cf62821b3e` |
| Rust client/primitives `0.1.2` | Passed with exact registry dependencies; application supplied node-advertised validity and a 500,000-micro-ZIN fee cap | 1,105,673 | `52e3219155c3883c` |
| npm `0.2.2` | Passed with automatic transfer fee and validity; no overrides | 1,104,098 | `4b460a6d970ba090` |
| PyPI `0.1.1` | Passed with automatic transfer fee and validity; no overrides | 1,104,204 | `2f7c285684ea80e3` |

The Rust low-level transaction constructor requires explicit transaction fields;
its supplied fee cap is not evidence of an automatic estimator. Actual charged
fees and balance reconciliation passed. npm and Python ship client libraries;
the shared `zincha` command comes from the Cargo CLI package.

The external Rust consumer used registry checksums matching the public archives,
with no local path overrides. Python ran in isolated mode against its installed
wheel. npm's explicit-version and subsequent unversioned installations had the
same integrity digest and loaded both the main and Node conversation exports.
The unversioned install verified distribution selection; its unchanged package
bytes had already passed the live npm transfer.

## Regression and packaging checks

- Sequential release checks passed **205 Rust, 76 TypeScript and 61 Python tests**.
- Python compatibility checks passed on **3.9, 3.10, 3.11 and 3.12**, one at a time.
- All **61 packaged Python tests** passed against the public PyPI installation.
- Archive content/synchronization checks, clean archive installations and the
  corrected workflow's `actionlint` checks passed.
- Strict Clippy remains a separate known gap: 30 pre-existing findings in
  unchanged primitives code were reproduced on the prior source. This record
  does not claim a strict-Clippy pass.

The corrected source fixes release faucet routing, CLI transaction validity,
native-transfer fee estimation and terminal-receipt waiting. See the
[original investigation](LIVE_REGISTRY_VALIDATION_2026_10_21.md) for the failed
old defaults and code attribution. Published package versions were never
overwritten.

## npm default version and retained failures

Publishing with `--tag vega` originally left `latest` on `0.2.0`. That made the
default npm page display the old version and its old README even though `0.2.2`
was published. The `0.2.2` archive contains `npm install @zincha/client@0.2.2`.

After the owner enabled the existing trusted publisher's dist-tag permission,
[run 39687938835](https://github.com/zinchain/zincha-sdk/actions/runs/39687938835)
successfully moved `latest` to `0.2.2`. Its immediate `npm view` verification
read stale metadata and failed. The failure is retained: the successful write
is visible in its log, and subsequent public tag reads plus the fresh plain
install independently verify the result.

Commit `17cdd99` uses `--prefer-online`, skips an already-correct tag, and bounds
read-only propagation retries to 12 observations with five-second intervals.
It never retries the mutation as part of that verification loop. The npm
website subsequently refreshed and visibly showed `0.2.2`, both updated tags,
and the corrected README install command. An already-open page may need a refresh.

[The corrected verification run](https://github.com/zinchain/zincha-sdk/actions/runs/39688256183)
passed after [sequential CI](https://github.com/zinchain/zincha-sdk/actions/runs/39688198558)
passed. It verified the existing `0.2.2` tag without republishing a package.

The initial npm and PyPI uploads also had brief metadata/index propagation
delays. Ordinary public-registry reads and installations succeeded after those
delays; no local archive was substituted and no version was republished.

## Distribution scope

Use the current install commands in [PACKAGE_PUBLISHING.md](PACKAGE_PUBLISHING.md).
These remain **Vega testnet SDK releases**. npm's `latest` tag does not designate
a mainnet launch.

At completion of this registry campaign, `zincha-releases` still provided the
older `v0.1.0` prebuilt CLI archives. A separate CLI binary build/finalization
was required to update that channel; this package campaign did not rebuild it.

Follow-up: [CLI v0.1.2 prebuilt archives](https://github.com/zinchain/zincha-releases/releases/tag/v0.1.2)
were built and finalized separately after this registry campaign. Their
[download-validation record](https://github.com/zinchain/zincha-releases/blob/main/validation/v0.1.2.json)
records the native platform results. The original `v0.1.0` archives remain
available as historical artifacts.
