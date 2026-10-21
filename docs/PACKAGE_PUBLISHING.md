# SDK package publishing

## Setup status — completed October 21, 2026

Cargo/crates.io, npm, and PyPI publishing are configured for
**zinchain/zincha-sdk**. Future releases use GitHub Actions trusted publishing
(short-lived OIDC credentials); no stored registry token is needed.

| Registry | Package | Published version | Purpose |
| --- | --- | --- | --- |
| crates.io | [zincha-primitives](https://crates.io/crates/zincha-primitives/0.1.2) | `0.1.2` | Types, cryptography and signing |
| crates.io | [zincha-client](https://crates.io/crates/zincha-client/0.1.2) | `0.1.2` | Rust RPC and conversation clients |
| crates.io | [zincha-cli-core](https://crates.io/crates/zincha-cli-core/0.1.2) | `0.1.2` | Shared public CLI implementation |
| crates.io | [zincha-cli](https://crates.io/crates/zincha-cli/0.1.2) | `0.1.2` | Installs the `zincha` executable |
| npm | [@zincha/client](https://www.npmjs.com/package/@zincha/client/v/0.2.2) | `0.2.2`, tags `latest` and `vega` | JavaScript/TypeScript client, including conversations |
| PyPI | [zincha](https://pypi.org/project/zincha/0.1.1/) | `0.1.1` | Python client, including conversations |

The initial SDK packages target the **Vega testnet**, not a mainnet launch.
SDK registry versions are independent of the node release tag `v0.1.0`.
The current prebuilt CLI release is `v0.1.2`, matching Cargo CLI `0.1.2`.
Cargo `0.1.2`, npm `0.2.2` and Python `0.1.1` include the live-Vega fixes
described in [the patch-release validation](LIVE_REGISTRY_PATCH_RELEASE_2026_10_21.md).
Cargo `0.1.1` already included the transaction fixes but displayed the stale CLI
version `0.1.0`; use `0.1.2`, whose banner derives from package metadata.

### Verified publishing state

| Registry | Completed verification | Evidence |
| --- | --- | --- |
| crates.io | All four `0.1.2` crates published through OIDC; public downloads and registry checksums match the sealed manifest. Fresh CLI installation reports `zincha 0.1.2`. | [Trusted publication](https://github.com/zinchain/zincha-sdk/actions/runs/39686098496) |
| npm | `0.2.2` published through OIDC. Public archive, installed exports, signatures, attestations and live finalized transfer verified. `latest` and `vega` both select `0.2.2`; fresh plain install and website verified. | [Trusted publication](https://github.com/zinchain/zincha-sdk/actions/runs/39683122678), [default-tag verification](https://github.com/zinchain/zincha-sdk/actions/runs/39688256183) |
| PyPI | `0.1.1` published through OIDC. Public wheel/source hashes and both attestations verified; all 61 packaged Python tests and a live finalized transfer passed against a fresh installation. | [Trusted publication](https://github.com/zinchain/zincha-sdk/actions/runs/39683122678), [public provenance](https://pypi.org/project/zincha/0.1.1/#security) |

The temporary **CARGO_REGISTRY_TOKEN** and **NPM_TOKEN** GitHub secrets were
removed, and their registry tokens were revoked. No PyPI token was created.
Leave **ZINCHA_RELEASES_TOKEN** unchanged: it serves GitHub binary releases,
not package registries. Account ownership, verified email and 2FA remain in place.

All publishers are bound to these settings:

| Field | Configured value |
| --- | --- |
| GitHub owner | `zinchain` |
| Repository | `zincha-sdk` |
| Workflow filename | `publish-packages.yml` |
| GitHub environment | `release` |

npm permits direct `npm publish` and the separately enabled `npm dist-tag`
operation; this workflow does not use staged publishing.
The existing `release` environment still requires its configured approval.
Registry trust and GitHub release approval are separate checks.

## Install the current packages

```sh
cargo add zincha-client@0.1.2 zincha-primitives@0.1.2
cargo install zincha-cli --version 0.1.2 --locked
npm install @zincha/client@0.2.2
python -m pip install zincha==0.1.1
```

Plain `npm install @zincha/client` and `npm install @zincha/client@vega` both
currently select `0.2.2`. Future `vega` uploads do not move `latest` automatically;
use the explicit promotion procedure below after validation.

Rust libraries and the executable require a Rust toolchain and native build
tools; release validation uses Rust 1.94.0. Prebuilt CLI archives are also
available from [the Vega CLI v0.1.2 prerelease](https://github.com/zinchain/zincha-releases/releases/tag/v0.1.2).
Those five native CLI archives include the same runtime fixes as the current
Cargo CLI. Check the release checksums before running a download. The node
binary remains unchanged at `v0.1.0` and its original Linux archives are also
attached directly to the v0.1.2 release. The v0.1.2 aggregate checksums cover
both component versions. All five prebuilt CLI downloads passed
[sequential native live-Vega validation](https://github.com/zinchain/zincha-releases/blob/main/validation/v0.1.2.json).
The npm client requires Node 22.6+ in Node. Python supports 3.9+.

## Live-client validation

The current registry packages include the corrected release faucet, node-derived
transaction validity, transfer fee estimation and terminal-receipt handling.
The [initial validation](LIVE_REGISTRY_VALIDATION_2026_10_21.md) preserves the
original failures; the [patch-release record](LIVE_REGISTRY_PATCH_RELEASE_2026_10_21.md)
records the public artifacts and their fresh-install results.

For every future runtime fix, run the sequential offline checks below and the
opt-in live transfer smoke from the README. After publishing, install the new
versions from each registry into fresh consumer environments and repeat the
live reads, submission, finality, nonce and balance checks. A successful build
or package import alone does not establish live transaction compatibility.

## Future releases

### Step 1 — Choose the packages and update their versions

1. Start from current `zincha-sdk` `main` and decide which registry needs a
   release. An npm-only change does not require a Rust or Python release.
   Documentation-only changes do not require republishing any package.
2. Choose unused versions appropriate to the API changes. Check the registry
   pages before preparing the release; published versions are immutable.
3. Update the relevant files:

   | Release | Files to update |
   | --- | --- |
   | Rust | `[workspace.package].version` in root `Cargo.toml`; the explicit `version` constraints on internal `zincha-*` path dependencies in `crates/*/Cargo.toml`; the affected workspace entries in `Cargo.lock` |
   | npm | `version` in `sdk/typescript/package.json`; update `sdk/typescript/pnpm-lock.yaml` when dependency declarations change |
   | PyPI | `[project].version` in `sdk/python/pyproject.toml` |

   All four Rust crates currently inherit one workspace version and publish as
   a set. Keep their internal dependency constraints aligned with that version.
   Refresh `Cargo.lock` with `cargo update --workspace` and review the diff for
   unintended dependency upgrades. A TypeScript version-only change does not
   require a dependency update or an npm `package-lock.json`.
4. Update the affected package README and compatibility/release notes. If
   canonical licenses, OpenAPI or test vectors changed, refresh the packaged
   copies with `python3 scripts/sync-package-files.py --write`, then review them.
5. Commit and push the reviewed changes to `main`. Record the full 40-character
   commit SHA with `git rev-parse HEAD`; this is the release's **source_ref**.
   Wait for [SDK CI](https://github.com/zinchain/zincha-sdk/actions/workflows/ci.yml)
   to pass for that commit. CI runs SDK tests sequentially, followed by the
   Python 3.9–3.12 compatibility jobs one at a time.

Do not reuse the initial source commit for a new release. Do not move existing
`v0.1.0` tags. Registry publication is manually dispatched and requires no new
Git tag; binary-release tagging/finalization remains a separate process.

### Step 2 — Start the publishing workflow

1. Open [SDK Registry Packages](https://github.com/zinchain/zincha-sdk/actions/workflows/publish-packages.yml)
   in **zinchain/zincha-sdk**.
2. Click **Run workflow**. If the button is absent, sign into GitHub with
   repository write access.
3. Leave **Use workflow from** set to **main**. This selects the workflow code;
   **source_ref** separately selects the package code.
4. Paste the full reviewed commit SHA from Step 1 into **source_ref**, rather
   than the moving name `main`.
5. Choose these inputs:

   | Intended release | registry | crates_auth | npm_auth |
   | --- | --- | --- | --- |
   | Validation only; no upload | `validate` | `trusted` | `trusted` |
   | Four Rust crates | `crates` | `trusted` | `trusted` |
   | JavaScript/TypeScript SDK | `npm` | `trusted` | `trusted` |
   | Python SDK | `pypi` | `trusted` | `trusted` |
   | All registries, each with new versions | `all` | `trusted` | `trusted` |

   Inputs for an unselected registry are unused. Set both authentication
   selectors explicitly to `trusted`; the form defaults to `auto`.
   `trusted` prevents fallback to a stored bootstrap secret. PyPI always uses
   trusted publishing and has no separate authentication selector.
6. Click the green **Run workflow** button and open the new run. Refresh the
   run list if necessary.

Prefer one registry per run. Use `all` only when every included package is
ready for its intended release; it is not a shortcut for publishing whichever
packages changed. In particular, unchanged npm/PyPI versions will fail upload.
An optional `validate` run can preview packaging, but every publishing run
performs the full build and validation again.

### Step 3 — Review the build and approve the release

1. Wait for **build** to succeed. It validates all SDKs sequentially, builds
   seven archives, verifies package contents and tests clean installations,
   even when only one registry was selected.
2. In the run's **Artifacts** section, download
   `sdk-registry-packages-<source-commit>`. Open `PACKAGE_MANIFEST.json` and check
   its source SHA, package names, versions, sizes and SHA-256 hashes against
   the intended release.
3. If the run says **Waiting for review**, select **Review deployments**, check
   **release**, and approve that publication. Use another configured reviewer
   if self-review is prohibited; keep the environment protection rules intact.
4. Wait for **publish** to succeed. A green `build` alone does not mean anything
   was uploaded. In `validate` mode, `publish` is deliberately skipped.
5. Save this run's URL and artifact outside GitHub's 30-day artifact retention
   window. Keep the manifest from this exact publishing run for Step 4.

The publish job downloads and checks the same archives approved in that run.
A separate build of the same source, especially Python distributions, can have
different archive hashes because of build timestamps. Do not substitute a
previous validation run's manifest for the publishing run's manifest.

### Step 4 — Verify the public release

Perform the checks for the selected registry below, one at a time. Record the
public package URLs, the source and workflow commits, the run URL, the manifest,
and the verification results. Then update this guide's published-version table
and installation examples as appropriate. Do not put credentials in evidence.

#### Rust / crates.io

1. Check **Obtain short-lived crates.io credentials after initial bootstrap**
   and **Publish crates in dependency order** both succeeded. The dependency
   order is primitives → client → CLI core → CLI.
2. Open each crate's new version page. Compare its registry `checksum` from
   `https://crates.io/api/v1/crates/<crate-name>/<version>` with the corresponding
   manifest `sha256`, and confirm `yanked` is `false`.
3. In a temporary consumer project outside the checkout, use the new versions
   of `zincha-client` and `zincha-primitives` and run `cargo check`. Also test
   `cargo install zincha-cli --version <version> --locked --root <temporary-dir>`
   and the installed `zincha --help`. Replace angle-bracket placeholders before
   running commands; use a temporary install root to preserve an existing CLI.
4. Save the exact upload result and manifest. OIDC uploads were demonstrated
   by `0.1.1` and `0.1.2`; each subsequent release still needs its own public
   checksum and clean-install verification.

#### npm / @zincha/client

1. Confirm the new version exists, `vega` points to it, and provenance is
   present on the package page. The workflow publishes with `--tag vega`; it
   does not intentionally move `latest` or create a mainnet release.
2. Check registry metadata. Substitute the intended new version for the
   example value before running:

   ```sh
   SDK_NPM_VERSION=0.2.2
   npm view "@zincha/client@$SDK_NPM_VERSION" version dist-tags dist.tarball dist.integrity
   ```

3. Download `dist.tarball` and compare its SHA-256 with this run's manifest.
   `dist.integrity` is an SRI digest (normally SHA-512), not the manifest's
   SHA-256; do not compare the two strings directly.
4. In a new temporary directory outside the checkout, run `npm init -y`, then
   `npm install --ignore-scripts "@zincha/client@$SDK_NPM_VERSION"` and
   `npm audit signatures`. Verify both `@zincha/client` and
   `@zincha/client/conversation-node` import successfully. Check the installed
   version and provenance point to the intended release.
5. Allow for npm processing delay after a successful upload. During initial
   publication, metadata was temporarily unavailable after the workflow passed.
   Recheck the public version before considering any retry; do not upload it
   again merely because the package page has not appeared yet.

#### Make a tested npm release the default

Publishing under `vega` leaves npm's separate `latest` tag unchanged. The default
package page and plain `npm install @zincha/client` therefore continue to use
that older version and its README until `latest` is promoted.

After registry hash/provenance checks and live tests pass:

1. In the existing npm trusted publisher for `zinchain/zincha-sdk`,
   `publish-packages.yml`, environment `release`, verify **Allow npm dist-tag**
   is enabled (completed October 21).
   Keep the other identity and publishing permissions unchanged. This is an
   explicit additional permission; npm may require password/2FA confirmation.
2. Run **SDK Registry Packages** from `main` with `registry=promote-npm-latest`
   and `source_ref` set to the reviewed commit that supplied the npm version.
   Keep both authentication selectors `trusted`.
3. Approve the existing `release` environment after confirming the intended
   version. This mode uploads no archives and runs no package build. It uses
   npm 11.21.0's trusted tag support, checks that the published version and the
   current `vega` tag match the selected source version, then updates `latest`
   only if needed. Verification requests fresh metadata
   and allows up to 12 read-only observations, five seconds apart, for registry
   propagation. A verification failure never repeats the tag write in that loop.
4. Verify `npm view @zincha/client dist-tags --json` shows both tags on the
   intended version. Test a fresh unversioned install. Allow registry/website
   caches to refresh before treating an old web-page display as a failure.

The `latest` label identifies the default SDK installation; it does not certify
a mainnet launch. Do not republish an immutable version just to change a tag.

#### Python / PyPI

1. Open the new release's **Files** tab at
   `https://pypi.org/project/zincha/<version>/`. It must list both the wheel and
   source distribution with provenance.
2. Retrieve `https://pypi.org/pypi/zincha/<version>/json`. Compare each file's
   `digests.sha256` and size with this run's manifest, confirm it is not yanked,
   then download both public files and verify their bytes/hashes as well.
3. Use a fresh virtual environment outside the checkout to install from
   public PyPI. Substitute the intended new version for this example:

   ```sh
   SDK_PYPI_VERSION=0.1.1
   python3 -m venv .venv
   .venv/bin/python -m pip --isolated install --index-url https://pypi.org/simple "zincha==$SDK_PYPI_VERSION"
   .venv/bin/python -m pip check
   .venv/bin/python -I -c 'from importlib.metadata import version; from zincha import Keypair, ZinchaClient, ConversationClient; assert Keypair.generate().address().startswith("zn1"); assert ZinchaClient.for_release("vega"); assert callable(ConversationClient); print(version("zincha"))'
   ```

4. Unpack the downloaded source distribution into that temporary directory.
   Run its `tests` directory against the installed wheel using
   `.venv/bin/python -I -m unittest discover -s zincha-<version>/tests`.
   Isolated mode prevents importing the source checkout instead of the
   installed package.
5. Verify both public attestations with `pypi-attestations` in a separate tool
   environment. For each wheel/source filename, run
   `pypi-attestations verify pypi --repository https://github.com/zinchain/zincha-sdk pypi:<filename>`.
   The initial release used verifier `0.0.30`. Check the public **Release
   security** panel identifies `zinchain/zincha-sdk`, `publish-packages.yml`,
   and the intended run. The attestation's publishing commit identifies the
   workflow revision; the archived manifest/build log records **source_ref**.

## Retry and recovery

| Situation | Action |
| --- | --- |
| Build or test failure | Investigate and fix the cause; commit a correction and validate the new source. Do not bypass failed checks. |
| Waiting for review | Approve the intended `release` deployment with an eligible reviewer; leave protection enabled. |
| Trusted authentication rejected | Check owner `zinchain`, repo `zincha-sdk`, workflow filename `publish-packages.yml`, environment `release`, and the workflow's `id-token: write` permission. For npm, direct publishing must be allowed. Do not recreate bootstrap tokens as the first response. |
| Rust upload interrupted | Inspect all four registry versions first. If retrying the same release, prefer **Re-run jobs → Re-run failed jobs** to reuse its successful build and artifacts. The uploader skips an existing version only when its checksum matches exactly and it is not yanked. |
| Rust checksum differs | Stop and compare source and artifacts. Do not bypass the check or modify an already published version. Even a new commit with unchanged Rust code may produce different package bytes. |
| npm/PyPI upload reports a timeout or server error | Check the public version and hashes before retrying. The server may have accepted the upload. Do not automatically rerun publication. |
| npm/PyPI version already exists | These workflow steps do not skip existing uploads. Verify the existing release; use a new version for changed contents. |
| PyPI accepted one file but not the other | Preserve the successful file and exact build artifacts. Plan recovery to upload only the missing verified file; the current workflow cannot automatically resume a partial Python upload. Do not blindly rerun both files or enable skipping without checking identity. |
| An `all` run partially succeeded | Verify every registry, then recover only the incomplete publication. A new single-registry run rebuilds archives; retain the original manifest and compare before uploading. |
| npm package settings redirect to 2FA | Use the owner account's correct browser session and complete its 2FA/sign-in check. Do not disable 2FA. |
| New maintainer needs access | Registry ownership and GitHub reviewer/write access are separate. Add only intended maintainers; trusted publishing does not make GitHub collaborators registry owners. |

Existing publishers do not need to be recreated for every version. If the
repository, workflow filename or environment changes, update the affected
registry trust settings before publishing. For a genuinely new package name,
configure its own publisher/initial-publication flow; the existing setup does
not automatically authorize additional crates or npm packages.

Official references: [crates.io trusted publishing](https://crates.io/docs/trusted-publishing),
[npm trusted publishing](https://docs.npmjs.com/trusted-publishers/),
[PyPI trusted publishing](https://docs.pypi.org/trusted-publishers/using-a-publisher/),
[PyPI attestation verification](https://docs.pypi.org/attestations/consuming-attestations/).

## Initial-release provenance and archived setup instructions

The first Rust packages, npm `0.2.0`, and Python `0.1.0` used package source
`dc2f22254ce2dc3df9efa1b4908a1f45a5694b31`. The npm `0.2.1` trusted release used
`90b8b655e7e7d5392b3dcd5adbbcdaad6103d1a0`. Initial evidence: [Cargo upload](https://github.com/zinchain/zincha-sdk/actions/runs/39572570719),
[Cargo OIDC exchange](https://github.com/zinchain/zincha-sdk/actions/runs/39637419749),
[npm bootstrap](https://github.com/zinchain/zincha-sdk/actions/runs/39640410838),
[npm OIDC upload](https://github.com/zinchain/zincha-sdk/actions/runs/39645127528),
and [PyPI first upload](https://github.com/zinchain/zincha-sdk/actions/runs/39648460574).
These source references are historical records, not defaults for the next release.

The [previous bootstrap guide](https://github.com/zinchain/zincha-sdk/blob/90b8b655e7e7d5392b3dcd5adbbcdaad6103d1a0/docs/PACKAGE_PUBLISHING.md)
retains account, first-token, pending-publisher and token-cleanup instructions
for reference. Those steps are complete for the packages listed here. Do not
repeat initial uploads or restore the removed tokens for normal releases.

## Optional local release validation

GitHub Actions performs release validation on Ubuntu with Rust 1.94.0, Node 22,
npm 11.15.0, pnpm 9.15.9, Python 3.12, `build==1.3.0`, and `twine==6.2.0`.
For local validation, install those tools and declared SDK dependencies, then
run from the repository root, sequentially:

```sh
python3 scripts/sync-package-files.py
scripts/ci-offline.sh
scripts/build-registry-packages.sh
scripts/smoke-registry-packages.sh
```

The package builder requires a clean committed checkout and an empty
`dist/packages` directory. Use `OUT_DIR` to build elsewhere, pass that same
path to `scripts/smoke-registry-packages.sh`, and use `PYTHON_BIN` when an
isolated Python tool environment is needed. Keep the hosted release's manifest
as the authority for its uploaded files; local archives are validation evidence.

Packaging documentation alone does not change `skill.md`, OpenAPI, SDK runtime
behavior or node consensus. GitHub binary releases remain a separate workflow.
Homebrew and operator container images are possible later distribution channels,
not prerequisites for these registry releases.
