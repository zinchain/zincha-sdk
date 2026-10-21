# SDK registry packages

The initial package set uses the SDK runtime shipped with the Vega `v0.1.0`
binary release. Packaging changes add registry metadata, licenses and standalone
test fixtures; they do not change transaction encoding or the node runtime.
The existing binary/source `v0.1.0` tags must not be moved.

| Registry | Package | Initial version | Purpose |
| --- | --- | --- | --- |
| crates.io | `zincha-primitives` | `0.1.0` | Types, cryptography and signing |
| crates.io | `zincha-client` | `0.1.0` | Rust RPC and conversation clients |
| crates.io | `zincha-cli-core` | `0.1.0` | Shared public CLI implementation |
| crates.io | `zincha-cli` | `0.1.0` | Installs the `zincha` executable |
| npm | `@zincha/client` | `0.2.0` | JavaScript/TypeScript client, including conversations |
| PyPI | `zincha` | `0.1.0` | Python client, including conversations |

TypeScript already had version `0.2.0` in the released SDK source. Package
versions belong to their respective SDK APIs; the chain binary tag remains
`v0.1.0`. npm initially uses the `vega` distribution tag. These packages target
the Vega testnet, not a mainnet launch. The registry workflow is manual and
defaults to validation without uploading.

## Installation after publication

```sh
cargo add zincha-client@0.1.0 zincha-primitives@0.1.0
cargo install zincha-cli --version 0.1.0 --locked
npm install @zincha/client@0.2.0
python -m pip install zincha==0.1.0
```

Rust libraries and the executable require a Rust toolchain and native build
tools; release validation uses Rust 1.94.0. Prebuilt CLI archives are also
available from [zincha-releases](https://github.com/zinchain/zincha-releases/releases/tag/v0.1.0).
The npm client requires Node 22.6+ when used in Node. Python supports 3.9+.

## Start here

All registry publishing runs from **zinchain/zincha-sdk**, not `zincha`,
`zincha-dev`, or `zincha-releases`. GitHub release binaries and package registries
are separate destinations: `ZINCHA_RELEASES_TOKEN` cannot publish to crates.io,
npm, or PyPI.

For the first package release, use this exact **source_ref**:

```text
dc2f22254ce2dc3df9efa1b4908a1f45a5694b31
```

This source already passed the
[SDK tests](https://github.com/zinchain/zincha-sdk/actions/runs/39569080671)
and [archive build and clean-install checks](https://github.com/zinchain/zincha-sdk/actions/runs/39569831733).
Later documentation/workflow changes do not replace that initial package source.
For subsequent releases, use the full reviewed commit with the new versions.
Never move the existing `v0.1.0` tags or change the contents of a published version.

Complete each registry separately. Account creation, email verification, 2FA,
and entering new tokens are maintainer steps. Once access is configured, a
maintainer or authorized release operator can run the workflow and verify uploads.
Do not send tokens through chat, issues, source files, or build artifacts.

## Where to save the initial GitHub secrets

Use these steps whenever this guide says to save an environment secret:

1. Open [zincha-sdk environments](https://github.com/zinchain/zincha-sdk/settings/environments).
2. Select the existing **release** environment. Do not create a similarly named
   environment or change its reviewer protection.
3. Scroll to **Environment secrets** and click **Add environment secret**.
4. Enter the exact secret name from the registry instructions below.
5. Paste the registry token into **Value**, then click **Add secret**.
6. Verify that the secret's **name** appears in the `release` environment list.
   GitHub hides the value after saving; that is expected.

Creating a token on a registry does **not** automatically save it in GitHub.
A GitHub Actions **variable** is also not a secret. A token saved in another
repository or environment is not available to this workflow.

| Destination | GitHub secret | Needed when |
| --- | --- | --- |
| crates.io | `CARGO_REGISTRY_TOKEN` | First upload, before trusted publishing exists |
| npm | `NPM_TOKEN` | First upload, before trusted publishing exists |
| PyPI | None | Configure a pending trusted publisher instead |
| GitHub release assets | `ZINCHA_RELEASES_TOKEN` | Existing binary-release workflow; leave it unchanged |

## How to run the registry workflow

1. Open [SDK Registry Packages](https://github.com/zinchain/zincha-sdk/actions/workflows/publish-packages.yml).
2. Click **Run workflow** near the top right of the run list. If it is absent,
   sign into GitHub with repository write access.
3. Leave **Use workflow from** set to **main**. This chooses the workflow code;
   the separate **source_ref** chooses the package code.
4. Paste the full package commit into **source_ref**. For this initial release,
   use the commit in **Start here**, not the moving `main` name.
5. Select the requested **registry** and **crates_auth** values:

   | Task | registry | crates_auth |
   | --- | --- | --- |
   | Build and test without uploading | `validate` | `auto` |
   | Initial Rust upload | `crates` | `auto` |
   | Verify/use Rust trusted publishing | `crates` | `trusted` |
   | Initial or subsequent npm upload | `npm` | `auto` (unused for npm) |
   | Initial or subsequent Python upload | `pypi` | `auto` (unused for PyPI) |

6. Click the green **Run workflow** button and open the new run. Refresh the
   list if it has not appeared yet.
7. Wait for **build** to finish. It runs the SDK checks sequentially, builds
   seven archives, tests clean installations, and saves a checksum manifest.
8. If the run says **Waiting for review**, click **Review deployments**, select
   **release**, and approve the intended publication. If GitHub prevents
   self-review, another configured reviewer must approve it; do not disable
   the environment's protection rules.
9. Wait for **publish** to finish. A green `build` alone does not mean packages
   were uploaded. In `validate` mode, `publish` is deliberately skipped.
10. Follow the registry-specific verification steps below and save the run URL.
    Download the run's `sdk-registry-packages-<commit>` artifact; its
    `PACKAGE_MANIFEST.json` records package versions, source, sizes, and hashes.

Use `all` only when all three registries are ready for the intended versions.
A Rust retry can skip exact existing versions, but the npm and PyPI upload
steps do not implement that same retry behavior. If one registry fails, inspect
what was uploaded before retrying only the affected registry.

## crates.io: four Rust packages

### Step 1 — Create and verify the owner account

1. Open [crates.io](https://crates.io/) and sign in with the GitHub account that
   should own the crates.
2. Open [account profile settings](https://crates.io/settings/profile). Under
   **User Email**, click **Edit**, enter the maintainer email, and click **Save**.
   Signing in with GitHub does not automatically populate this field.
3. Open the verification email from crates.io and follow its link. Return to
   profile settings and confirm verification is complete. Creating an API
   token is possible before this step, but publishing is not.
4. Keep this account signed in for Step 4. The first publishing account becomes
   the crate owner; being a GitHub repository collaborator alone does not make
   someone a crates.io owner.

### Step 2 — Save the initial publish token in GitHub

1. Open [crates.io API tokens](https://crates.io/settings/tokens).
2. Click **New Token**. Set **Name** to `zincha-sdk-initial-publish` and
   **Expiration** to **7 days**.
3. Under **Scopes**, select **publish-new** and **publish-update**. Leave
   **change-owners**, **trusted-publishing**, and **yank** unchecked for this
   upload-only token; Step 4 configures trusted publishing through the website.
4. Under **Crates**, click **Add pattern** once per name and enter exactly
   `zincha-primitives`, `zincha-client`, `zincha-cli-core`, and `zincha-cli` in
   four separate **Crate name pattern** fields. Do not leave it unrestricted.
5. Click **Generate Token**. Copy the token once and save it as
   **CARGO_REGISTRY_TOKEN** using the GitHub
   environment-secret instructions above. Keep its name/expiry in the release
   record so the correct token can be revoked later.
6. Verify the GitHub secret name is present before proceeding. If the one-time
   token value was lost before saving, revoke it on crates.io and create a new
   one; GitHub cannot recover a value that was never saved.

### Step 3 — Publish and verify all four crates

1. Run the workflow with the initial source commit, **registry = crates**,
   **crates_auth = auto**, and workflow branch **main**.
2. Approve the `release` deployment when requested.
3. Open the **Publish crates in dependency order** log. Publication is
   sequential: primitives → client → CLI core → CLI.
4. Confirm that `publish` succeeds and all four pages show version **0.1.0**:

   - [zincha-primitives](https://crates.io/crates/zincha-primitives/0.1.0)
   - [zincha-client](https://crates.io/crates/zincha-client/0.1.0)
   - [zincha-cli-core](https://crates.io/crates/zincha-cli-core/0.1.0)
   - [zincha-cli](https://crates.io/crates/zincha-cli/0.1.0)

5. Compare each registry version's `checksum` with its `sha256` in the saved
   manifest. The public JSON URL is
   `https://crates.io/api/v1/crates/<crate-name>/0.1.0`; also verify `yanked`
   is `false`. The release operator can perform this check automatically.
6. If only publication fails, fix the reported cause, then open that run and
   select **Re-run jobs → Re-run failed jobs**. This reuses the successful
   build's artifacts; approve `release` again if prompted. A new workflow run
   also works, but must use the **same source** and `registry = crates`.
   The script skips an existing version only when its checksum matches and
   it is not yanked. It refuses changed contents. If the error was HTTP 503,
   check whether the version appeared before retrying: a network/server error
   does not by itself prove the upload was rejected.

### Step 4 — Configure and verify trusted publishing

This step becomes available only after Step 3. Configure **each** crate; one
crate's settings do not cover the other three.

1. While signed into the owner account, open each crate's settings:

   - [zincha-primitives settings](https://crates.io/crates/zincha-primitives/settings)
   - [zincha-client settings](https://crates.io/crates/zincha-client/settings)
   - [zincha-cli-core settings](https://crates.io/crates/zincha-cli-core/settings)
   - [zincha-cli settings](https://crates.io/crates/zincha-cli/settings)

2. Find **Trusted Publishing**, click **Add**, and select **GitHub**.
3. Enter these values exactly, then save:

   | Field | Value |
   | --- | --- |
   | Repository owner | `zinchain` |
   | Repository name | `zincha-sdk` |
   | Workflow filename | `publish-packages.yml` |
   | Environment | `release` |

   Enter only the workflow filename, not `.github/workflows/` and not the
   display name “SDK Registry Packages”. `zinchain` is the GitHub owner; it
   need not match the crates.io display name.

4. Return to each settings page and confirm its publisher lists all four values.
5. Keep the bootstrap secret temporarily. Rerun the workflow with the **same
   initial source commit**, **registry = crates**, **crates_auth = trusted**.
   This forces short-lived OIDC credentials and excludes the bootstrap secret.
6. Confirm **Obtain short-lived crates.io credentials after initial bootstrap**
   succeeds and the publish step reports all four versions already present
   with the expected checksums. This checks OIDC exchange and installed
   package identity without creating another version. It is not a test upload
   with the new credential; the next real version will exercise that upload.
   Keep the four verified publisher settings as part of the verification record.
7. Only after those checks, delete **CARGO_REGISTRY_TOKEN** from the GitHub
   `release` environment. Leave **ZINCHA_RELEASES_TOKEN** intact.
8. On the [crates.io token page](https://crates.io/settings/tokens), revoke only
   the bootstrap token created in Step 2. Deleting the GitHub secret does not
   revoke the token at crates.io.
9. For later Rust releases, use `crates_auth = trusted` and a reviewed source
   commit with incremented versions. No stored crates.io token is needed.

If OIDC fails, check the four configuration fields against the actual workflow
repository, filename, and environment. Do not remove the working bootstrap
credential until the mismatch is resolved. Add other intended crate owners
separately; trusted publishing does not grant them ownership.

See the [official crates.io trusted-publishing guide](https://crates.io/docs/trusted-publishing).

## npm: @zincha/client

### Step 1 — Establish account and scope ownership

1. Create or sign into the maintainer account on [npm](https://www.npmjs.com/).
   Verify its email, enable 2FA, and store recovery codes safely.
2. Confirm you control the **@zincha** scope. An npm user named `zincha` owns
   its personal scope; alternatively, an npm organization named `zincha`
   can own the scope and grant the maintainer publishing access. Do not create
   an organization if the intended scope already belongs to your user account.
3. Verify access through npm's account/organization settings. GitHub ownership
   of `zinchain` does not automatically grant npm scope ownership. Resolve a
   scope conflict before uploading; do not silently rename the package.

### Step 2 — Save a short-lived initial publish token

1. Open your npm profile menu → **Access Tokens** → **Generate New Token**.
2. Give it a recognizable bootstrap name and a short expiration.
3. Under **Packages and scopes**, choose the permission that permits direct
   publication, then restrict it to **@zincha**. The package does not yet exist,
   so selecting only an existing package will not cover the first upload.
4. For this noninteractive bootstrap, enable **Bypass two-factor authentication**
   on this narrowly scoped token. Keep account 2FA enabled. Organization
   administration permission alone does not grant package publication.
5. Generate the token and save it as **NPM_TOKEN** in the GitHub `release`
   environment using the instructions above.

The [official token guide](https://docs.npmjs.com/creating-and-viewing-access-tokens/)
explains the current form and permissions.

### Step 3 — Publish the actual SDK

1. Run the workflow with the initial source commit and **registry = npm**.
2. Approve `release`, then wait for **publish** to succeed.
3. Verify [@zincha/client](https://www.npmjs.com/package/@zincha/client)
   contains **0.2.0**, has provenance, and has `vega` pointing to that version.
   A terminal check is `npm view @zincha/client@0.2.0 version dist-tags dist.integrity`.
4. Save the run URL and archive manifest. Do not upload an empty placeholder.

### Step 4 — Configure trusted publishing for future versions

1. Open the package page → **Settings** → **Trusted Publisher** and choose GitHub.
2. Set owner `zinchain`, repository `zincha-sdk`, workflow
   `publish-packages.yml`, and environment `release`.
3. Where npm offers **Allowed actions**, explicitly allow direct **npm publish**.
   This workflow does not use staged publication.
4. Save the configuration. Coordinate its activation with the next planned
   version and npm's current activation-window requirements; do not change
   package contents under version `0.2.0` simply to test it.
5. For the first intended OIDC publication, remove `NPM_TOKEN` from GitHub so
   the workflow uses trusted publishing. Confirm the new version and provenance
   before revoking the bootstrap token on npm. Retain it securely during this
   transition; do not paste it into troubleshooting logs.

Unlike the Rust uploader, rerunning the npm step with an already published
version fails. Trusted publishing and GitHub's release approval are separate
checks. See [npm's trusted-publisher instructions](https://docs.npmjs.com/trusted-publishers/).

## PyPI: zincha

### Step 1 — Create and secure the maintainer account

1. Create an account at [PyPI registration](https://pypi.org/account/register/)
   or sign into the intended existing account.
2. Verify its email and configure 2FA with recovery codes.
3. Use **pypi.org**, not TestPyPI, for this release. A TestPyPI account or
   publisher does not configure the production registry.

### Step 2 — Add a pending publisher (no API token)

1. Open [PyPI account publishing](https://pypi.org/manage/account/publishing/).
2. Under **Add a new pending publisher**, choose **GitHub**.
3. Fill in the form and save it:

   | Field | Value |
   | --- | --- |
   | PyPI project name | `zincha` |
   | Owner | `zinchain` |
   | Repository name | `zincha-sdk` |
   | Workflow name | `publish-packages.yml` |
   | Environment name | `release` |

4. Confirm the pending publisher appears in the account's list. It authorizes
   project creation on first use; it does not reserve the name in advance.

### Step 3 — Publish and verify

1. Run the workflow with the initial source commit and **registry = pypi**.
2. Approve `release` and wait for **publish** to succeed. No PyPI secret is needed.
3. Verify [zincha 0.1.0](https://pypi.org/project/zincha/0.1.0/) exists and its
   **Download files** tab lists both a wheel and a source distribution.
4. Compare both file hashes with `PACKAGE_MANIFEST.json`. Confirm the pending
   publisher became an active publisher under the project's publishing settings.
5. Add other intended project maintainers after creation. Use a new version for
   subsequent releases; the workflow does not skip existing PyPI uploads.

See [PyPI's pending-publisher guide](https://docs.pypi.org/trusted-publishers/creating-a-project-through-oidc/).

## Troubleshooting

| Symptom | Check and action |
| --- | --- |
| `CARGO_REGISTRY_TOKEN` is missing | Save the crates.io token under **zinchain/zincha-sdk → Settings → Environments → release → Environment secrets**. Creating it on crates.io alone is insufficient. |
| Initial crates run tries OIDC and fails | Use `crates_auth = auto` and verify the bootstrap secret exists; initial crate creation needs that token. |
| Crates publish is denied | Check verified email, token expiry, new-crate permission/name restrictions, and ownership if the name already exists. |
| Crates requires a verified email | Open [profile settings](https://crates.io/settings/profile), add/save an email if empty, then follow the verification email. GitHub login and token creation do not complete this step. |
| Crates returns HTTP 503 | Inspect registry state, then retry the failed publish job with unchanged artifacts. If the service keeps failing, preserve the evidence and wait for registry recovery. |
| Rust checksum mismatch | Stop. Compare the source commit, package manifest, compiler and generated archives. Do not bypass the check or overwrite a version. |
| Trusted publishing rejects the workflow | Check `zinchain`, `zincha-sdk`, `publish-packages.yml`, and `release` exactly on every package. |
| Run is waiting for review | Approve the `release` deployment using an eligible configured reviewer. |
| npm returns 403 | Check scope ownership, direct-publish permission, token expiry and bootstrap 2FA policy, or OIDC publisher permissions after migration. |
| PyPI reports an invalid publisher | Check production PyPI, the pending project name `zincha`, and the exact GitHub fields. |
| npm/PyPI says the version already exists | Check whether an earlier run already uploaded it. Do not blindly rerun `all` or change the same version's contents. |
| Build passes, package page is absent | Check that `registry` was not `validate`, that release approval happened, and that **publish** succeeded. |

## Local validation and release records

The workflow validates archives against the exact package-source checkout
before publishing. It builds four crates, one npm tarball, one Python wheel,
and one Python source distribution. Retain the run URL and manifest for each
registry, and compare registry checksums after publication.

For local validation, install Rust 1.94.0, Node 22, npm, pnpm 9.15.9, Python
3.12+, `build==1.3.0`, and `twine==6.2.0`, plus SDK dependencies, then run these
commands sequentially:

```sh
python3 scripts/sync-package-files.py
scripts/ci-offline.sh
scripts/build-registry-packages.sh
scripts/smoke-registry-packages.sh
```

The workflow installs npm 11.15.0, which supports trusted publishing. Python
3.12+ here is for packaging tools; the distributed SDK supports Python 3.9+.
Package sources must be committed, and `dist/packages` must be empty before
building. Use `OUT_DIR` for a fresh output location and `PYTHON_BIN` for an
isolated Python tool environment. The fixture synchronization check compares
package-local copies with canonical vectors and OpenAPI; refresh copies with
`--write` after those sources change. Packaging does not change `skill.md` or
OpenAPI semantics.

## Additional distribution channels

Homebrew for the prebuilt CLI and an OCI container image for node operators
are useful next steps. The conversation service can have its own operator
container. They are deployment conveniences, not additional client libraries.
A separate conversation SDK, an npm wrapper that downloads the Rust binary,
or extra language packages are unnecessary for the current public surface.
