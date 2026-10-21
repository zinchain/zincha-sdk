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

## One-time owner setup

GitHub's `ZINCHA_RELEASES_TOKEN` only publishes GitHub release assets. It does
not grant access to these independent registries. Never commit or paste registry
credentials into an issue, chat, artifact, or workflow source.

### crates.io

1. Sign into [crates.io](https://crates.io/) with the project's chosen GitHub
   maintainer account and verify its email address.
2. For the initial upload, create a short-lived API token with permission to
   publish the four crate names above. Save it as `CARGO_REGISTRY_TOKEN` in the
   `release` environment of `zinchain/zincha-sdk`.
3. Run the registry workflow with `registry=crates`. It publishes primitives,
   client, CLI core and CLI in dependency order. A retry accepts an existing
   version only when its registry checksum matches the validated archive and
   the version has not been yanked.
4. Configure each crate's trusted publisher for owner `zinchain`, repository
   `zincha-sdk`, workflow `publish-packages.yml`, environment `release`. Then
   remove the bootstrap secret and revoke its token. Future runs request
   short-lived credentials through `rust-lang/crates-io-auth-action`.

[crates.io trusted publishing](https://crates.io/docs/trusted-publishing)
requires an initial publication before configuring the crate's publisher.
Add the appropriate project maintainers or GitHub team as crate owners; initial
publication alone makes the publishing account the owner.

### npm

1. Create/verify the maintainer account on [npm](https://www.npmjs.com/) and
   enable two-factor authentication. Ensure the account has publishing access
   to the `@zincha` scope; create the `zincha` organization if available and
   appropriate for the project's ownership.
2. Bootstrap the actual `@zincha/client` package using a short-lived granular
   token authorized for that scope and publication. Store it as `NPM_TOKEN` in
   the SDK repository's `release` environment. A CI bootstrap token must allow
   noninteractive publishing under the account's 2FA policy.
3. Run `registry=npm`. The workflow publishes the tested tarball with public
   access, provenance and the `vega` tag.
4. In the package's trusted-publisher settings, authorize GitHub owner
   `zinchain`, repository `zincha-sdk`, workflow `publish-packages.yml`,
   environment `release`, with permission to run `npm publish`. Remove the
   bootstrap secret and revoke its token after successful configuration.

[npm trusted publishing](https://docs.npmjs.com/trusted-publishers/) supports
short-lived CI authentication and automatic provenance. The workflow installs
npm 11.15.0 on Node 22. New trust configurations must be used within npm's
documented activation window. Do not upload an empty placeholder package to
reserve a name; bootstrap the validated SDK archive.

### PyPI

1. Create/verify the maintainer account on [PyPI](https://pypi.org/account/register/)
   and configure two-factor authentication.
2. At [account publishing](https://pypi.org/manage/account/publishing/), add a
   **pending publisher** for project `zincha`: GitHub owner `zinchain`,
   repository `zincha-sdk`, workflow `publish-packages.yml`, environment
   `release`.
3. Run `registry=pypi`. The first successful trusted publication creates the
   project and uploads the validated wheel and source distribution. No PyPI
   API token is needed. Add the other project maintainers after creation.

[PyPI pending-publisher documentation](https://docs.pypi.org/trusted-publishers/creating-a-project-through-oidc/)
explains first-project creation. A pending configuration does not reserve a
package name; a registry rejection must be resolved before publication.

## Validation and publication

Use **SDK Registry Packages** in GitHub Actions with a reviewed commit or tag
as `source_ref`. `registry=validate` runs all SDK suites sequentially, builds
all seven archives (four crates, one npm tarball, one wheel, one sdist), tests
clean installations, and saves the archives with `PACKAGE_MANIFEST.json` as an
Actions artifact. The manifest records source commit, names, versions, sizes
and SHA-256 checksums.

The publish job checks out the build's resolved commit, downloads that run's
artifacts, rechecks their hashes and contents, and uses the existing `release`
environment. Select `crates`, `npm`, or `pypi` while setting up each registry;
use `all` only after all three are configured. If a later registry fails, retry
that registry alone. Published versions are immutable: do not overwrite them
or silently publish changed contents under the same version.

For local validation, install Rust 1.94.0, Node 22, npm, pnpm 9.15.9, Python
3.12+, `build==1.3.0`, and `twine==6.2.0`, plus SDK dependencies, then run:

```sh
python3 scripts/sync-package-files.py
scripts/ci-offline.sh
scripts/build-registry-packages.sh
scripts/smoke-registry-packages.sh
```

Package sources must be committed, and `dist/packages` must be empty before
building. Use `OUT_DIR` to select a fresh output location. `PYTHON_BIN` selects
an isolated Python tool environment. The fixture synchronization check keeps
the copies inside Rust crates and the Python sdist equal to shared canonical
vectors and OpenAPI; refresh them with `--write` after those sources change.
`skill.md` and OpenAPI semantics are unchanged by packaging.

## Additional distribution channels

Homebrew for the prebuilt CLI and an OCI container image for node operators
are useful next steps. The conversation service can have its own operator
container. They are deployment conveniences, not additional client libraries.
A separate conversation SDK, an npm wrapper that downloads the Rust binary,
or extra language packages are unnecessary for the current public surface.
