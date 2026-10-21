#!/usr/bin/env bash
# Build actual registry archives after scripts/ci-offline.sh has passed.
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="${PYTHON_BIN:-python3}"
OUT_DIR="${OUT_DIR:-$ROOT_DIR/dist/packages}"
export RUST_TEST_THREADS=1
export CARGO_BUILD_JOBS=1
cd "$ROOT_DIR"
mkdir -p "$OUT_DIR"
OUT_DIR="$(cd "$OUT_DIR" && pwd)"
if [ -n "$(ls -A "$OUT_DIR")" ]; then
    echo "Package output directory must be empty: $OUT_DIR" >&2
    exit 1
fi
if [ -n "$(git status --porcelain --untracked-files=normal)" ]; then
    echo "Commit package sources before building attributable release archives." >&2
    exit 1
fi
"$PYTHON_BIN" scripts/sync-package-files.py
cargo package --workspace --locked
TARGET_DIR="$(cargo metadata --no-deps --format-version 1 | "$PYTHON_BIN" -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')"
for name in zincha-primitives zincha-client zincha-cli-core zincha-cli; do
    version="$(cargo metadata --no-deps --format-version 1 | "$PYTHON_BIN" -c 'import json,sys; print(next(p["version"] for p in json.load(sys.stdin)["packages"] if p["name"] == sys.argv[1]))' "$name")"
    cp "$TARGET_DIR/package/$name-$version.crate" "$OUT_DIR/"
done
(
    cd sdk/typescript
    npm pack --pack-destination "$OUT_DIR"
)
"$PYTHON_BIN" -m build --outdir "$OUT_DIR" sdk/python
"$PYTHON_BIN" -m twine check --strict "$OUT_DIR"/*.whl "$OUT_DIR"/*.tar.gz
"$PYTHON_BIN" scripts/check-registry-archives.py "$OUT_DIR"
echo "Registry archives and PACKAGE_MANIFEST.json are ready in $OUT_DIR"
