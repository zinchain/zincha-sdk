#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'USAGE'
Usage: scripts/package-cli-binary.sh TAG TARGET_TRIPLE PLATFORM [BINARY_PATH]

Environment:
  OUT_DIR             Output directory, default: dist
  BINARY_NAME         Binary file name, default: zincha
  SOURCE_REPO         Source repo slug, default: zinchain/zincha-sdk
  SOURCE_TAG          Source tag, default: TAG
  SOURCE_COMMIT       Source commit, default: git rev-parse HEAD
  WORKFLOW_RUN_URL    GitHub Actions run URL, default: local
  BUILD_TIME          ISO-like build time, default: current UTC time
USAGE
}

tag_name="${1:-${TAG_NAME:-}}"
target_triple="${2:-${TARGET_TRIPLE:-${TARGET:-}}}"
platform="${3:-${PLATFORM:-}}"
binary_name="${BINARY_NAME:-zincha}"
binary_path="${4:-${BINARY_PATH:-}}"

if [ -z "$tag_name" ] || [ -z "$target_triple" ] || [ -z "$platform" ]; then
  usage
  exit 2
fi

if [ -z "$binary_path" ]; then
  binary_path="target/$target_triple/release/$binary_name"
  if [ ! -f "$binary_path" ] && [ -f "target/release/$binary_name" ]; then
    binary_path="target/release/$binary_name"
  fi
fi

if [ ! -f "$binary_path" ]; then
  echo "binary not found: $binary_path" >&2
  exit 1
fi

case "$platform" in
  windows-*) archive_format="zip" ;;
  *) archive_format="tar.gz" ;;
esac

artifact_base="zincha-$tag_name-$platform"
archive_name="$artifact_base.$archive_format"
build_manifest_name="$artifact_base.build.json"
out_dir="${OUT_DIR:-dist}"
package_dir="$artifact_base"
source_repo="${SOURCE_REPO:-zinchain/zincha-sdk}"
source_tag="${SOURCE_TAG:-$tag_name}"
source_commit="${SOURCE_COMMIT:-$(git rev-parse HEAD)}"
workflow_run_url="${WORKFLOW_RUN_URL:-local}"
build_time="${BUILD_TIME:-$(date -u +"%Y-%m-%dT%H:%M:%SZ")}"

mkdir -p "$out_dir"
staging_dir="$(mktemp -d)"
trap 'rm -rf "$staging_dir"' EXIT

mkdir -p "$staging_dir/$package_dir"
cp "$binary_path" "$staging_dir/$package_dir/$binary_name"
chmod +x "$staging_dir/$package_dir/$binary_name" 2>/dev/null || true
cp README.md LICENSE "$staging_dir/$package_dir/"
cat > "$staging_dir/$package_dir/VERSION" <<EOF
tag=$tag_name
binary=zincha
source_repo=$source_repo
source_tag=$source_tag
source_commit=$source_commit
target_triple=$target_triple
platform=$platform
built_at=$build_time
EOF

python3 - "$out_dir/$archive_name" "$staging_dir" "$package_dir" "$archive_format" <<'PY'
import os
import sys
import tarfile
import zipfile
from pathlib import Path

dest = Path(sys.argv[1])
staging = Path(sys.argv[2])
package_dir = sys.argv[3]
archive_format = sys.argv[4]
root = staging / package_dir

if archive_format == "zip":
    with zipfile.ZipFile(dest, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(root.rglob("*")):
            if path.is_file():
                archive.write(path, Path(package_dir) / path.relative_to(root))
else:
    with tarfile.open(dest, "w:gz") as archive:
        archive.add(root, arcname=package_dir)
PY

archive_sha256="$(
  python3 - "$out_dir/$archive_name" <<'PY'
import hashlib
import sys
from pathlib import Path
print(hashlib.sha256(Path(sys.argv[1]).read_bytes()).hexdigest())
PY
)"
archive_size_bytes="$(python3 - "$out_dir/$archive_name" <<'PY'
import sys
from pathlib import Path
print(Path(sys.argv[1]).stat().st_size)
PY
)"

python3 - "$out_dir/$build_manifest_name" <<PY
import json
import sys
from pathlib import Path

manifest = {
    "schema_version": 1,
    "artifact": "$archive_name",
    "binary": "zincha",
    "release_tag": "$tag_name",
    "source_repo": "$source_repo",
    "source_tag": "$source_tag",
    "source_commit": "$source_commit",
    "workflow_run_url": "$workflow_run_url",
    "target_triple": "$target_triple",
    "platform": "$platform",
    "built_at": "$build_time",
    "archive_format": "$archive_format",
    "archive_sha256": "$archive_sha256",
    "archive_size_bytes": int("$archive_size_bytes"),
}
Path(sys.argv[1]).write_text(json.dumps(manifest, indent=2) + "\\n")
PY

echo "$out_dir/$archive_name"
echo "$out_dir/$build_manifest_name"
