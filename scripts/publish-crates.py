#!/usr/bin/env python3
"""Publish in dependency order; retry only missing, checksum-identical versions."""
import hashlib
import json
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

directory = Path(sys.argv[1]).resolve()
manifest = json.loads((directory / "PACKAGE_MANIFEST.json").read_text())
artifacts = {a["name"]: a for a in manifest["artifacts"] if a["registry"] == "crates.io"}
for name in ("zincha-primitives", "zincha-client", "zincha-cli-core", "zincha-cli"):
    artifact = artifacts[name]
    url = f'https://crates.io/api/v1/crates/{name}/{artifact["version"]}'
    request = urllib.request.Request(url, headers={"User-Agent": "zincha-sdk-release (https://github.com/zinchain/zincha-sdk)"})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            existing = json.load(response)["version"]
    except urllib.error.HTTPError as error:
        if error.code != 404:
            raise
    else:
        if existing.get("yanked") or existing["checksum"] != artifact["sha256"]:
            raise SystemExit(f"Refusing to reuse different/yanked published package {name}")
        print(f"Already published with the expected checksum: {name}", flush=True)
        continue
    # Verify the individual registry-bound package before any irreversible upload.
    subprocess.run(["cargo", "package", "-p", name, "--locked"], check=True)
    metadata = json.loads(subprocess.check_output(["cargo", "metadata", "--no-deps", "--format-version", "1"]))
    built = Path(metadata["target_directory"]) / "package" / artifact["file"]
    if hashlib.sha256(built.read_bytes()).hexdigest() != artifact["sha256"]:
        raise SystemExit(f"Package changed since validation: {name}")
    subprocess.run(["cargo", "publish", "-p", name, "--locked"], check=True)
