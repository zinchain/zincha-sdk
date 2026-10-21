#!/usr/bin/env python3
"""Keep standalone package licenses/test fixtures equal to their canonical files."""
import argparse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CRATE_FIXTURES = {
    "zincha-primitives": [
        "golden-agent-tool-lifecycle.json", "golden-agreement-lifecycle.json",
        "golden-rpc-read-delegation-v1.json", "golden-token-operations.json",
    ],
    "zincha-client": [
        "golden-conversation-v1.json", "golden-conversation-e2e-v1.json",
        "golden-conversation-profile-v2.json", "golden-rpc-read-delegation-v1.json",
    ],
    "zincha-cli": ["golden-staking-validator.json"],
}


def package_files():
    for directory in sorted((ROOT / "crates").iterdir()):
        if (directory / "Cargo.toml").is_file():
            yield ROOT / "LICENSE", directory / "LICENSE"
    for language in ("typescript", "python"):
        yield ROOT / "LICENSE", ROOT / "sdk" / language / "LICENSE"
    for crate, names in CRATE_FIXTURES.items():
        for name in names:
            yield ROOT / "sdk/testdata" / name, ROOT / "crates" / crate / "tests/fixtures" / name
    yield ROOT / "openapi/openapi.json", ROOT / "crates/zincha-cli-core/tests/fixtures/openapi.json"
    for source in sorted((ROOT / "sdk/testdata").glob("*.json")):
        yield source, ROOT / "sdk/python/tests/fixtures" / source.name


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="refresh copies; default checks only")
    args = parser.parse_args()
    stale = []
    for source, destination in package_files():
        expected = source.read_bytes()
        if destination.is_file() and destination.read_bytes() == expected:
            continue
        if args.write:
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(expected)
        else:
            stale.append(str(destination.relative_to(ROOT)))
    if stale:
        raise SystemExit("Stale package files; run scripts/sync-package-files.py --write:\n" + "\n".join(stale))
    print("Standalone package licenses and fixtures match canonical sources")


if __name__ == "__main__":
    main()
