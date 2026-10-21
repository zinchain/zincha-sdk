#!/usr/bin/env python3
"""Validate package contents and write hashes tied to the current Git commit."""
import argparse
import hashlib
import json
import subprocess
import tarfile
import tomllib
import zipfile
from email.parser import BytesParser
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def tar_files(path):
    with tarfile.open(path) as archive:
        result = {}
        for item in archive.getmembers():
            require(not item.name.startswith("/") and ".." not in PurePosixPath(item.name).parts, "unsafe archive path")
            require(item.isdir() or item.isfile(), "unexpected archive link or special file")
            if item.isfile():
                result[item.name] = archive.extractfile(item).read()
        return result


def validate(directory):
    metadata = json.loads(subprocess.check_output(["cargo", "metadata", "--no-deps", "--format-version", "1"], cwd=ROOT))
    expected = []
    for crate in metadata["packages"]:
        name, version = crate["name"], crate["version"]
        filename = f"{name}-{version}.crate"
        files = tar_files(directory / filename)
        prefix = f"{name}-{version}/"
        require(files[prefix + "LICENSE"] == (ROOT / "LICENSE").read_bytes(), filename + " license mismatch")
        require(prefix + "README.md" in files, filename + " missing README")
        info = json.loads(files[prefix + ".cargo_vcs_info.json"])
        require(not info["git"].get("dirty", False), filename + " came from dirty sources")
        require(info["git"]["sha1"] == git_commit(), filename + " source mismatch")
        source_dir = Path(crate["manifest_path"]).parent
        for source in source_dir.rglob("*.rs"):
            require(files.get(prefix + str(source.relative_to(source_dir))) == source.read_bytes(), filename + " source/test mismatch")
        for source in (source_dir / "tests/fixtures").glob("*.json"):
            require(files.get(prefix + str(source.relative_to(source_dir))) == source.read_bytes(), filename + " missing test fixture")
        expected.append((filename, "crates.io", name, version))

    package = json.loads((ROOT / "sdk/typescript/package.json").read_text())
    name, version = package["name"], package["version"]
    filename = f"{name.removeprefix('@').replace('/', '-')}-{version}.tgz"
    files = tar_files(directory / filename)
    require(json.loads(files["package/package.json"]) == package, "npm metadata mismatch")
    require(files["package/LICENSE"] == (ROOT / "LICENSE").read_bytes(), "npm license mismatch")
    for entry in package["exports"].values():
        for target in entry.values():
            require("package/" + target.removeprefix("./") in files, "missing npm export " + target)
    require(not any("node_modules" in name.split("/") or "/test/" in name for name in files), "npm package contains development files")
    expected.append((filename, "npm", name, version))

    wheels = list(directory.glob("*.whl"))
    require(len(wheels) == 1, "expected exactly one Python wheel")
    with zipfile.ZipFile(wheels[0]) as archive:
        files = {name: archive.read(name) for name in archive.namelist()}
    header = BytesParser().parsebytes(next(data for name, data in files.items() if name.endswith(".dist-info/METADATA")))
    name, version = header["Name"], header["Version"]
    project = tomllib.loads((ROOT / "sdk/python/pyproject.toml").read_text())["project"]
    require((name, version) == (project["name"], project["version"]), "Python identity/version mismatch")
    require(header["Requires-Python"] == project["requires-python"], "Python compatibility metadata mismatch")
    require(header["License-Expression"] == project["license"], "Python license expression mismatch")
    require("zincha/py.typed" in files, "missing Python typing marker")
    require(any(n.endswith("/licenses/LICENSE") and data == (ROOT / "LICENSE").read_bytes() for n, data in files.items()), "wheel license mismatch")
    for source in (ROOT / "sdk/python/src/zincha").glob("*.py"):
        require(files.get("zincha/" + source.name) == source.read_bytes(), "wheel source mismatch")
    sdist = directory / f"{name}-{version}.tar.gz"
    files = tar_files(sdist)
    require(files[f"{name}-{version}/LICENSE"] == (ROOT / "LICENSE").read_bytes(), "sdist license mismatch")
    for source in (ROOT / "sdk/python/tests").rglob("*"):
        if source.is_file() and source.suffix in (".json", ".py"):
            require(files.get(f"{name}-{version}/" + str(source.relative_to(ROOT / "sdk/python"))) == source.read_bytes(), "sdist missing test/fixture")
    expected.extend([(wheels[0].name, "pypi", name, version), (sdist.name, "pypi", name, version)])
    require({p.name for p in directory.iterdir()} - {"PACKAGE_MANIFEST.json"} == {x[0] for x in expected}, "unexpected or stale package files")
    return {"schema_version": 1, "source_repository": "https://github.com/zinchain/zincha-sdk", "source_commit": git_commit(), "artifacts": [
        {"file": filename, "registry": registry, "name": name, "version": version,
         "sha256": hashlib.sha256((directory / filename).read_bytes()).hexdigest(), "bytes": (directory / filename).stat().st_size}
        for filename, registry, name, version in expected
    ]}


def git_commit():
    return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--verify-manifest", action="store_true")
    args = parser.parse_args()
    manifest = validate(args.directory)
    output = args.directory / "PACKAGE_MANIFEST.json"
    if args.verify_manifest:
        require(json.loads(output.read_text()) == manifest, "package manifest differs from verified contents")
    else:
        output.write_text(json.dumps(manifest, indent=2) + "\n")
    print("Validated all seven registry archives, bundled fixtures, licenses, exports and source hashes")
