#!/usr/bin/env bash
# Install from archives outside the checkout; no source-tree imports.
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="${PYTHON_BIN:-python3}"
PACKAGE_DIR="$(cd "${1:-$ROOT_DIR/dist/packages}" && pwd)"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT
cd "$WORK_DIR"
mkdir node-consumer
cd node-consumer
printf '{"private":true,"type":"module"}\n' > package.json
npm install --ignore-scripts --no-audit --no-fund "$PACKAGE_DIR"/*.tgz
node --input-type=module <<'JS'
import assert from 'node:assert/strict';
import { Keypair, ZinchaClient, ConversationClient } from '@zincha/client';
import { createNodeConversationClient } from '@zincha/client/conversation-node';
assert.ok(Keypair.generate().address().startsWith('zn1'));
assert.ok(ZinchaClient.forRelease('vega'));
assert.equal(typeof ConversationClient, 'function');
assert.equal(typeof createNodeConversationClient, 'function');
console.log('Installed npm package: main and Node conversation exports pass');
JS
cd "$WORK_DIR"
"$PYTHON_BIN" -m venv python-consumer
python-consumer/bin/python -m pip install --disable-pip-version-check "$PACKAGE_DIR"/*.whl
python-consumer/bin/python -I - <<'PY'
from importlib.metadata import version
from zincha import Keypair, ZinchaClient, ConversationClient
assert Keypair.generate().address().startswith('zn1')
assert ZinchaClient.for_release('vega')
assert callable(ConversationClient)
print('Installed Python package:', version('zincha'))
PY
"$PYTHON_BIN" - "$PACKAGE_DIR" "$WORK_DIR" <<'PY'
import sys, tarfile
from pathlib import Path
source, target = map(Path, sys.argv[1:])
with tarfile.open(next(source.glob('*.tar.gz'))) as archive:
    archive.extractall(target, filter='data')
PY
# These are the sdist's tests, executing against the installed wheel.
python-consumer/bin/python -I -m unittest discover -s "$WORK_DIR"/zincha-*/tests
