#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
export PIP_CACHE_DIR="${PIP_CACHE_DIR:-$PWD/.cache/pip}"
python3 -c 'import sys; sys.exit("Python 3.10+ is required") if sys.version_info < (3, 10) else None'
if [ ! -d .venv ]; then
    python3 -m venv .venv
fi
.venv/bin/python -c 'import sys; assert sys.version_info >= (3, 10); assert sys.prefix != sys.base_prefix; print("Virtual environment ready:", sys.version.split()[0])'
mkdir -p configs fixtures/ground_truth samples src/pcaplens/{formats,dissect,flows,filter,analysis,detect,output} eval tests docs .github/workflows
.venv/bin/python -m pip install --disable-pip-version-check -r requirements.lock
.venv/bin/python -m pip install --disable-pip-version-check --no-build-isolation --no-deps -e .
.venv/bin/python -m pip check
echo 'Activate with: source .venv/bin/activate'
