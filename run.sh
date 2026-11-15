#!/usr/bin/env bash
# One-shot: install deps, seed the simulated estate, run tests + eval, start the console.
set -euo pipefail
cd "$(dirname "$0")"

python3 -m pip install -q -r requirements.txt
python3 -m bankshield seed
python3 -m pytest -q tests
python3 eval/run_eval.py || true

echo
echo "Console: http://localhost:${PORT:-8000}   (API docs: /docs)"
exec python3 -m bankshield serve --host "${HOST:-127.0.0.1}" --port "${PORT:-8000}"
