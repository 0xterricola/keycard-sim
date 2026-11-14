#!/usr/bin/env bash
# Shell side of the blind BabyJubJub signature (Keycard Shell, STM32H573 Cortex-M33): emulated cost and T=1 time.
# Needs clang, ld.lld and the Python packages unicorn, capstone, pyelftools.
set -euo pipefail
cd "$(dirname "$0")"
for t in clang ld.lld; do
  command -v "$t" >/dev/null || { echo "$t absent : sudo apt install clang lld" >&2; exit 1; }
done
python3 -c "import unicorn, capstone, elftools" 2>/dev/null || {
  echo "modules Python absents : python3 -m pip install unicorn capstone pyelftools" >&2; exit 1; }
exec python3 shell/run.py "$@"
