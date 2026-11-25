#!/usr/bin/env bash
# Installer for standalone quipu package
set -euo pipefail

cd "$(dirname "$0")"
echo "==> Installing quipu in editable mode..."
python3 -m pip install --upgrade pip
python3 -m pip install -e .

echo "==> Verifying quipu CLI..."
quipu verify --json >/dev/null

echo "==> Installation complete! Run 'quipu --help' or 'quipu mcp' to get started."
