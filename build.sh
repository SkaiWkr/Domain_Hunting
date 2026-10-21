#!/usr/bin/env bash
# Build the Linux one-file executable: dist/DomainHunter
set -euo pipefail
cd "$(dirname "$0")"
python3 -m venv .venv
. .venv/bin/activate
pip install -q -r requirements.txt
pyinstaller --noconfirm --clean --onefile --windowed --name DomainHunter main.py
echo "Built: $(pwd)/dist/DomainHunter"
