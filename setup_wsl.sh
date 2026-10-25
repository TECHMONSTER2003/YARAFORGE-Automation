#!/usr/bin/env bash
# One-shot environment setup for Ubuntu 22.04/24.04 on WSL2 (or any Debian-based Linux).
# Safe to re-run.
set -euo pipefail

echo "[*] apt packages (python, mingw cross-compiler for the harmless test corpus, unzip)"
sudo apt-get update -q
sudo apt-get install -y -q python3 python3-venv python3-pip mingw-w64 unzip curl

echo "[*] python virtualenv"
python3 -m venv .venv
# shellcheck disable=SC1091
source .venv/bin/activate
pip install -q --upgrade pip
pip install -q -r requirements.txt

echo "[*] capa official rules (optional - custom lab rules in rules/capa_custom work offline)"
if [ ! -d rules/capa_official ]; then
  CAPA_RULES_VER="v9.3.0"
  if curl -fsSL -o /tmp/capa-rules.zip "https://github.com/mandiant/capa-rules/archive/refs/tags/${CAPA_RULES_VER}.zip"; then
    unzip -q /tmp/capa-rules.zip -d rules/ && mv "rules/capa-rules-${CAPA_RULES_VER#v}" rules/capa_official
  else
    echo "    could not download capa-rules; continuing with rules/capa_custom"
  fi
fi

echo "[*] versions"
python -c "import yara, pefile; print('yara-python', yara.__version__, '| pefile', pefile.__version__)"
floss --version
capa --version
echo "[+] done. Activate with: source .venv/bin/activate"
