#!/bin/bash
#
# Dependency installer for ProcessFuzzyHash (Volatility 3 / Python 3).
#
# It installs the system libraries, creates a virtualenv and installs
# Volatility 3 plus the fuzzy-hash backends used by the plugin.
#
# The original Volatility 2.6 installer (Python 2.7 + jessie-backports) is
# preserved on the `volatility2-latest` branch.
#
# Override the virtualenv location with: VENV=/path/to/venv ./setup.sh

set -e

VENV="${VENV:-$HOME/.venv-vol3}"
PLUGIN_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "[*] Installing system dependencies (sudo may prompt for a password)..."
sudo apt-get update
sudo apt-get install -y \
    build-essential cmake git \
    python3 python3-dev python3-venv python3-pip \
    libfuzzy-dev libffi-dev ssdeep

echo "[*] Creating a virtualenv at: $VENV"
python3 -m venv "$VENV"
"$VENV/bin/pip" install --upgrade pip wheel

echo "[*] Installing required Python 3 packages..."
# volatility3: the framework; pefile: PE parsing; python-tlsh & ssdeep: hashing.
# (dcfldd is bundled with the plugin -- pure Python, no dependency.)
"$VENV/bin/pip" install volatility3 pefile python-tlsh ssdeep

echo "[*] Installing optional sdhash backend (fuzzyhashlib)..."
"$VENV/bin/pip" install fuzzyhashlib || \
    echo "    [!] fuzzyhashlib (sdhash) failed to install; the other algorithms still work."

cat <<EOF

Done!

Run the plugin with the virtualenv's interpreter, e.g.:

  $VENV/bin/vol -p "$PLUGIN_DIR" -f memory.dmp processfuzzyhash \\
      --mode pe --algorithm ssdeep --name svchost.exe

Available algorithms: ssdeep, tlsh, dcfldd (bundled) and -- if fuzzyhashlib
installed above -- sdhash.
EOF
