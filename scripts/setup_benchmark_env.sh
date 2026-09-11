#!/usr/bin/env bash
set -euo pipefail

echo "Setting up CodeGraph benchmark environment..."

if ! command -v java >/dev/null || ! command -v javac >/dev/null || ! command -v mvn >/dev/null; then
    echo "JDK 21 and Maven are required to build the Java analysis adapter." >&2
    exit 1
fi
if ! command -v uv >/dev/null; then
    echo "uv is required. Install it before running benchmark setup." >&2
    exit 1
fi
make java-parser-build

# 1. Sync Python dependencies
echo "Syncing Python virtual environment with uv..."
uv sync --locked

# 2. Check and install OPA directly into the virtual environment
VENV_BIN=".venv/bin"
OPA_BIN="$VENV_BIN/opa"
OPA_VERSION=v1.20.2

if [ -x "$OPA_BIN" ] && [ "$("$OPA_BIN" version | awk '/^Version:/ {print $2}')" = "${OPA_VERSION#v}" ]; then
    echo "OPA $OPA_VERSION is already installed at $OPA_BIN"
else
    echo "Downloading OPA CLI for benchmark evaluations..."
    OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
    ARCH="$(uname -m)"
    
    # Map architectures to OPA release targets
    if [ "$ARCH" = "x86_64" ]; then
        OPA_ARCH="amd64"
    elif [ "$ARCH" = "arm64" ] || [ "$ARCH" = "aarch64" ]; then
        OPA_ARCH="arm64"
    else
        echo "Unsupported architecture: $ARCH for automatic OPA install."
        exit 1
    fi
    
    # Map OS to OPA release targets
    if [ "$OS" = "darwin" ]; then
        OPA_OS="darwin"
        OPA_SUFFIX=""
    elif [ "$OS" = "linux" ]; then
        OPA_OS="linux"
        OPA_SUFFIX="_static"
    else
        echo "Unsupported OS: $OS for automatic OPA install."
        exit 1
    fi

    DOWNLOAD_URL="https://github.com/open-policy-agent/opa/releases/download/${OPA_VERSION}/opa_${OPA_OS}_${OPA_ARCH}${OPA_SUFFIX}"
    OPA_TMP="$(mktemp "$VENV_BIN/.opa-download.XXXXXX")"
    OPA_CHECKSUM="$OPA_TMP.sha256"
    trap 'rm -f -- "$OPA_TMP" "$OPA_CHECKSUM"' EXIT
    
    echo "Fetching OPA from: $DOWNLOAD_URL"
    curl -fLsS -o "$OPA_TMP" "$DOWNLOAD_URL"
    curl -fLsS -o "$OPA_CHECKSUM" "$DOWNLOAD_URL.sha256"
    "$VENV_BIN/python" -c '
import hashlib
import pathlib
import sys

with open(sys.argv[1], "rb") as stream:
    actual = hashlib.file_digest(stream, "sha256").hexdigest()
expected = pathlib.Path(sys.argv[2]).read_text(encoding="ascii").split()[0]
if actual != expected:
    raise SystemExit("OPA download checksum mismatch")
' "$OPA_TMP" "$OPA_CHECKSUM"
    chmod +x "$OPA_TMP"
    if [ "$("$OPA_TMP" version | awk '/^Version:/ {print $2}')" != "${OPA_VERSION#v}" ]; then
        echo "Downloaded OPA does not report the required version $OPA_VERSION" >&2
        exit 1
    fi
    mv "$OPA_TMP" "$OPA_BIN"
    
    echo "OPA successfully installed to $OPA_BIN"
fi

echo "Verifying OPA installation:"
"$OPA_BIN" version

echo "Benchmark environment setup complete."
