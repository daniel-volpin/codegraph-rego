#!/usr/bin/env bash
set -e

echo "Setting up CodeGraph benchmark environment..."

mkdir -p .venv/bin

# 0. Ensure uv is installed
if ! command -v uv &> /dev/null; then
    echo "uv not found on PATH. Attempting to install via curl installer..."
    curl -LsSf https://astral.sh/uv/install.sh | sh || { echo "Failed to install uv. Please install uv manually: https://docs.astral.sh/uv/"; exit 1; }
    export PATH="$HOME/.local/bin:$PATH"
fi

# 1. Sync Python dependencies
echo "Syncing Python virtual environment with uv..."
uv sync

# 2. Check and install OPA directly into the virtual environment
VENV_BIN=".venv/bin"
OPA_BIN="$VENV_BIN/opa"

if [ -x "$OPA_BIN" ]; then
    echo "OPA CLI is already installed at $OPA_BIN"
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
    elif [ "$OS" = "linux" ]; then
        OPA_OS="linux"
    else
        echo "Unsupported OS: $OS for automatic OPA install."
        exit 1
    fi

    DOWNLOAD_URL="https://github.com/open-policy-agent/opa/releases/download/v1.15.1/opa_${OPA_OS}_${OPA_ARCH}_static"
    
    echo "Fetching OPA from: $DOWNLOAD_URL"
    curl -L -o "$OPA_BIN" "$DOWNLOAD_URL"
    chmod +x "$OPA_BIN"
    
    echo "OPA successfully installed to $OPA_BIN"
fi

echo "Verifying OPA installation:"
"$OPA_BIN" version

echo "Benchmark environment setup complete."
