#!/usr/bin/env bash

set -euo pipefail

# --- Defaults ---
REMOTE_VERSION=$(curl -fsSL "https://raw.githubusercontent.com/unsinc/siemagent/refs/heads/main/agent-version" 2>/dev/null | tr -d '[:space:]')
VERSION="${REMOTE_VERSION:-8.19.16}"
FLEET_URL=""
ENROLLMENT_TOKEN=""
FORCE=false

# --- Helpers ---
usage() {
    echo "Usage: $0 [--force] [--version <version>] [--token <enrollment-token>] [--fleet <fleet URL>]"
    echo ""
    echo "  --force                  Skip checks for running Elastic Agent/Endpoint services."
    echo "  --version <version>      Specify Elastic Agent version (default: $VERSION)."
    echo "  --token <enrollment-token>  Provide the enrollment token directly (non-interactive)."
    echo "  --fleet <fleet-url>      Provide the fleet URL directly (non-interactive)."
    echo "  -h, --help               Show this help message."
    exit 1
}

error_exit() {
    echo "[ERROR] $1" >&2
    exit 1
}

# --- Root check ---
if [[ $EUID -ne 0 ]]; then
    error_exit "This script must be run as root (sudo)."
fi

while [[ $# -gt 0 ]]; do
    case $1 in
        --force)
            FORCE=true
            shift
            ;;
        --version)
            VERSION="$2"
            shift 2
            ;;
        --token)
            ENROLLMENT_TOKEN="$2"
            shift 2
            ;;
        --fleet)
            FLEET_URL="$2"
            shift 2
            ;;
        -h|--help)
            usage
            ;;
        *)
            usage
            ;;
    esac
done

# --- Check for existing services ---
if ! $FORCE; then
    for svc in ElasticEndpoint.service elastic-agent.service; do
        if command -v systemctl >/dev/null 2>&1; then
            if systemctl is-active --quiet "$svc"; then
                error_exit "Active service $svc detected. Use --force to override."
            fi
        else
            if pgrep -f "$svc" >/dev/null 2>&1; then
                error_exit "Active service $svc detected. Use --force to override."
            fi
        fi
    done
fi

# --- Ask for enrollment token ---
if [[ -z "$ENROLLMENT_TOKEN" ]]; then
    read -rp "Enter your enrollment token: " ENROLLMENT_TOKEN
fi
if [[ -z "$ENROLLMENT_TOKEN" ]]; then
    error_exit "Enrollment token cannot be empty."
fi

# --- Detect arch ---
ARCH=$(uname -m)
if [[ "$ARCH" == "x86_64" ]]; then
    PKG="linux-x86_64.tar.gz"
elif [[ "$ARCH" == "aarch64" || "$ARCH" == "arm64" ]]; then
    PKG="linux-arm64.tar.gz"
else
    error_exit "Unsupported architecture: $ARCH"
fi

echo "[INFO] Installing Elastic Agent $VERSION ($ARCH)"

# --- Download and install ---
BASE_URL="https://artifacts.elastic.co/downloads/beats/elastic-agent"
FILE="elastic-agent-${VERSION}-${PKG}"

curl -L -o "/tmp/${FILE}" "${BASE_URL}/${FILE}"

tar xzvf "/tmp/${FILE}" -C /tmp
DIR="/tmp/elastic-agent-${VERSION}-linux-${ARCH}"
cd "$DIR"
./elastic-agent install --url="$FLEET_URL" --enrollment-token="$ENROLLMENT_TOKEN"

cd /
echo "[INFO] Deleting Elastic Agent temporary files."
rm -f "/tmp/${FILE}"
rm -rf "$DIR"

echo "[SUCCESS] Elastic Agent $VERSION installed and enrolled."
