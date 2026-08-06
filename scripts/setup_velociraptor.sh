#!/usr/bin/env bash
# Download and GPG-verify the official Velociraptor release binary.
#
# Source: https://github.com/Velocidex/velociraptor (upstream, AGPLv3).
# We use Velociraptor as an independent service reached over its own API/VQL —
# this script only fetches the official signed release, it does not modify or
# embed Velociraptor source into this repository.
set -euo pipefail

VERSION="0.77.1"
PLATFORM="linux-amd64"
BASE_URL="https://github.com/Velocidex/velociraptor/releases/download/v${VERSION}"
BINARY="velociraptor-v${VERSION}-${PLATFORM}"
GPG_FINGERPRINT="0572F28B4EF19A043F4CBBE0B22A7FB19CB6CFA1"

DEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/tools/velociraptor"
mkdir -p "$DEST_DIR"
cd "$DEST_DIR"

echo "==> Downloading ${BINARY}"
curl -fsSL -O "${BASE_URL}/${BINARY}"
curl -fsSL -O "${BASE_URL}/${BINARY}.sig"

echo "==> Importing Velocidex release signing key (${GPG_FINGERPRINT})"
gpg --keyserver keyserver.ubuntu.com --recv-keys "${GPG_FINGERPRINT}"

echo "==> Verifying signature"
gpg --verify "${BINARY}.sig" "${BINARY}"

chmod +x "${BINARY}"
echo "==> OK: ${BINARY} verified and executable"
echo "==> SHA-256: $(sha256sum "${BINARY}" | cut -d' ' -f1)"
