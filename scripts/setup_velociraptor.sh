#!/usr/bin/env bash
# Download and GPG-verify the official Velociraptor release binary.
#
# Source: https://github.com/Velocidex/velociraptor (upstream, AGPLv3).
# We use Velociraptor as an independent service reached over its own API/VQL —
# this script only fetches the official signed release, it does not modify or
# embed Velociraptor source into this repository.
set -euo pipefail

VERSION="0.77.1"

# The asset must match the machine that will RUN the binary, not the machine
# this script was written on. PLATFORM was pinned to linux-amd64, so on Windows
# (Git Bash / MSYS) or macOS it fetched a Linux ELF and the live suite then
# reported "binary not present" while looking for the right name. Upstream
# publishes every asset as velociraptor-v<version>-<os>-<arch>, with .exe on
# Windows only. Set VELOCIRAPTOR_PLATFORM to fetch for a target other than this
# host. Keep the naming in step with tools/velociraptor/release.py.
case "$(uname -s)" in
    Linux*)               _os="linux" ;;
    Darwin*)              _os="darwin" ;;
    MINGW*|MSYS*|CYGWIN*) _os="windows" ;;
    *) echo "Unsupported OS: $(uname -s)" >&2; exit 1 ;;
esac
case "$(uname -m)" in
    x86_64|amd64)  _arch="amd64" ;;
    arm64|aarch64) _arch="arm64" ;;
    *) echo "Unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

PLATFORM="${VELOCIRAPTOR_PLATFORM:-${_os}-${_arch}}"
BASE_URL="https://github.com/Velocidex/velociraptor/releases/download/v${VERSION}"
BINARY="velociraptor-v${VERSION}-${PLATFORM}"
case "$PLATFORM" in windows-*) BINARY="${BINARY}.exe" ;; esac
GPG_FINGERPRINT="0572F28B4EF19A043F4CBBE0B22A7FB19CB6CFA1"

DEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/tools/velociraptor"
mkdir -p "$DEST_DIR"
cd "$DEST_DIR"

echo "==> Downloading ${BINARY}"
curl -fsSL -O "${BASE_URL}/${BINARY}"
curl -fsSL -O "${BASE_URL}/${BINARY}.sig"

echo "==> Importing Velocidex release signing key (${GPG_FINGERPRINT})"
# The keyserver protocol needs a port that restricted networks routinely block
# (observed: "keyserver receive failed: Connection timed out" behind an
# HTTPS-only egress proxy). Fall back to the same keyserver's HTTPS interface.
# The transport is not what makes this safe: whatever arrives is still pinned
# by the VALIDSIG assertion below, so a hostile fetch fails loudly instead of
# substituting a key.
gpg --keyserver keyserver.ubuntu.com --recv-keys "${GPG_FINGERPRINT}" || {
    echo "==> keyserver protocol failed; retrying over HTTPS"
    curl -fsSL "https://keyserver.ubuntu.com/pks/lookup?op=get&options=mr&search=0x${GPG_FINGERPRINT}" \
        | gpg --import
}

echo "==> Verifying signature"
# `gpg --verify` alone only proves SOME key in the local keyring signed this.
# The property this script claims is stronger -- that the release was signed by
# the pinned key -- so assert VALIDSIG against the fingerprint rather than
# trusting the exit code and a human reading the prose output.
if ! gpg --status-fd 1 --verify "${BINARY}.sig" "${BINARY}" 2>/dev/null \
        | grep -q "^\[GNUPG:\] VALIDSIG ${GPG_FINGERPRINT} "; then
    echo "==> FAIL: ${BINARY} is not signed by ${GPG_FINGERPRINT}" >&2
    echo "    Refusing to install an unverified forensic collector." >&2
    exit 1
fi
gpg --verify "${BINARY}.sig" "${BINARY}"

chmod +x "${BINARY}"
echo "==> OK: ${BINARY} verified and executable"
echo "==> SHA-256: $(sha256sum "${BINARY}" | cut -d' ' -f1)"

# The Windows release embeds requestedExecutionLevel="highestAvailable", so it
# refuses to start from an unelevated shell -- even for `version`. Say so here
# rather than letting the live suite report an opaque elevation error.
case "$PLATFORM" in windows-*)
    echo "==> NOTE: the Windows build requires an elevated shell (UAC);"
    echo "          run the live collection from an Administrator terminal." ;;
esac
