"""Where the Velociraptor binary is, for the machine actually running.

The release asset name was hardcoded to ``linux-amd64`` in both the live test
and the live demo script. On any other platform that made the suite report
"Velociraptor binary not present" while the correct signed binary sat in the
directory it was looking in -- a lookup bug that reads as an environment gap,
which is worse than a failure: it makes a platform look untested when it was
merely unlooked-at.

Kept here, next to the adapter, because the test and the demo script both need
it and a helper shared by two callers should not live inside either of them.
"""

from __future__ import annotations

import platform
import sys
from pathlib import Path

#: The release this repository pins. ``scripts/setup_velociraptor.sh`` fetches
#: this version and verifies its signature against the upstream fingerprint.
VERSION = "0.77.1"

BINARY_DIR = Path(__file__).resolve().parent


#: What ``platform.machine()`` reports, mapped to upstream's asset naming.
#: Unknown machines fall through to amd64: the consequence is a "binary not
#: present" skip on an exotic host, which is honest degradation, never a wrong
#: verdict. 32-bit x86 is listed explicitly because upstream really does
#: publish a ``-386`` asset, so guessing amd64 there would miss a binary that
#: exists.
_ARCH_ALIASES = {
    "x86_64": "amd64", "amd64": "amd64",
    "arm64": "arm64", "aarch64": "arm64",
    "i386": "386", "i686": "386", "x86": "386",
}


def target_triple() -> tuple[str, str]:
    """``(os, arch)`` as upstream names them for this machine."""
    arch = _ARCH_ALIASES.get(platform.machine().lower(), "amd64")
    if sys.platform == "win32":
        return "windows", arch
    if sys.platform == "darwin":
        return "darwin", arch
    return "linux", arch


def release_asset_name(os_name: str | None = None, arch: str | None = None) -> str:
    """The official asset filename, e.g. ``velociraptor-v0.77.1-linux-amd64``.

    Upstream publishes every asset as ``velociraptor-v<version>-<os>-<arch>``,
    with ``.exe`` appended for Windows only.
    """
    default_os, default_arch = target_triple()
    os_name = os_name or default_os
    arch = arch or default_arch
    suffix = ".exe" if os_name == "windows" else ""
    return f"velociraptor-v{VERSION}-{os_name}-{arch}{suffix}"


def default_binary_path() -> Path:
    """Where ``scripts/setup_velociraptor.sh`` puts the binary on this machine."""
    return BINARY_DIR / release_asset_name()


def host_block(client_id: str = "C.localhost") -> dict:
    """Host custody for a collection taken on THIS machine.

    The host block is sealed into the evidence window and travels with the
    evidence, so it is a provenance claim, not decoration. Both call sites used
    to hardcode ``"os": "linux"``, which meant a collection taken anywhere else
    carried a sealed assertion contradicted by the machine that produced it.
    Lowercase to match the naming the rest of the suite already uses.
    """
    return {
        "client_id": client_id,
        "hostname": platform.node() or "unknown-host",
        "os": platform.system().lower(),
    }
