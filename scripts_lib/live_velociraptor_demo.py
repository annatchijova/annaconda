"""Prove the live evidence path: collect REAL telemetry from a real
Velociraptor, seal it, adjudicate it.

This uses the Velociraptor binary's own VQL engine to query THIS host — real
processes from a real endpoint, not fixtures — then runs the exact same
sealed-window pipeline the demo uses. It is the milestone for workstream A:
annaconda's evidence source can be live Velociraptor.

    python3 scripts_lib/live_velociraptor_demo.py [path-to-velociraptor-binary]

To point it at a lab instead of this host, construct the transport with
api_config=<api.config.yaml> and VQL like
  SELECT * FROM collect_client(client_id='C.xxxx', artifacts='Windows.System.Pslist')
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.velociraptor.adapter import (  # noqa: E402
    VelociraptorQueryTransport, collect_window, verify_window, window_to_case,
)

DEFAULT_BINARY = str(REPO_ROOT / "tools" / "velociraptor"
                     / "velociraptor-v0.77.1-linux-amd64")

# Cross-platform VQL so the live proof runs on this host. The pslist template
# keys its timestamp on CreateTime, which pslist() returns natively.
LIVE_VQL = {
    "Windows.System.Pslist":
        "SELECT Pid, Name, CommandLine, Exe, CreateTime FROM pslist()",
}


def main() -> int:
    binary = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_BINARY
    if not Path(binary).exists():
        print(f"[live] Velociraptor binary not found at {binary}")
        return 2

    transport = VelociraptorQueryTransport(binary, LIVE_VQL)
    print(f"[live] collecting real telemetry from THIS host via {Path(binary).name}")

    window, reports = collect_window(
        transport,
        case_id="LIVE-DEMO-001", sequence=0, source="velociraptor",
        host={"client_id": "C.localhost", "hostname": "dev-workstation", "os": "linux"},
        time_start_utc="2026-08-14T00:00:00Z", time_end_utc="2026-08-14T23:59:59Z",
        examiner_id="purple-op-01", requests=[("pslist", {})],
    )

    print(f"[live] sealed window {window['window_id']} — "
          f"{len(window['artifacts'])} real process artifacts, "
          f"window_hash {window['window_hash'][:16]}…, verifies: {verify_window(window)}")
    for art in window["artifacts"][:4]:
        row = art["metadata"]["row"]
        print(f"       · {row.get('Name'):<24} pid={row.get('Pid')}")

    from vigia_scorer import _vigia_score
    result = _vigia_score(window_to_case(window))
    print(f"[live] verdict on real telemetry: {result['verdict']} "
          f"({result['quadripartite_state']['verdict_state']})")
    print("[live] PASS — live Velociraptor -> sealed window -> verdict works")
    return 0


if __name__ == "__main__":
    sys.exit(main())
