"""Child process for the evidence-window determinism test.

Builds one window from the shared fixtures via MockTransport and prints its
window_hash. Run in fresh interpreters (with different PYTHONHASHSEED) to
prove the window seal is bit-for-bit reproducible across processes.
"""

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tools.velociraptor.adapter import MockTransport, collect_window  # noqa: E402

FIXTURES = REPO_ROOT / "tests" / "fixtures" / "velociraptor"


def main() -> None:
    window, _reports = collect_window(
        MockTransport(FIXTURES),
        case_id="WINDOW-DET-001",
        sequence=0,
        source="replay",
        host={"client_id": "C.mock01", "hostname": "WIN11-VICTIM", "os": "windows"},
        time_start_utc="2026-08-12T14:00:00Z",
        time_end_utc="2026-08-12T14:05:00Z",
        requests=[
            ("pslist", {}),
            ("netstat", {}),
            ("process_creation_evtx", {"Channel": "Security", "IdFilter": "4688"}),
        ],
    )
    print(window["window_hash"])


if __name__ == "__main__":
    main()
