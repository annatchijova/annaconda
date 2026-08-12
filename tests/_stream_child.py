"""Child process for the verdict-stream determinism test.

Builds a two-window chain from the shared fixtures through the REAL scorer
and prints the final entry_hash. Run in fresh interpreters with different
PYTHONHASHSEED to prove the whole live pipeline — collect, normalize, seal,
score, chain — replays bit-for-bit.
"""

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from core.verdict_stream import GENESIS_HASH, build_stream_entry  # noqa: E402
from tools.velociraptor.adapter import (  # noqa: E402
    MockTransport, collect_window, window_to_case,
)
from vigia_scorer import _vigia_score  # noqa: E402

FIXTURES = REPO_ROOT / "tests" / "fixtures" / "velociraptor"
HOST = {"client_id": "C.mock01", "hostname": "WIN11-VICTIM", "os": "windows"}

WINDOW_SPECS = [
    (0, "2026-08-12T14:00:00Z", "2026-08-12T14:05:00Z",
     [("pslist", {}), ("netstat", {})]),
    (1, "2026-08-12T14:05:00Z", "2026-08-12T14:10:00Z",
     [("process_creation_evtx", {"Channel": "Security"})]),
]


def main() -> None:
    transport = MockTransport(FIXTURES)
    prev = GENESIS_HASH
    for sequence, start, end, requests in WINDOW_SPECS:
        window, _ = collect_window(
            transport, case_id="STREAM-DET-001", sequence=sequence,
            source="replay", host=HOST, time_start_utc=start,
            time_end_utc=end, examiner_id="purple-op-01", requests=requests,
        )
        result = _vigia_score(window_to_case(window))
        entry = build_stream_entry(
            window=window, scorer_result=result, prev_entry_hash=prev,
        )
        prev = entry["entry_hash"]
    print(prev)


if __name__ == "__main__":
    main()
