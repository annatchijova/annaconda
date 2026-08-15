"""Child process: seal a verdict WITH the ML nominator running in the same
pipeline, and print the sealed entry_hash.

If the nominator's floats (surprisal_bits) leaked into any sealed value, the
hash would vary with PYTHONHASHSEED across processes. It must not.
"""

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from core.verdict_stream import GENESIS_HASH, build_stream_entry  # noqa: E402
from ml.nominator import nominate_window  # noqa: E402
from tools.velociraptor.adapter import (  # noqa: E402
    MockTransport, collect_window, window_to_case)
from vigia_scorer import _vigia_score  # noqa: E402

FIXTURES = REPO_ROOT / "tests" / "fixtures" / "attack"


def main() -> None:
    window, _ = collect_window(
        MockTransport(FIXTURES), case_id="SEAL-NOM", sequence=0, source="replay",
        host={"client_id": "C.1", "hostname": "H", "os": "windows"},
        time_start_utc="2026-08-12T14:10:00Z", time_end_utc="2026-08-12T14:15:00Z",
        examiner_id="op", requests=[("pslist", {}), ("netstat", {})])
    result = _vigia_score(window_to_case(window))
    entry = build_stream_entry(
        window=window, scorer_result=result, prev_entry_hash=GENESIS_HASH)
    # The nominator runs in the same process, producing floats — after sealing.
    noms = nominate_window(window)
    assert noms and any(isinstance(n["surprisal_bits"], float) for n in noms)
    print(entry["entry_hash"])


if __name__ == "__main__":
    main()
