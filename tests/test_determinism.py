"""Cross-process determinism check for the scoring path.

Contract (CLAUDE.md section 5.2): the decision path must be reproducible
bit-for-bit. Two fresh interpreter runs over the same case — with different
PYTHONHASHSEED values, so hash-randomized set/dict ordering leaks are
exposed — must produce byte-identical canonical output, hence equal SHA-256.

This intentionally runs the scorer in subprocesses, not in-process: an
in-process double run shares interned objects and hash seed and would hide
exactly the class of leak this test exists to catch.
"""

import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CHILD = Path(__file__).resolve().parent / "_determinism_child.py"

SYNTHETIC_CASE = {
    "case_id": "DET-CHECK-001",
    "artifacts": [
        {
            "artifact_id": "art-mem-001",
            "evidence_type": "memory",
            "raw_score": "3/4",
            "timestamp": "2026-05-06T12:00:00Z",
            "metadata": {"tool": "volatility3", "plugin": "malfind"},
        },
        {
            "artifact_id": "art-log-001",
            "evidence_type": "event_log",
            "raw_score": "1/2",
            "timestamp": "2026-05-06T12:01:30Z",
            "metadata": {"tool": "evtx", "event_id": 4688},
        },
        {
            "artifact_id": "art-net-001",
            "evidence_type": "network",
            "raw_score": "2/3",
            "timestamp": "2026-05-06T12:02:00Z",
            "metadata": {"tool": "pcap_parser", "dst": "198.51.100.7"},
        },
    ],
    "temporal_violations": [],
    "provenance_analysis": {},
}


def _run_once(case_path: Path, hashseed: str) -> str:
    proc = subprocess.run(
        [sys.executable, str(CHILD), str(case_path)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=300,
        env={"PYTHONHASHSEED": hashseed, "PATH": "/usr/bin:/bin"},
    )
    assert proc.returncode == 0, (
        f"scorer child failed (exit {proc.returncode}):\n{proc.stderr[-2000:]}"
    )
    return proc.stdout.strip()


def test_scorer_is_deterministic_across_processes(tmp_path):
    case_path = tmp_path / "case.json"
    case_path.write_text(json.dumps(SYNTHETIC_CASE), encoding="utf-8")

    line_a = _run_once(case_path, hashseed="0")
    line_b = _run_once(case_path, hashseed="12345")

    digest_a, verdict_a = line_a.split()
    digest_b, verdict_b = line_b.split()

    assert verdict_a != "ERROR", (
        "synthetic case was rejected by the scorer — the determinism check "
        "did not exercise the real decision path"
    )
    assert digest_a == digest_b, (
        "non-determinism in the decision path: same case, two fresh "
        f"processes, different digests ({digest_a[:12]}… vs {digest_b[:12]}…). "
        "Common leaks: a float, set/dict ordering, an unpinned timestamp."
    )
    assert verdict_a == verdict_b
