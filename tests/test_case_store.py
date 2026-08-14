"""Tests for the analyst case workflow: persistence + a continuing sealed chain.

The load-bearing invariant: verdicts for a host accumulate across many
investigation runs into ONE unbroken tamper-evident chain per case.
"""

import os

from core.verdict_stream import verify_stream
from service.case_store import (
    MemoryCaseStore, build_case_store, verdict_rank,
)


def test_forced_memory_backend_is_honest():
    os.environ["VIGIA_CASE_BACKEND"] = "memory"
    try:
        store = build_case_store()
        assert store.backend == "memory"
    finally:
        del os.environ["VIGIA_CASE_BACKEND"]


def test_worst_verdict_and_status_track_the_worst_run():
    store = MemoryCaseStore()
    store.create_case("C1", {"hostname": "H"}, "op")
    store.apply_run("C1", entries=[], verdicts=[{"verdict_state": "BENIGN_HIGH"}], audit=[])
    assert store.get_case("C1")["worst_verdict"] == "BENIGN_HIGH"
    assert store.get_case("C1")["status"] == "benign"
    store.apply_run("C1", entries=[], verdicts=[{"verdict_state": "MALICE_HIGH"}], audit=[])
    assert store.get_case("C1")["worst_verdict"] == "MALICE_HIGH"
    assert store.get_case("C1")["status"] == "malice"
    # A later benign run must NOT lower the worst verdict — the case remembers.
    store.apply_run("C1", entries=[], verdicts=[{"verdict_state": "BENIGN_HIGH"}], audit=[])
    assert store.get_case("C1")["worst_verdict"] == "MALICE_HIGH"


def test_queue_orders_needs_attention_first():
    store = MemoryCaseStore()
    store.create_case("benign-case", {"hostname": "A"}, "op")
    store.apply_run("benign-case", [], [{"verdict_state": "BENIGN_HIGH"}], [])
    store.create_case("malice-case", {"hostname": "B"}, "op")
    store.apply_run("malice-case", [], [{"verdict_state": "MALICE_HIGH"}], [])
    order = [row["case_id"] for row in store.list_cases()]
    assert order[0] == "malice-case"  # needs attention on top


def test_case_chain_continues_and_verifies_across_runs(tmp_path):
    """Two real investigation runs into one case produce a single chain that
    verifies from genesis — the examiner's tamper-evident record."""
    from pathlib import Path
    from agent.tools import PurpleTeamSession
    from core.verdict_stream import GENESIS_HASH
    from tools.velociraptor.adapter import MockTransport

    REPO = Path(__file__).resolve().parent.parent
    benign = MockTransport(REPO / "tests" / "fixtures" / "velociraptor")
    store = MemoryCaseStore()
    store.create_case("IR-1", {"client_id": "C.1", "hostname": "H", "os": "windows"}, "op")

    def run_once():
        case = store.get_case("IR-1")
        entries = case["entries"]
        s = PurpleTeamSession(
            benign, case_id="IR-1",
            host={"client_id": "C.1", "hostname": "H", "os": "windows"},
            examiner_id="op", out_dir=tmp_path / os.urandom(4).hex(),
            source="replay", time_base="2026-08-12T14:00:00Z",
            start_sequence=len(entries),
            start_prev_hash=entries[-1]["entry_hash"] if entries else GENESIS_HASH,
        )
        sm = s.run_hunt(["pslist"], reason="run")
        v = s.adjudicate(sm["window_id"])
        store.apply_run("IR-1", list(s._entries), [v], s.audit_trail)

    run_once()
    run_once()
    run_once()

    case = store.get_case("IR-1")
    assert case["runs"] == 3
    assert len(case["entries"]) == 3
    # Sequences are contiguous 0,1,2 across the three separate runs.
    assert [e["sequence"] for e in case["entries"]] == [0, 1, 2]
    report = verify_stream(case["entries"])
    assert report["chain_ok"], report["errors"]


def test_verdict_rank_orders_severity():
    assert verdict_rank("MALICE_HIGH") > verdict_rank("ABSTAIN_INSUFFICIENT")
    assert verdict_rank("ABSTAIN_INSUFFICIENT") > verdict_rank("BENIGN_HIGH")
    assert verdict_rank(None) == 0
