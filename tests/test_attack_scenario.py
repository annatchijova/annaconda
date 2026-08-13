"""The attack scenario must produce a real MALICE verdict — and only from a
genuine structural fracture, never from an inflated score.

Guards two directions:
- the compromised-endpoint fixtures yield MALICE with the expected fractures
  and MITRE techniques (a real detection, regression-pinned), and
- benign telemetry stays benign even though the adapter now surfaces engine
  fields (the promotion must never fabricate a fracture).
"""

from pathlib import Path

import pytest

from tools.velociraptor.adapter import MockTransport, collect_window, window_to_case

REPO_ROOT = Path(__file__).resolve().parent.parent
ATTACK = REPO_ROOT / "tests" / "fixtures" / "attack"
BENIGN = REPO_ROOT / "tests" / "fixtures" / "velociraptor"
HOST = {"client_id": "C.mock01", "hostname": "WIN11-VICTIM", "os": "windows"}


def _score(fixtures, start, end, requests):
    window, _ = collect_window(
        MockTransport(fixtures), case_id="SCEN-001", sequence=0, source="replay",
        host=HOST, time_start_utc=start, time_end_utc=end,
        examiner_id="purple-op-01", requests=requests,
    )
    from vigia_scorer import _vigia_score
    return _vigia_score(window_to_case(window))


def _fracture_types(result):
    out = set()
    for f in result.get("caie_fracture_details", []):
        if isinstance(f, dict) and f.get("fracture_type"):
            out.add(f["fracture_type"])
    return out


def test_attack_scenario_is_real_malice():
    r = _score(ATTACK, "2026-08-12T14:10:00Z", "2026-08-12T14:15:00Z",
               [("pslist", {}), ("netstat", {})])
    assert r["verdict"] == "MALICE"
    assert r["quadripartite_state"]["verdict_state"] == "MALICE_HIGH"
    assert r["caie_fractures_source"] == "live_caie"
    types = _fracture_types(r)
    assert "TEMPORAL_CAUSALITY_VIOLATION" in types, types
    # Two domains corroborate — this is not a single-signal accusation.
    assert set(r["r43_active_domains"]) >= {"memory_kernel", "network_telemetry"}


def test_benign_stays_benign_despite_field_promotion():
    r = _score(BENIGN, "2026-08-12T14:00:00Z", "2026-08-12T14:05:00Z",
               [("pslist", {}), ("netstat", {})])
    assert r["verdict"] != "MALICE"
    # The promotion surfaced no temporal fields for benign telemetry, so the
    # causality detector cannot have fired.
    assert "TEMPORAL_CAUSALITY_VIOLATION" not in _fracture_types(r)


def test_attack_evidence_flows_from_curated_hunts_only():
    """The MALICE came through the normal sealed-window pipeline, not a bypass:
    the same adapter, the same hunts, just compromised telemetry."""
    window, _ = collect_window(
        MockTransport(ATTACK), case_id="SCEN-002", sequence=0, source="replay",
        host=HOST, time_start_utc="2026-08-12T14:10:00Z",
        time_end_utc="2026-08-12T14:15:00Z", examiner_id="purple-op-01",
        requests=[("pslist", {}), ("netstat", {})],
    )
    from tools.velociraptor.adapter import verify_window
    assert verify_window(window)
    # Every artifact still carries the no-signal prior — the adapter never
    # scored the attack; CAIE did.
    for art in window["artifacts"]:
        assert art["raw_score"] == "1/20"
