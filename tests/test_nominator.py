"""Tests for the ML nominator: it surfaces candidates, and NEVER decides."""

import json
import re
from pathlib import Path

from ml.nominator import SurprisalNominator, nominate_window
from tools.velociraptor.adapter import MockTransport, collect_window

REPO = Path(__file__).resolve().parent.parent
ATTACK = REPO / "tests" / "fixtures" / "attack"
SCHEMA = json.loads(
    (REPO / "contracts" / "ml_nomination.schema.json").read_text())


def _attack_window():
    window, _ = collect_window(
        MockTransport(ATTACK), case_id="NOM-T", sequence=0, source="replay",
        host={"client_id": "C.1", "hostname": "H", "os": "windows"},
        time_start_utc="2026-08-12T14:10:00Z", time_end_utc="2026-08-12T14:15:00Z",
        examiner_id="op", requests=[("pslist", {}), ("netstat", {})])
    return window


def test_nominations_conform_to_the_contract():
    noms = nominate_window(_attack_window())
    assert noms
    required = set(SCHEMA["required"])
    for n in noms:
        assert required <= set(n), f"missing {required - set(n)}"
        assert n["schema_version"] == 1
        assert n["nominated_by"] == "ml"
        assert isinstance(n["surprisal_bits"], (int, float))
        assert n["rank"] >= 1
        assert re.fullmatch(r"[A-Za-z0-9._-]{1,128}", n["nomination_id"])


def test_it_only_nominates_never_decides():
    """The nominator's output must carry no verdict, score, or decision — the
    guardrail that keeps ML out of the sealed path, checked structurally."""
    noms = nominate_window(_attack_window())
    forbidden = {"verdict", "verdict_state", "score", "confidence",
                 "sealed", "entry_hash"}
    for n in noms:
        assert not (forbidden & set(n)), f"nomination leaked a decision field: {n}"


def test_it_surfaces_the_real_malicious_signals():
    noms = nominate_window(_attack_window())
    reasons = " ".join(n["reason"] for n in noms)
    detectors = {n["detector"] for n in noms}
    # The C2 destination is singled out (rare-dest).
    assert "203.0.113.66" in reasons
    # The encoded PowerShell is flagged (content entropy).
    assert "content" in detectors
    # The Temp-path implant is among the unusual-location executables.
    assert "Temp" in reasons


def test_ranking_is_deterministic():
    a = nominate_window(_attack_window())
    b = nominate_window(_attack_window())
    assert [(n["detector"], n["surprisal_bits"], n["event_ref"]) for n in a] == \
           [(n["detector"], n["surprisal_bits"], n["event_ref"]) for n in b]
    # ranks are a clean 1..N sequence
    assert [n["rank"] for n in a] == list(range(1, len(a) + 1))


def test_empty_and_degenerate_inputs_are_safe():
    nom = SurprisalNominator()
    assert nom.nominate([], "w") == []
    # All-unique categorical values carry no discriminative signal -> nothing.
    events = [{"id": f"e{i}", "type": f"t{i}", "name": f"n{i}", "path": None,
               "dest": None, "content": None} for i in range(5)]
    assert nom.nominate(events, "w") == []


def test_per_detector_quota_limits_one_facet():
    nom = SurprisalNominator(top_k=20, per_detector_quota=2)
    # Many events in unusual paths; quota should cap how many one detector
    # contributes so the shortlist stays diverse.
    events = ([{"id": f"sys{i}", "type": "p", "path": "C:/Windows/System32/a.exe",
                "name": None, "dest": None, "content": None} for i in range(6)]
              + [{"id": f"tmp{i}", "type": "p", "path": f"C:/Temp/x{i}.exe",
                  "name": None, "dest": None, "content": None} for i in range(6)])
    noms = nom.nominate(events, "w")
    assert sum(1 for n in noms if n["detector"] == "rare-path") <= 2
