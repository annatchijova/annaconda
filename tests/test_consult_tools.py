"""Tests for the mentor agent's consultation tools (deterministic, offline).

These verify the tools return real, grounded repo knowledge and never invent
a forensic fact.
"""

import pytest

from agent.consult_tools import ConsultTools
from verdict.quadripartite import VerdictState


def test_explain_verdict_state_teaches_action_and_daubert():
    t = ConsultTools()
    out = t.explain_verdict_state("ABSTAIN_INSUFFICIENT")
    assert out["found"] is True
    assert out["state"] == "ABSTAIN_INSUFFICIENT"
    assert out["recommended_action"]  # a concrete next action
    assert out["daubert_note"]        # admissibility explanation, not invented
    # case-insensitive
    assert t.explain_verdict_state("benign_high")["found"] is True


def test_list_verdict_states_covers_all_eight():
    t = ConsultTools()
    states = {s["state"] for s in t.list_verdict_states()["states"]}
    assert states == {s.value for s in VerdictState}


def test_explain_unknown_verdict_state_is_honest():
    t = ConsultTools()
    out = t.explain_verdict_state("DEFINITELY_GUILTY")
    assert out["found"] is False
    assert "not a recognized verdict state" in out["message"]


def test_explain_mitre_grounded_or_honest():
    t = ConsultTools()
    # Any technique present in the master dictionary resolves with real fields.
    from tools.mitre_mapping import MASTER_TTP_DICTIONARY
    a_known = sorted(MASTER_TTP_DICTIONARY)[0]
    out = t.explain_mitre_technique(a_known)
    assert out["found"] is True
    assert out["technique_id"] == a_known
    assert out["name"] and out["description"] and out["attack_url"]
    # An unknown id does not get fabricated.
    miss = t.explain_mitre_technique("T9999.999")
    assert miss["found"] is False


def test_explain_investigation_reports_sealed_facts_only():
    store = {
        "abc123": {
            "investigation_id": "abc123",
            "case_id": "CASE-1",
            "mode": "scripted",
            "chain": {"chain_ok": True},
            "verdicts": [
                {"sequence": 0, "verdict_state": "BENIGN_HIGH", "score": "203/5000",
                 "confidence": "24/25", "mitre_techniques": [],
                 "entry_hash": "a" * 64},
            ],
        }
    }
    t = ConsultTools(store=store)
    out = t.explain_investigation("abc123")
    assert out["found"] is True
    assert out["chain_intact"] is True
    assert out["sealed_verdicts"][0]["verdict_state"] == "BENIGN_HIGH"
    assert out["sealed_verdicts"][0]["score"] == "203/5000"
    # unknown case is not invented
    assert t.explain_investigation("nope")["found"] is False


def test_tools_are_read_only_no_verdict_producer():
    """The mentor's toolset must contain no way to produce or alter a verdict —
    only lookups. Guardrail verified structurally."""
    t = ConsultTools()
    public = [m for m in dir(t) if not m.startswith("_") and callable(getattr(t, m))]
    assert set(public) == {
        "explain_mitre_technique", "explain_verdict_state", "list_verdict_states",
        "list_available_hunts", "explain_investigation",
    }
