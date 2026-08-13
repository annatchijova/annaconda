"""Tests for the agent tool layer (deterministic, no Gemini/ADK calls).

The point of these tests is the guardrail: the agent's tools can drive an
investigation and read sealed verdicts, but cannot decide or alter one.
"""

import json
from pathlib import Path

import pytest

from agent.tools import PurpleTeamSession
from tools.velociraptor.adapter import MockTransport, verify_window

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURES = REPO_ROOT / "tests" / "fixtures" / "velociraptor"

HOST = {"client_id": "C.mock01", "hostname": "WIN11-VICTIM", "os": "windows"}


def _session(out_dir):
    return PurpleTeamSession(
        MockTransport(FIXTURES),
        case_id="AGENT-TEST-001",
        host=HOST,
        examiner_id="purple-op-01",
        out_dir=out_dir,
        source="replay",
        time_base="2026-08-12T14:00:00Z",
        interval_s=60,
    )


def test_list_available_hunts_only_curated(tmp_path):
    s = _session(tmp_path)
    hunts = s.list_available_hunts()["hunts"]
    assert "pslist" in hunts and "netstat" in hunts
    assert "raw_vql" not in hunts


def test_run_hunt_freezes_sealed_window_without_a_verdict(tmp_path):
    s = _session(tmp_path)
    summary = s.run_hunt(["pslist", "netstat"], reason="baseline sweep")
    assert summary["sequence"] == 0
    assert summary["artifacts"] > 0
    # A hunt summary must not carry a verdict — adjudication is separate.
    assert "verdict_state" not in summary and "score" not in summary
    window = json.loads(
        (tmp_path / "windows" / "window-000000.json").read_text())
    assert verify_window(window)


def test_run_hunt_rejects_unknown_hunt(tmp_path):
    s = _session(tmp_path)
    out = s.run_hunt(["pslist", "exfiltrate_everything"], reason="x")
    assert "error" in out and "unknown hunt" in out["error"]


def test_adjudicate_returns_sealed_verdict_agent_cannot_alter(tmp_path):
    s = _session(tmp_path)
    summary = s.run_hunt(["pslist", "netstat"], reason="sweep")
    verdict = s.adjudicate(summary["window_id"])
    assert verdict["sealed"] is True
    assert verdict["verdict_state"] in {
        "MALICE_HIGH", "MALICE_MEDIUM", "BENIGN_HIGH", "BENIGN_MEDIUM",
        "ABSTAIN_CONTRADICTION", "ABSTAIN_INSUFFICIENT", "ABSTAIN_DEGRADED",
        "ESCALATE",
    }
    # score is an exact fraction string, never a float the model could nudge
    assert "/" in verdict["score"]
    assert len(verdict["entry_hash"]) == 64
    # The tool signature offers no way to pass a score/state/hash: the agent
    # can only name a window. That is the guardrail — verified structurally.
    import inspect
    params = set(inspect.signature(s.adjudicate).parameters)
    assert params == {"window_id"}


def test_adjudicate_refuses_unknown_window(tmp_path):
    s = _session(tmp_path)
    out = s.adjudicate("nope-000000")
    assert "error" in out and "unknown window_id" in out["error"]


def test_full_loop_chains_and_verifies(tmp_path):
    s = _session(tmp_path)
    for hunts in (["pslist"], ["netstat"], ["process_creation_evtx"]):
        summary = s.run_hunt(hunts, reason="loop")
        s.adjudicate(summary["window_id"])
    chain = s.verify_chain()
    assert chain["chain_ok"], chain["errors"]
    assert chain["sealed_verdicts"] == 3
    # Audit trail recorded every tool call in order.
    actions = [e["action"] for e in s.audit_trail]
    assert actions.count("run_hunt") == 3
    assert actions.count("adjudicate") == 3
    assert actions[-1] == "verify_chain"


def test_adjudicate_refuses_tampered_window(tmp_path):
    s = _session(tmp_path)
    summary = s.run_hunt(["pslist"], reason="sweep")
    # Tamper with the in-session window after freezing.
    wid = summary["window_id"]
    s._windows[wid]["artifacts"][0]["evidence_type"] = "cryptographic_hash"
    out = s.adjudicate(wid)
    assert "error" in out and "failed its seal check" in out["error"]
