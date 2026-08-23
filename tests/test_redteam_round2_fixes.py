"""Regression tests for the Red Team Round 2 findings.

Every test here was written RED against `3f2c19c` — the commit the audit ran
on — and each names the finding it pins. See docs/redteam/ROUND2_ARCHITECTURE.md
for the causal chain behind each one, and docs/redteam/repro/ for the original
adversarial scripts.
"""
from __future__ import annotations

import json
from pathlib import Path
from tempfile import mkdtemp

import pytest

from agent.tools import PurpleTeamSession
from core.verdict_stream import verify_stream
from tools.velociraptor.adapter import MockTransport

FIXTURES = Path(__file__).parent / "fixtures"


def _session(case_id="CASE-VICTIM-A", hostname="WIN11-VICTIM-A",
             client_id="C.aaa", scenario="attack"):
    return PurpleTeamSession(
        MockTransport(FIXTURES / scenario), case_id=case_id,
        host={"client_id": client_id, "hostname": hostname, "os": "windows"},
        examiner_id="perito-01", out_dir=Path(mkdtemp()), source="replay",
        time_base="2026-08-12T14:10:00Z")


def _sealed_one(**kwargs):
    """One sealed verdict plus the window it judged."""
    session = _session(**kwargs)
    summary = session.run_hunt(["pslist", "netstat"], reason="collect")
    session.adjudicate(summary["window_id"])
    return session._entries[0], session._windows[summary["window_id"]]


# --- A-1: the seal must bind the verdict to its forensic identity -----------

def test_a1_the_entry_seals_the_host_it_judged():
    """A sealed verdict that does not name the machine it is about cannot be
    presented as evidence: the host would be a free-text label beside it."""
    entry, window = _sealed_one()
    assert entry["host_hash"], "the entry must commit to the host it judged"
    from core.verdict_stream import host_hash
    assert entry["host_hash"] == host_hash(window["host"])


def test_a1_a_chain_relabelled_to_another_case_is_refused():
    """The exact substitution the audit confirmed: entries sealed for one case
    presented under another case's identity."""
    entry, _ = _sealed_one(case_id="CASE-VICTIM-A")
    report = verify_stream([entry], case_id="CASE-INNOCENT-B")
    assert not report["chain_ok"]
    assert any("case_id" in e for e in report["errors"]), report["errors"]


def test_a1_a_chain_relabelled_to_another_host_is_refused():
    entry, window = _sealed_one(hostname="WIN11-VICTIM-A")
    innocent = dict(window["host"], hostname="WIN11-INNOCENT-B")
    report = verify_stream([entry], case_id="CASE-VICTIM-A", host=innocent)
    assert not report["chain_ok"]
    assert any("host" in e for e in report["errors"]), report["errors"]


def test_a1_the_honest_identity_still_verifies():
    """The negative control: the check must not reject a genuine exhibit."""
    entry, window = _sealed_one()
    report = verify_stream([entry], case_id="CASE-VICTIM-A",
                           host=window["host"],
                           windows={window["window_hash"]: window})
    assert report["chain_ok"], report["errors"]


def test_a1_entries_from_two_different_cases_cannot_be_spliced():
    entry_a, _ = _sealed_one(case_id="CASE-A")
    entry_b, _ = _sealed_one(case_id="CASE-B")
    # make them chain-shaped so only the identity check can catch it
    entry_b = dict(entry_b, sequence=1, prev_entry_hash=entry_a["entry_hash"])
    report = verify_stream([entry_a, entry_b])
    assert not report["chain_ok"]
    assert any("case_id" in e for e in report["errors"]), report["errors"]


def test_a1_a_window_belonging_to_another_case_is_refused():
    """The window is the only place the host lives; a window from a different
    case must not satisfy an entry's window reference."""
    entry, _ = _sealed_one(case_id="CASE-A")
    _, other_window = _sealed_one(case_id="CASE-B")
    report = verify_stream([entry], windows={entry["window_hash"]: other_window})
    assert not report["chain_ok"]


# --- A-1: the independent verifier must make the same checks ---------------

def test_a1_independent_verifier_refuses_a_relabelled_exhibit(tmp_path):
    import subprocess
    import sys
    entry, window = _sealed_one(case_id="CASE-VICTIM-A", hostname="WIN11-VICTIM-A")
    forged = {
        "format": "annaconda-exhibit", "format_version": 1,
        "case_id": "CASE-INNOCENT-B",
        "case": {"case_id": "CASE-INNOCENT-B",
                 "host": {"client_id": "C.zzz", "hostname": "WIN11-INNOCENT-B",
                          "os": "windows"},
                 "examiner_id": "somebody-else",
                 "worst_verdict": "MALICE_HIGH", "entries": [entry]},
        "windows": [window]}
    path = tmp_path / "forged.json"
    path.write_text(json.dumps(forged), encoding="utf-8")
    repo = str(Path(__file__).resolve().parent.parent)
    proc = subprocess.run(
        [sys.executable, "-m", "tools.verify_bundle", str(path)],
        cwd=repo, capture_output=True, text=True,
        env={"PYTHONPATH": repo, "PATH": "/usr/bin:/bin"})
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "FAIL" in proc.stdout


def test_a1_independent_verifier_accepts_the_honest_exhibit(tmp_path):
    import subprocess
    import sys
    entry, window = _sealed_one(case_id="CASE-VICTIM-A", hostname="WIN11-VICTIM-A")
    honest = {
        "format": "annaconda-exhibit", "format_version": 1,
        "case_id": "CASE-VICTIM-A",
        "case": {"case_id": "CASE-VICTIM-A", "host": window["host"],
                 "examiner_id": "perito-01", "worst_verdict": "MALICE_HIGH",
                 "entries": [entry]},
        "windows": [window]}
    path = tmp_path / "honest.json"
    path.write_text(json.dumps(honest), encoding="utf-8")
    repo = str(Path(__file__).resolve().parent.parent)
    proc = subprocess.run(
        [sys.executable, "-m", "tools.verify_bundle", "--strict", str(path)],
        cwd=repo, capture_output=True, text=True,
        env={"PYTHONPATH": repo, "PATH": "/usr/bin:/bin"})
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "PASS" in proc.stdout


def test_a1_a_historical_entry_without_a_host_hash_warns_rather_than_passes():
    """Honest degradation: a v1 entry sealed before host binding existed cannot
    be checked against a host. That must be said, never silently passed."""
    entry, window = _sealed_one()
    legacy = {k: v for k, v in entry.items() if k != "host_hash"}
    legacy["schema_version"] = 1
    from core.verdict_stream import _sha256_canonical
    legacy["entry_hash"] = _sha256_canonical(
        {k: v for k, v in legacy.items() if k != "entry_hash"})
    report = verify_stream([legacy], case_id="CASE-VICTIM-A", host=window["host"])
    assert report["chain_ok"], report["errors"]
    assert report["warnings"], "an unbindable host must produce a warning"


# --- A-2: the engine's mandatory escalation is not suppressible by ordering --

def _cycle(order):
    """One cycle on a host the engine adjudicates MALICE_HIGH, driving the
    commander's own tools in the given order — every call permitted."""
    import asyncio
    from agent import autonomy, mission as mem

    session = _session(case_id="A2", hostname="WIN11-VICTIM")
    case = {"case_id": "A2", "examiner_id": "p", "entries": [], "verdicts": [],
            "audit_trail": [], "runs": 0, "worst_verdict": None,
            "status": "open", "host": session.host,
            "mission": mem.new_mission("A2")}
    mission = mem.attach(case)
    tools = {t.__name__: t for t in
             autonomy.commander_tools(session, case, mission)}
    if order == "escalate-first":
        tools["escalate_to_human"]("routine note: continuing to observe",
                                   "nothing specific yet")
    summary = tools["task_hunter"]("windows-hunter", "collect")
    verdict = tools["request_adjudication"](summary["window_id"])
    assert verdict["verdict_state"].startswith("MALICE"), verdict
    autonomy.raise_unescalated_malice(session, mission, [])
    return mission


def test_a2_the_engine_escalates_a_sealed_malice_verdict():
    from agent import mission as mem
    mission = _cycle("adjudicate-first")
    basis = [b for e in mission["escalations"] for b in e["sealed_basis"]]
    assert any(b["verdict_state"].startswith("MALICE") for b in basis)


def test_a2_an_unrelated_open_escalation_does_not_suppress_the_engine():
    """The confirmed vector: escalate_to_human BEFORE request_adjudication is a
    permitted call in a permitted order, and it used to make the engine's
    mandatory escalation not fire."""
    mission = _cycle("escalate-first")
    covered = [b for e in mission["escalations"] for b in e["sealed_basis"]
               if b["verdict_state"].startswith("MALICE")]
    assert covered, ("the engine must still escalate the sealed MALICE verdict "
                     "even though an unrelated escalation was already open")
    assert any(not e["unsupported_by_seal"] for e in mission["escalations"])


def test_a2_the_engine_does_not_re_raise_the_same_verdict_twice():
    """The negative control: the fix must not turn every cycle into a duplicate
    escalation for a verdict already reported."""
    import asyncio
    from agent import autonomy, mission as mem
    mission = _cycle("adjudicate-first")
    before = len(mission["escalations"])
    session = _session(case_id="A2")
    summary = session.run_hunt(["pslist", "netstat"], reason="c")
    session.adjudicate(summary["window_id"])
    # same sealed verdicts already cited -> nothing new
    sealed = [b for e in mission["escalations"] for b in e["sealed_basis"]]
    assert sealed
    autonomy.raise_unescalated_malice(_MockSession(sealed), mission, [])
    assert len(mission["escalations"]) == before


class _MockSession:
    """A session whose audit trail replays exactly the given sealed verdicts."""
    def __init__(self, verdicts):
        self.audit_trail = [{"seq": i, "action": "adjudicate", "detail": v}
                            for i, v in enumerate(verdicts)]
