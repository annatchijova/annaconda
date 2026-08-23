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


# --- A-3 / A-9: the catalog must gate every path to the sealed core ---------

@pytest.fixture()
def client(monkeypatch):
    monkeypatch.setenv("VIGIA_CASE_BACKEND", "memory")
    monkeypatch.setenv("VIGIA_RATE_MAX", "500")
    from fastapi.testclient import TestClient
    import importlib
    import service.app as app_mod
    importlib.reload(app_mod)
    return TestClient(app_mod.app)


def test_a3_a_department_that_may_not_adjudicate_is_refused_at_investigate(client):
    """The confirmed vector: the catalog denies 'soc' the correlator on the
    agentic path, while /cases/{id}/investigate reached the sealed core
    unconditionally."""
    client.post("/cases", json={"case_id": "A3", "examiner_id": "x",
                                "scenario": "attack"})
    r = client.post("/cases/A3/investigate",
                    json={"mode": "scripted", "scenario": "attack",
                          "department": "soc"})
    assert r.status_code == 403, r.text
    assert "soc" in r.text


def test_a3_a_department_that_may_adjudicate_still_works(client):
    """Negative control: the gate must not break the honest path."""
    client.post("/cases", json={"case_id": "A3B", "examiner_id": "x",
                                "scenario": "attack"})
    r = client.post("/cases/A3B/investigate",
                    json={"mode": "scripted", "scenario": "attack",
                          "department": "incident-response"})
    assert r.status_code == 200, r.text
    assert r.json()["run_verdicts"][0]["verdict_state"].startswith("MALICE")


def test_a3_the_one_off_investigate_route_is_gated_too(client):
    r = client.post("/investigate",
                    json={"case_id": "A3C", "examiner_id": "x",
                          "mode": "scripted", "scenario": "attack",
                          "department": "training"})
    assert r.status_code == 403, r.text


def test_a3_an_unknown_department_is_refused_not_silently_accepted(client):
    client.post("/cases", json={"case_id": "A3D", "examiner_id": "x"})
    r = client.post("/cases/A3D/investigate",
                    json={"mode": "scripted", "department": "; DROP TABLE --"})
    assert r.status_code == 403, r.text


def test_a9_the_commander_is_authorized_against_the_catalog():
    """A department the catalog does not publish the fleet-commander to must
    not be able to run a cycle at all — the delegator was never gated, only
    its delegates."""
    import asyncio
    from agent import autonomy, catalog, mission as mem

    for dept in ("training", "compliance"):
        assert dept not in catalog.publication("fleet-commander")["available_to"]
        session = _session(case_id=f"A9-{dept}", scenario="velociraptor")
        case = {"case_id": f"A9-{dept}", "examiner_id": "p", "entries": [],
                "verdicts": [], "audit_trail": [], "runs": 0,
                "worst_verdict": None, "status": "open", "host": session.host,
                "mission": mem.new_mission(f"A9-{dept}")}
        with pytest.raises(PermissionError):
            asyncio.run(autonomy.run_cycle(session, case, department=dept,
                                           trigger="t", force=True))
        assert not case["mission"]["journal"], (
            "a refused tasking must not have opened a cycle or written memory")


def test_a9_a_published_department_still_runs_a_cycle():
    """Negative control."""
    import asyncio
    from agent import autonomy, mission as mem
    session = _session(case_id="A9-OK", scenario="velociraptor")
    case = {"case_id": "A9-OK", "examiner_id": "p", "entries": [],
            "verdicts": [], "audit_trail": [], "runs": 0,
            "worst_verdict": None, "status": "open", "host": session.host,
            "mission": mem.new_mission("A9-OK")}
    result = asyncio.run(autonomy.run_cycle(
        session, case, department="incident-response", trigger="t", force=True))
    assert result["acted"]
    assert case["mission"]["journal"]


# --- A-5: authenticating must never leave a caller worse off ---------------

def _resolve(monkeypatch, email, claimed=None):
    from agent import principal as P
    monkeypatch.setattr(P, "verify_identity_token", lambda tok: email)
    return P.resolve(authorization_header="Bearer t" if email else None,
                     claimed_department=claimed,
                     default_department=P.default_department())


def test_a5_a_verified_identity_outside_the_roster_is_not_worse_off_than_anonymous(
        monkeypatch):
    """The confirmed inversion: a real, verified token that this deployment has
    not rostered was the ONLY input that got a 403, while dropping the header
    entirely was allowed. An attacker holding such a token simply deleted it."""
    from agent import principal as P
    monkeypatch.setenv("VIGIA_DEPARTMENT_ROSTER", "alice@example.com:forensics")
    anonymous = _resolve(monkeypatch, None, claimed="soc")
    verified = _resolve(monkeypatch, "mallory@evil.com", claimed="soc")
    P.enforce(anonymous)          # must not raise
    P.enforce(verified)           # must not raise either
    assert verified["department"] == anonymous["department"]
    assert verified["authenticated"] is False
    assert verified["identity"] == "mallory@evil.com", (
        "the identity we verified must still be recorded — it is strictly more "
        "than an anonymous caller gives us")


def test_a5_a_rostered_identity_still_wins_over_what_the_request_claims(
        monkeypatch):
    monkeypatch.setenv("VIGIA_DEPARTMENT_ROSTER", "alice@example.com:forensics")
    resolved = _resolve(monkeypatch, "alice@example.com", claimed="soc")
    assert resolved["department"] == "forensics"
    assert resolved["authenticated"] is True


def test_a5_an_unknown_claimed_department_never_becomes_the_principal(monkeypatch):
    """It used to be lowercased and carried straight through — into the sealed
    mission journal as the department that ran the cycle."""
    from agent import principal as P
    resolved = _resolve(monkeypatch, None, claimed="; DROP TABLE --")
    assert resolved["department"] is None
    with pytest.raises(P.UnauthenticatedPrincipalError):
        P.enforce(resolved)


def test_a5_the_unauthenticated_default_department_is_explicit(monkeypatch):
    """The default an anonymous caller is treated as must be a stated posture,
    not an accident of which constant was in scope."""
    from agent import principal as P
    monkeypatch.setenv("VIGIA_DEFAULT_DEPARTMENT", "soc")
    assert P.default_department() == "soc"
    monkeypatch.setenv("VIGIA_DEFAULT_DEPARTMENT", "not-a-department")
    assert P.default_department() is None, (
        "an unusable configured default must refuse, not silently fall back to "
        "a privileged one")


def test_a5_requiring_authentication_still_refuses_an_asserted_principal(
        monkeypatch):
    """Negative control: the production posture must be unchanged."""
    from agent import principal as P
    monkeypatch.setenv("VIGIA_REQUIRE_AUTHENTICATED_PRINCIPAL", "true")
    monkeypatch.setenv("VIGIA_DEPARTMENT_ROSTER", "alice@example.com:forensics")
    with pytest.raises(P.UnauthenticatedPrincipalError):
        P.enforce(_resolve(monkeypatch, None, claimed="forensics"))
    with pytest.raises(P.UnauthenticatedPrincipalError):
        P.enforce(_resolve(monkeypatch, "mallory@evil.com", claimed="forensics"))
    P.enforce(_resolve(monkeypatch, "alice@example.com"))


# --- A-4 / A-6: ABSTAIN must have an exit toward a human -------------------

ABSTAIN_FIX = Path(__file__).parent / "fixtures" / "abstain"


def _abstain_case(case_id="A4"):
    from agent import mission as mem
    session = PurpleTeamSession(
        MockTransport(ABSTAIN_FIX), case_id=case_id,
        host={"client_id": "C.a", "hostname": "WIN11-VICTIM", "os": "windows"},
        examiner_id="p", out_dir=Path(mkdtemp()), source="replay",
        time_base="2026-08-12T14:00:00Z")
    case = {"case_id": case_id, "examiner_id": "p", "entries": [],
            "verdicts": [], "audit_trail": [], "runs": 0, "worst_verdict": None,
            "status": "open", "host": session.host,
            "mission": mem.new_mission(case_id)}
    return session, case


def test_a4_a_host_that_cannot_be_concluded_eventually_reaches_a_human():
    """The confirmed vector: eight cycles sealing ABSTAIN_* raised zero
    escalations. "We could not tell" had no path to a person at all."""
    import asyncio
    from agent import autonomy, mission as mem
    from service.case_store import MemoryCaseStore

    store = MemoryCaseStore()
    session, seed = _abstain_case("A4-LOOP")
    store.create_case("A4-LOOP", seed["host"], "p", scenario="abstain")
    for _ in range(autonomy.ABSTAIN_ESCALATION_CYCLES + 1):
        case = store.get_case("A4-LOOP")
        s, _ = _abstain_case("A4-LOOP")
        s._seq = len(case.get("entries", []))
        s._prev_entry_hash = (case["entries"][-1]["entry_hash"]
                              if case.get("entries") else s._prev_entry_hash)
        result = asyncio.run(autonomy.run_cycle(s, case, trigger="t", force=True))
        store.apply_cycle("A4-LOOP", list(s._entries), result["verdicts"],
                          s.audit_trail, case["mission"])
    mission = store.get_case("A4-LOOP")["mission"]
    assert mem.has_open_escalation(mission), (
        "a host the engine has been unable to conclude on for "
        f"{autonomy.ABSTAIN_ESCALATION_CYCLES} cycles never reached a human")
    basis = [b for e in mission["escalations"] for b in e["sealed_basis"]]
    assert any(b["verdict_state"].startswith("ABSTAIN") for b in basis)


def test_a4_an_unresolved_case_cannot_be_stood_down():
    """stand_down was permitted on a case whose sealed record says the
    analyzers were disabled and the result is unreliable."""
    from agent import autonomy
    session, case = _abstain_case("A4-SD")
    case["worst_verdict"] = "ABSTAIN_DEGRADED"
    case["open_question"] = {"state": "ABSTAIN_DEGRADED", "resolved": False,
                             "why": "critical analyzers were disabled",
                             "what_would_resolve": "re-run with full integrity"}
    tools = {t.__name__: t for t in
             autonomy.commander_tools(session, case, case["mission"])}
    out = tools["stand_down"]("the host has been quiet")
    assert "error" in out, out
    assert case["mission"]["standing_down"] is None


def test_a4_an_unresolved_case_cannot_be_parked_for_a_month():
    from agent import autonomy
    session, case = _abstain_case("A4-SCH")
    case["worst_verdict"] = "ABSTAIN_DEGRADED"
    case["open_question"] = {"state": "ABSTAIN_DEGRADED", "resolved": False,
                             "why": "critical analyzers were disabled",
                             "what_would_resolve": "re-run with full integrity"}
    tools = {t.__name__: t for t in
             autonomy.commander_tools(session, case, case["mission"])}
    assert "error" in tools["schedule_next_cycle"]("look again", 720, "quiet")
    ok = tools["schedule_next_cycle"](
        "re-collect the surface that could not be read",
        autonomy.UNRESOLVED_MAX_INTERVAL_H, "still unresolved")
    assert "error" not in ok, ok


def test_a4_a_benign_case_may_still_stand_down_and_take_a_long_interval():
    """Negative control: the new guard must only bind unresolved cases."""
    from agent import autonomy
    session, case = _abstain_case("A4-OK")
    case["worst_verdict"] = "BENIGN_HIGH"
    tools = {t.__name__: t for t in
             autonomy.commander_tools(session, case, case["mission"])}
    assert "error" not in tools["schedule_next_cycle"]("routine", 24, "quiet")
    assert "error" not in tools["stand_down"]("three benign cycles, nothing open")


def test_a6_a_superseded_abstain_is_never_silent_in_the_queue():
    """The transition itself is deliberate — an abstain is a fact about a
    collection, and a later complete one may supersede it (two tests in
    test_case_store pin that). What the audit found is that it was SILENT:
    status read 'benign' while worst_verdict still read ABSTAIN_*, and the
    analyst row showed only the optimistic half.

    Note the remaining, deeper gap, tracked in the report rather than papered
    over: the transition fires on any later conclusive verdict, including one
    from a different surface than the abstain said was missing.
    """
    from service.case_store import _apply_run, _summarize
    from agent.mission import new_mission
    case = {"case_id": "A6", "entries": [], "verdicts": [], "audit_trail": [],
            "runs": 0, "worst_verdict": None, "status": "open",
            "open_question": None, "mission": new_mission("A6")}
    _apply_run(case, [], [{"verdict_state": "ABSTAIN_INSUFFICIENT"}], [])
    assert case["status"] == "abstain"
    _apply_run(case, [], [{"verdict_state": "BENIGN_HIGH"}], [])
    assert case["worst_verdict"] == "ABSTAIN_INSUFFICIENT"
    row = _summarize(dict(case, host={}, examiner_id="x", created_utc="",
                          updated_utc=""))
    assert row["supersedes_unresolved"] is True, (
        "a row whose status and worst_verdict disagree must say so")


def test_a6_an_open_gap_still_blocks_the_planner_from_treating_it_as_quiet():
    """The dangerous consequence of the divergence, closed: while the gap is
    open the fleet may not park or close the case, whatever status reads."""
    from agent import autonomy
    session, case = _abstain_case("A6C")
    case["status"] = "benign"          # the optimistic reading
    case["worst_verdict"] = "ABSTAIN_INSUFFICIENT"
    case["open_question"] = {"state": "ABSTAIN_INSUFFICIENT", "resolved": False,
                             "why": "incomplete collection",
                             "what_would_resolve": "collect both surfaces"}
    assert autonomy.is_unresolved(session, case)
    tools = {t.__name__: t for t in
             autonomy.commander_tools(session, case, case["mission"])}
    assert "error" in tools["stand_down"]("looks clean now")
    # ...and once the gap is genuinely closed, the case is free again
    case["open_question"]["resolved"] = True
    session2, _ = _abstain_case("A6D")
    assert not autonomy.is_unresolved(session2, case)


def test_a6_a_conclusive_case_still_settles():
    """Negative control: a case whose worst verdict IS benign still reads
    benign, and a malicious one still reads malice."""
    from service.case_store import _apply_run
    from agent.mission import new_mission
    for states, expected in ((["BENIGN_HIGH"], "benign"),
                             (["MALICE_HIGH"], "malice")):
        case = {"case_id": "A6B", "entries": [], "verdicts": [],
                "audit_trail": [], "runs": 0, "worst_verdict": None,
                "status": "open", "open_question": None,
                "mission": new_mission("A6B")}
        _apply_run(case, [], [{"verdict_state": s} for s in states], [])
        assert case["status"] == expected
