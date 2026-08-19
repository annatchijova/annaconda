"""The autonomous cycle: real agency over the investigation, none over the verdict.

These tests run the unattended path end to end with no model reachable, so what
they exercise is the deterministic fallback planner driving the *same* tool
contract the Gemini commander drives. What is being proven is structural and
holds for both planners: the commander cannot collect or adjudicate itself, the
catalog refuses taskings outside its department, memory carries across cycles,
and the verdict comes from the sealed engine.
"""

import asyncio
import tempfile
from pathlib import Path

import pytest

from agent import autonomy, catalog, mission as mem
from agent.fleet import contract_names
from agent.tools import PurpleTeamSession
from tools.velociraptor.adapter import MockTransport

REPO = Path(__file__).resolve().parent.parent
ATTACK = REPO / "tests" / "fixtures" / "attack"
BENIGN = REPO / "tests" / "fixtures" / "velociraptor"
HOST = {"client_id": "C.1", "hostname": "WIN11-VICTIM", "os": "windows"}


def _session(fixtures=ATTACK, case_id="AUTO-T"):
    return PurpleTeamSession(
        MockTransport(fixtures), case_id=case_id, host=HOST, examiner_id="op",
        out_dir=tempfile.mkdtemp(), source="replay",
        time_base="2026-08-12T14:10:00Z")


def _case(case_id="AUTO-T"):
    return {"case_id": case_id, "host": HOST, "status": "open",
            "worst_verdict": None, "entries": [], "verdicts": [],
            "audit_trail": [], "runs": 0}


def _cycle(session, case, **kw):
    return asyncio.run(autonomy.run_cycle(session, case, **kw))


def test_a_cycle_runs_the_case_and_seals_a_verdict_without_a_human():
    case = _case()
    result = _cycle(_session(), case)
    assert result["acted"]
    assert result["planner"] == "deterministic-fallback"  # no model in CI
    states = [v["verdict_state"] for v in result["verdicts"]]
    assert any(s.startswith("MALICE") for s in states), states
    roles = {e["role"] for e in result["fleet_log"]}
    assert {"fleet-commander", "windows-hunter", "correlator"} <= roles


def test_the_commander_holds_no_collection_or_adjudication_tool_of_its_own():
    """The delegation boundary, structurally: the commander's contract is
    disjoint from every specialist's, so the only way it reaches evidence or
    the sealed core is by tasking somebody who is cleared for it."""
    session = _session()
    commander = {t.__name__ for t in
                 autonomy.commander_tools(session, _case(), mem.new_mission("X"))}
    for role, tools in contract_names(session).items():
        shared = commander & set(tools)
        assert not shared, f"commander shares {shared} with {role}"
    # and it owns nothing that collects or adjudicates directly
    assert not any("survey" in t or t.startswith("adjudicate") for t in commander)


def test_a_malicious_verdict_escalates_to_a_human_with_its_reasoning():
    case = _case()
    result = _cycle(_session(), case)
    escalation = result["escalation"]
    assert escalation is not None
    assert "MALICE" in escalation["why"]
    assert escalation["what_to_check"]
    assert not escalation["acknowledged"]


def test_every_cycle_leaves_a_decision_about_the_cases_future():
    case = _case()
    result = _cycle(_session(), case)
    assert (result["next_action"] or result["standing_down"]) is not None


def test_a_case_that_is_not_due_is_skipped_without_opening_a_cycle():
    case = _case()
    first = _cycle(_session(), case)
    before = case["mission"]["cycles"]
    second = _cycle(_session(), case)
    assert not second["acted"] and second["reason"] == "not due"
    assert case["mission"]["cycles"] == before, "a skipped tick must not burn a cycle"
    assert first["cycle"] == 1


def test_memory_carries_across_cycles_so_work_is_not_repeated():
    case = _case()
    _cycle(_session(), case)
    tried_first = [t["hunts"] for t in case["mission"]["tried_hunts"]]
    _cycle(_session(), case, force=True)
    tried_all = [t["hunts"] for t in case["mission"]["tried_hunts"]]
    assert len(tried_all) == 2
    assert tried_all[1] != tried_first[0], (
        "the second cycle repeated the first cycle's collection — memory was "
        "not consulted")


def test_the_catalog_refuses_a_tasking_outside_the_running_department():
    """Least privilege, demonstrated: the SOC may task collectors but may not
    request adjudication — that belongs to forensics. The cycle still completes
    and records the refusal rather than working around it."""
    case = _case()
    result = _cycle(_session(), case, department="soc")
    assert result["acted"]
    refusals = [e for e in result["fleet_log"]
                if e["action"] == "refused_by_catalog"]
    assert refusals and refusals[0]["role"] == "correlator"
    assert not result["verdicts"], "SOC obtained a verdict it is not cleared for"
    # the collection it *was* cleared for still happened
    assert any(e["action"] == "collect" for e in result["fleet_log"])


def test_incident_response_is_cleared_for_the_whole_loop():
    case = _case()
    result = _cycle(_session(), case, department="incident-response")
    assert not [e for e in result["fleet_log"]
                if e["action"] == "refused_by_catalog"]
    assert result["verdicts"]


def test_an_unknown_department_cannot_run_the_fleet():
    case = _case()
    result = _cycle(_session(), case, department="marketing")
    assert all(e["action"] != "collect" for e in result["fleet_log"])


def test_the_cycles_memory_is_tamper_evident():
    case = _case()
    result = _cycle(_session(), case)
    assert result["memory"]["memory_ok"]
    case["mission"]["journal"][0]["detail"]["trigger"] = "forged"
    assert not mem.verify_mission(case["mission"])["memory_ok"]


def test_a_benign_host_earns_a_long_interval_and_eventually_a_stand_down():
    case = _case("AUTO-B")
    session = _session(BENIGN, "AUTO-B")
    for _ in range(4):
        _cycle(session, case, force=True)
    mission = case["mission"]
    assert mission["standing_down"] is not None, (
        "the fleet never stopped on a quiet host — an agent that cannot stop "
        "is a loop")
    assert not mem.is_due(mission)


def test_the_commander_is_gated_by_the_sealed_registry():
    from agent.registry import UnapprovedAgentError, require_approved, REGISTRY_VERSION
    tools = [t.__name__ for t in
             autonomy.commander_tools(_session(), _case(), mem.new_mission("X"))]
    require_approved(autonomy.COMMANDER_NAME, REGISTRY_VERSION, tools)
    with pytest.raises(UnapprovedAgentError):
        require_approved(autonomy.COMMANDER_NAME, REGISTRY_VERSION,
                         tools + ["exfiltrate_everything"])


def test_the_commanders_department_is_published_to_task_what_it_needs():
    for specialist in ("windows-hunter", "persistence-agent", "correlator"):
        catalog.authorize(specialist,
                          department=autonomy.COMMANDER_DEPARTMENT,
                          data_classes=[])


def test_a_failed_collection_is_not_reported_as_a_quiet_host():
    """The honest-degradation case. The 'insufficient' fixture has no netstat,
    so the collection fails. A cycle that shrugged and scheduled the long
    'quiet host' interval would let the next cycle read an unobserved endpoint
    as an observed clean one."""
    INSUFFICIENT = REPO / "tests" / "fixtures" / "insufficient"
    case = _case("AUTO-FAIL")
    result = _cycle(_session(INSUFFICIENT, "AUTO-FAIL"), case)
    assert any(e["action"] == "collect_failed" for e in result["fleet_log"])
    assert not result["verdicts"]
    plan = result["next_action"]
    assert plan["in_hours"] <= 2, "an unobserved host got a quiet-host interval"
    assert "unobserved" in plan["why"]
    questions = [q["question"] for q in case["mission"]["open_questions"]]
    assert any("could not collect" in q for q in questions), questions


def test_an_abstain_question_reaches_the_fleets_memory():
    """ABSTAIN-as-memory has to be memory the *fleet* reads, not a field only
    the UI renders — otherwise the next cycle re-collects blind."""
    from service.case_store import MemoryCaseStore

    store = MemoryCaseStore()
    case = store.create_case("AB-1", HOST, "perito")
    store.apply_run("AB-1", [], [{"verdict_state": "ABSTAIN_INSUFFICIENT"}], [])
    questions = [q["question"] for q in case["mission"]["open_questions"]]
    assert any(q.startswith("ABSTAIN_INSUFFICIENT") for q in questions), questions
    assert mem.brief(case["mission"])["unresolved_questions"]

    # and a later definitive run closes it in memory too
    store.apply_run("AB-1", [], [{"verdict_state": "BENIGN_HIGH"}], [])
    assert not mem.brief(case["mission"])["unresolved_questions"]
