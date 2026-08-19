"""The commander's ADK loop, driven end to end by a scripted model.

Everything else about the fleet can be tested through the deterministic
planner, which leaves the part that actually runs in production — ADK building
the tool declarations, dispatching the model's function calls, feeding the
results back, and the narration coming out the far end — exercised only by the
live demo. That is the wrong thing to discover at 3am.

So the loop runs here against a model that is scripted rather than absent: a
BaseLlm that reads the real tool results out of the conversation and plays a
fixed investigative plan. What stays untested without credentials is Gemini's
judgement — not the machinery it drives.

The second and third cases are the adversarial ones: a commander that escalates
and narrates a verdict the engine never sealed.
"""

import asyncio
import tempfile
from pathlib import Path
from typing import AsyncGenerator

import pytest

pytest.importorskip("google.adk")

from google.adk.models.base_llm import BaseLlm  # noqa: E402
from google.adk.models.llm_response import LlmResponse  # noqa: E402
from google.genai import types  # noqa: E402

from agent import autonomy, mission as mem  # noqa: E402
from agent.tools import PurpleTeamSession  # noqa: E402
from tools.velociraptor.adapter import MockTransport  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
ATTACK = REPO / "tests" / "fixtures" / "attack"
INSUFFICIENT = REPO / "tests" / "fixtures" / "insufficient"
HOST = {"client_id": "C.1", "hostname": "WIN11-VICTIM", "os": "windows"}


class ScriptedModel(BaseLlm):
    """Plays a fixed plan, reading the real tool results from the transcript."""

    model: str = "scripted-test-model"
    plan: list = []

    async def generate_content_async(self, llm_request,
                                     stream: bool = False) -> AsyncGenerator[LlmResponse, None]:
        called = _calls(llm_request)
        results = _results(llm_request)
        for step in self.plan:
            name = step["tool"]
            if name in called:
                continue
            args = step["args"](results) if callable(step["args"]) else dict(step["args"])
            yield _fn_call(name, args)
            return
        yield _text(self.final(results))
        return

    def final(self, results) -> str:
        state = results.get("request_adjudication", {}).get("verdict_state", "nothing")
        return f"Cycle complete. Sealed verdict: {state}."


def _calls(req):
    return [p.function_call.name
            for c in (req.contents or []) for p in (c.parts or [])
            if getattr(p, "function_call", None)]


def _results(req):
    out = {}
    for c in req.contents or []:
        for p in c.parts or []:
            fr = getattr(p, "function_response", None)
            if fr:
                out[fr.name] = fr.response or {}
    return out


def _fn_call(name, args):
    return LlmResponse(content=types.Content(
        role="model",
        parts=[types.Part(function_call=types.FunctionCall(name=name, args=args))]))


def _text(text):
    return LlmResponse(content=types.Content(
        role="model", parts=[types.Part(text=text)]))


def _session(fixtures=ATTACK, case_id="LOOP"):
    return PurpleTeamSession(
        MockTransport(fixtures), case_id=case_id, host=HOST, examiner_id="op",
        out_dir=tempfile.mkdtemp(), source="replay",
        time_base="2026-08-12T14:10:00Z")


def _case(case_id="LOOP"):
    return {"case_id": case_id, "host": HOST, "status": "open",
            "worst_verdict": None, "entries": [], "verdicts": [],
            "audit_trail": [], "runs": 0}


FULL_INVESTIGATION = [
    {"tool": "read_mission_brief", "args": {}},
    {"tool": "task_hunter", "args": {"specialist": "windows-hunter",
                                     "reason": "baseline running state"}},
    {"tool": "request_adjudication",
     "args": lambda r: {"window_id": r.get("task_hunter", {}).get("window_id")}},
    {"tool": "escalate_to_human",
     "args": lambda r: {
         "why": f"the engine adjudicated "
                f"{r.get('request_adjudication', {}).get('verdict_state', '?')}",
         "what_to_check": "confirm containment on the host"}},
    {"tool": "schedule_next_cycle",
     "args": {"action": "re-check running state", "in_hours": 1,
              "why": "watching a host under an adjudicated verdict"}},
]


def _run(session, case, plan, **kw):
    model = ScriptedModel(plan=plan)
    return asyncio.run(autonomy.run_cycle(session, case, model=model,
                                          trigger="test", **kw))


def test_the_adk_loop_runs_the_whole_investigation():
    """The load-bearing one: this is the production path, not the fallback."""
    result = _run(_session(), _case(), FULL_INVESTIGATION)
    assert result["planner"] == "gemini", result["planner_error"]
    assert result["planner_error"] is None

    actions = [(e["role"], e["action"]) for e in result["fleet_log"]]
    assert ("fleet-commander", "read_mission_brief") in actions
    assert ("windows-hunter", "collect") in actions
    assert ("correlator", "adjudicate") in actions

    assert [v["verdict_state"] for v in result["verdicts"]] == ["MALICE_HIGH"]
    assert result["narration"], "no narration came out of the loop"
    assert result["next_action"]["in_hours"] == 1


def test_tool_results_flow_back_to_the_model():
    """The window_id in the adjudication came from the hunter's real return
    value, so the model saw genuine tool output rather than an echo."""
    session = _session()
    result = _run(session, _case(), FULL_INVESTIGATION)
    collected = next(e for e in result["fleet_log"] if e["action"] == "collect")
    adjudicated = next(e for e in result["fleet_log"] if e["action"] == "adjudicate")
    assert adjudicated["window_id"] == collected["window_id"]
    assert result["verdicts"][0]["mitre_techniques"] == ["T1055.012", "T1070.006"]


def test_an_escalation_carries_the_sealed_facts_it_rests_on():
    case = _case()
    _run(_session(), case, FULL_INVESTIGATION)
    escalation = case["mission"]["escalation"]
    assert escalation["sealed_basis"], "the escalation cited no sealed verdict"
    assert escalation["sealed_basis"][0]["verdict_state"] == "MALICE_HIGH"
    assert len(escalation["sealed_basis"][0]["entry_hash"]) == 64
    assert escalation["unsupported_by_seal"] is False
    assert escalation["unsealed_verdict_claims"] == []


ESCALATE_ON_NOTHING = [
    {"tool": "read_mission_brief", "args": {}},
    {"tool": "task_hunter", "args": {"specialist": "windows-hunter",
                                     "reason": "baseline"}},
    {"tool": "escalate_to_human",
     "args": {"why": "the engine adjudicated MALICE_HIGH on this host",
              "what_to_check": "isolate it now"}},
    {"tool": "schedule_next_cycle",
     "args": {"action": "re-check", "in_hours": 1, "why": "watching"}},
]


def test_an_escalation_resting_on_nothing_says_so():
    """The failure this parameter exists for. The insufficient fixture has no
    netstat, so the collection fails and nothing is adjudicated — and the
    commander escalates anyway, naming a verdict that was never reached. The
    escalation is recorded, because refusing to escalate could strand a real
    incident; what it cannot do is appear supported."""
    case = _case("LOOP-NOTHING")
    result = _run(_session(INSUFFICIENT, "LOOP-NOTHING"), case, ESCALATE_ON_NOTHING)
    assert result["planner"] == "gemini"
    assert not result["verdicts"]

    escalation = case["mission"]["escalation"]
    assert escalation["sealed_basis"] == []
    assert escalation["unsupported_by_seal"] is True
    assert escalation["unsealed_verdict_claims"] == ["MALICE_HIGH"]


class NarratesAVerdictItNeverSealed(ScriptedModel):
    def final(self, results) -> str:
        return "I reviewed the host and concluded BENIGN_HIGH. No action needed."


def test_a_narration_that_invents_a_verdict_is_flagged_against_the_seal():
    """A mechanical comparison against the sealed record — not another model
    judging the first one."""
    session, case = _session(), _case("LOOP-LIE")
    model = NarratesAVerdictItNeverSealed(plan=FULL_INVESTIGATION)
    result = asyncio.run(autonomy.run_cycle(session, case, model=model,
                                            trigger="test"))
    assert result["verdicts"][0]["verdict_state"] == "MALICE_HIGH"
    assert result["unsealed_verdict_claims"] == ["BENIGN_HIGH"]
    assert any(e["action"] == "narration_unsupported" for e in result["fleet_log"])
    # and the sealed record is untouched by the lie
    assert case["mission"]["escalation"]["sealed_basis"][0]["verdict_state"] == "MALICE_HIGH"


class Explodes(ScriptedModel):
    async def generate_content_async(self, llm_request, stream: bool = False):
        raise RuntimeError("model unreachable: 503")
        yield  # pragma: no cover — makes this an async generator


def test_a_model_failure_falls_back_instead_of_stranding_the_case():
    """An unattended cycle must not die because the model was rate limited."""
    case = _case("LOOP-DOWN")
    result = asyncio.run(autonomy.run_cycle(
        _session(case_id="LOOP-DOWN"), case, model=Explodes(), trigger="test"))
    assert result["planner"] == "deterministic-fallback"
    assert "503" in result["planner_error"]
    assert any(e["action"] == "agent_turn_failed" for e in result["fleet_log"])
    # the fallback still did the work
    assert result["verdicts"] and result["next_action"]


def test_the_catalog_still_refuses_the_soc_on_the_agent_path():
    """The gate is at the tool boundary, so it holds whichever planner runs."""
    case = _case("LOOP-SOC")
    result = _run(_session(case_id="LOOP-SOC"), case, FULL_INVESTIGATION,
                  department="soc")
    assert result["planner"] == "gemini"
    assert any(e["action"] == "refused_by_catalog" for e in result["fleet_log"])
    assert not result["verdicts"]
