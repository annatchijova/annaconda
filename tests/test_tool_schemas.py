"""The contract the model actually sees.

Everything else about the fleet is testable offline; the one thing that is not
is whether Gemini calls these tools correctly at 3am. Most of what would break
there is not the model's judgement, though — it is the tool *declaration* ADK
derives from each function and sends to it: a parameter the model cannot see, a
type it cannot satisfy, a tool with no docstring to explain itself.

So the declarations are pinned here. What remains untested without credentials
is the model's behaviour, not the surface it is given.
"""

import tempfile
from pathlib import Path

import pytest

pytest.importorskip("google.adk")

from google.adk.tools import FunctionTool  # noqa: E402

from agent import autonomy, fleet, mission as mem  # noqa: E402
from agent.tools import PurpleTeamSession  # noqa: E402
from tools.velociraptor.adapter import MockTransport  # noqa: E402

REPO = Path(__file__).resolve().parent.parent


def _session():
    return PurpleTeamSession(
        MockTransport(REPO / "tests" / "fixtures" / "attack"), case_id="SCHEMA",
        host={"client_id": "C.1", "hostname": "H", "os": "windows"},
        examiner_id="op", out_dir=tempfile.mkdtemp(), source="replay",
        time_base="2026-08-12T14:10:00Z")


def _declaration(tool):
    """The FunctionDeclaration ADK sends to Gemini, and its parameter schema.

    ADK 2.x carries the schema on ``parameters_json_schema``; older builds used
    ``parameters``. Read whichever is populated rather than assuming, so this
    test fails on a real regression and not on an ADK upgrade.
    """
    decl = FunctionTool(tool)._get_declaration()
    schema = getattr(decl, "parameters_json_schema", None)
    if schema:
        return decl, dict(schema.get("properties") or {}), list(schema.get("required") or [])
    params = getattr(decl, "parameters", None)
    props = dict(getattr(params, "properties", None) or {})
    return decl, props, list(getattr(params, "required", None) or [])


def _all_agent_tools():
    """Every tool of every agent the registry approves, by role."""
    session = _session()
    groups = {
        "fleet-commander": autonomy.commander_tools(
            session, {"case_id": "SCHEMA"}, mem.new_mission("SCHEMA")),
        "vigia_purple_team": [session.list_available_hunts, session.run_hunt,
                              session.adjudicate, session.verify_chain],
    }
    for role, spec in fleet.FLEET.items():
        groups[role] = spec["tools"](session)
    return groups


ALL_TOOLS = [(role, tool) for role, tools in _all_agent_tools().items()
             for tool in tools]
IDS = [f"{role}.{tool.__name__}" for role, tool in ALL_TOOLS]


@pytest.mark.parametrize("role,tool", ALL_TOOLS, ids=IDS)
def test_every_tool_declares_exactly_its_signature(role, tool):
    """A parameter the declaration omits is a parameter the model cannot pass —
    and the call arrives missing an argument the function requires."""
    import inspect
    decl, props, required = _declaration(tool)
    expected = [p for p in inspect.signature(tool).parameters]
    assert sorted(props) == sorted(expected), (
        f"{role}.{tool.__name__}: the model is shown {sorted(props)} but the "
        f"function takes {sorted(expected)}")
    assert sorted(required) == sorted(expected), (
        f"{role}.{tool.__name__}: {set(expected) - set(required)} would be "
        f"optional to the model but is required by the function")
    assert decl.name == tool.__name__


@pytest.mark.parametrize("role,tool", ALL_TOOLS, ids=IDS)
def test_every_tool_explains_itself_to_the_model(role, tool):
    """The docstring is the entire instruction the model gets for a tool. An
    undocumented tool is one it will use wrongly or not at all."""
    decl, _, _ = _declaration(tool)
    assert decl.description and len(decl.description.strip()) > 40, (
        f"{role}.{tool.__name__} has no usable description")


def test_the_schedule_is_a_number_the_model_can_satisfy():
    """schedule_next_cycle rejects a non-int in_hours. If it were declared as a
    string the model would send "6" and every scheduling call would fail."""
    tools = {t.__name__: t for t in autonomy.commander_tools(
        _session(), {"case_id": "S"}, mem.new_mission("S"))}
    _, props, _ = _declaration(tools["schedule_next_cycle"])
    assert props["in_hours"]["type"] == "integer"
    assert props["action"]["type"] == "string"


def test_no_tool_name_is_ambiguous_across_the_fleet():
    """Two agents may hold tools with the same name only if they are the same
    tool; otherwise a fleet log attributes an action to the wrong specialist."""
    seen = {}
    for role, tool in ALL_TOOLS:
        seen.setdefault(tool.__name__, set()).add(role)
    shared = {n: r for n, r in seen.items() if len(r) > 1}
    assert not shared, f"tool names held by more than one agent: {shared}"


def test_every_approved_agent_can_actually_be_built():
    """The registry gate and ADK construction, exercised. Without this the first
    time build_commander runs is in production, on the cron."""
    session = _session()
    commander = autonomy.build_commander(
        session, {"case_id": "SCHEMA", "host": {"hostname": "H"}},
        mem.new_mission("SCHEMA"))
    assert commander.name == "vigia_fleet_commander"
    assert len(commander.tools) == 8
    assert commander.instruction.strip()

    for role in fleet.FLEET:
        specialist = fleet.build_specialist(role, session)
        assert specialist.tools

    from agent.purple_team_agent import build_agent
    assert build_agent(session).tools


def test_an_agent_whose_tools_drifted_is_refused_before_it_is_built():
    """The gate is on the build path, not only on a manifest helper."""
    from agent.registry import UnapprovedAgentError

    session = _session()
    original = autonomy.commander_tools

    def with_an_extra_tool(*args, **kwargs):
        def exfiltrate_everything() -> dict:
            """An out-of-band tool nobody approved."""
            return {}
        return original(*args, **kwargs) + [exfiltrate_everything]

    autonomy.commander_tools = with_an_extra_tool
    try:
        with pytest.raises(UnapprovedAgentError):
            autonomy.build_commander(session, {"case_id": "S", "host": {}},
                                     mem.new_mission("S"))
    finally:
        autonomy.commander_tools = original
