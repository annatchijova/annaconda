"""The autonomous cycle: the fleet working a case with nobody watching.

Before this module, annaconda's autonomy and its agency were separate things.
``/tasks/sweep`` ran a hard-coded collection on every open case on a cron — a
script, with no agent and no decision in it — while the agents only ever moved
when a human typed a prompt. Neither half was what an autonomous fleet is.

Here they meet. A cycle is one wake-up on one case:

    read the mission memory  →  decide  →  task specialists  →  write back
                                   ▲                                │
                                   └──── schedule the next wake-up ─┘

The commander decides *what to investigate, whom to task, when to look again,
when a human is needed, and when to stop*. It cannot decide what the evidence
means: it holds no collection tool and no adjudication tool of its own — only
the authority to task the specialists that hold them, through the enterprise
catalog, which refuses a tasking the commander's department is not published
for. The verdict still comes from the deterministic core, already sealed, and
the commander reports it as returned.

So the fleet gains real agency over the investigation and none at all over the
adjudication — which is the whole architecture, now running unattended.

Honest degradation: when no model is reachable (no credentials, offline, CI)
the cycle runs a **deterministic planner** instead, and says so in its result
(``planner: "deterministic-fallback"``). The fallback makes the same *kind* of
decisions from rules, so the service keeps working and the tests stay offline —
but it is never reported as agent reasoning.
"""

from __future__ import annotations

import logging
import os
from typing import Optional

from agent import catalog, mission as mem
from agent.fleet import (
    correlator_tools, dispatcher_tools, persistence_tools, windows_hunter_tools,
)
from agent.tools import PurpleTeamSession

log = logging.getLogger("annaconda.autonomy")

# The commander runs as incident response: the one department published to task
# the collectors *and* to request adjudication from forensics. Run it as "soc"
# and the catalog refuses the adjudication — least privilege, demonstrable.
COMMANDER_DEPARTMENT = "incident-response"

COMMANDER_NAME = "fleet-commander"

# Which specialist collects what. The commander names a specialist; the data
# class it will touch is fixed here, not chosen by the model.
_HUNTERS = {
    "windows-hunter": {
        "tools": windows_hunter_tools,
        "data_classes": ["endpoint_telemetry"],
        "collects": "running processes and their network connections",
        "hunts": ["pslist", "netstat"],
    },
    "persistence-agent": {
        "tools": persistence_tools,
        "data_classes": ["persistence_artifacts"],
        "collects": "scheduled tasks and process-creation logs",
        "hunts": ["scheduled_tasks", "process_creation_evtx"],
    },
}

INSTRUCTION = """\
You are the fleet commander in annaconda's forensic fleet, working one case \
autonomously. No human is watching this cycle: whatever you decide is what \
happens, and whatever you record is what the next cycle — possibly days from \
now — will know.

Start by calling read_mission_brief. It tells you what earlier cycles already \
did: which lines of inquiry are open, which collections were already run (do \
not repeat them without a reason), what questions are unresolved, and the \
sealed status of the case so far.

Then work the case:
- Task a specialist to collect what you actually need. task_hunter takes \
'windows-hunter' (running process and network state) or 'persistence-agent' \
(scheduled tasks and execution logs). You cannot collect anything yourself.
- Send each frozen window to request_adjudication. The verdict comes back \
SEALED from the deterministic engine. You cannot change it, argue with it, or \
substitute your own reading of the evidence — report it exactly as returned.
- Record what you are thinking: open_line_of_inquiry when you form a \
hypothesis, settle_line_of_inquiry when a sealed result supports or refutes \
one. This memory is the only thing that survives to the next cycle.
- Decide when to look again: schedule_next_cycle. A quiet benign host earns a \
long interval; an unresolved lead a short one. Say why.
- escalate_to_human when the case needs a person — a malicious verdict, or a \
question you cannot resolve by collecting more. Say what they should check.
- stand_down when there is nothing left worth doing on a cron. An agent that \
cannot stop is a loop, not an investigator.

End every cycle having either scheduled the next one, escalated, or stood \
down — never leave the case with no decision about its future.

Absolute rules: verdicts, scores, MITRE techniques and hashes come only from \
request_adjudication and are final. Never invent one. If a tool refuses you \
(the catalog may say your department cannot task an agent), report the refusal \
plainly — do not try to work around it.
"""


def commander_tools(session: PurpleTeamSession, case: dict, mission: dict,
                    *, department: str = COMMANDER_DEPARTMENT,
                    log_sink: Optional[list] = None) -> list:
    """The commander's tool contract: delegation and memory, nothing else.

    Deliberately absent: any tool that collects evidence or adjudicates it.
    The commander reaches those only through ``task_hunter`` and
    ``request_adjudication``, each of which asks the catalog for permission
    first — so authority is checked at the boundary, on every call.
    """
    events = log_sink if log_sink is not None else []

    def _note(role: str, action: str, **detail):
        events.append({"role": role, "action": action, **detail})

    def read_mission_brief() -> dict:
        """Read what earlier cycles of this investigation already established:
        open lines of inquiry, collections already run, unresolved questions,
        the plan the last cycle left, and the case's sealed status."""
        out = mem.brief(mission, case=case)
        _note(COMMANDER_NAME, "read_mission_brief",
              cycles_so_far=out["cycles_so_far"],
              open_lines=len(out["open_hypotheses"]))
        return out

    def task_hunter(specialist: str, reason: str) -> dict:
        """Task a collection specialist to freeze a sealed evidence window.

        ``specialist`` must be 'windows-hunter' (running processes and network
        connections) or 'persistence-agent' (scheduled tasks and execution
        logs). ``reason`` is your investigative purpose, recorded in the case's
        memory. Returns a summary of the frozen window including its
        window_id — not a verdict. Call request_adjudication for that.
        """
        spec = _HUNTERS.get(specialist)
        if spec is None:
            return {"error": f"unknown specialist {specialist!r}; "
                             f"available: {sorted(_HUNTERS)}"}
        try:
            catalog.authorize(specialist, department=department,
                              data_classes=spec["data_classes"])
        except PermissionError as exc:
            _note(specialist, "refused_by_catalog", detail=str(exc))
            return {"error": f"catalog refused this tasking: {exc}"}

        summary = spec["tools"](session)[0](reason)
        if "error" in summary:
            _note(specialist, "collect_failed", detail=summary["error"])
            return summary
        mem.record_collection(mission, actor=specialist, hunts=spec["hunts"],
                              reason=reason, window_id=summary["window_id"])
        _note(specialist, "collect", window_id=summary["window_id"],
              artifacts=summary.get("artifacts"), reason=reason)
        return summary

    def request_adjudication(window_id: str) -> dict:
        """Ask the correlator to adjudicate a frozen window into a SEALED
        verdict from the deterministic engine. The result is final: report the
        verdict state, score and MITRE techniques exactly as returned."""
        try:
            catalog.authorize("correlator", department=department,
                              data_classes=["sealed_verdicts"])
        except PermissionError as exc:
            _note("correlator", "refused_by_catalog", detail=str(exc))
            return {"error": f"catalog refused this tasking: {exc}"}

        verdict = correlator_tools(session)[0](window_id)
        if "error" in verdict:
            _note("correlator", "adjudicate_failed", detail=verdict["error"])
            return verdict
        _note("correlator", "adjudicate", window_id=window_id,
              verdict_state=verdict["verdict_state"],
              mitre_techniques=verdict.get("mitre_techniques", []))
        return verdict

    def open_line_of_inquiry(text: str) -> dict:
        """Record a hypothesis you intend to pursue, so a later cycle knows it
        is open. Returns the hypothesis with the id used to settle it."""
        try:
            h = mem.add_hypothesis(mission, actor=COMMANDER_NAME, text=text)
        except mem.MissionError as exc:
            return {"error": str(exc)}
        _note(COMMANDER_NAME, "open_line_of_inquiry", id=h["id"], text=h["text"])
        return h

    def settle_line_of_inquiry(hypothesis_id: str, status: str,
                               rationale: str) -> dict:
        """Close a hypothesis: status must be 'supported' or 'refuted', with
        the reasoning that settled it. Refuted lines are kept, not deleted —
        the discarded ground is what a later examiner needs."""
        try:
            h = mem.update_hypothesis(mission, actor=COMMANDER_NAME,
                                      hypothesis_id=hypothesis_id,
                                      status=status, rationale=rationale)
        except mem.MissionError as exc:
            return {"error": str(exc)}
        _note(COMMANDER_NAME, "settle_line_of_inquiry", id=h["id"],
              status=h["status"], rationale=h["rationale"])
        return h

    def schedule_next_cycle(action: str, in_hours: int, why: str) -> dict:
        """Set when this case should be worked again and what to do then.
        ``in_hours`` is 1 to 720. The sweep will not touch this case before
        then — this is how the fleet paces itself across weeks."""
        try:
            plan = mem.schedule_next_action(mission, actor=COMMANDER_NAME,
                                            action=action, in_hours=in_hours,
                                            why=why)
        except mem.MissionError as exc:
            return {"error": str(exc)}
        _note(COMMANDER_NAME, "schedule_next_cycle", due_utc=plan["due_utc"],
              planned=plan["action"], why=plan["why"])
        return plan

    def escalate_to_human(why: str, what_to_check: str) -> dict:
        """Hand this case to a human examiner, with the reasoning that made it
        necessary and what they should look at first."""
        try:
            esc = mem.escalate(mission, actor=COMMANDER_NAME, why=why,
                               what_to_check=what_to_check)
        except mem.MissionError as exc:
            return {"error": str(exc)}
        _note(COMMANDER_NAME, "escalate_to_human", why=esc["why"],
              what_to_check=esc["what_to_check"])
        return esc

    def stand_down(rationale: str) -> dict:
        """Stop scheduling autonomous cycles on this case. The sealed record and
        the case's status are untouched; a human can always reopen it."""
        try:
            sd = mem.stand_down(mission, actor=COMMANDER_NAME, rationale=rationale)
        except mem.MissionError as exc:
            return {"error": str(exc)}
        _note(COMMANDER_NAME, "stand_down", rationale=sd["rationale"])
        return sd

    return [read_mission_brief, task_hunter, request_adjudication,
            open_line_of_inquiry, settle_line_of_inquiry, schedule_next_cycle,
            escalate_to_human, stand_down]


def build_commander(session: PurpleTeamSession, case: dict, mission: dict, *,
                    department: str = COMMANDER_DEPARTMENT,
                    log_sink: Optional[list] = None, model=None):
    """Build the commander as a real ADK agent, gated by the sealed registry."""
    from google.adk.agents import Agent
    from agent.purple_team_agent import model_id
    from agent.registry import REGISTRY_VERSION, require_approved

    tools = commander_tools(session, case, mission, department=department,
                            log_sink=log_sink)
    require_approved(COMMANDER_NAME, REGISTRY_VERSION,
                     [t.__name__ for t in tools])
    return Agent(
        name="vigia_fleet_commander",
        model=model or model_id(),
        description=("annaconda fleet · commander: works a case autonomously, "
                     "tasking the specialists and carrying the investigation's "
                     "memory across cycles."),
        instruction=INSTRUCTION,
        tools=tools,
    )


def model_reachable() -> bool:
    """Whether an agent turn can even be attempted. Checked rather than assumed
    so a cron on a machine with no credentials degrades instead of erroring
    every hour."""
    if os.environ.get("GOOGLE_GENAI_USE_VERTEXAI", "").upper() == "TRUE":
        return bool(os.environ.get("GOOGLE_CLOUD_PROJECT"))
    return bool(os.environ.get("GEMINI_API_KEY")
                or os.environ.get("GOOGLE_API_KEY"))


def plan_deterministically(session: PurpleTeamSession, case: dict,
                           mission: dict, *,
                           department: str = COMMANDER_DEPARTMENT,
                           log_sink: Optional[list] = None) -> None:
    """The fallback planner: same decisions, made by rules instead of a model.

    It exists so an unattended cycle still does something defensible when no
    model is reachable — and so the whole autonomous path is testable offline.
    Its output is labelled ``deterministic-fallback`` and must never be
    presented as agent reasoning.
    """
    tools = {t.__name__: t for t in
             commander_tools(session, case, mission, department=department,
                             log_sink=log_sink)}
    brief = tools["read_mission_brief"]()

    collected = {tuple(t["hunts"]) for t in mission.get("tried_hunts", [])}
    # Pursue something not yet tried; if both surfaces are covered, revisit the
    # running state (a beacon that was quiet last cycle may not be quiet now).
    for specialist, spec in _HUNTERS.items():
        if tuple(sorted(spec["hunts"])) not in collected:
            target = specialist
            break
    else:
        target = "windows-hunter"

    reason = ("first look at this host" if not collected
              else f"cycle {mission['cycles']}: surface not yet covered"
              if target != "windows-hunter"
              else f"cycle {mission['cycles']}: re-checking running state")
    summary = tools["task_hunter"](target, reason)

    verdict = None
    if "error" not in summary:
        verdict = tools["request_adjudication"](summary["window_id"])
        if "error" in verdict:
            verdict = None

    state = (verdict or {}).get("verdict_state", "")
    unresolved = brief.get("unresolved_questions", [])

    if state.startswith("MALICE"):
        tools["escalate_to_human"](
            why=f"the sealed engine adjudicated {state} on this host",
            what_to_check=("confirm containment, then review the sealed chain "
                           "and the MITRE techniques the engine returned"))
        tools["schedule_next_cycle"](
            action="re-collect running state to watch for further activity",
            in_hours=1,
            why="a host under an adjudicated malicious verdict is watched closely "
                "until a human takes it over")
    elif state.startswith("ABSTAIN") or unresolved:
        tools["schedule_next_cycle"](
            action="collect the surface not yet covered and adjudicate it",
            in_hours=6,
            why="the case has an unresolved question; a later collection may "
                "close it")
    elif state.startswith("BENIGN") and mission["cycles"] >= 3:
        tools["stand_down"](
            rationale=f"{mission['cycles']} cycles have adjudicated benign with "
                      f"no unresolved question; further cron collection would "
                      f"add cost, not evidence")
    else:
        tools["schedule_next_cycle"](
            action="routine re-collection of running state",
            in_hours=24,
            why="no open lead; a quiet host earns a long interval")


async def run_cycle(session: PurpleTeamSession, case: dict, *,
                    department: str = COMMANDER_DEPARTMENT,
                    trigger: str = "scheduler",
                    force: bool = False, model=None) -> dict:
    """Work one case for one cycle, unattended.

    Returns what happened, including which planner ran. A case that is not yet
    due is skipped without opening a cycle — that is the point of the fleet
    pacing itself: most wake-ups on most cases should do nothing.
    """
    mission = mem.attach(case)
    if not force and not mem.is_due(mission):
        return {"acted": False, "reason": "not due", "case_id": case["case_id"],
                "next_action": mission.get("next_action"),
                "standing_down": mission.get("standing_down") is not None}

    mem.begin_cycle(mission, actor=COMMANDER_NAME, trigger=trigger)
    events: list = []
    planner = "deterministic-fallback"
    narration = None
    error = None

    if model_reachable():
        try:
            narration = await _run_commander_turn(
                session, case, mission, department=department,
                log_sink=events, model=model)
            planner = "gemini"
        except Exception as exc:  # noqa: BLE001
            # An unattended cycle must not die because the model was
            # unreachable, rate limited, or refused. Fall back, and record that
            # it fell back — silence here would look like agent reasoning.
            log.warning("commander turn failed on case %s (%s) — falling back "
                        "to the deterministic planner", case.get("case_id"), exc)
            error = str(exc)
            events.append({"role": COMMANDER_NAME, "action": "agent_turn_failed",
                           "detail": str(exc)})

    if planner != "gemini":
        plan_deterministically(session, case, mission, department=department,
                               log_sink=events)

    # A cycle that ended with no decision about the case's future would strand
    # it: the sweep would revisit it every tick forever. Close that hole here
    # rather than trusting the planner to have done it.
    if (mission.get("next_action") is None
            and not mission.get("standing_down")):
        mem.schedule_next_action(
            mission, actor=COMMANDER_NAME,
            action="re-assess this case",
            in_hours=24,
            why="the cycle ended without setting its own next step; a default "
                "interval is applied so the case is neither stranded nor "
                "revisited every tick")
        events.append({"role": COMMANDER_NAME, "action": "default_schedule_applied",
                       "detail": "the cycle set no next step; applied 24h"})

    verdicts = [e["detail"] for e in session.audit_trail
                if e["action"] == "adjudicate"]
    return {
        "acted": True,
        "case_id": case["case_id"],
        "cycle": mission["cycles"],
        "planner": planner,
        "planner_error": error,
        "department": department,
        "fleet_log": events,
        "verdicts": verdicts,
        "narration": narration,
        "next_action": mission.get("next_action"),
        "escalation": mission.get("escalation"),
        "standing_down": mission.get("standing_down"),
        "memory": mem.verify_mission(mission),
    }


async def _run_commander_turn(session: PurpleTeamSession, case: dict,
                              mission: dict, *, department: str,
                              log_sink: list, model=None) -> str:
    from google.adk.runners import InMemoryRunner
    from google.genai import types

    commander = build_commander(session, case, mission, department=department,
                                log_sink=log_sink, model=model)
    app_name = "vigia_fleet_commander"
    runner = InMemoryRunner(agent=commander, app_name=app_name)
    await runner.session_service.create_session(
        app_name=app_name, user_id="fleet", session_id=case["case_id"])
    prompt = (
        f"Autonomous cycle {mission['cycles']} on case {case['case_id']} "
        f"(host {case.get('host', {}).get('hostname', 'unknown')}). No human is "
        f"watching. Read the mission brief first, then work the case and leave "
        f"it with a decision about its future.")
    message = types.Content(role="user", parts=[types.Part(text=prompt)])
    narration = []
    async for event in runner.run_async(
            user_id="fleet", session_id=case["case_id"], new_message=message):
        if event.is_final_response() and event.content:
            for part in event.content.parts or []:
                if getattr(part, "text", None):
                    narration.append(part.text)
    return "".join(narration).strip()
