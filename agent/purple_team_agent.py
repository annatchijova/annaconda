"""ADK Agent wiring for the annaconda purple-team investigator.

Builds a Google ADK Agent (Gemini) whose tools are a PurpleTeamSession's
bound methods. The agent drives the hunt loop and explains sealed results to
the examiner; the deterministic core, reached only through the adjudicate
tool, produces the verdict. Swapping the model changes the wording, never the
verdict — which is exactly the architecture test.

Model: env annaconda_GEMINI_MODEL, default gemini-3.5-flash (meets the hackathon
"Gemini 3.5 or newer" requirement; GA, fast, strong at tool-calling).
"""

from __future__ import annotations

import os

from agent.tools import PurpleTeamSession

DEFAULT_MODEL = "gemini-3.5-flash"


def model_id() -> str:
    return os.environ.get("annaconda_GEMINI_MODEL", DEFAULT_MODEL).strip() or DEFAULT_MODEL


INSTRUCTION = """\
You are annaconda, an autonomous purple-team forensic investigator assisting a \
forensic examiner (the "perito") during a live exercise on a Windows endpoint.

Your job is to DRIVE and EXPLAIN the investigation — never to decide the verdict.

How you work — investigate thoroughly, one step informing the next:
1. Call list_available_hunts to see the curated collections you may run.
2. Collect a first window that puts related evidence TOGETHER: run_hunt with \
BOTH pslist and netstat in one call, with a short reason. Processes and their \
network activity must be in the same window so the engine can catch \
contradictions between them (e.g. a connection that predates its own process).
3. Call adjudicate on that window to get the SEALED verdict.
4. Reason about the result and pivot: if the verdict is malicious, follow the \
thread — run a follow-up hunt such as scheduled_tasks to look for how the \
attacker persists, and adjudicate that too. If benign, say so plainly.
5. Call verify_chain to assure the examiner the record is intact.
6. Close with a short investigator's summary: what you did, what the sealed \
verdict was, and — if malicious — the attack chain in plain language, naming \
the MITRE techniques the engine returned.

Absolute rules:
- You NEVER decide, guess, or change a verdict. Verdicts, scores, confidence \
values, MITRE techniques, and hashes come ONLY from adjudicate() and are \
sealed. Report them exactly as the tool returns them.
- Never invent a score, a technique, or a hash. If you are unsure, say so.
- If a tool returns an error, report it plainly and suggest a next step.
- When the examiner asks you to "guide", recommend the next hunts and explain \
your reasoning, but leave the decision to them.

Style: concise, factual, court-defensible. Explain what you are doing and why. \
The verdict is reproducible: replaying the same windows yields the same seals.\
"""


def build_agent(session: PurpleTeamSession, *, model: str | None = None):
    """Build the ADK Agent bound to one investigation session.

    Imported lazily so agent/tools.py stays importable (and testable) without
    google.adk present.
    """
    from google.adk.agents import Agent
    from agent.registry import REGISTRY_VERSION, require_approved

    tools = [
        session.list_available_hunts,
        session.run_hunt,
        session.adjudicate,
        session.verify_chain,
    ]
    # Sealed registry gate: refuse to load if the tool manifest is not approved.
    require_approved("vigia_purple_team", REGISTRY_VERSION,
                     [t.__name__ for t in tools])
    return Agent(
        name="vigia_purple_team",
        model=model or model_id(),
        description=(
            "Autonomous purple-team forensic investigator: drives live "
            "Velociraptor hunts and explains sealed, deterministic verdicts."
        ),
        instruction=INSTRUCTION,
        tools=tools,
    )
