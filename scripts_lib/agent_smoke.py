"""Live smoke test: drive the ADK+Gemini purple-team agent for one exercise.

Not part of the pytest suite — it needs GEMINI_API_KEY and a network call.
It proves the agent loop actually runs against real Gemini: the model picks
hunts, freezes sealed windows, adjudicates them through the deterministic
core, and narrates the sealed verdicts. Determinism of the underlying seals
is covered offline by the pytest suite; this checks the live agent wiring.

    GEMINI_API_KEY=... python3 scripts_lib/agent_smoke.py

Uses MockTransport + a fixed time base, so the FORENSIC result is
deterministic even though the model's wording is not.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from google.adk.runners import InMemoryRunner  # noqa: E402
from google.genai import types  # noqa: E402

from agent.purple_team_agent import build_agent, model_id  # noqa: E402
from agent.tools import PurpleTeamSession  # noqa: E402
from tools.velociraptor.adapter import MockTransport  # noqa: E402

APP = "vigia_purple_team"
FIXTURES = REPO_ROOT / "tests" / "fixtures" / "velociraptor"

PROMPT = (
    "Investigate this Windows endpoint. Run a baseline sweep of processes and "
    "network connections as one window, adjudicate it, then tell me the sealed "
    "verdict and whether the custody chain is intact. Be concise."
)


async def main() -> int:
    out_dir = REPO_ROOT / "scratch" / "agent_smoke_out"
    if (out_dir / "stream.jsonl").exists():
        (out_dir / "stream.jsonl").unlink()

    session = PurpleTeamSession(
        MockTransport(FIXTURES),
        case_id="SMOKE-001",
        host={"client_id": "C.mock01", "hostname": "WIN11-VICTIM", "os": "windows"},
        examiner_id="purple-op-01",
        out_dir=out_dir,
        source="replay",
        time_base="2026-08-12T14:00:00Z",
    )
    agent = build_agent(session)
    print(f"[smoke] model = {model_id()}")

    runner = InMemoryRunner(agent=agent, app_name=APP)
    await runner.session_service.create_session(
        app_name=APP, user_id="perito", session_id="s1")

    message = types.Content(role="user", parts=[types.Part(text=PROMPT)])
    tool_calls = []
    final_text = []
    async for event in runner.run_async(
            user_id="perito", session_id="s1", new_message=message):
        for part in (getattr(event.content, "parts", None) or []):
            fc = getattr(part, "function_call", None)
            if fc:
                tool_calls.append(fc.name)
        if event.is_final_response() and event.content:
            for part in event.content.parts or []:
                if getattr(part, "text", None):
                    final_text.append(part.text)

    print(f"[smoke] tools the agent called: {tool_calls}")
    print("[smoke] agent narration:\n")
    print("".join(final_text).strip() or "(no text returned)")
    print("\n[smoke] sealed stream on disk:")
    from core.verdict_stream import read_stream, verify_stream
    entries = read_stream(session.stream_path)
    report = verify_stream(entries)
    for e in entries:
        v = e["verdict"]
        print(f"  seq {e['sequence']}  {v['state']:<14} score={v['score']:<10} "
              f"entry={e['entry_hash'][:12]}")
    print(f"[smoke] chain_ok={report['chain_ok']} sealed_verdicts={report['entries']}")
    # The agent must have gone through the tools, not answered from thin air.
    ok = "run_hunt" in tool_calls and "adjudicate" in tool_calls and report["chain_ok"]
    print(f"\n[smoke] {'PASS' if ok else 'CHECK'} — "
          f"agent used the sealed tool path: {ok}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
