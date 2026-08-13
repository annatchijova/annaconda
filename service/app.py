"""FastAPI app for the VIGIA live purple-team backend.

Endpoints:
  GET  /health                     liveness + build/model info (Cloud Run probe)
  GET  /hunts                      the curated VQL hunts available
  POST /investigate                run an investigation, return sealed stream
  GET  /investigations/{id}        fetch a stored investigation
  GET  /investigations/{id}/stream the sealed verdict entries (dashboard reads this)

Investigation modes (POST /investigate body: {"mode": ...}):
  scripted : run the given hunt groups through the sealed loop, no LLM
             (deterministic, free — the replay/dashboard path)
  agent    : the ADK+Gemini agent drives the hunt and narrates

State is in-memory per instance: fine for a single-instance demo. Firestore is
the production upgrade for shared, durable state (noted in PLAN.md); it does
not touch the seal, only where the seal is stored.
"""

from __future__ import annotations

import os
import uuid
from pathlib import Path
from tempfile import mkdtemp
from typing import Any, Optional

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field

from agent.purple_team_agent import model_id
from agent.tools import PurpleTeamSession
from core.verdict_stream import verify_stream
from tools.velociraptor.adapter import MockTransport
from tools.velociraptor.vql_templates import TEMPLATES

REPO_ROOT = Path(__file__).resolve().parent.parent
STATIC_DIR = Path(__file__).resolve().parent / "static"
DEMO_EVIDENCE = Path(
    os.environ.get("VIGIA_DEMO_EVIDENCE",
                   str(REPO_ROOT / "tests" / "fixtures" / "velociraptor")))

app = FastAPI(
    title="VIGIA — Live Purple Team",
    description="Deterministic DFIR engine with sealed verdicts, driven by an "
                "ADK+Gemini agent that guides but never decides.",
    version="0.1.0",
)

# In-memory investigation store: {investigation_id: {...}}.
_STORE: dict[str, dict] = {}


def _transport():
    """Demo transport. Live Velociraptor (RestTransport) is swapped in via env
    once a lab endpoint exists; until then the service runs on bundled demo
    evidence, deterministically."""
    return MockTransport(DEMO_EVIDENCE)


def _new_session(case_id: str, examiner_id: str) -> PurpleTeamSession:
    return PurpleTeamSession(
        _transport(),
        case_id=case_id,
        host={"client_id": "C.demo01", "hostname": "WIN11-VICTIM", "os": "windows"},
        examiner_id=examiner_id,
        out_dir=Path(mkdtemp(prefix="vigia-inv-")),
        source="replay",
        time_base="2026-08-12T14:00:00Z",
    )


# ---------------------------------------------------------------------------
# models
# ---------------------------------------------------------------------------

class InvestigateRequest(BaseModel):
    case_id: str = Field(..., pattern=r"^[A-Za-z0-9._-]{1,128}$")
    examiner_id: str = Field(..., min_length=1, max_length=128)
    mode: str = Field("scripted", pattern=r"^(scripted|agent)$")
    # scripted mode: list of hunt groups, one sealed window per group.
    hunt_groups: Optional[list[list[str]]] = None
    # agent mode: natural-language instruction for the ADK agent.
    prompt: Optional[str] = None


# ---------------------------------------------------------------------------
# routes
# ---------------------------------------------------------------------------

@app.get("/", include_in_schema=False)
def home() -> FileResponse:
    """Landing page — what VIGIA is, how it works, and how to use it."""
    return FileResponse(STATIC_DIR / "home.html")


@app.get("/exhibit", include_in_schema=False)
def dashboard() -> FileResponse:
    """The court-exhibit dashboard — run a live sealed investigation."""
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/consult", include_in_schema=False)
def consult_page() -> FileResponse:
    """The mentor console — a junior examiner consults the advisory agent here."""
    return FileResponse(STATIC_DIR / "consult.html")


@app.get("/health")
def health() -> dict:
    return {
        "status": "ok",
        "service": "vigia-live-purple-team",
        "version": app.version,
        "model": model_id(),
        "vertex_ai": os.environ.get("GOOGLE_GENAI_USE_VERTEXAI", "").upper() == "TRUE",
        "sealed_verdicts": True,
        "llm_in_decision_path": False,
    }


@app.get("/hunts")
def hunts() -> dict:
    return {
        "hunts": {
            tid: {"collects": t["description"], "evidence_type": t["evidence_type"]}
            for tid, t in sorted(TEMPLATES.items())
        }
    }


def _run_scripted(session: PurpleTeamSession, hunt_groups: list[list[str]]) -> dict:
    verdicts = []
    for group in hunt_groups:
        summary = session.run_hunt(group, reason="scripted investigation")
        if "error" in summary:
            raise HTTPException(status_code=400, detail=summary["error"])
        verdict = session.adjudicate(summary["window_id"])
        if "error" in verdict:
            raise HTTPException(status_code=400, detail=verdict["error"])
        verdicts.append(verdict)
    return {"verdicts": verdicts, "narration": None}


async def _run_agent(session: PurpleTeamSession, prompt: str) -> dict:
    from google.adk.runners import InMemoryRunner
    from google.genai import types
    from agent.purple_team_agent import build_agent

    agent = build_agent(session)
    runner = InMemoryRunner(agent=agent, app_name="vigia_purple_team")
    await runner.session_service.create_session(
        app_name="vigia_purple_team", user_id="perito", session_id="s")
    message = types.Content(role="user", parts=[types.Part(text=prompt)])
    narration = []
    async for event in runner.run_async(
            user_id="perito", session_id="s", new_message=message):
        if event.is_final_response() and event.content:
            for part in event.content.parts or []:
                if getattr(part, "text", None):
                    narration.append(part.text)
    verdicts = [e["detail"] for e in session.audit_trail if e["action"] == "adjudicate"]
    return {"verdicts": verdicts, "narration": "".join(narration).strip()}


@app.post("/investigate")
async def investigate(req: InvestigateRequest) -> dict:
    session = _new_session(req.case_id, req.examiner_id)

    if req.mode == "scripted":
        groups = req.hunt_groups or [["pslist", "netstat"], ["process_creation_evtx"]]
        result = _run_scripted(session, groups)
    else:
        if not req.prompt:
            raise HTTPException(status_code=400,
                                detail="agent mode requires a 'prompt'")
        result = await _run_agent(session, req.prompt)

    chain = session.verify_chain()
    entries = list(session._entries)  # sealed stream for this investigation
    inv_id = uuid.uuid4().hex[:12]
    record = {
        "investigation_id": inv_id,
        "case_id": req.case_id,
        "mode": req.mode,
        "verdicts": result["verdicts"],
        "narration": result["narration"],
        "chain": chain,
        "stream": entries,
        "audit_trail": session.audit_trail,
    }
    _STORE[inv_id] = record
    return record


@app.get("/investigations/{inv_id}")
def get_investigation(inv_id: str) -> dict:
    record = _STORE.get(inv_id)
    if record is None:
        raise HTTPException(status_code=404, detail="investigation not found")
    return record


# --- mentor consultation agent (a second ADK agent, multi-turn) -------------

CONSULT_APP = "vigia_mentor"
_consult_runner = None
_consult_sessions: set[str] = set()


def _get_consult_runner():
    """Lazy singleton ADK runner for the mentor agent, bound to the live
    investigation store so it can read real sealed cases."""
    global _consult_runner
    if _consult_runner is None:
        from google.adk.runners import InMemoryRunner
        from agent.consult_agent import build_consult_agent
        from agent.consult_tools import ConsultTools
        agent = build_consult_agent(ConsultTools(store=_STORE))
        _consult_runner = InMemoryRunner(agent=agent, app_name=CONSULT_APP)
    return _consult_runner


class ConsultRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=4000)
    session_id: Optional[str] = None


@app.post("/consult")
async def consult(req: ConsultRequest) -> dict:
    """One turn with the mentor agent. Pass the returned session_id back on the
    next call to keep the conversation (the junior examiner's follow-ups)."""
    from google.genai import types
    runner = _get_consult_runner()
    sid = req.session_id or uuid.uuid4().hex[:12]
    if sid not in _consult_sessions:
        await runner.session_service.create_session(
            app_name=CONSULT_APP, user_id="perito", session_id=sid)
        _consult_sessions.add(sid)
    message = types.Content(role="user", parts=[types.Part(text=req.message)])
    answer = []
    async for event in runner.run_async(
            user_id="perito", session_id=sid, new_message=message):
        if event.is_final_response() and event.content:
            for part in event.content.parts or []:
                if getattr(part, "text", None):
                    answer.append(part.text)
    return {"session_id": sid, "answer": "".join(answer).strip()}


@app.get("/investigations/{inv_id}/stream")
def get_stream(inv_id: str) -> Any:
    record = _STORE.get(inv_id)
    if record is None:
        raise HTTPException(status_code=404, detail="investigation not found")
    # Re-verify on read so the caller never trusts an unchecked chain.
    report = verify_stream(record["stream"])
    return JSONResponse({"chain_ok": report["chain_ok"],
                         "entries": record["stream"]})
