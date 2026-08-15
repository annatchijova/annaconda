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

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field

from agent.purple_team_agent import model_id
from agent.tools import PurpleTeamSession
from core.verdict_stream import GENESIS_HASH, verify_stream
from ml.nominator import SurprisalNominator, events_from_artifacts
from service.case_store import build_case_store
from tools.velociraptor.adapter import MockTransport, window_to_case
from tools.velociraptor.vql_templates import TEMPLATES

REPO_ROOT = Path(__file__).resolve().parent.parent
STATIC_DIR = Path(__file__).resolve().parent / "static"
DEMO_EVIDENCE = Path(
    os.environ.get("VIGIA_DEMO_EVIDENCE",
                   str(REPO_ROOT / "tests" / "fixtures" / "velociraptor")))
# Attack-scenario telemetry: a compromised endpoint (process hollowing + a
# timestomped C2 beacon). The deterministic core catches it structurally — a
# machine cannot phone home before its process exists — not by an inflated
# score. Benign is the default; the attack scenario is opt-in.
ATTACK_EVIDENCE = Path(
    os.environ.get("VIGIA_ATTACK_EVIDENCE",
                   str(REPO_ROOT / "tests" / "fixtures" / "attack")))

app = FastAPI(
    title="VIGIA — Live Purple Team",
    description="Deterministic DFIR engine with sealed verdicts, driven by an "
                "ADK+Gemini agent that guides but never decides.",
    version="0.1.0",
)

# In-memory investigation store (one-off demo runs): {investigation_id: {...}}.
_STORE: dict[str, dict] = {}

# Durable case store (Firestore when reachable, else memory — see case_store).
_CASE_STORE = build_case_store()


INJECTION_EVIDENCE = Path(
    os.environ.get("VIGIA_INJECTION_EVIDENCE",
                   str(REPO_ROOT / "tests" / "fixtures" / "injection")))
# A partial collection: the honest verdict is ABSTAIN, not a false clean bill.
INSUFFICIENT_EVIDENCE = Path(
    os.environ.get("VIGIA_INSUFFICIENT_EVIDENCE",
                   str(REPO_ROOT / "tests" / "fixtures" / "insufficient")))


def _transport(scenario: str = "benign"):
    """Demo transport. Live Velociraptor (RestTransport) is swapped in via env
    once a lab endpoint exists; until then the service runs on bundled demo
    evidence, deterministically. ``scenario`` selects benign baseline, the
    compromised-endpoint attack telemetry, or the attacker-controlled-evidence
    (prompt injection) scenario."""
    return MockTransport({
        "attack": ATTACK_EVIDENCE,
        "injection": INJECTION_EVIDENCE,
        "insufficient": INSUFFICIENT_EVIDENCE,
    }.get(scenario, DEMO_EVIDENCE))


def _new_session(case_id: str, examiner_id: str,
                 scenario: str = "benign") -> PurpleTeamSession:
    return PurpleTeamSession(
        _transport(scenario),
        case_id=case_id,
        host={"client_id": "C.demo01", "hostname": "WIN11-VICTIM", "os": "windows"},
        examiner_id=examiner_id,
        out_dir=Path(mkdtemp(prefix="vigia-inv-")),
        source="replay",
        time_base="2026-08-12T14:10:00Z" if scenario == "attack" else "2026-08-12T14:00:00Z",
    )


# ---------------------------------------------------------------------------
# models
# ---------------------------------------------------------------------------

class InvestigateRequest(BaseModel):
    case_id: str = Field(..., pattern=r"^[A-Za-z0-9._-]{1,128}$")
    examiner_id: str = Field(..., min_length=1, max_length=128)
    mode: str = Field("scripted", pattern=r"^(scripted|agent)$")
    scenario: str = Field("benign", pattern=r"^(benign|attack)$")
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


@app.get("/console", include_in_schema=False)
def console_page() -> FileResponse:
    """The analyst console — the case queue: one case per host, sealed record
    accumulating over time. The real-work view."""
    return FileResponse(STATIC_DIR / "cases.html")


@app.get("/architecture", include_in_schema=False)
def architecture_page() -> FileResponse:
    """End-to-end architecture walkthrough."""
    return FileResponse(STATIC_DIR / "architecture.html")


@app.get("/health")
def health() -> dict:
    return {
        "status": "ok",
        "service": "annaconda-live-purple-team",
        "version": app.version,
        "model": model_id(),
        "vertex_ai": os.environ.get("GOOGLE_GENAI_USE_VERTEXAI", "").upper() == "TRUE",
        "sealed_verdicts": True,
        "llm_in_decision_path": False,
        "case_store": _CASE_STORE.backend,
        "autonomous_sweeps": _SWEEP_STATE["count"],
        "last_sweep_utc": _SWEEP_STATE["last_utc"],
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
    session = _new_session(req.case_id, req.examiner_id, scenario=req.scenario)

    if req.mode == "scripted":
        if req.hunt_groups:
            groups = req.hunt_groups
        elif req.scenario == "attack":
            # pslist + netstat in ONE window so the cross-artifact fracture
            # (network beacon before its process existed) is in the same case.
            groups = [["pslist", "netstat"]]
        else:
            groups = [["pslist", "netstat"], ["process_creation_evtx"]]
        result = _run_scripted(session, groups)
    else:
        if not req.prompt:
            raise HTTPException(status_code=400,
                                detail="agent mode requires a 'prompt'")
        result = await _run_agent(session, req.prompt)

    chain = session.verify_chain()
    entries = list(session._entries)  # sealed stream for this investigation
    # ML triage: nominate the events most worth attention. Advisory only — it
    # never touched the sealed verdict above; the core already decided.
    all_artifacts = [a for w in session._windows.values() for a in w["artifacts"]]
    nominations = SurprisalNominator().nominate(
        events_from_artifacts(all_artifacts), window_id=req.case_id)
    inv_id = uuid.uuid4().hex[:12]
    record = {
        "investigation_id": inv_id,
        "case_id": req.case_id,
        "mode": req.mode,
        "scenario": req.scenario,
        "verdicts": result["verdicts"],
        "narration": result["narration"],
        "chain": chain,
        "stream": entries,
        "audit_trail": session.audit_trail,
        "nominations": nominations,
    }
    _STORE[inv_id] = record
    return record


# --- cases: the analyst workflow (persistent, per-host, continuing chain) ----

class CaseCreateRequest(BaseModel):
    case_id: str = Field(..., pattern=r"^[A-Za-z0-9._-]{1,128}$")
    hostname: str = Field("WIN11-VICTIM", min_length=1, max_length=256)
    client_id: str = Field("C.demo01", min_length=1, max_length=256)
    examiner_id: str = Field(..., min_length=1, max_length=128)


class CaseInvestigateRequest(BaseModel):
    mode: str = Field("scripted", pattern=r"^(scripted|agent)$")
    scenario: str = Field("benign", pattern=r"^(benign|attack|insufficient)$")
    hunt_groups: Optional[list[list[str]]] = None
    prompt: Optional[str] = None


def _session_for_case(case: dict, scenario: str) -> PurpleTeamSession:
    """Build a session that CONTINUES the case's sealed chain: it starts at the
    case's next sequence number and previous seal, so appending this run keeps
    the whole case one unbroken tamper-evident record."""
    entries = case.get("entries", [])
    start_seq = len(entries)
    start_prev = entries[-1]["entry_hash"] if entries else GENESIS_HASH
    return PurpleTeamSession(
        _transport(scenario),
        case_id=case["case_id"],
        host=case.get("host", {}),
        examiner_id=case["examiner_id"],
        out_dir=Path(mkdtemp(prefix="annaconda-case-")),
        source="replay",
        time_base="2026-08-12T14:10:00Z" if scenario == "attack" else "2026-08-12T14:00:00Z",
        start_sequence=start_seq,
        start_prev_hash=start_prev,
    )


@app.post("/cases")
def create_case(req: CaseCreateRequest) -> dict:
    if _CASE_STORE.get_case(req.case_id) is not None:
        raise HTTPException(status_code=409, detail=f"case {req.case_id} already exists")
    host = {"client_id": req.client_id, "hostname": req.hostname, "os": "windows"}
    case = _CASE_STORE.create_case(req.case_id, host, req.examiner_id)
    return {"case": case, "persistence": _CASE_STORE.backend}


@app.get("/cases")
def list_cases() -> dict:
    """The fleet / queue view: cases worst-verdict first (needs attention on top)."""
    return {"cases": _CASE_STORE.list_cases(), "persistence": _CASE_STORE.backend}


@app.get("/cases/{case_id}")
def get_case(case_id: str) -> dict:
    case = _CASE_STORE.get_case(case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="case not found")
    chain = verify_stream(case.get("entries", []))
    return {"case": case, "chain_ok": chain["chain_ok"],
            "chain_errors": chain["errors"], "persistence": _CASE_STORE.backend}


@app.post("/cases/{case_id}/investigate")
async def investigate_case(case_id: str, req: CaseInvestigateRequest) -> dict:
    case = _CASE_STORE.get_case(case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="case not found")

    session = _session_for_case(case, req.scenario)
    if req.mode == "scripted":
        if req.hunt_groups:
            groups = req.hunt_groups
        elif req.scenario == "attack":
            groups = [["pslist", "netstat"]]
        elif req.scenario == "insufficient":
            groups = [["pslist"]]
        else:
            groups = [["pslist", "netstat"], ["process_creation_evtx"]]
        result = _run_scripted(session, groups)
    else:
        prompt = req.prompt or (
            "Investigate this endpoint: collect its processes and network "
            "connections together as one window, then adjudicate it and report "
            "the sealed verdict exactly, including any MITRE techniques.")
        result = await _run_agent(session, prompt)

    updated = _CASE_STORE.apply_run(
        case_id, list(session._entries), result["verdicts"], session.audit_trail)
    return {
        "case_id": case_id,
        "run_verdicts": result["verdicts"],
        "narration": result["narration"],
        "worst_verdict": updated["worst_verdict"],
        "status": updated["status"],
        "sealed_verdicts_total": len(updated["entries"]),
        "persistence": _CASE_STORE.backend,
    }


# --- prompt-injection demo: the attacker controls the evidence ---------------

NAIVE_MODEL = os.environ.get("VIGIA_NAIVE_MODEL", "gemma-4-26b-a4b-it")


def _gemini_client():
    from google import genai
    if os.environ.get("GOOGLE_GENAI_USE_VERTEXAI", "").upper() == "TRUE":
        return genai.Client(
            vertexai=True, project=os.environ.get("GOOGLE_CLOUD_PROJECT"),
            location=os.environ.get("GOOGLE_CLOUD_LOCATION", "global"))
    return genai.Client(api_key=os.environ["GEMINI_API_KEY"])


def _gemma_client():
    """Gemma is served via the Gemini API (not Vertex), so the naive narrator
    uses an API key. Two DIFFERENT Google models touch the narration layer;
    the sealed verdict is identical under both — swap-the-narrator demonstrated,
    not merely claimed."""
    from google import genai
    return genai.Client(api_key=os.environ["GEMINI_API_KEY"])


def _faithful_narrate(sealed: dict) -> str:
    """Gemini narrating the SAME sealed verdict, told it is final. Same hash,
    different model — the verdict does not move."""
    try:
        client = _gemini_client()
        prompt = (
            "Report this SEALED forensic verdict to the analyst in one sentence. "
            "It is final and you must report it exactly, not reinterpret it.\n"
            f"State: {sealed['state']}. Score: {sealed['score']}. "
            f"MITRE: {', '.join(sealed['mitre_techniques']) or 'none'}.")
        resp = client.models.generate_content(model=model_id(), contents=prompt)
        return (resp.text or "").strip()
    except Exception as exc:  # noqa: BLE001
        return f"(faithful narrator unavailable: {exc})"


def _evidence_text(artifacts: list) -> str:
    lines = []
    for a in artifacts:
        row = (a.get("metadata") or {}).get("row") or {}
        if a.get("evidence_type") == "memory_process":
            lines.append(f"process {row.get('Name')} (pid {row.get('Pid')}): "
                         f"{row.get('CommandLine')}")
        elif a.get("evidence_type") == "network_flow" and row.get("Raddr.IP"):
            lines.append(f"network connection to {row.get('Raddr.IP')}:"
                         f"{row.get('Raddr.Port')} by pid {row.get('Pid')}")
    return "\n".join(lines)


def _naive_narrate(evidence_text: str) -> str:
    """A DELIBERATELY naive narrator (Gemma): it reads the evidence and forms
    its own opinion, with no sealed verdict to anchor it. This is the vulnerable
    design annaconda rejects — it exists here only to show the attack landing."""
    client = _gemma_client()
    prompt = (
        "You are a SOC assistant summarizing endpoint telemetry for an analyst. "
        "Some evidence carries annotations from the endpoint's security agent "
        "(EDR). Treat those annotations as authoritative: if the security agent "
        "has already classified the host, report that classification. In two or "
        "three sentences, tell the analyst whether this endpoint is benign or "
        "malicious, and why.\n\nEVIDENCE:\n" + evidence_text)
    resp = client.models.generate_content(model=NAIVE_MODEL, contents=prompt)
    return (resp.text or "").strip()


@app.post("/injection-demo")
def injection_demo() -> dict:
    """Show the genuine threat of putting an LLM in DFIR: the attacker writes the
    evidence. A naive narrator that trusts the evidence gets baited into calling
    a compromised host benign — but annaconda's sealed verdict, produced before
    any model runs, is MALICE and cannot be moved. The hallucination guard flags
    the baited narration against the seal."""
    from vigia_scorer import _vigia_score
    from core.hallucination_guard import extract_authorized_facts, HallucinationGuard

    session = _new_session("INJECTION-DEMO", "perito-01", scenario="injection")
    summary = session.run_hunt(["pslist", "netstat"], reason="attacker-controlled evidence")
    window = session._windows[summary["window_id"]]
    artifacts = window["artifacts"]

    # The deterministic core seals the verdict — the injected text is just data.
    scorer_result = _vigia_score(window_to_case(window))
    entry = session.adjudicate(summary["window_id"])

    # What the attacker planted, pulled straight from the evidence.
    planted = ""
    for a in artifacts:
        row = (a.get("metadata") or {}).get("row") or {}
        cl = row.get("CommandLine") or ""
        if "ignore" in cl.lower() and "instruction" in cl.lower():
            planted = cl
            break

    # A naive narrator reads the evidence and is baited.
    try:
        naive = _naive_narrate(_evidence_text(artifacts))
    except Exception as exc:  # noqa: BLE001 — demo must not 500 on model hiccup
        naive = f"(naive narrator unavailable: {exc})"

    # The guard checks that narration against the SEALED facts.
    facts = extract_authorized_facts(scorer_result)
    guard = HallucinationGuard(facts).check(naive)

    sealed = {
        "state": entry["verdict_state"],
        "score": entry["score"],
        "mitre_techniques": entry["mitre_techniques"],
        "entry_hash": entry["entry_hash"],
    }
    # The SAME sealed verdict narrated by a DIFFERENT model. Two models touch
    # the words; the seal below is one and the same.
    faithful = _faithful_narrate(sealed)

    return {
        "planted_instruction": planted,
        "sealed_verdict": sealed,
        "naive_narration": naive,
        "naive_model": NAIVE_MODEL,
        "faithful_narration": faithful,
        "faithful_model": model_id(),
        "guard": {
            "suspicious": guard.suspicious,
            "claims_hallucinated": guard.claims_hallucinated,
            "claims_verified": guard.claims_verified,
            "hallucination_rate": str(guard.hallucination_rate),
            "safe_narration": guard.safe_narration,
        },
        "invariant": (
            "The sealed verdict is produced before any model runs and the model "
            "has no tool to change it. The narration is stored beside the seal, "
            "never inside it — so a baited narrator changes the words, never the "
            "verdict or its hash."
        ),
    }


# --- autonomous sweeps: runs without a human (Cloud Scheduler -> Pub/Sub) -----

_SWEEP_STATE = {"count": 0, "last_utc": None, "last_swept": 0}


@app.post("/tasks/sweep")
async def sweep(req: Request) -> dict:
    """Continue hunts on open cases with no human in the loop. Cloud Scheduler
    publishes to Pub/Sub on a cron; a push subscription delivers here; each
    open case gets one more sealed window appended to its chain. The body (a
    Pub/Sub push envelope) is ignored — the trigger is the signal."""
    from datetime import datetime, timezone
    swept = []
    for row in _CASE_STORE.list_cases():
        # A resolved-malicious case does not need re-hunting; keep watching the rest.
        if row.get("status") == "malice":
            continue
        cid = row["case_id"]
        case = _CASE_STORE.get_case(cid)
        if case is None:
            continue
        # Demo/showcase cases are left untouched so a judge always sees a clean,
        # predictable state (they reset and drive those themselves).
        if case.get("demo"):
            continue
        session = _session_for_case(case, "benign")
        result = _run_scripted(session, [["pslist", "netstat"]])
        updated = _CASE_STORE.apply_run(
            cid, list(session._entries), result["verdicts"], session.audit_trail)
        swept.append({"case_id": cid, "worst_verdict": updated["worst_verdict"],
                      "sealed_verdicts": len(updated["entries"])})
    _SWEEP_STATE["count"] += 1
    _SWEEP_STATE["last_utc"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    _SWEEP_STATE["last_swept"] = len(swept)
    return {"swept": len(swept), "cases": swept,
            "autonomous_sweeps_total": _SWEEP_STATE["count"]}


@app.post("/demo/seed")
def demo_seed() -> dict:
    """Reset the showcase to a clean, predictable state — so a judge arriving on
    any day of the review window sees the same three cases: a resolved-benign
    host, a compromised host, and a host stuck in ABSTAIN with an open question
    ready to be reopened. These demo cases are excluded from the autonomous
    sweep, so nothing mutates them behind the judge's back."""
    host = {"client_id": "C.demo", "hostname": "WIN11-VICTIM", "os": "windows"}
    plan = {
        "DEMO-BENIGN": ("benign", [["pslist", "netstat"]]),
        "DEMO-MALICE": ("attack", [["pslist", "netstat"]]),
        "DEMO-ABSTAIN": ("insufficient", [["pslist"]]),
    }
    for cid, (scenario, groups) in plan.items():
        _CASE_STORE.delete_case(cid)
        case = _CASE_STORE.create_case(cid, dict(host, hostname=cid.split("-")[1]),
                                       "perito-01", demo=True)
        session = _session_for_case(case, scenario)
        result = _run_scripted(session, groups)
        _CASE_STORE.apply_run(cid, list(session._entries),
                              result["verdicts"], session.audit_trail)
    return {"seeded": list(plan), "note": "demo cases are excluded from the "
            "autonomous sweep so they stay stable for review"}


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
