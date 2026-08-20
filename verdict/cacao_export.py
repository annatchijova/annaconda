"""Deterministic CACAO 2.0 export of an autonomous investigation.

annaconda's fleet keeps a tamper-evident *mission journal*: an ordered, hash-
chained record of every decision it made on a case (begin a cycle, form a
hypothesis, collect a sealed window, open or settle a line of inquiry, schedule
the next look, escalate, stand down). This module projects that sealed journal
into an OASIS **CACAO 2.0** playbook, so what the fleet did and why becomes a
portable, machine-readable artifact a SOAR platform or Google SecOps can consume.

Like the STIX export, this is *output of an already-sealed record*, never an
input to one:

- No model in the path. Each workflow step is one sealed journal entry; the step
  order is the journal order; adjudication steps reference the sealed verdict they
  produced. A step *records* a sealed decision — it never re-decides.
- Deterministic. Step and playbook ids are ``uuid5`` over the seals; every
  timestamp comes from the sealed record, never a clock. Re-exporting the same
  stored case is byte-for-byte identical.
- The seals are referenced, not recomputed, so a consumer can independently
  re-verify the journal and the verdict chain against the playbook.
"""
from __future__ import annotations

import uuid

_NS = uuid.uuid5(uuid.NAMESPACE_URL, "https://annaconda.dev/cacao")


def _id(kind: str, seed: str) -> str:
    return f"{kind}--{uuid.uuid5(_NS, kind + ':' + seed)}"


# Journal action -> a human-readable CACAO step name.
_ACTION_NAME = {
    "begin_cycle": "Begin autonomous cycle",
    "add_hypothesis": "Form a hypothesis",
    "update_hypothesis": "Update a hypothesis",
    "record_collection": "Collect a sealed evidence window",
    "note_open_question": "Open a line of inquiry",
    "resolve_open_question": "Settle a line of inquiry",
    "schedule_next_action": "Schedule the next cycle",
    "escalate_to_human": "Escalate to a human analyst",
    "acknowledge_escalation": "Human acknowledged the escalation",
    "stand_down": "Stand down",
}


def _command(action: str, detail: dict) -> str:
    """A concise manual-command string describing what the step recorded."""
    if action == "record_collection":
        hunts = ", ".join(detail.get("hunts") or []) or "hunts"
        return f"Collected {hunts}; froze and sealed one evidence window."
    if action == "escalate_to_human":
        return f"Escalated to a human: {detail.get('reason', 'analyst attention required')}."
    if action in ("add_hypothesis", "update_hypothesis"):
        return f"Recorded hypothesis: {detail.get('statement', detail.get('label', 'reasoning step'))}."
    if action == "schedule_next_action":
        return f"Scheduled the next cycle: {detail.get('reason', 'continue monitoring')}."
    if action == "stand_down":
        return f"Stood down: {detail.get('reason', 'no further action')}."
    return _ACTION_NAME.get(action, action)


def case_to_cacao(case: dict, *, mission_ok: bool | None = None,
                  chain_ok: bool | None = None) -> dict:
    """Map a sealed case (with its mission journal) to a CACAO 2.0 playbook.

    Pure and deterministic; does not touch the seal path."""
    case_id = case["case_id"]
    host = case.get("host") or {}
    created = case.get("created_utc")
    modified = case.get("updated_utc") or created
    mission = case.get("mission") or {}
    journal = mission.get("journal") or []
    entries = case.get("entries") or []

    # Index the sealed verdicts so a collection step can reference the verdict it
    # produced (by the window id the journal recorded). Never recomputed.
    verdicts = []
    by_window_id = {}
    for e in entries:
        v = e.get("verdict", {})
        seq = e.get("sequence")
        rec = {
            "sequence": seq,
            "state": v.get("state"),
            "score": v.get("score"),
            "confidence": v.get("confidence"),
            "mitre_techniques": v.get("mitre_techniques") or [],
            "entry_hash": e.get("entry_hash"),
            "window_hash": e.get("window_hash"),
        }
        verdicts.append(rec)
        if isinstance(seq, int):
            by_window_id[f"{case_id}-w{seq:06d}"] = rec

    author_id = _id("organization", "annaconda-fleet")
    start_id = _id("start", case_id)
    end_id = _id("end", case_id)
    step_ids = [_id("action", f"{case_id}:{en.get('seq')}:{en.get('entry_hash', '')}")
                for en in journal]

    workflow: dict = {
        start_id: {"type": "start",
                   "on_completion": step_ids[0] if step_ids else end_id},
    }
    for i, en in enumerate(journal):
        action = en.get("action", "")
        detail = en.get("detail") or {}
        step = {
            "type": "action",
            "name": f"{_ACTION_NAME.get(action, action)} (cycle {en.get('cycle')})",
            "description": _command(action, detail),
            "on_completion": step_ids[i + 1] if i + 1 < len(step_ids) else end_id,
            "commands": [{"type": "manual", "command": _command(action, detail)}],
            "agent": author_id,
            # annaconda extensions: reference the seals so the playbook is
            # self-verifying against the journal and the verdict chain.
            "x_annaconda_actor": en.get("actor"),
            "x_annaconda_cycle": en.get("cycle"),
            "x_annaconda_recorded_utc": en.get("recorded_utc"),
            "x_annaconda_journal_seal": en.get("entry_hash"),
        }
        window_id = detail.get("window_id")
        if window_id and window_id in by_window_id:
            rec = by_window_id[window_id]
            step["x_annaconda_sealed_verdict"] = {
                "state": rec["state"], "entry_hash": rec["entry_hash"],
                "window_hash": rec["window_hash"]}
        if action == "escalate_to_human" and detail.get("sealed_basis"):
            step["x_annaconda_sealed_basis"] = detail["sealed_basis"]
        workflow[step_ids[i]] = step

    workflow[end_id] = {"type": "end"}

    return {
        "type": "playbook",
        "spec_version": "cacao-2.0",
        "id": _id("playbook", f"{case_id}:{modified or ''}"),
        "name": f"annaconda autonomous investigation — {case_id}",
        "description": (
            "A record of what annaconda's autonomous fleet did on this case and "
            "why, as an OASIS CACAO 2.0 playbook. Each step is a sealed mission-"
            "journal entry, in order; collection steps reference the sealed "
            "verdict they produced. This is a projection of the sealed record: "
            "the fleet's decisions are the seals, not this narrative."),
        "playbook_types": ["investigation"],
        "created_by": author_id,
        "created": created,
        "modified": modified,
        "revoked": False,
        "workflow_start": start_id,
        "workflow": workflow,
        "agent_definitions": {
            author_id: {
                "type": "organization",
                "name": "annaconda autonomous fleet",
                "description": f"annaconda purple-team fleet operating case {case_id}"},
        },
        # Everything below is referenced from the seal, never recomputed.
        "x_annaconda_target_host": {
            "client_id": host.get("client_id"), "hostname": host.get("hostname"),
            "os": host.get("os")},
        "x_annaconda_sealed_verdicts": verdicts,
        "x_annaconda_worst_verdict": case.get("worst_verdict"),
        "x_annaconda_memory_verified": mission_ok,
        "x_annaconda_chain_verified": chain_ok,
    }
