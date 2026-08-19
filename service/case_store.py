"""Case persistence for the analyst workflow.

A *case* is how a real examiner uses annaconda: verdicts for one host
accumulate over time into a single, tamper-evident record that can be
reopened, handed off, and defended later. Each investigation run appends its
sealed windows to the case's chain, continuing it — the whole case remains one
unbroken sealed record from its first window.

Two backends, with honest degradation:
- FirestoreCaseStore: durable, shared across instances (production).
- MemoryCaseStore: in-process fallback used when Firestore is unavailable.

The active backend is reported (health endpoint, UI) — the service never
pretends data is durable when it is not.
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from typing import Optional

from agent.mission import new_mission

log = logging.getLogger("annaconda.case_store")

# Worst-first ordering for the analyst queue: higher rank = needs attention.
_VERDICT_RANK = {
    "MALICE_HIGH": 7, "MALICE_MEDIUM": 6, "ESCALATE": 5,
    "ABSTAIN_CONTRADICTION": 4, "ABSTAIN_DEGRADED": 4, "ABSTAIN_INSUFFICIENT": 3,
    "BENIGN_MEDIUM": 2, "BENIGN_HIGH": 1,
}


def verdict_rank(state: Optional[str]) -> int:
    return _VERDICT_RANK.get(state or "", 0)


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _summarize(case: dict) -> dict:
    """The row an analyst scans in the fleet/queue view."""
    return {
        "case_id": case["case_id"],
        "host": case.get("host", {}),
        "examiner_id": case.get("examiner_id"),
        "status": case.get("status", "open"),
        "worst_verdict": case.get("worst_verdict"),
        "sealed_verdicts": len(case.get("entries", [])),
        "runs": case.get("runs", 0),
        "created_utc": case.get("created_utc"),
        "updated_utc": case.get("updated_utc"),
        # What the fleet is doing with this case, so the queue shows unattended
        # work in progress rather than just its last human-driven run.
        "autonomy": _autonomy_summary(case.get("mission")),
    }


def _autonomy_summary(mission) -> dict:
    """The fleet's state on one case, for the analyst queue."""
    if not isinstance(mission, dict):
        return {"cycles": 0, "next_due_utc": None, "escalated": False,
                "standing_down": False, "open_questions": 0}
    plan = mission.get("next_action") or {}
    return {
        "cycles": mission.get("cycles", 0),
        "next_due_utc": plan.get("due_utc"),
        "next_action": plan.get("action"),
        "escalated": mission.get("escalation") is not None,
        "standing_down": mission.get("standing_down") is not None,
        "open_questions": sum(1 for q in mission.get("open_questions", [])
                              if not q.get("resolved")),
    }


# What an ABSTAIN remembers: why it could not conclude, and what would resolve
# it. This is the case's working memory — not a chat log, but discarded ground
# and the missing evidence — so an autonomous re-hunt knows what to look for.
_ABSTAIN_MEMORY = {
    "ABSTAIN_INSUFFICIENT": (
        "The collection was incomplete — evidence was acquired but not fully "
        "extracted, so certifying the host clean would be a false bill of health.",
        "Re-collect once artifact extraction completes, and correlate processes "
        "with their network activity in one window.",
    ),
    "ABSTAIN_CONTRADICTION": (
        "The evidence contradicts itself; the abductive cycle could not settle.",
        "Gather independent corroborating evidence to break the contradiction.",
    ),
    "ABSTAIN_DEGRADED": (
        "Critical analyzers were disabled during analysis; the result is unreliable.",
        "Re-run the investigation with full analyzer integrity.",
    ),
}


def _update_open_question(case: dict, verdicts: list) -> None:
    """Turn ABSTAIN into memory and reentry. Opens a question when a run cannot
    conclude; resolves it when a later run reaches a definitive verdict."""
    states = [v.get("verdict_state", "") for v in verdicts]
    abstained = next((s for s in states if s.startswith("ABSTAIN")), None)
    concluded = next((s for s in states
                      if s.startswith("MALICE") or s.startswith("BENIGN")), None)
    q = case.get("open_question")

    if abstained and (q is None or q.get("resolved")):
        why, resolves = _ABSTAIN_MEMORY.get(
            abstained, ("Could not conclude.", "Collect more evidence."))
        case["open_question"] = {
            "state": abstained, "why": why, "what_would_resolve": resolves,
            "opened_at_run": case.get("runs", 0), "resolved": False,
            "resolved_at_run": None, "resolved_verdict": None,
        }
    elif concluded and q is not None and not q.get("resolved"):
        q["resolved"] = True
        q["resolved_at_run"] = case.get("runs", 0)
        q["resolved_verdict"] = concluded
        # Reflect the conclusion the reentry reached — but NEVER downgrade a case
        # that already has a worse verdict in its history. A case whose worst is
        # MALICE must never display "benign" just because a later partial
        # collection resolved cleanly (red-team finding, self-corrected).
        worst = case.get("worst_verdict") or ""
        if not (worst.startswith("MALICE") or worst == "ESCALATE"):
            case["status"] = "malice" if concluded.startswith("MALICE") else "benign"


def _apply_run(case: dict, entries: list, verdicts: list, audit: list) -> dict:
    """Append one investigation run's sealed output to the case, recompute the
    worst verdict and status. Pure dict update — the sealing already happened
    upstream; this only accumulates it."""
    case.setdefault("entries", []).extend(entries)
    case.setdefault("verdicts", []).extend(verdicts)
    case.setdefault("audit_trail", []).extend(audit)
    case["runs"] = case.get("runs", 0) + 1
    case["updated_utc"] = _now()

    worst = case.get("worst_verdict")
    for v in verdicts:
        st = v.get("verdict_state")
        if verdict_rank(st) > verdict_rank(worst):
            worst = st
    case["worst_verdict"] = worst
    # Status the analyst reads at a glance.
    if worst and worst.startswith("MALICE"):
        case["status"] = "malice"
    elif worst == "ESCALATE":
        case["status"] = "escalate"
    elif worst and worst.startswith("ABSTAIN"):
        case["status"] = "abstain"
    elif worst and worst.startswith("BENIGN"):
        case["status"] = "benign"
    else:
        case["status"] = "open"

    _update_open_question(case, verdicts)
    return case


class MemoryCaseStore:
    backend = "memory"

    def __init__(self):
        self._cases: dict[str, dict] = {}

    def create_case(self, case_id: str, host: dict, examiner_id: str,
                    demo: bool = False, scenario: str = "benign") -> dict:
        case = {
            "case_id": case_id, "host": host, "examiner_id": examiner_id,
            "created_utc": _now(), "updated_utc": _now(),
            "status": "open", "worst_verdict": None,
            "entries": [], "verdicts": [], "audit_trail": [], "runs": 0,
            "open_question": None, "demo": demo,
            # Which bundled telemetry this host reports, so an unattended cycle
            # replays the same host it replayed last time.
            "scenario": scenario,
            "mission": new_mission(case_id),
        }
        self._cases[case_id] = case
        return case

    def get_case(self, case_id: str) -> Optional[dict]:
        return self._cases.get(case_id)

    def delete_case(self, case_id: str) -> None:
        self._cases.pop(case_id, None)

    def list_cases(self) -> list[dict]:
        rows = [_summarize(c) for c in self._cases.values()]
        rows.sort(key=lambda r: (verdict_rank(r["worst_verdict"]),
                                 r["updated_utc"] or ""), reverse=True)
        return rows

    def apply_run(self, case_id: str, entries, verdicts, audit) -> dict:
        case = self._cases[case_id]
        _apply_run(case, entries, verdicts, audit)
        return case

    def save_mission(self, case_id: str, mission: dict) -> None:
        self._cases[case_id]["mission"] = mission


class FirestoreCaseStore:
    backend = "firestore"

    def __init__(self, project: str):
        from google.cloud import firestore  # lazy: only when actually used
        self._db = firestore.Client(project=project)
        self._col = self._db.collection("cases")
        # Fail fast at construction if we cannot reach Firestore, so the
        # factory can degrade to memory rather than crash on first request.
        next(iter(self._col.limit(1).stream()), None)

    def create_case(self, case_id: str, host: dict, examiner_id: str,
                    demo: bool = False, scenario: str = "benign") -> dict:
        case = {
            "case_id": case_id, "host": host, "examiner_id": examiner_id,
            "created_utc": _now(), "updated_utc": _now(),
            "status": "open", "worst_verdict": None,
            "entries": [], "verdicts": [], "audit_trail": [], "runs": 0,
            "open_question": None, "demo": demo,
            # Which bundled telemetry this host reports, so an unattended cycle
            # replays the same host it replayed last time.
            "scenario": scenario,
            "mission": new_mission(case_id),
        }
        self._col.document(case_id).set(case)
        return case

    def get_case(self, case_id: str) -> Optional[dict]:
        snap = self._col.document(case_id).get()
        return snap.to_dict() if snap.exists else None

    def delete_case(self, case_id: str) -> None:
        self._col.document(case_id).delete()

    def list_cases(self) -> list[dict]:
        rows = [_summarize(s.to_dict()) for s in self._col.stream()]
        rows.sort(key=lambda r: (verdict_rank(r["worst_verdict"]),
                                 r["updated_utc"] or ""), reverse=True)
        return rows

    def apply_run(self, case_id: str, entries, verdicts, audit) -> dict:
        case = self.get_case(case_id)
        if case is None:
            raise KeyError(case_id)
        _apply_run(case, entries, verdicts, audit)
        self._col.document(case_id).set(case)
        return case

    def save_mission(self, case_id: str, mission: dict) -> None:
        """Persist the fleet's working memory on its own, so an autonomous
        cycle's reasoning survives even when it appended no sealed verdict.
        Written after apply_run: that call re-reads the stored document, so
        writing the mission first would be overwritten by it."""
        self._col.document(case_id).update({"mission": mission})


def build_case_store():
    """Pick the durable backend when reachable, otherwise degrade to memory
    and say so (never silently lose durability)."""
    if os.environ.get("VIGIA_CASE_BACKEND", "").lower() == "memory":
        log.warning("case store: forced memory backend (VIGIA_CASE_BACKEND=memory)")
        return MemoryCaseStore()
    project = os.environ.get("GOOGLE_CLOUD_PROJECT")
    if not project:
        log.warning("case store: no GOOGLE_CLOUD_PROJECT — using memory backend")
        return MemoryCaseStore()
    try:
        store = FirestoreCaseStore(project)
        log.info("case store: Firestore backend active (project %s)", project)
        return store
    except Exception as exc:  # noqa: BLE001 — honest degradation, any failure
        log.warning("case store: Firestore unavailable (%s) — degrading to "
                    "memory; cases will not persist across restarts", exc)
        return MemoryCaseStore()
