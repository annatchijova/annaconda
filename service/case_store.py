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
import threading
from datetime import datetime, timezone
from typing import Optional

from agent.mission import (
    load_mission, new_mission, note_open_question, resolve_open_question,
)
from core.verdict_stream import GENESIS_HASH
from service.chain_store import (
    ConcurrentModificationError, SegmentedChain, new_index,
)


def _check_continuation(case: dict, entries: list) -> None:
    """Reject a run whose sealed entries do not chain onto the case's current
    tail — the signature of a concurrent writer that advanced the chain after
    this run read it (red-team R3-2). Mirrors SegmentedChain.check for the
    in-memory backend, which stores its chain inline.

    Like SegmentedChain.check, a first run into an empty case is not checked
    (there is nothing to chain onto — the entry's own seq-0/GENESIS validity is
    the sealer's contract, not the store's). Otherwise the first new entry must
    be sequence-contiguous with the stored tail, and — when it declares one —
    chain onto the stored tail's hash.
    """
    if not entries:
        return
    existing = case.get("entries") or []
    if not existing:
        return
    tail = existing[-1]
    tail_seq = tail.get("sequence", len(existing) - 1)
    first = entries[0]
    if first.get("sequence") != tail_seq + 1:
        raise ConcurrentModificationError(
            f"run sequence {first.get('sequence')!r} is not contiguous with the "
            f"stored tail {tail_seq!r} — another writer advanced the sealed chain")
    prev = first.get("prev_entry_hash") or first.get("prev_hash")
    if prev and prev != tail.get("entry_hash"):
        raise ConcurrentModificationError(
            "run's first new entry does not chain onto the case's current tail — "
            "it was minted against state that has since been replaced")

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


def _chain_count(case: dict, field: str) -> int:
    """How many entries a chain holds, without loading it.

    A segmented case carries only an index in its document, so the queue view
    can be rendered from the case documents alone — listing every case must not
    read every case's whole history."""
    index = (case.get("chain_index") or {}).get(field)
    if isinstance(index, dict) and "count" in index:
        return int(index["count"])
    return len(case.get(field, []))


def _summarize(case: dict) -> dict:
    """The row an analyst scans in the fleet/queue view."""
    return {
        "case_id": case["case_id"],
        "host": case.get("host", {}),
        "examiner_id": case.get("examiner_id"),
        "status": case.get("status", "open"),
        "worst_verdict": case.get("worst_verdict"),
        "sealed_verdicts": _chain_count(case, "entries"),
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


def _mission_of(case: dict) -> dict:
    """The case's mission, attached (and migrated) if it is not there yet."""
    mission = load_mission(case)
    case["mission"] = mission
    return mission


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
        # The fleet reads mission memory, not this field: an ABSTAIN that only
        # existed here would be invisible to the next autonomous cycle, which
        # would then re-collect blind instead of pursuing the missing evidence.
        note_open_question(_mission_of(case), actor="adjudication",
                           question=f"{abstained}: {why}",
                           what_would_resolve=resolves)
    elif concluded and q is not None and not q.get("resolved"):
        q["resolved"] = True
        q["resolved_at_run"] = case.get("runs", 0)
        q["resolved_verdict"] = concluded
        mission = _mission_of(case)
        for mq in mission.get("open_questions", []):
            if not mq.get("resolved") and mq["question"].startswith(q["state"]):
                resolve_open_question(
                    mission, actor="adjudication", question_id=mq["id"],
                    how=f"a later run reached {concluded}")
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
        # Serialize writes to the same case: two concurrent runs must not both
        # extend one sealed chain, which would break it permanently (R3-2). The
        # lock makes each write atomic; _check_continuation rejects the loser.
        self._lock = threading.Lock()

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
        with self._lock:
            case = self._cases[case_id]
            _check_continuation(case, entries)
            _apply_run(case, entries, verdicts, audit)
            return case

    def save_mission(self, case_id: str, mission: dict) -> None:
        with self._lock:
            self._cases[case_id]["mission"] = mission

    def apply_cycle(self, case_id: str, entries, verdicts, audit,
                    mission: dict) -> dict:
        with self._lock:
            case = self._cases[case_id]
            # Mission is attached BEFORE the run so _apply_run mutates the same
            # mission object the cycle reasoned into (one object, one chain).
            case["mission"] = mission
            if verdicts:
                _check_continuation(case, entries)
                _apply_run(case, entries, verdicts, audit)
            else:
                case["updated_utc"] = _now()
            return case


# The four lists that grow without bound on a long-running case. They are
# stored in bounded segment documents (service/chain_store.py) rather than
# inside the case document, which would meet Firestore's 1 MiB limit after
# roughly 270 cycles — about eleven days on a host re-checked hourly.
# "journal" lives inside the mission; the rest are top level.
_CHAINED = ("entries", "verdicts", "audit_trail", "journal")


def _split_chains(case: dict) -> tuple:
    """Separate a whole case into (document, chains-by-field).

    The document is what goes in cases/{id}; the chains are appended to their
    segments. The case dict itself is not modified — callers keep working with
    the assembled view.
    """
    doc = dict(case)
    mission = dict(doc.get("mission") or {})
    chains = {
        "entries": list(doc.get("entries", [])),
        "verdicts": list(doc.get("verdicts", [])),
        "audit_trail": list(doc.get("audit_trail", [])),
        "journal": list(mission.get("journal", [])),
    }
    for field in ("entries", "verdicts", "audit_trail"):
        doc[field] = []
    mission["journal"] = []
    doc["mission"] = mission
    return doc, chains


class FirestoreCaseStore:
    backend = "firestore"

    def __init__(self, project: str):
        from google.cloud import firestore  # lazy: only when actually used
        self._db = firestore.Client(project=project)
        self._col = self._db.collection("cases")
        # Fail fast at construction if we cannot reach Firestore, so the
        # factory can degrade to memory rather than crash on first request.
        next(iter(self._col.limit(1).stream()), None)

    # -- segment plumbing --------------------------------------------------

    def _segments(self, case_id: str, transaction=None):
        """A minimal document-collection view over this case's segments.

        When a Firestore ``transaction`` is supplied, reads and writes join it,
        so a segment write and the case-document commit land atomically (R3-1).
        Without one (the direct path, and the test double), it behaves exactly
        as before.
        """
        col = self._col.document(case_id).collection("chain")

        class _Collection:
            @staticmethod
            def read(doc_id):
                ref = col.document(doc_id)
                snap = ref.get(transaction=transaction) if transaction else ref.get()
                return snap.to_dict() if snap.exists else None

            @staticmethod
            def write(doc_id, data):
                ref = col.document(doc_id)
                if transaction is not None:
                    transaction.set(ref, data)
                else:
                    ref.set(data)

            @staticmethod
            def ids():
                return [d.id for d in col.list_documents()]

            @staticmethod
            def delete(doc_id):
                col.document(doc_id).delete()

        return _Collection

    def _append_chains(self, case_id: str, index: dict, chains: dict,
                       transaction=None) -> dict:
        """Append each chain's NEW entries and return the updated index."""
        collection = self._segments(case_id, transaction=transaction)
        updated = dict(index or {})
        # Check every chain BEFORE writing any of them. A divergence found half
        # way through would leave segments written that no index references —
        # one logical operation must not land in pieces.
        for field in _CHAINED:
            SegmentedChain(collection, field).check(
                updated.get(field) or new_index(), chains.get(field, []))
        for field in _CHAINED:
            updated[field] = SegmentedChain(collection, field).append_from(
                updated.get(field) or new_index(), chains.get(field, []))
        return updated

    def _assemble(self, case: dict) -> dict:
        """Put the segmented chains back, so every caller and every verifier
        sees one unbroken history exactly as before segmentation.

        A field with no index has never been segmented — which is exactly the
        shape of every case written before segmentation existed, with its
        chains still inline in the document. Reading those from segments would
        return nothing and *replace* the real history with an empty list, so a
        deploy would erase the sealed chain of every case already in the
        database. A field without an index is therefore left exactly as stored,
        and the next write migrates it into segments.
        """
        collection = self._segments(case["case_id"])
        index = case.get("chain_index") or {}
        for field in ("entries", "verdicts", "audit_trail"):
            if field in index:
                case[field] = SegmentedChain(collection, field).read_all(
                    index[field])
        mission = case.get("mission")
        if isinstance(mission, dict) and "journal" in index:
            mission["journal"] = SegmentedChain(collection, "journal").read_all(
                index["journal"])
        return case

    def _persist(self, case: dict) -> None:
        doc, chains = _split_chains(case)
        case_ref = self._col.document(case["case_id"])

        # Concurrency (R3-1): the segment writes and the case-document commit
        # must land atomically, and the append must be checked against the
        # CURRENT stored index — not the (possibly stale) one this run read — so
        # a second writer that advanced the chain in between is rejected rather
        # than silently overwriting a sealed run. A backend without transactions
        # (the test double) takes the direct path: the same check runs, but with
        # no concurrency guarantee (the doubles never exercise two writers).
        if getattr(self._db, "transaction", None) is None:
            doc["chain_index"] = self._append_chains(
                case["case_id"], case.get("chain_index") or {}, chains)
            case_ref.set(doc)
            case["chain_index"] = doc["chain_index"]
            return

        from google.cloud import firestore  # lazy

        @firestore.transactional
        def _commit(transaction) -> dict:
            # Re-read the committed index INSIDE the transaction. All reads must
            # precede all writes in a Firestore transaction; _append_chains only
            # writes, so this ordering holds.
            snap = case_ref.get(transaction=transaction)
            current_index = ((snap.to_dict() or {}).get("chain_index") or {}
                             if snap.exists else {})
            # _append_chains runs SegmentedChain.check against current_index: if
            # another writer advanced the chain, the run's entries no longer
            # chain onto the stored head and check raises ConcurrentModificationError.
            new_index = self._append_chains(
                case["case_id"], current_index, chains, transaction=transaction)
            payload = dict(doc, chain_index=new_index)
            transaction.set(case_ref, payload)
            return new_index

        case["chain_index"] = _commit(self._db.transaction())

    # -- store interface ---------------------------------------------------

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
            "chain_index": {},
        }
        self._persist(case)
        return case

    def get_case(self, case_id: str) -> Optional[dict]:
        snap = self._col.document(case_id).get()
        if not snap.exists:
            return None
        return self._assemble(snap.to_dict())

    def delete_case(self, case_id: str) -> None:
        snap = self._col.document(case_id).get()
        if snap.exists:
            case = snap.to_dict()
            collection = self._segments(case_id)
            index = case.get("chain_index") or {}
            for field in _CHAINED:
                SegmentedChain(collection, field).delete_all(index.get(field))
        self._col.document(case_id).delete()

    def list_cases(self) -> list[dict]:
        # Deliberately not assembled: the queue is rendered from the case
        # documents alone, so listing cases does not read every case's history.
        rows = [_summarize(s.to_dict()) for s in self._col.stream()]
        rows.sort(key=lambda r: (verdict_rank(r["worst_verdict"]),
                                 r["updated_utc"] or ""), reverse=True)
        return rows

    def apply_run(self, case_id: str, entries, verdicts, audit) -> dict:
        case = self.get_case(case_id)
        if case is None:
            raise KeyError(case_id)
        _apply_run(case, entries, verdicts, audit)
        self._persist(case)
        return case

    def save_mission(self, case_id: str, mission: dict) -> None:
        """Persist the fleet's working memory on its own, for a caller that
        changed only the memory. A cycle that also sealed verdicts must use
        apply_cycle instead — see the note there."""
        case = self.get_case(case_id)
        if case is None:
            raise KeyError(case_id)
        case["mission"] = mission
        self._persist(case)

    def apply_cycle(self, case_id: str, entries, verdicts, audit,
                    mission: dict) -> dict:
        """Persist one cycle's sealed output and its memory in a single write.

        Why this exists rather than apply_run followed by save_mission: each of
        those re-reads the stored case, so the run's own memory mutations (the
        ABSTAIN question _apply_run opens, say) land on a *different* mission
        object than the one the cycle reasoned into. Two objects appending to
        one hash chain produce a broken chain — the entries written second
        chain onto a head the entries written first never had. Attaching the
        cycle's mission before applying the run keeps it to one object, one
        chain, one write.
        """
        case = self.get_case(case_id)
        if case is None:
            raise KeyError(case_id)
        case["mission"] = mission
        if verdicts:
            _apply_run(case, entries, verdicts, audit)
        else:
            case["updated_utc"] = _now()
        self._persist(case)
        return case


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
