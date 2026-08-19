"""Mission memory: what the fleet knows about a case between sweeps.

A case's sealed verdict chain records *what was adjudicated*. It does not
record what the fleet was thinking: which hypotheses are still open, which
hunts it already tried (and therefore need not repeat), what it is waiting
for, and when it decided to look again. Without that, an autonomous agent
waking up on a cron has amnesia — it re-runs the same collection forever and
never pursues a thread across days.

Mission memory is that missing half: the case's *working* memory, durable
across weeks of asynchronous operation, written by the fleet and read back at
the start of every cycle.

Two properties make it safe to hand an autonomous agent:

1. **It is tamper-evident.** Every mutation appends a journal entry sealed over
   the previous one with the same canonical-v2 + SHA-256 recipe that seals
   verdicts (core/canonicalize). Memory that survives weeks is memory an
   attacker has weeks to edit; ``verify_mission`` proves nobody did. Rewriting
   or reordering the fleet's own history breaks the chain.

2. **It cannot reach the verdict.** Nothing in this module produces or alters a
   verdict, a score, or a seal. The case's status is computed by
   ``service/case_store._apply_run`` from the sealed chain alone — mission
   memory is never an input to it. So an agent (or a prompt injection that
   reaches one) can write anything it likes here and the adjudication is
   unmoved. This is the same boundary as narration: stored beside the seal,
   never inside it, and ``tests/test_mission.py`` proves it by filling memory
   with lies and showing every seal and status unchanged.

The invariant, restated for the autonomous case: the fleet decides *what to
investigate and when*; the deterministic engine decides *what it means*.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from typing import Optional

from core.canonicalize import _canonicalize

# Versioned because this data outlives the code that wrote it: a case opened
# under v1 must still load after the schema grows. ``load_mission`` migrates
# forward; readers never assume the current shape.
MISSION_SCHEMA_VERSION = "1"

GENESIS_HASH = "0" * 64

_TS_FMT = "%Y-%m-%dT%H:%M:%SZ"

# Hypothesis lifecycle. An agent may move a hypothesis between these; it may
# not invent a state (a typo'd status is refused, not silently stored).
HYPOTHESIS_STATES = frozenset({"open", "supported", "refuted"})

# The mission's lists are a working summary; the journal is the record. Every
# entry in these lists was written to the journal first, and the journal is
# stored in bounded segments, so trimming the summary loses nothing that cannot
# be read back from the sealed history.
#
# Without a bound the summary alone grows ~300 bytes a cycle, which fills a
# Firestore document in about 145 days at hourly cadence — the chain
# segmentation moved that ceiling from eleven days, it did not remove it.
#
# Each list is capped absolutely, dropping SETTLED entries before open ones and
# oldest before newest — a closed line of inquiry is history, an open one is
# work — and what was dropped is counted so no reader mistakes the working view
# for the whole record.
HYPOTHESIS_LIMIT = 100
QUESTION_LIMIT = 50
TRIED_HUNTS_LIMIT = 100
ESCALATION_LIMIT = 50


class MissionError(ValueError):
    """Invalid input reached the mission-memory boundary."""


def _now() -> str:
    return datetime.now(timezone.utc).strftime(_TS_FMT)


def _seal(obj) -> str:
    """The one sealing recipe, shared with verdicts and agent manifests."""
    serialized = json.dumps(
        _canonicalize(obj), sort_keys=True, ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(serialized).hexdigest()


def _trim(mission: dict) -> None:
    """Bound the working summary. Counts of what was trimmed are kept so the
    brief can say the history is longer than the summary shows, rather than
    presenting a truncated view as the whole of it."""
    dropped = mission.setdefault("summarized_away",
                                 {"hypotheses": 0, "open_questions": 0,
                                  "tried_hunts": 0, "escalations": 0})
    dropped.setdefault("escalations", 0)
    mission.setdefault("escalations", [])

    def cap(items: list, limit: int, is_settled) -> list:
        """Keep the newest ``limit`` entries, giving up settled ones first."""
        excess = len(items) - limit
        if excess <= 0:
            return items
        # Oldest settled entries go first; only then oldest open ones.
        order = sorted(range(len(items)),
                       key=lambda i: (0 if is_settled(items[i]) else 1, i))
        drop = set(order[:excess])
        return [item for i, item in enumerate(items) if i not in drop]

    for key, limit, settled in (
        ("hypotheses", HYPOTHESIS_LIMIT, lambda h: h.get("status") != "open"),
        ("open_questions", QUESTION_LIMIT, lambda q: bool(q.get("resolved"))),
        ("tried_hunts", TRIED_HUNTS_LIMIT, lambda t: True),
        ("escalations", ESCALATION_LIMIT, lambda e: bool(e.get("acknowledged"))),
    ):
        before = len(mission[key])
        mission[key] = cap(mission[key], limit, settled)
        dropped[key] += before - len(mission[key])


def _text(value, field: str, *, limit: int = 2000) -> str:
    """Accept a non-empty string, bounded. Memory an agent writes on a cron for
    weeks is memory that grows without bound unless something says no."""
    if not isinstance(value, str) or not value.strip():
        raise MissionError(f"{field} must be a non-empty string")
    out = value.strip()
    if len(out) > limit:
        raise MissionError(f"{field} exceeds {limit} characters")
    return out


# --- construction and migration ---------------------------------------------

def new_mission(case_id: str) -> dict:
    """An empty mission for a fresh case."""
    return {
        "schema_version": MISSION_SCHEMA_VERSION,
        "case_id": case_id,
        "cycles": 0,
        "hypotheses": [],
        "tried_hunts": [],
        "open_questions": [],
        "next_action": None,
        "escalations": [],
        "escalation": None,
        "standing_down": None,
        "journal": [],
        "memory_head": GENESIS_HASH,
    }


def load_mission(case: dict) -> dict:
    """Read a case's mission, migrating older shapes forward.

    A case written before mission memory existed carries only the legacy
    ``open_question`` dict; it is carried in as the mission's first open
    question so the fleet inherits what the old code knew instead of starting
    blind. The migration is recorded in the journal — a case that was migrated
    says so, rather than pretending it was always this shape.
    """
    mission = case.get("mission")
    if isinstance(mission, dict) and mission.get("journal") is not None:
        version = mission.get("schema_version")
        if version != MISSION_SCHEMA_VERSION:
            # No forward migration exists yet: refuse rather than silently
            # misread a shape this code does not know.
            raise MissionError(
                f"mission schema {version!r} is not readable by version "
                f"{MISSION_SCHEMA_VERSION} — refusing to guess its shape")
        return mission

    mission = new_mission(case.get("case_id", "unknown"))
    legacy = case.get("open_question")
    if isinstance(legacy, dict) and legacy.get("state"):
        note_open_question(
            mission, actor="migration",
            question=f"{legacy['state']}: {legacy.get('why', 'no reason recorded')}",
            what_would_resolve=legacy.get("what_would_resolve",
                                          "not recorded by the legacy shape"),
            resolved=bool(legacy.get("resolved")))
    return mission


def attach(case: dict) -> dict:
    """Load (migrating if needed) and attach the mission to the case dict."""
    mission = load_mission(case)
    case["mission"] = mission
    return mission


# --- the sealed journal ------------------------------------------------------

def record(mission: dict, *, actor: str, action: str, detail: dict) -> dict:
    """Append one sealed entry to the mission journal.

    Every mutation in this module goes through here, so the journal is the
    complete history of the fleet's own reasoning about this case — chained,
    so a later edit is detectable.
    """
    actor = _text(actor, "actor", limit=120)
    action = _text(action, "action", limit=120)
    if not isinstance(detail, dict):
        raise MissionError("detail must be a dict")

    body = {
        "seq": len(mission["journal"]),
        "cycle": mission.get("cycles", 0),
        "actor": actor,
        "action": action,
        "detail": detail,
        "recorded_utc": _now(),
        "prev_hash": mission.get("memory_head", GENESIS_HASH),
    }
    entry = dict(body, entry_hash=_seal(body))
    mission["journal"].append(entry)
    mission["memory_head"] = entry["entry_hash"]
    return entry


def verify_mission(mission: dict) -> dict:
    """Re-derive the journal chain. Reports every break, not just the first —
    an examiner needs the whole picture, not the earliest symptom."""
    errors = []
    prev = GENESIS_HASH
    for i, entry in enumerate(mission.get("journal", [])):
        if not isinstance(entry, dict):
            errors.append(f"entry {i} is not an object")
            continue
        if entry.get("seq") != i:
            errors.append(f"entry {i} has seq {entry.get('seq')!r} — "
                          f"an entry was inserted, dropped, or reordered")
        if entry.get("prev_hash") != prev:
            errors.append(f"entry {i} does not chain onto its predecessor")
        body = {k: v for k, v in entry.items() if k != "entry_hash"}
        if _seal(body) != entry.get("entry_hash"):
            errors.append(f"entry {i} was altered after it was sealed")
        prev = entry.get("entry_hash", prev)

    head_ok = prev == mission.get("memory_head", GENESIS_HASH)
    if not head_ok:
        errors.append("memory_head does not match the end of the journal")
    return {
        "memory_ok": not errors,
        "journal_entries": len(mission.get("journal", [])),
        "memory_head": mission.get("memory_head", GENESIS_HASH),
        "errors": errors,
    }


# --- what the fleet may write ------------------------------------------------
# Every function below is a bounded, typed mutation that ends in a sealed
# journal entry. There is deliberately no function here that writes a verdict,
# a score, a confidence, a MITRE technique, or a seal: those exist only in the
# adjudicated chain, and the fleet reaches them through the correlator's
# adjudicate tool, which returns them already sealed.

def add_hypothesis(mission: dict, *, actor: str, text: str) -> dict:
    """Open a line of inquiry. Returns the stored hypothesis (with its id)."""
    hypothesis = {
        "id": f"H{len(mission['hypotheses']) + 1}",
        "text": _text(text, "hypothesis text"),
        "status": "open",
        "rationale": None,
        "opened_cycle": mission.get("cycles", 0),
        "updated_cycle": mission.get("cycles", 0),
    }
    mission["hypotheses"].append(hypothesis)
    record(mission, actor=actor, action="add_hypothesis", detail=dict(hypothesis))
    _trim(mission)
    return hypothesis


def update_hypothesis(mission: dict, *, actor: str, hypothesis_id: str,
                      status: str, rationale: str) -> dict:
    """Move a hypothesis to supported or refuted, with the reasoning that moved
    it. Refuted hypotheses are kept, never deleted — the ground a later
    examiner needs is the ground that was discarded and why."""
    if status not in HYPOTHESIS_STATES:
        raise MissionError(
            f"status must be one of {sorted(HYPOTHESIS_STATES)}, not {status!r}")
    for h in mission["hypotheses"]:
        if h["id"] == hypothesis_id:
            h["status"] = status
            h["rationale"] = _text(rationale, "rationale")
            h["updated_cycle"] = mission.get("cycles", 0)
            record(mission, actor=actor, action="update_hypothesis",
                   detail=dict(h))
            _trim(mission)
            return h
    raise MissionError(f"unknown hypothesis {hypothesis_id!r}")


def record_collection(mission: dict, *, actor: str, hunts: list, reason: str,
                      window_id: Optional[str] = None) -> dict:
    """Remember that this collection was already run, so the next cycle can
    pursue something new instead of repeating it."""
    if not isinstance(hunts, list) or not hunts:
        raise MissionError("hunts must be a non-empty list")
    tried = {
        "hunts": sorted(str(h) for h in hunts),
        "reason": _text(reason, "reason"),
        "window_id": window_id,
        "cycle": mission.get("cycles", 0),
        "collected_utc": _now(),
    }
    mission["tried_hunts"].append(tried)
    record(mission, actor=actor, action="record_collection", detail=dict(tried))
    _trim(mission)
    return tried


def note_open_question(mission: dict, *, actor: str, question: str,
                       what_would_resolve: str, resolved: bool = False) -> dict:
    """Record something the fleet could not settle, and what would settle it.
    Idempotent on the question text: a cron that wakes daily must not
    accumulate a thousand copies of the same unanswered question."""
    question = _text(question, "question")
    for q in mission["open_questions"]:
        if q["question"] == question:
            return q
    entry = {
        "id": f"Q{len(mission['open_questions']) + 1}",
        "question": question,
        "what_would_resolve": _text(what_would_resolve, "what_would_resolve"),
        "opened_cycle": mission.get("cycles", 0),
        "resolved": bool(resolved),
        "resolved_cycle": None,
    }
    mission["open_questions"].append(entry)
    record(mission, actor=actor, action="note_open_question", detail=dict(entry))
    _trim(mission)
    return entry


def resolve_open_question(mission: dict, *, actor: str, question_id: str,
                          how: str) -> dict:
    for q in mission["open_questions"]:
        if q["id"] == question_id:
            q["resolved"] = True
            q["resolved_cycle"] = mission.get("cycles", 0)
            q["resolved_how"] = _text(how, "how")
            record(mission, actor=actor, action="resolve_open_question",
                   detail=dict(q))
            return q
    raise MissionError(f"unknown question {question_id!r}")


def schedule_next_action(mission: dict, *, actor: str, action: str,
                         in_hours: int, why: str,
                         now: Optional[datetime] = None) -> dict:
    """The fleet sets its own next wake-up.

    This is what makes the operation asynchronous rather than a fixed cron:
    the schedule is a decision the fleet makes about *this* case (a quiet
    benign host earns a long interval; an unresolved beacon a short one), and
    the sweep only acts on cases whose action is due.
    """
    if not isinstance(in_hours, int) or isinstance(in_hours, bool):
        raise MissionError("in_hours must be an integer number of hours")
    if not 1 <= in_hours <= 24 * 30:
        raise MissionError("in_hours must be between 1 and 720 (30 days)")
    base = now or datetime.now(timezone.utc)
    due = base + timedelta(hours=in_hours)
    entry = {
        "action": _text(action, "action"),
        "why": _text(why, "why"),
        "in_hours": in_hours,
        "scheduled_utc": base.strftime(_TS_FMT),
        "due_utc": due.strftime(_TS_FMT),
        "scheduled_at_cycle": mission.get("cycles", 0),
    }
    mission["next_action"] = entry
    record(mission, actor=actor, action="schedule_next_action", detail=dict(entry))
    return entry


# Every quadripartite state the engine can seal. Used to spot a verdict named
# in an agent's prose — the only way to tell "MALICE_HIGH" as a report of a
# sealed fact from "MALICE_HIGH" as something the model produced.
_VERDICT_TOKENS = (
    "MALICE_HIGH", "MALICE_MEDIUM", "BENIGN_HIGH", "BENIGN_MEDIUM",
    "ABSTAIN_CONTRADICTION", "ABSTAIN_INSUFFICIENT", "ABSTAIN_DEGRADED",
    "ESCALATE",
)


def unsealed_verdict_claims(text: str, sealed_states) -> list:
    """Verdict states named in ``text`` that are not in ``sealed_states``.

    A mechanical comparison against the sealed record — not another model
    judging the first one. This is the same discipline the narration guard
    applies to a verdict's description, moved to where an autonomous cycle
    needs it: an agent working unattended can escalate or narrate at any point,
    including after a collection failed and nothing was adjudicated at all.

    Empty result means every verdict the text names was actually sealed. It
    does not mean the text is true — only that it invented no verdict.
    """
    if not isinstance(text, str) or not text:
        return []
    upper = text.upper()
    sealed = {str(s).upper() for s in sealed_states or ()}
    named = [t for t in _VERDICT_TOKENS if t in upper]
    # MALICE_HIGH contains no other token, but ESCALATE is a substring of
    # nothing and ABSTAIN_* share a prefix — compare whole tokens only.
    return sorted({t for t in named if t not in sealed})


def _escalation_rank(entry: dict) -> int:
    """How loudly an escalation needs to be heard, from its SEALED basis only.

    Deliberately coarse: one that rests on an adjudicated malicious verdict
    outranks one that rests on anything else, which outranks one that rests on
    nothing. The agent's prose has no bearing on it.
    """
    states = [str(b.get("verdict_state", ""))
              for b in (entry.get("sealed_basis") or [])]
    if any(st.startswith("MALICE") for st in states):
        return 3
    if any(st == "ESCALATE" for st in states):
        return 2
    return 1 if states else 0


def _current_escalation(mission: dict) -> Optional[dict]:
    """What a human should be shown: the most severe escalation nobody has
    acknowledged yet, most recent breaking ties. Only when every escalation has
    been acknowledged does the latest stand as the current view."""
    entries = mission.get("escalations") or []
    if not entries:
        return None
    open_ones = [(i, e) for i, e in enumerate(entries)
                 if not e.get("acknowledged")]
    if not open_ones:
        return entries[-1]
    return max(open_ones, key=lambda pair: (_escalation_rank(pair[1]), pair[0]))[1]


def escalate(mission: dict, *, actor: str, why: str, what_to_check: str,
             sealed_basis=()) -> dict:
    """Hand the case to a human, with the reasoning that made it necessary.

    Escalation is an operational decision — "this needs a person" — not an
    adjudication. It changes who looks next; it does not change the verdict.

    ``sealed_basis`` is what the cycle actually sealed, supplied by the caller
    from the adjudicated record. The agent cannot pass it, suppress it, or
    edit it. An escalation therefore always arrives beside the sealed facts,
    and an escalation that rests on nothing says so — which matters most in
    the case that produced this parameter: a cycle whose collection failed,
    whose adjudication never ran, and whose commander escalated anyway,
    citing a verdict that was never reached.

    Escalations accumulate rather than replacing one another. A single slot
    meant a later routine escalation could displace an unacknowledged one for a
    sealed malicious verdict: nobody handled it, it simply stopped being shown
    where a human looks. ``mission["escalation"]`` is now derived — the most
    severe unacknowledged one — and the full list is kept.
    """
    basis = [
        {"verdict_state": str(v.get("verdict_state", "")),
         "entry_hash": str(v.get("entry_hash", "")),
         "sequence": v.get("sequence")}
        for v in (sealed_basis or ()) if isinstance(v, dict)
    ]
    sealed_states = [b["verdict_state"] for b in basis if b["verdict_state"]]
    entry = {
        "why": _text(why, "why"),
        "what_to_check": _text(what_to_check, "what_to_check"),
        "raised_at_cycle": mission.get("cycles", 0),
        "raised_utc": _now(),
        "acknowledged": False,
        # The sealed facts this escalation rests on, and whether its own words
        # stayed inside them.
        "sealed_basis": basis,
        "unsupported_by_seal": not basis,
        "unsealed_verdict_claims": unsealed_verdict_claims(
            f"{why} {what_to_check}", sealed_states),
    }

    entries = mission.setdefault("escalations", [])
    # A mission written before escalations were a list carries only the slot;
    # bring it in so its history is not lost by this change.
    previous = mission.get("escalation")
    if isinstance(previous, dict) and previous not in entries:
        entries.append(previous)
    entries.append(entry)
    mission["escalation"] = _current_escalation(mission)
    record(mission, actor=actor, action="escalate_to_human", detail=dict(entry))
    _trim(mission)
    return entry


def acknowledge_escalation(mission: dict, *, actor: str, index: int,
                           note: str, authenticated: bool = False) -> dict:
    """Mark one escalation as taken up by a human, with who and what they said.

    The point of acknowledging is that the *next* unacknowledged one becomes
    what the case shows — an escalation stops being displayed because somebody
    handled it, never because something newer arrived.

    ``authenticated`` says whether the examiner's identity was verified or
    merely claimed. Acknowledging is how a malicious verdict stops demanding
    attention, so "who says they handled it, and do we know that" is exactly
    the pair that has to travel together — the same distinction the principal
    carries everywhere else.
    """
    entries = mission.get("escalations") or []
    if not 0 <= index < len(entries):
        raise MissionError(f"no escalation at index {index}")
    entries[index]["acknowledged"] = True
    entries[index]["acknowledged_by"] = _text(actor, "actor", limit=120)
    entries[index]["acknowledged_by_authenticated"] = bool(authenticated)
    entries[index]["acknowledged_note"] = _text(note, "note")
    entries[index]["acknowledged_utc"] = _now()
    mission["escalation"] = _current_escalation(mission)
    record(mission, actor=actor, action="acknowledge_escalation",
           detail={"index": index, "note": entries[index]["acknowledged_note"],
                   "authenticated": bool(authenticated)})
    return entries[index]


def stand_down(mission: dict, *, actor: str, rationale: str) -> dict:
    """Stop scheduling further autonomous cycles on this case.

    Standing down ends the fleet's *activity*, not the case: the sealed chain,
    the status, and the verdict are untouched, and a human (or a new run) can
    pick it up again. An autonomous agent that cannot decide to stop is not
    autonomous, it is a loop.
    """
    entry = {
        "rationale": _text(rationale, "rationale"),
        "at_cycle": mission.get("cycles", 0),
        "at_utc": _now(),
    }
    mission["standing_down"] = entry
    mission["next_action"] = None
    record(mission, actor=actor, action="stand_down", detail=dict(entry))
    return entry


def begin_cycle(mission: dict, *, actor: str, trigger: str,
                principal: Optional[dict] = None) -> int:
    """Open an autonomous cycle. Returns the new cycle number.

    ``principal`` is who asked and how well we know it (see agent/principal.py).
    It is sealed into the journal because "which department ran this" is only
    worth recording alongside "and was that claim verified".
    """
    mission["cycles"] = mission.get("cycles", 0) + 1
    detail = {"cycle": mission["cycles"], "trigger": _text(trigger, "trigger")}
    if isinstance(principal, dict):
        detail["principal"] = {
            "department": principal.get("department"),
            "identity": principal.get("identity"),
            "authenticated": bool(principal.get("authenticated")),
            "how": principal.get("how"),
        }
    record(mission, actor=actor, action="begin_cycle", detail=detail)
    return mission["cycles"]


# --- what the fleet reads ----------------------------------------------------

def is_due(mission: dict, *, now: Optional[datetime] = None) -> bool:
    """Should the fleet act on this case at this tick?

    A case that has stood down is never due. A case with no scheduled action
    is due (it has never been planned, so plan it). Otherwise the schedule the
    fleet set for itself decides.
    """
    if mission.get("standing_down"):
        return False
    action = mission.get("next_action")
    if not action or not action.get("due_utc"):
        return True
    moment = now or datetime.now(timezone.utc)
    try:
        due = datetime.strptime(action["due_utc"], _TS_FMT).replace(
            tzinfo=timezone.utc)
    except (ValueError, TypeError):
        # An unreadable schedule must not park a case forever: treat it as due
        # and let this cycle rewrite it.
        return True
    return moment >= due


def brief(mission: dict, *, case: Optional[dict] = None) -> dict:
    """The compact picture the fleet reads at the start of a cycle: what is
    still open, what was already tried, what it decided last time.

    Verdict facts are read from the sealed case, never from memory, so the
    brief cannot drift from the adjudicated record even if memory is wrong.
    """
    out = {
        "case_id": mission.get("case_id"),
        "cycles_so_far": mission.get("cycles", 0),
        "open_hypotheses": [
            {"id": h["id"], "text": h["text"]}
            for h in mission.get("hypotheses", []) if h.get("status") == "open"
        ],
        "settled_hypotheses": [
            {"id": h["id"], "text": h["text"], "status": h["status"],
             "rationale": h.get("rationale")}
            for h in mission.get("hypotheses", []) if h.get("status") != "open"
        ],
        "already_collected": [
            {"hunts": t["hunts"], "cycle": t["cycle"], "reason": t["reason"]}
            for t in mission.get("tried_hunts", [])
        ],
        "unresolved_questions": [
            {"id": q["id"], "question": q["question"],
             "what_would_resolve": q["what_would_resolve"]}
            for q in mission.get("open_questions", []) if not q.get("resolved")
        ],
        "last_plan": mission.get("next_action"),
        "escalated": mission.get("escalation") is not None,
        "standing_down": mission.get("standing_down") is not None,
        "memory_head": mission.get("memory_head", GENESIS_HASH),
    }
    # Say when the summary is shorter than the history, so a reader (or an
    # agent) never mistakes the working view for the whole record.
    away = mission.get("summarized_away") or {}
    if any(away.values()):
        out["older_entries_in_sealed_journal"] = {
            k: v for k, v in away.items() if v}
    if case is not None:
        # Sealed facts, straight from the adjudicated record.
        out["sealed_status"] = case.get("status")
        out["sealed_worst_verdict"] = case.get("worst_verdict")
        out["sealed_verdicts"] = len(case.get("entries", []))
    return out
