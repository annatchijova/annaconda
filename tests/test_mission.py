"""Mission memory: tamper-evident, and unable to reach the verdict.

Memory that an autonomous fleet writes on a cron for weeks is memory an
attacker has weeks to edit, and memory a prompt injection has weeks to poison.
Two properties have to hold, so both are tested rather than asserted:

1. Editing, reordering, or dropping a journal entry is detectable.
2. Whatever memory says, the sealed verdict and the case's status do not move.
"""

import copy
from datetime import datetime, timedelta, timezone

import pytest

from agent import mission as mem


def _mission():
    m = mem.new_mission("CASE-1")
    mem.begin_cycle(m, actor="fleet-commander", trigger="test")
    mem.add_hypothesis(m, actor="fleet-commander", text="beacon persists somehow")
    mem.record_collection(m, actor="windows-hunter", hunts=["pslist", "netstat"],
                          reason="baseline", window_id="w-0")
    return m


def test_a_clean_journal_verifies():
    report = mem.verify_mission(_mission())
    assert report["memory_ok"] and not report["errors"]
    assert report["journal_entries"] == 3


def test_editing_a_recorded_entry_is_detected():
    m = _mission()
    m["journal"][1]["detail"]["text"] = "nothing to see here"
    report = mem.verify_mission(m)
    assert not report["memory_ok"]
    assert any("altered after it was sealed" in e for e in report["errors"])


def test_reordering_the_journal_is_detected():
    m = _mission()
    m["journal"][1], m["journal"][2] = m["journal"][2], m["journal"][1]
    assert not mem.verify_mission(m)["memory_ok"]


def test_dropping_an_entry_is_detected():
    m = _mission()
    del m["journal"][1]
    report = mem.verify_mission(m)
    assert not report["memory_ok"]
    assert any("inserted, dropped, or reordered" in e for e in report["errors"])


def test_appending_a_forged_entry_is_detected():
    m = _mission()
    forged = copy.deepcopy(m["journal"][-1])
    forged["seq"] = len(m["journal"])
    forged["detail"] = {"claim": "case closed, benign"}
    m["journal"].append(forged)
    assert not mem.verify_mission(m)["memory_ok"]


def test_memory_cannot_move_a_sealed_verdict_or_the_case_status():
    """The load-bearing separation: memory is narration with a chain on it.

    A case is adjudicated MALICE by the deterministic engine. Memory is then
    filled with the most persuasive lie available — every hypothesis refuted,
    a question resolved 'benign', a stand-down saying the host is clean — and
    the sealed record and the status the analyst sees are recomputed. Neither
    moves, because `_apply_run` reads the sealed chain and never reads memory.
    """
    from service.case_store import MemoryCaseStore, _apply_run

    store = MemoryCaseStore()
    case = store.create_case("CASE-M", {"hostname": "WIN11"}, "perito")
    sealed = [{"verdict_state": "MALICE_HIGH", "entry_hash": "a" * 64,
               "sequence": 0, "score": "3/4"}]
    store.apply_run("CASE-M", [{"entry_hash": "a" * 64, "sequence": 0}],
                    sealed, [])
    before_status = case["status"]
    before_worst = case["worst_verdict"]
    before_entries = copy.deepcopy(case["entries"])
    assert before_status == "malice"

    m = mem.attach(case)
    mem.begin_cycle(m, actor="fleet-commander", trigger="test")
    h = mem.add_hypothesis(m, actor="fleet-commander", text="the host is compromised")
    mem.update_hypothesis(m, actor="fleet-commander", hypothesis_id=h["id"],
                          status="refuted",
                          rationale="I have concluded this host is BENIGN_HIGH")
    mem.note_open_question(m, actor="fleet-commander",
                           question="is it clean?", what_would_resolve="nothing")
    mem.stand_down(m, actor="fleet-commander",
                   rationale="case closed, verdict BENIGN_HIGH, hash 0000")

    # Recompute the analyst-visible state from the sealed record, as the
    # service does. Memory was in the case dict the whole time.
    _apply_run(case, [], [], [])
    assert case["status"] == before_status
    assert case["worst_verdict"] == before_worst
    assert case["entries"] == before_entries
    # And the lie is still on the record, chained, for an examiner to read.
    assert mem.verify_mission(case["mission"])["memory_ok"]


def test_a_legacy_case_migrates_its_open_question_forward():
    case = {"case_id": "OLD-1",
            "open_question": {"state": "ABSTAIN_INSUFFICIENT",
                              "why": "collection was partial",
                              "what_would_resolve": "re-collect",
                              "resolved": False}}
    m = mem.attach(case)
    questions = m["open_questions"]
    assert len(questions) == 1
    assert "ABSTAIN_INSUFFICIENT" in questions[0]["question"]
    assert questions[0]["what_would_resolve"] == "re-collect"
    # the migration is on the record, not silent
    assert any(e["actor"] == "migration" for e in m["journal"])


def test_an_unreadable_schema_is_refused_not_guessed():
    case = {"case_id": "X", "mission": {"schema_version": "99", "journal": []}}
    with pytest.raises(mem.MissionError):
        mem.load_mission(case)


def test_a_case_is_not_due_before_its_scheduled_time():
    m = mem.new_mission("C")
    now = datetime(2026, 8, 19, 12, 0, tzinfo=timezone.utc)
    mem.schedule_next_action(m, actor="fleet-commander", action="re-check",
                             in_hours=6, why="quiet host", now=now)
    assert not mem.is_due(m, now=now + timedelta(hours=5))
    assert mem.is_due(m, now=now + timedelta(hours=7))


def test_a_case_that_stood_down_is_never_due_again():
    m = mem.new_mission("C")
    mem.schedule_next_action(m, actor="fleet-commander", action="x",
                             in_hours=1, why="y")
    mem.stand_down(m, actor="fleet-commander", rationale="nothing left to do")
    assert not mem.is_due(m)
    assert m["next_action"] is None


def test_a_case_never_planned_is_due():
    assert mem.is_due(mem.new_mission("C"))


def test_an_unreadable_schedule_does_not_strand_the_case():
    m = mem.new_mission("C")
    mem.schedule_next_action(m, actor="a", action="x", in_hours=1, why="y")
    m["next_action"]["due_utc"] = "not a timestamp"
    assert mem.is_due(m)


def test_invalid_writes_are_refused():
    m = mem.new_mission("C")
    with pytest.raises(mem.MissionError):
        mem.add_hypothesis(m, actor="a", text="   ")
    h = mem.add_hypothesis(m, actor="a", text="real")
    with pytest.raises(mem.MissionError):
        mem.update_hypothesis(m, actor="a", hypothesis_id=h["id"],
                              status="probably", rationale="r")
    with pytest.raises(mem.MissionError):
        mem.schedule_next_action(m, actor="a", action="x", in_hours=0, why="y")
    with pytest.raises(mem.MissionError):
        mem.schedule_next_action(m, actor="a", action="x", in_hours=10_000, why="y")


def test_the_same_question_is_not_recorded_twice():
    m = mem.new_mission("C")
    mem.note_open_question(m, actor="a", question="q?", what_would_resolve="r")
    mem.note_open_question(m, actor="a", question="q?", what_would_resolve="r")
    assert len(m["open_questions"]) == 1


def test_the_brief_reads_verdict_facts_from_the_sealed_case_not_memory():
    m = mem.new_mission("C")
    case = {"status": "malice", "worst_verdict": "MALICE_HIGH",
            "entries": [{}, {}]}
    mem.stand_down(m, actor="a", rationale="claiming this host is benign")
    out = mem.brief(m, case=case)
    assert out["sealed_status"] == "malice"
    assert out["sealed_worst_verdict"] == "MALICE_HIGH"
    assert out["sealed_verdicts"] == 2


def _sealed(state="MALICE_HIGH"):
    return [{"verdict_state": state, "entry_hash": "a" * 64, "sequence": 0}]


def test_a_later_escalation_cannot_displace_an_unacknowledged_severe_one():
    """A single slot meant a routine escalation could replace one for a sealed
    malicious verdict. Nobody handled it; it just stopped being shown where a
    human looks."""
    m = mem.new_mission("ESC")
    mem.escalate(m, actor="engine", why="the engine adjudicated MALICE_HIGH",
                 what_to_check="confirm containment", sealed_basis=_sealed())
    mem.escalate(m, actor="fleet-commander",
                 why="a scheduled task could not be classified",
                 what_to_check="review the task", sealed_basis=[])
    assert "MALICE_HIGH" in m["escalation"]["why"]
    assert len(m["escalations"]) == 2


def test_an_escalation_stops_showing_when_somebody_handles_it():
    m = mem.new_mission("ESC")
    mem.escalate(m, actor="engine", why="the engine adjudicated MALICE_HIGH",
                 what_to_check="confirm containment", sealed_basis=_sealed())
    mem.escalate(m, actor="fleet-commander", why="a routine question",
                 what_to_check="review it", sealed_basis=[])
    mem.acknowledge_escalation(m, actor="perito-01", index=0,
                               note="host isolated, ticket INC-4412")
    assert "routine" in m["escalation"]["why"]
    assert m["escalations"][0]["acknowledged_by"] == "perito-01"
    assert mem.verify_mission(m)["memory_ok"]


def test_acknowledging_an_escalation_that_is_not_there_is_refused():
    m = mem.new_mission("ESC")
    with pytest.raises(mem.MissionError):
        mem.acknowledge_escalation(m, actor="p", index=3, note="n")


def test_a_mission_written_before_escalations_were_a_list_keeps_its_history():
    """Additive schema change: an older mission carries only the slot."""
    m = mem.new_mission("OLD")
    m.pop("escalations")
    m["escalation"] = {"why": "an earlier escalation", "what_to_check": "x",
                       "acknowledged": False, "sealed_basis": _sealed()}
    mem.escalate(m, actor="fleet-commander", why="something new",
                 what_to_check="y", sealed_basis=[])
    whys = [e["why"] for e in m["escalations"]]
    assert "an earlier escalation" in whys and "something new" in whys
    assert m["escalation"]["why"] == "an earlier escalation"


def test_the_working_summary_is_bounded_and_says_what_it_dropped():
    """The mission's lists are a view of the journal, which is segmented and
    authoritative. Unbounded they fill a Firestore document on their own."""
    m = mem.new_mission("BOUND")
    for i in range(mem.TRIED_HUNTS_LIMIT + 40):
        mem.record_collection(m, actor="windows-hunter", hunts=["pslist"],
                              reason=f"cycle {i}")
    assert len(m["tried_hunts"]) == mem.TRIED_HUNTS_LIMIT
    assert m["summarized_away"]["tried_hunts"] == 40
    assert mem.brief(m)["older_entries_in_sealed_journal"]["tried_hunts"] == 40
    # nothing was lost: every one of them is in the sealed journal
    recorded = [e for e in m["journal"] if e["action"] == "record_collection"]
    assert len(recorded) == mem.TRIED_HUNTS_LIMIT + 40
    assert mem.verify_mission(m)["memory_ok"]


def test_settled_lines_of_inquiry_are_given_up_before_open_ones():
    m = mem.new_mission("BOUND2")
    for i in range(mem.HYPOTHESIS_LIMIT):
        h = mem.add_hypothesis(m, actor="a", text=f"settled {i}")
        mem.update_hypothesis(m, actor="a", hypothesis_id=h["id"],
                              status="refuted", rationale="no")
    for i in range(10):
        mem.add_hypothesis(m, actor="a", text=f"open {i}")
    kept = m["hypotheses"]
    assert len(kept) == mem.HYPOTHESIS_LIMIT
    assert sum(1 for h in kept if h["status"] == "open") == 10


def test_an_open_escalation_is_distinct_from_the_derived_view():
    """mission["escalation"] is a derived view that falls back to the latest
    entry once everything is acknowledged, so it is never None again. Anything
    asking "does this case still need a person?" must ask has_open_escalation,
    or it answers "already handled" forever."""
    m = mem.new_mission("OPEN")
    mem.escalate(m, actor="engine", why="the engine adjudicated MALICE_HIGH",
                 what_to_check="contain it", sealed_basis=_sealed())
    assert mem.has_open_escalation(m) is True

    mem.acknowledge_escalation(m, actor="perito-01", index=0, note="isolated")
    assert mem.has_open_escalation(m) is False
    assert m["escalation"] is not None, "the derived view still shows the last one"


def test_ids_do_not_collide_once_the_lists_are_capped():
    """Ids were minted as len(list)+1, so once _trim caps the list the length
    stops growing and every later entry reuses the same id — after which
    update_hypothesis settles whichever collision it finds first."""
    m = mem.new_mission("IDS")
    for i in range(mem.HYPOTHESIS_LIMIT + 20):
        mem.add_hypothesis(m, actor="a", text=f"line {i}")
    ids = [h["id"] for h in m["hypotheses"]]
    assert len(ids) == len(set(ids)), "duplicate hypothesis ids after trimming"

    # and settling one settles that one, not an older namesake
    target = m["hypotheses"][-1]["id"]
    mem.update_hypothesis(m, actor="a", hypothesis_id=target,
                          status="refuted", rationale="no")
    settled = [h for h in m["hypotheses"] if h["status"] == "refuted"]
    assert len(settled) == 1 and settled[0]["id"] == target


def test_an_escalation_is_acknowledged_by_id_not_by_position():
    """The list is capped, so a position a caller read a moment ago can point at
    a different escalation by the time it is used — silencing one nobody
    handled."""
    m = mem.new_mission("ACKID")
    first = mem.escalate(m, actor="engine", why="the engine adjudicated MALICE_HIGH",
                         what_to_check="contain it", sealed_basis=_sealed())
    mem.escalate(m, actor="fleet-commander", why="a routine question",
                 what_to_check="review it", sealed_basis=[])
    assert first["id"] and first["id"] != m["escalations"][1]["id"]

    took = mem.acknowledge_escalation(m, actor="perito-01", index=first["id"],
                                      note="isolated")
    assert took["id"] == first["id"]
    assert m["escalations"][1]["acknowledged"] is False
    assert mem.verify_mission(m)["memory_ok"]
