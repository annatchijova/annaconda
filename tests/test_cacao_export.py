"""CACAO 2.0 export is a deterministic projection of the sealed mission journal.

The playbook must mirror the journal order, reference the sealed verdicts rather
than recompute them, introduce no float, and re-export byte-identically.
"""
import json

from agent import mission as M
from verdict.cacao_export import case_to_cacao

CASE_ID = "CACAO-T"
ENTRY0_HASH = "a" * 64
WINDOW0_HASH = "b" * 64


def _case():
    m = M.new_mission(CASE_ID)
    M.record(m, actor="fleet-commander", action="begin_cycle", detail={"cycle": 1})
    M.record(m, actor="fleet-commander", action="add_hypothesis",
             detail={"label": "H1", "statement": "possible process injection"})
    M.record(m, actor="windows-hunter", action="record_collection",
             detail={"hunts": ["pslist", "netstat"],
                     "window_id": f"{CASE_ID}-w000000", "reason": "baseline"})
    M.record(m, actor="fleet-commander", action="escalate_to_human",
             detail={"reason": "sealed MALICE_HIGH",
                     "sealed_basis": [{"entry_hash": ENTRY0_HASH,
                                       "state": "MALICE_HIGH"}]})
    M.record(m, actor="fleet-commander", action="stand_down",
             detail={"reason": "handed off to IR"})
    entries = [{
        "sequence": 0, "entry_hash": ENTRY0_HASH, "window_hash": WINDOW0_HASH,
        "verdict": {"state": "MALICE_HIGH", "score": "5569/10000",
                    "confidence": "19/20", "mitre_techniques": ["T1055.012"]},
    }]
    return {
        "case_id": CASE_ID,
        "host": {"client_id": "C.1", "hostname": "WIN11-VICTIM", "os": "windows"},
        "created_utc": "2026-08-20T01:29:36Z",
        "updated_utc": "2026-08-20T01:35:00Z",
        "worst_verdict": "MALICE_HIGH",
        "mission": m,
        "entries": entries,
    }


def _has_float(obj):
    if isinstance(obj, bool):
        return False
    if isinstance(obj, float):
        return True
    if isinstance(obj, dict):
        return any(_has_float(v) for v in obj.values())
    if isinstance(obj, (list, tuple)):
        return any(_has_float(v) for v in obj)
    return False


def test_playbook_shape():
    pb = case_to_cacao(_case(), mission_ok=True, chain_ok=True)
    assert pb["type"] == "playbook"
    assert pb["spec_version"] == "cacao-2.0"
    assert pb["id"].startswith("playbook--")
    assert pb["playbook_types"] == ["investigation"]
    assert pb["created_by"] in pb["agent_definitions"]
    assert not _has_float(pb)


def test_workflow_mirrors_the_journal_in_order():
    case = _case()
    pb = case_to_cacao(case)
    journal = case["mission"]["journal"]
    actions = [s for s in pb["workflow"].values() if s["type"] == "action"]
    assert len(actions) == len(journal)  # one step per sealed journal entry

    # start links to the first action; every action chains to the next; the last
    # lands on the single end step.
    start = pb["workflow"][pb["workflow_start"]]
    assert start["type"] == "start"
    step = pb["workflow"][start["on_completion"]]
    seen = 0
    while step["type"] == "action":
        seen += 1
        step = pb["workflow"][step["on_completion"]]
    assert step["type"] == "end"
    assert seen == len(journal)


def test_collection_step_references_its_sealed_verdict():
    pb = case_to_cacao(_case())
    ref = next(s for s in pb["workflow"].values()
               if s.get("x_annaconda_sealed_verdict"))
    assert ref["x_annaconda_sealed_verdict"]["entry_hash"] == ENTRY0_HASH
    assert ref["x_annaconda_sealed_verdict"]["state"] == "MALICE_HIGH"


def test_escalation_step_carries_its_sealed_basis():
    pb = case_to_cacao(_case())
    esc = next(s for s in pb["workflow"].values()
               if s.get("type") == "action" and "Escalate" in s["name"])
    assert esc["x_annaconda_sealed_basis"][0]["entry_hash"] == ENTRY0_HASH


def test_sealed_verdicts_are_referenced_not_recomputed():
    pb = case_to_cacao(_case())
    v = pb["x_annaconda_sealed_verdicts"]
    assert len(v) == 1
    assert v[0]["entry_hash"] == ENTRY0_HASH        # exactly the stored seal
    assert v[0]["score"] == "5569/10000"            # exact fraction, never a float


def test_export_is_deterministic():
    case = _case()  # build once, so the sealed journal is fixed
    a = json.dumps(case_to_cacao(case, mission_ok=True, chain_ok=True), sort_keys=True)
    b = json.dumps(case_to_cacao(case, mission_ok=True, chain_ok=True), sort_keys=True)
    assert a == b


def test_empty_mission_still_yields_a_valid_start_end_playbook():
    case = _case()
    case["mission"] = {"journal": []}
    pb = case_to_cacao(case)
    start = pb["workflow"][pb["workflow_start"]]
    assert pb["workflow"][start["on_completion"]]["type"] == "end"
