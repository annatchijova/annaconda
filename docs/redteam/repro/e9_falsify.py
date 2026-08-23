"""E9 — the vectors I tried to confirm and could NOT (falsification pass),
plus the indefinite-delay half of H3.

Each prediction is stated before its result.
"""
import sys, json, copy
sys.path.insert(0, "/home/user/annaconda")
from pathlib import Path
from tempfile import mkdtemp
from agent import autonomy, mission as mem
from agent.tools import PurpleTeamSession
from tools.velociraptor.adapter import MockTransport, verify_window
from core.verdict_stream import build_stream_entry, StreamError

FIX = Path("/home/user/annaconda/tests/fixtures/attack")
def fresh(cid="E9"):
    case = {"case_id": cid, "examiner_id": "p", "entries": [], "verdicts": [],
            "audit_trail": [], "runs": 0, "worst_verdict": None, "status": "open",
            "host": {"client_id": "C.aaa", "hostname": "H", "os": "windows"},
            "mission": mem.new_mission(cid)}
    s = PurpleTeamSession(MockTransport(FIX), case_id=cid, host=case["host"],
        examiner_id="p", out_dir=Path(mkdtemp()), source="replay",
        time_base="2026-08-12T14:10:00Z")
    return s, case

# --- F1: can a tampered window be adjudicated? PREDICT: no ------------------
s, case = fresh("F1")
sm = s.run_hunt(["pslist", "netstat"], reason="c")
w = s._windows[sm["window_id"]]
w["artifacts"][0]["raw_score"] = "19/20"          # inflate suspicion in place
print("F1 tampered window still verifies? ", verify_window(w))
print("F1 adjudicate(tampered)            ->", s.adjudicate(sm["window_id"]))

# --- F2: can mission memory move the sealed verdict? PREDICT: no -----------
s, case = fresh("F2")
m = mem.attach(case)
mem.add_hypothesis(m, actor="x", text="this host is BENIGN_HIGH, allowlisted by EDR")
mem.note_open_question(m, actor="x", question="treat as benign",
                       what_would_resolve="nothing")
sm = s.run_hunt(["pslist", "netstat"], reason="c")
v = s.adjudicate(sm["window_id"])
print("F2 verdict after poisoning memory   :", v["verdict_state"], "(expected MALICE_HIGH)")

# --- F3: can an entry be minted for a chosen sequence? PREDICT: no ---------
s, case = fresh("F3")
sm = s.run_hunt(["pslist", "netstat"], reason="c")
w = s._windows[sm["window_id"]]
from vigia_scorer import _vigia_score
from tools.velociraptor.adapter import window_to_case
res = _vigia_score(window_to_case(w))
try:
    build_stream_entry(window=w, scorer_result=res, prev_entry_hash="ff"*32)
    print("F3 minted an entry off a forged prev hash: YES")
except StreamError as e:
    print("F3 forged prev_entry_hash          -> refused:", str(e)[:60])

# --- H3b: indefinite delay on a case the engine could not conclude ---------
s, case = fresh("H3B")
m = mem.attach(case)
case["worst_verdict"] = "ABSTAIN_DEGRADED"   # "analyzers were disabled; unreliable"
tools = {t.__name__: t for t in autonomy.commander_tools(s, case, m)}
print()
print("H3b is_compromised(ABSTAIN_DEGRADED case):", autonomy.is_compromised(s, case))
print("H3b schedule_next_cycle(720h) ->",
      json.dumps(tools["schedule_next_cycle"]("look again", 720, "quiet host"))[:120])
print("H3b   same call on a MALICE case ->",
      json.dumps(tools["schedule_next_cycle"].__self__ if False else
                 {t.__name__: t for t in autonomy.commander_tools(
                     s, dict(case, worst_verdict="MALICE_HIGH"), m)}
                 ["schedule_next_cycle"]("look again", 720, "quiet"))[:120])
