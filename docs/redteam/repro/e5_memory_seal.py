"""E5 (H3) — what does verify_mission actually prove?

Invariant the architecture claims (agent/mission.py:16-21):
  "It is tamper-evident. EVERY MUTATION appends a journal entry sealed over
   the previous one ... Memory that survives weeks is memory an attacker has
   weeks to edit; verify_mission proves nobody did. Rewriting or reordering
   the fleet's own history breaks the chain."

PREDICTION (before the run):
 P1 the journal is sealed, but the WORKING STATE the system actually reads
    (standing_down, next_action, tried_hunts, escalations, hypotheses) is NOT
    covered by any hash -> rewriting it leaves verify_mission == memory_ok True;
 P2 rewriting only standing_down changes is_due() to False forever, so the
    sweep never collects evidence from this host again;
 P3 rewriting only tried_hunts changes which surface the planner collects next,
    i.e. it changes what evidence COMES TO EXIST.
"""
import asyncio, sys, json, copy
sys.path.insert(0, "/home/user/annaconda")
from pathlib import Path
from tempfile import mkdtemp
from agent import autonomy, mission as mem
from agent.tools import PurpleTeamSession
from tools.velociraptor.adapter import MockTransport
from core.verdict_stream import GENESIS_HASH

FIX = Path("/home/user/annaconda/tests/fixtures/velociraptor")
def sess(case):
    e = case.get("entries", [])
    return PurpleTeamSession(MockTransport(FIX), case_id=case["case_id"],
        host=case["host"], examiner_id="p", out_dir=Path(mkdtemp()), source="replay",
        time_base="2026-08-12T14:00:00Z", start_sequence=len(e),
        start_prev_hash=e[-1]["entry_hash"] if e else GENESIS_HASH)

case = {"case_id": "E5", "examiner_id": "p", "entries": [], "verdicts": [],
        "audit_trail": [], "runs": 0, "worst_verdict": None, "status": "open",
        "host": {"client_id": "C.demo01", "hostname": "WIN11-VICTIM", "os": "windows"},
        "mission": mem.new_mission("E5")}
s = sess(case)
asyncio.run(autonomy.run_cycle(s, case, trigger="t", force=True))
m = case["mission"]
print("baseline: verify_mission =", mem.verify_mission(m)["memory_ok"],
      "| journal entries =", len(m["journal"]), "| is_due =", mem.is_due(m))
print("baseline tried_hunts    =", [t["hunts"] for t in m["tried_hunts"]])
print()

# --- P1/P2: forge standing_down, touch NOTHING in the journal ---------------
tampered = copy.deepcopy(m)
tampered["standing_down"] = {"rationale": "nothing further to collect",
                             "at_cycle": 99, "at_utc": "2026-01-01T00:00:00Z"}
tampered["next_action"] = None
v = mem.verify_mission(tampered)
print("P1/P2  forged standing_down (journal untouched)")
print("       verify_mission memory_ok :", v["memory_ok"], "  errors:", v["errors"])
print("       memory_head unchanged    :", tampered["memory_head"] == m["memory_head"])
print("       is_due(tampered)         :", mem.is_due(tampered), " <- sweep never wakes this case again")
print("       journal says stand_down? :",
      any(e["action"] == "stand_down" for e in tampered["journal"]))
print()

# --- P3: forge tried_hunts -> change what the planner collects next ---------
def next_target(mission):
    collected = {tuple(t["hunts"]) for t in mission.get("tried_hunts", [])}
    for spec_name, spec in autonomy._HUNTERS.items():
        if tuple(sorted(spec["hunts"])) not in collected:
            return spec_name
    return "windows-hunter"

honest = copy.deepcopy(m)
forged = copy.deepcopy(m)
forged["tried_hunts"].append({
    "hunts": sorted(autonomy._HUNTERS["persistence-agent"]["hunts"]),
    "reason": "already covered", "window_id": "E5-w000099", "cycle": 1,
    "collected_utc": "2026-01-01T00:00:00Z"})
print("P3     forged tried_hunts (journal untouched)")
print("       verify_mission memory_ok :", mem.verify_mission(forged)["memory_ok"])
print("       planner target, honest   :", next_target(honest))
print("       planner target, forged   :", next_target(forged),
      " <- the persistence surface is now never collected")
print("       journal record of it?    :",
      any(e["action"] == "record_collection"
          and "scheduled_tasks" in json.dumps(e["detail"]) for e in forged["journal"]))
print()

# --- what IS covered by the journal seal? ----------------------------------
body_keys = sorted(k for k in m["journal"][0] if k != "entry_hash")
print("fields the journal seal commits to :", body_keys)
print("fields the SYSTEM READS but the seal does NOT cover:")
for k in ("standing_down", "next_action", "tried_hunts", "hypotheses",
          "open_questions", "escalations", "escalation", "cycles",
          "summarized_away", "_next_hypothesis"):
    print(f"   mission[{k!r}]")
