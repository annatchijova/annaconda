"""E3b (H4) — ABSTAIN as a state machine, with a host that really adjudicates
ABSTAIN on every cycle.

PREDICTION (before the run):
 P1  every cycle seals ABSTAIN_* and schedules another cycle;
 P2  ZERO escalations are raised across all cycles;
 P3  the case never stands down and never reaches a human;
 P4  is_compromised() is False on it, so stand_down is PERMITTED -> an agent
     may park "we could not tell" permanently.
"""
import asyncio, os, sys
sys.path.insert(0, "/home/user/annaconda")
os.environ["VIGIA_CASE_BACKEND"] = "memory"
from pathlib import Path
from tempfile import mkdtemp
from agent import autonomy, mission as mem
from agent.tools import PurpleTeamSession
from tools.velociraptor.adapter import MockTransport
from service.case_store import MemoryCaseStore
from core.verdict_stream import GENESIS_HASH

FIX = Path(__file__).resolve().parent / "abstain_fix"
store = MemoryCaseStore()
store.create_case("E3B", {"client_id": "C.demo01", "hostname": "WIN11-VICTIM",
                          "os": "windows"}, "perito-01", scenario="abstain")

def session_for(case):
    e = case.get("entries", [])
    return PurpleTeamSession(MockTransport(FIX), case_id=case["case_id"],
        host=case["host"], examiner_id=case["examiner_id"], out_dir=Path(mkdtemp()),
        source="replay", time_base="2026-08-12T14:00:00Z",
        start_sequence=len(e), start_prev_hash=e[-1]["entry_hash"] if e else GENESIS_HASH)

print(f"{'cycle':<6} {'sealed':<24} {'worst':<22} {'escal':<7} {'stand_down':<11} {'next':<7} {'decision'}")
print("-"*105)
for i in range(8):
    c = store.get_case("E3B"); s = session_for(c)
    r = asyncio.run(autonomy.run_cycle(s, c, trigger="cloud-scheduler", force=True))
    store.apply_cycle("E3B", list(s._entries), r["verdicts"], s.audit_trail, c["mission"])
    c = store.get_case("E3B"); m = c["mission"]
    states = ",".join(v["verdict_state"] for v in r["verdicts"]) or "(none)"
    acts = [e["action"] for e in r["fleet_log"] if e.get("action") in
            ("escalate_to_human","stand_down","schedule_next_cycle","default_schedule_applied")]
    print(f"{i+1:<6} {states:<24} {str(c['worst_verdict']):<22} "
          f"{len(m.get('escalations') or []):<7} "
          f"{str(m.get('standing_down') is not None):<11} "
          f"{str((m.get('next_action') or {}).get('in_hours'))+'h':<7} {acts}")

final = store.get_case("E3B"); m = final["mission"]
print()
print("P2  escalations raised over 8 cycles :", len(m.get("escalations") or []))
print("P3  stood down                       :", m.get("standing_down") is not None)
print("P3  a human was ever notified        :", mem.has_open_escalation(m))
print("P4  is_compromised(ABSTAIN case)     :", autonomy.is_compromised(session_for(final), final))
print("P4  -> stand_down() permitted?       :", not autonomy.is_compromised(session_for(final), final))
print()
print("case status shown to the analyst     :", final["status"])
print("worst_verdict                        :", final["worst_verdict"])
# Now: an agent (or an injected one) calls stand_down on this case.
tools = {t.__name__: t for t in autonomy.commander_tools(session_for(final), final, m)}
out = tools["stand_down"]("the host has been quiet; nothing further to collect")
print("stand_down() on the ABSTAIN case     :", out)
print("is_due after stand_down              :", mem.is_due(m))
print("verify_mission after stand_down      :", mem.verify_mission(m)["memory_ok"])
