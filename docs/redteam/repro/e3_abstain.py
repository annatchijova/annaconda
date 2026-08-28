"""E3 (H4) — ABSTAIN as a state machine.

Invariant the architecture claims (agent/autonomy.py:524-527):
  "A malicious verdict reaches a human because the ENGINE reached it ...
   a cycle that seals MALICE and tells nobody is the failure this whole
   system exists to prevent."
and (service/case_store.py:132-146) ABSTAIN_DEGRADED means
  "Critical analyzers were disabled during analysis; the result is unreliable."

PREDICTION (before the run):
  A host that adjudicates ABSTAIN_* on every cycle will loop
  ABSTAIN -> schedule -> ABSTAIN -> ... indefinitely, raising ZERO
  escalations, so "we could not tell" never reaches a human.
"""
import asyncio, os, sys
sys.path.insert(0, "/home/user/annaconda")
os.environ["VIGIA_CASE_BACKEND"] = "memory"
from pathlib import Path
from tempfile import mkdtemp
from datetime import datetime, timedelta, timezone

from agent import autonomy, mission as mem
from agent.tools import PurpleTeamSession
from tools.velociraptor.adapter import MockTransport
from service.case_store import MemoryCaseStore
from core.verdict_stream import GENESIS_HASH

FIX = Path("/home/user/annaconda/tests/fixtures/insufficient")
store = MemoryCaseStore()
case = store.create_case("E3", {"client_id": "C.demo01", "hostname": "WIN11-VICTIM",
                                "os": "windows"}, "perito-01", scenario="insufficient")

def session_for(case):
    entries = case.get("entries", [])
    return PurpleTeamSession(
        MockTransport(FIX), case_id=case["case_id"], host=case["host"],
        examiner_id=case["examiner_id"], out_dir=Path(mkdtemp()), source="replay",
        time_base="2026-08-12T14:00:00Z",
        start_sequence=len(entries),
        start_prev_hash=entries[-1]["entry_hash"] if entries else GENESIS_HASH)

print(f"{'cycle':<6} {'sealed state':<24} {'worst':<22} {'escalations':<12} "
      f"{'standing_down':<14} {'next in':<9} {'open Qs'}")
print("-"*110)
now = datetime(2026, 8, 23, tzinfo=timezone.utc)
for i in range(12):
    c = store.get_case("E3")
    m = mem.attach(c)
    # simulate the scheduler waking up when the fleet said it was due
    plan = m.get("next_action")
    if plan:
        now = datetime.strptime(plan["due_utc"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    if not mem.is_due(m, now=now):
        print(f"{i+1:<6} NOT DUE -> sweep skips forever"); break
    s = session_for(c)
    r = asyncio.run(autonomy.run_cycle(s, c, trigger="cloud-scheduler", force=False))
    if not r["acted"]:
        print(f"{i+1:<6} not acted: {r['reason']}"); break
    store.apply_cycle("E3", list(s._entries), r["verdicts"], s.audit_trail, c["mission"])
    c = store.get_case("E3"); m = c["mission"]
    states = [v["verdict_state"] for v in r["verdicts"]] or ["(none)"]
    opens = sum(1 for e in (m.get("escalations") or []) if not e.get("acknowledged"))
    openq = sum(1 for q in m.get("open_questions", []) if not q.get("resolved"))
    print(f"{i+1:<6} {','.join(states):<24} {str(c['worst_verdict']):<22} "
          f"{len(m.get('escalations') or [])} (open {opens}){'':<3} "
          f"{str(m.get('standing_down') is not None):<14} "
          f"{str((m.get('next_action') or {}).get('in_hours'))+'h':<9} {openq}")

print()
print("TOTAL escalations raised over 12 cycles:", len(case.get("mission",{}).get("escalations") or []))
final = store.get_case("E3")
print("case status:", final["status"], "| worst:", final["worst_verdict"])
print("has_open_escalation:", mem.has_open_escalation(final["mission"]))
print("is_compromised (gate on stand_down / short interval):",
      autonomy.is_compromised(session_for(final), final))
