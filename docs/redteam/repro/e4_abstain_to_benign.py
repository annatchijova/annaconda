"""E4 (H4) — does "we could not observe X" become "X was not there"?

Invariant the architecture claims (service/case_store.py:190-196):
  "Reflect the conclusion the reentry reached — but NEVER downgrade a case
   that already has a worse verdict in its history."

PREDICTION (before the run):
  A case whose sealed history is ABSTAIN_* and which later gets ONE BENIGN
  window will display status='benign' while worst_verdict stays ABSTAIN_*,
  i.e. the two disagree and the analyst-facing field is the optimistic one.
  Then the planner stands the case down as resolved-benign.
"""
import sys; sys.path.insert(0, "/home/user/annaconda")
from service.case_store import _apply_run, verdict_rank
from agent.mission import new_mission

case = {"case_id": "E4", "entries": [], "verdicts": [], "audit_trail": [],
        "runs": 0, "worst_verdict": None, "status": "open",
        "open_question": None, "mission": new_mission("E4")}

def run(states):
    _apply_run(case, [], [{"verdict_state": s} for s in states], [])
    q = case.get("open_question") or {}
    print(f"  after {states}: status={case['status']!r:<12} "
          f"worst_verdict={case['worst_verdict']!r:<24} "
          f"open_question={'open' if q and not q.get('resolved') else ('resolved' if q else 'none')}")

print("ranks: ABSTAIN_INSUFFICIENT=%d  BENIGN_MEDIUM=%d  BENIGN_HIGH=%d"
      % (verdict_rank("ABSTAIN_INSUFFICIENT"), verdict_rank("BENIGN_MEDIUM"),
         verdict_rank("BENIGN_HIGH")))
print()
print("run 1 — the collection could not conclude:")
run(["ABSTAIN_INSUFFICIENT"])
print("run 2 — one later window comes back clean:")
run(["BENIGN_HIGH"])
print()
print("RESULT: status=%r  worst_verdict=%r  -> they DISAGREE: %s"
      % (case["status"], case["worst_verdict"],
         case["status"] == "benign" and case["worst_verdict"].startswith("ABSTAIN")))
print()
print("what the analyst queue row shows (service/case_store._summarize):")
from service.case_store import _summarize
row = _summarize(dict(case, host={}, examiner_id="x", created_utc="", updated_utc=""))
print("  status         :", row["status"])
print("  worst_verdict  :", row["worst_verdict"])
print("  open_questions :", row["autonomy"]["open_questions"])
print()
print("and the deterministic planner's next decision, given BENIGN + no unresolved Q:")
print("  agent/autonomy.py:449  elif state.startswith('BENIGN') and mission['cycles'] >= 3:")
print("      -> stand_down()  (permitted: is_compromised() only tests MALICE/ESCALATE)")
