"""E10 (H2) — the stable-escalation-id defence vs the route that calls it.

agent/mission.py:558-563 states the hazard and the fix:
  "``index`` may be a stable escalation id ("E3") or a position. Prefer the id:
   the list is capped by _trim, so a position a caller read a moment ago can
   point at a different escalation by the time it is used — and taking up the
   wrong one silences an escalation nobody handled."

The only caller is service/app.py:1027-1028:
    async def acknowledge_escalation(case_id: str, index: int, ...)

PREDICTION (before the run):
 P1 the route types the parameter as int, so the stable-id branch is
    unreachable through the API (a stable id is rejected by validation);
 P2 therefore acknowledging is positional, and a _trim eviction between the
    read and the acknowledge silences a DIFFERENT escalation than the one the
    human took up.
"""
import os, sys
sys.path.insert(0, "/home/user/annaconda")
os.environ["VIGIA_CASE_BACKEND"] = "memory"; os.environ["VIGIA_RATE_MAX"]="500"
from fastapi.testclient import TestClient
from service.app import app
from agent import mission as mem

c = TestClient(app)
c.post("/cases", json={"case_id": "E10", "examiner_id": "p", "scenario": "benign"})
case = __import__("service.app", fromlist=["_CASE_STORE"])._CASE_STORE.get_case("E10")
m = mem.attach(case)
# the engine raises one escalation on a sealed malicious verdict
mem.escalate(m, actor="engine", why="the sealed engine adjudicated MALICE_HIGH",
             what_to_check="confirm containment",
             sealed_basis=[{"verdict_state": "MALICE_HIGH", "entry_hash": "a"*64,
                            "sequence": 0}])
print("escalation raised, stable id =", m["escalations"][0]["id"])

r = c.post("/cases/E10/escalations/E1/acknowledge",
           json={"note": "handled", "examiner_id": "alice"})
print("P1 POST .../escalations/E1/acknowledge   ->", r.status_code,
      "(stable id rejected by the route's int type)" if r.status_code == 422 else "")

r = c.post("/cases/E10/escalations/0/acknowledge",
           json={"note": "handled", "examiner_id": "alice"})
print("P1 POST .../escalations/0/acknowledge    ->", r.status_code, "(positional only)")
print("   acknowledged_by            :", r.json()["acknowledged"]["acknowledged_by"])
print("   acknowledged_by_authenticated:", r.json()["acknowledged"]["acknowledged_by_authenticated"])
print("   -> a MALICE escalation was retired by an unauthenticated caller who")
print("      typed their own examiner_id, with no Authorization header sent.")

# P2: show the eviction that makes position unstable
print()
m2 = mem.new_mission("E10B")
mem.escalate(m2, actor="engine", why="sealed MALICE_HIGH on this host",
             what_to_check="contain", sealed_basis=[{"verdict_state":"MALICE_HIGH",
             "entry_hash":"b"*64, "sequence":0}])
first_id = m2["escalations"][0]["id"]
for i in range(mem.ESCALATION_LIMIT + 5):
    mem.escalate(m2, actor="fleet-commander", why=f"routine note {i}",
                 what_to_check="nothing specific")
ids = [e["id"] for e in m2["escalations"]]
print("P2 after", mem.ESCALATION_LIMIT + 6, "escalations, list len =", len(ids))
print("   the engine's MALICE escalation", first_id, "still present?", first_id in ids)
print("   _trim dropped (mission['summarized_away']):", m2["summarized_away"])
print("   entry now at POSITION 0 :", m2["escalations"][0]["why"][:40],
      "| sealed_basis:", m2["escalations"][0]["sealed_basis"])
