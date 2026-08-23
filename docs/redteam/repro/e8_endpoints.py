"""E8 (H1) — human endpoints vs the internal catalog gate.

Invariant the architecture claims (agent/catalog.py:12-14, and /catalog's own
docstring, service/app.py:274-276):
  "This module is that layer, and it is a gate, not documentation ...
   the SOC may task the collectors, but adjudication belongs to forensics."
  correlator.available_to = ['forensics', 'incident-response']
  correlator.reaches_sealed_core = True

PREDICTION (before the run):
  POST /cases/{id}/investigate reaches session.adjudicate() — the correlator's
  effect — with NO Authorization header, NO department, and NO catalog call,
  appending a sealed verdict to the case chain.
"""
import os, sys
sys.path.insert(0, "/home/user/annaconda")
os.environ["VIGIA_CASE_BACKEND"] = "memory"
os.environ["VIGIA_RATE_MAX"] = "500"
from fastapi.testclient import TestClient
from service.app import app
from agent import catalog

c = TestClient(app)
print("catalog says who may reach the sealed core:")
p = catalog.publication("correlator")
print("   correlator.available_to      =", p["available_to"])
print("   correlator.reaches_sealed_core =", p["reaches_sealed_core"])
print("   SOC may task the correlator? =", "soc" in p["available_to"])
print()

r = c.post("/cases", json={"case_id": "E8", "examiner_id": "anonymous",
                           "scenario": "attack"})
print("POST /cases                       ->", r.status_code, "(no auth header sent)")
r = c.post("/cases/E8/investigate", json={"mode": "scripted", "scenario": "attack"})
print("POST /cases/E8/investigate        ->", r.status_code, "(no auth header sent)")
body = r.json()
print("   sealed verdict appended        :", [v["verdict_state"] for v in body["run_verdicts"]])
print("   case status                    :", body["status"])
print("   sealed_verdicts_total          :", body["sealed_verdicts_total"])
print("   entry_hash                     :", body["run_verdicts"][0]["entry_hash"][:24], "...")
print()
r = c.get("/cases/E8/exhibit")
print("GET /cases/E8/exhibit             ->", r.status_code,
      "chain_ok =", r.json()["chain_ok"])
print()
print("Now the SAME effect through the gated path, as department 'soc':")
c.post("/cases", json={"case_id": "E8B", "examiner_id": "anon", "scenario": "attack"})
r = c.post("/cases/E8B/cycle", json={"department": "soc", "force": True})
log = r.json()["cycle"]["fleet_log"]
refusals = [e for e in log if "refused" in str(e.get("action"))]
print("POST /cases/E8B/cycle {'department':'soc'} ->", r.status_code)
print("   catalog refusals               :", [e["detail"][:70] for e in refusals])
print("   sealed verdicts this cycle     :", [v["verdict_state"] for v in r.json()["cycle"]["verdicts"]])
print()
print("=> the SAME sealed-core effect the catalog denies to 'soc' at /cycle")
print("   is unconditional and unauthenticated at /cases/{id}/investigate.")
