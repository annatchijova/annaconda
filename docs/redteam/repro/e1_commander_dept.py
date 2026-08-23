"""E1 (H1) — composition: is the fleet-commander itself ever authorized
against the catalog for the department it runs as?

Invariant the architecture claims (agent/catalog.py:12-14):
  "authorize refuses a tasking that the catalog does not permit, and the
   refusal is the mechanism, not a prompt instruction."
  fleet-commander available_to = [soc, incident-response, forensics]

PREDICTION (stated before the run):
  A cycle run as department='training' (a published department that the
  catalog does NOT publish fleet-commander to) will be REFUSED if the
  commander is authorized; it will RUN and write case memory if it is not.
"""
import asyncio, os, sys
sys.path.insert(0, "/home/user/annaconda")
os.environ["VIGIA_CASE_BACKEND"] = "memory"

from agent import autonomy, catalog, mission as mem
from agent.tools import PurpleTeamSession
from tools.velociraptor.adapter import MockTransport
from pathlib import Path
from tempfile import mkdtemp

FIX = Path("/home/user/annaconda/tests/fixtures/velociraptor")

def make(case_id="E1"):
    case = {"case_id": case_id, "examiner_id": "attacker",
            "host": {"client_id": "C.demo01", "hostname": "WIN11-VICTIM", "os": "windows"},
            "entries": [], "verdicts": [], "audit_trail": [], "runs": 0,
            "worst_verdict": None, "status": "open", "mission": mem.new_mission(case_id)}
    s = PurpleTeamSession(MockTransport(FIX), case_id=case_id,
                          host=case["host"], examiner_id="attacker",
                          out_dir=Path(mkdtemp()), source="replay",
                          time_base="2026-08-12T14:00:00Z")
    return s, case

print("catalog publication for fleet-commander:")
print("  available_to =", catalog.publication("fleet-commander")["available_to"])
print("  data_classes =", catalog.publication("fleet-commander")["data_classes"])
print("  writes_case_memory =", catalog.publication("fleet-commander")["writes_case_memory"])
print()

for dept in ("incident-response", "soc", "forensics", "training", "compliance"):
    s, case = make(f"E1-{dept}")
    res = asyncio.run(autonomy.run_cycle(s, case, department=dept,
                                         trigger="test", force=True))
    m = case["mission"]
    published = dept in catalog.publication("fleet-commander")["available_to"]
    print(f"dept={dept:<18} published_to_commander={published!s:<5} "
          f"acted={res['acted']} cycle={res.get('cycle')} "
          f"journal_entries={len(m['journal'])} "
          f"sealed_verdicts={len(res.get('verdicts', []))} "
          f"next_action={'set' if m.get('next_action') else 'none'}")
    roles = sorted({e.get('role') for e in res['fleet_log']})
    refused = [e for e in res['fleet_log'] if 'refused' in str(e.get('action'))]
    print(f"   roles touched: {roles}")
    print(f"   catalog refusals: {[e['action'] for e in refused] or 'NONE'}")
