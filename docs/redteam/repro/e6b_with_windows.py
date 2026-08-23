"""E6b — does including the evidence windows close the substitution?

PREDICTION: no. The verifier looks windows up BY window_hash and only
re-seals them; it never compares window['host'] or window['case_id'] to the
exhibit envelope. So a full exhibit WITH windows still PASSes under a
rewritten host/case identity.
"""
import json, copy, sys
sys.path.insert(0, "/home/user/annaconda")
from pathlib import Path
from tempfile import mkdtemp
from agent.tools import PurpleTeamSession
from tools.velociraptor.adapter import MockTransport

FIX = Path("/home/user/annaconda/tests/fixtures/attack")
s = PurpleTeamSession(MockTransport(FIX), case_id="CASE-VICTIM-A",
    host={"client_id": "C.aaa", "hostname": "WIN11-VICTIM-A", "os": "windows"},
    examiner_id="perito-01", out_dir=Path(mkdtemp()), source="replay",
    time_base="2026-08-12T14:10:00Z")
sm = s.run_hunt(["pslist", "netstat"], reason="collect")
s.adjudicate(sm["window_id"])
window = s._windows[sm["window_id"]]
entry = s._entries[0]

full = {"format": "annaconda-exhibit", "format_version": 1,
        "case_id": "CASE-INNOCENT-B",
        "case": {"case_id": "CASE-INNOCENT-B",
                 "host": {"client_id": "C.zzz", "hostname": "WIN11-INNOCENT-B",
                          "os": "windows"},
                 "examiner_id": "somebody-else",
                 "worst_verdict": "MALICE_HIGH",
                 "entries": [entry]},
        "windows": [window]}       # <-- the FULL exhibit, windows included
Path("exhibit_full_relabelled.json").write_text(json.dumps(full, indent=1))
print("envelope claims  host =", full["case"]["host"]["hostname"],
      " case =", full["case"]["case_id"])
print("sealed window says host =", window["host"]["hostname"],
      " case =", window["case_id"])
print("sealed entry says  case =", entry["case_id"])
