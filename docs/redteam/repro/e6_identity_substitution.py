"""E6 (H2) — what does the seal commit to, and what is re-resolved later
from a mutable reference?

Invariant the architecture claims (GET /cases/{id}/exhibit, service/app.py:513-528):
  "Carries the sealed verdict chain and the case metadata needed to re-derive
   every seal without this service ... this exhibit proves INTEGRITY — nothing
   was altered, reordered, inserted, or dropped after sealing."

PREDICTION (before the run):
 P1 the sealed entry commits to case_id, sequence, window_hash, verdict —
    and NOT to the host;
 P2 the exhibit's `case.host` and `case.case_id` are outside every seal, so
    rewriting them yields PASS from the independent verifier;
 P3 neither verify_stream nor verify_bundle compares entry['case_id'] to the
    case it is stored under, so a chain sealed for host/case A verifies as the
    record of host/case B.
"""
import json, sys, copy, subprocess
sys.path.insert(0, "/home/user/annaconda")
from pathlib import Path
from tempfile import mkdtemp
from agent.tools import PurpleTeamSession
from tools.velociraptor.adapter import MockTransport
from core.verdict_stream import verify_stream

FIX = Path("/home/user/annaconda/tests/fixtures/attack")
s = PurpleTeamSession(MockTransport(FIX), case_id="CASE-VICTIM-A",
    host={"client_id": "C.aaa", "hostname": "WIN11-VICTIM-A", "os": "windows"},
    examiner_id="perito-01", out_dir=Path(mkdtemp()), source="replay",
    time_base="2026-08-12T14:10:00Z")
sm = s.run_hunt(["pslist", "netstat"], reason="collect")
v = s.adjudicate(sm["window_id"])
entry = s._entries[0]
print("sealed verdict:", v["verdict_state"])
print("P1 fields the entry seal commits to:", sorted(k for k in entry if k != "entry_hash"))
print("P1 does any sealed field name the host?  ",
      "host" in json.dumps(entry) or "WIN11" in json.dumps(entry))
print()

# the exhibit as GET /cases/{id}/exhibit builds it
exhibit = {"format": "annaconda-exhibit", "format_version": 1,
           "case_id": "CASE-VICTIM-A",
           "case": {"case_id": "CASE-VICTIM-A",
                    "host": {"client_id": "C.aaa", "hostname": "WIN11-VICTIM-A",
                             "os": "windows"},
                    "created_utc": "2026-08-12T14:00:00Z",
                    "updated_utc": "2026-08-12T14:20:00Z",
                    "examiner_id": "perito-01",
                    "worst_verdict": v["verdict_state"],
                    "entries": [entry]},
           "chain_ok": True}
Path("exhibit_real.json").write_text(json.dumps(exhibit, indent=1))

# --- P2: relabel the exhibit: different host, different examiner ------------
forged = copy.deepcopy(exhibit)
forged["case"]["host"] = {"client_id": "C.zzz", "hostname": "WIN11-INNOCENT-B",
                          "os": "windows"}
forged["case"]["examiner_id"] = "somebody-else"
Path("exhibit_relabelled_host.json").write_text(json.dumps(forged, indent=1))

# --- P3: same sealed chain presented under a different case identity --------
forged2 = copy.deepcopy(forged)
forged2["case_id"] = "CASE-INNOCENT-B"
forged2["case"]["case_id"] = "CASE-INNOCENT-B"
Path("exhibit_relabelled_case.json").write_text(json.dumps(forged2, indent=1))
print("entry['case_id'] inside the sealed chain :", entry["case_id"])
print("envelope case.case_id now claims         :", forged2["case"]["case_id"])
print()

for name in ("exhibit_real", "exhibit_relabelled_host", "exhibit_relabelled_case"):
    out = subprocess.run([sys.executable, "-m", "tools.verify_bundle", f"{name}.json"],
                         cwd="/home/user/annaconda", capture_output=True, text=True,
                         env={**__import__("os").environ,
                              "PYTHONPATH": "/home/user/annaconda"})
    first = [l for l in (out.stdout+out.stderr).splitlines() if l.strip()][:4]
    print(f"--- annaconda-verify {name}.json  (exit {out.returncode})")
    for l in first: print("   ", l)

print()
print("service's own verify_stream on the relabelled chain:",
      verify_stream(forged2["case"]["entries"]))
