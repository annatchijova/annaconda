"""E2 (H5) — declared identity vs effective identity.

Full matrix: (token state) x (claimed department) -> effective department,
stored principal, and whether the call is allowed.

PREDICTION (before the run):
 (a) invalid / expired / malformed / absent token all collapse to the SAME
     effective identity: whatever the request claims.
 (b) a VALID, verified, non-rostered identity is REFUSED (403) while an
     ANONYMOUS caller in the same request is ALLOWED  -> presenting a real
     credential is strictly worse than presenting none.
 (c) the default department for an anonymous caller is the MOST privileged
     department in the catalog.
"""
import os, sys
sys.path.insert(0, "/home/user/annaconda")
from agent import principal as P, catalog

# --- (c) which department is most privileged? -------------------------------
from collections import Counter
c = Counter()
for name in ["dispatcher","windows-hunter","persistence-agent","threat-intel",
             "detection-engineer","correlator","vigia_purple_team",
             "fleet-commander","vigia_mentor"]:
    for d in catalog.publication(name)["available_to"]:
        c[d] += 1
print("agents each department may task:", dict(sorted(c.items(), key=lambda kv:-kv[1])))
print("DEFAULT department for an anonymous caller:", "incident-response",
      "(service/app.py:957 default_department=autonomy.COMMANDER_DEPARTMENT)")
print()

# --- (a)+(b) the matrix -----------------------------------------------------
os.environ["VIGIA_DEPARTMENT_ROSTER"] = "alice@example.com:forensics"
os.environ["VIGIA_EXPECTED_AUDIENCE"] = "https://svc.example.com"

class FakeVerify:
    """Stand in for google id_token verification so the matrix is executable
    offline. Each case names exactly what the real verifier would return."""
    def __init__(self, email): self.email = email

import agent.principal as pmod
real_verify = pmod.verify_identity_token

CASES = [
    ("absent",              None,                    None),
    ("malformed (not bearer)", "Token abc",          None),
    ("bearer garbage",      "Bearer @@@",            None),   # verify -> None
    ("expired",             "Bearer expired",        None),   # verify -> None
    ("wrong audience",      "Bearer wrongaud",       None),   # verify -> None
    ("VALID, rostered",     "Bearer valid-alice",    "alice@example.com"),
    ("VALID, NOT rostered", "Bearer valid-mallory",  "mallory@evil.com"),
]

print(f"{'token state':<24} {'claims':<12} -> {'eff.dept':<18} {'auth':<6} {'identity':<20} {'enforce'}")
print("-"*100)
for label, header, verified_email in CASES:
    pmod.verify_identity_token = lambda tok, _e=verified_email: _e
    for claimed in ("incident-response", "forensics", "soc", None):
        r = P.resolve(authorization_header=header, claimed_department=claimed,
                      default_department="incident-response")
        try:
            P.enforce(r); verdict = "ALLOWED"
        except P.UnauthenticatedPrincipalError as e:
            verdict = "403 REFUSED"
        print(f"{label:<24} {str(claimed):<12} -> {str(r['department']):<18} "
              f"{str(r['authenticated']):<6} {str(r['identity']):<20} {verdict}")
    print()
pmod.verify_identity_token = real_verify

# --- does resolve() validate the claimed department at all? -----------------
r = P.resolve(authorization_header=None, claimed_department="; DROP TABLE --",
              default_department="incident-response")
print("claimed_department='; DROP TABLE --' ->", r)
print("is it a published department?", "; drop table --" in catalog.DEPARTMENTS)
