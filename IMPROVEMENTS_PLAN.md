# Improvements plan — threat-intel enrichment + standards export

Two additions at the intersection of *what Google values* and *what the DFIR
community uses*, both built so the **founding invariant holds**: the language
model and any external service stay **out of the sealed verdict**. They are
either *evidence fed to the deterministic core* (VirusTotal) or *output derived
from an already-sealed verdict* (STIX). `tests/test_determinism.py` must stay
green, and each feature adds its own determinism assertion.

Ship order: **A (STIX) first** — self-contained, no external dependency, pure
output. Then **B (VirusTotal)** — needs a key, so it ships with honest
degradation and runs keyless in CI against a cached fixture.

---

## A — STIX 2.1 (+ CACAO) export of sealed verdicts

**Why.** DFIR interoperability: a sealed case travels to a SIEM, a TIP (MISP),
or a court exhibit as a standard bundle, with the tamper-evident seal inside it.
Google value: **Google SecOps (Chronicle)** ingests STIX/UDM. It strengthens the
court-defensibility posture rather than diluting it.

**Design.**
- New pure module `verdict/stix_export.py`: `case_to_stix(case) -> dict`. No I/O,
  no model, no float — a deterministic mapping of an already-sealed case.
  - each analyzed host → an `identity` / `observed-data` SDO;
  - each MITRE ATT&CK technique on the verdict (e.g. `T1055.012`) → an
    `attack-pattern` SDO with the MITRE `external_reference`;
  - the sealed verdict → a custom `x-annaconda-sealed-verdict` SDO carrying the
    verdict state, the **score as the exact fraction string**, `entry_hash`,
    `prev_hash`, and the seal — so the bundle is self-describing and
    tamper-evident;
  - `relationship` SDOs tie attack-pattern → observed-data and verdict → technique.
- **Determinism is mandatory** (this is a forensic artifact): STIX object IDs are
  derived with **UUIDv5** from a fixed namespace + the case's seal, never random
  UUIDv4; timestamps come from the sealed record, never `now()`. Re-exporting the
  same sealed case is **byte-identical**.
- Endpoint: `GET /cases/{id}/stix` (and `/investigations/{id}/stix`), returning
  `application/stix+json`.
- Phase 2 (optional): the autonomous cycle → a **CACAO 2.0** playbook.

**Tests** (`tests/test_stix_export.py`):
1. a sealed *attack* case exports a valid STIX 2.1 bundle with the expected
   `attack-pattern`s and the sealed-verdict SDO;
2. re-exporting the same case is byte-identical (determinism);
3. the `entry_hash` in the bundle matches the case's sealed chain.

**Touches:** `verdict/stix_export.py` (new), `service/app.py` (endpoint),
`tests/test_stix_export.py` (new). No change to `core/` or the seal path.

---

## B — VirusTotal / Google Threat Intelligence enrichment specialist

**Why.** VirusTotal / Google Threat Intelligence is a Google product and the
enrichment analysts actually rely on (file/IP/domain reputation and prevalence).
It fits the fleet's catalog-gated specialist model.

**Design (invariant-preserving).**
- New specialist in `agent/fleet.py` (an *external-enrichment* hunter) with its
  own disjoint tool contract, published in `agent/catalog.py` /
  `agent/registry.py` with an explicit clearance (data class, region).
- Client `agent/threat_intel.py`: reads `VT_API_KEY` (or the GTI key) from env.
  **Honest degradation** (mirroring `service/case_store.py`): no key → the
  specialist records *"enrichment unavailable: no threat-intel key"* and does not
  fabricate; `/health` reports `threat_intel: "virustotal" | "unavailable"`.
- **Determinism via cache-into-seal.** The enrichment result is written into the
  **sealed evidence window** at collection time as an enrichment observation with
  provenance (`source`, `queried_at`, the reputation fields). Adjudication and
  every replay read the **cached** value from the sealed window — never a live VT
  call. So replay stays bit-for-bit. VT is *evidence*, never a decider.
- Only IoCs actually observed in the window are enriched (cost/rate control), and
  the specialist is billed/rate-limited behind the catalog gate.

**Tests** (`tests/test_threat_intel.py`):
1. with a fixture VT response, the enrichment seals into the window and the core
   adjudicates from the cached value;
2. determinism: the same case with the cached enrichment reproduces byte-identical
   seals across two `PYTHONHASHSEED`s;
3. no key → honest degradation, no crash, recorded as unavailable;
4. the catalog refuses the enrichment specialist for a department not cleared for it.

**Touches:** `agent/threat_intel.py` (new), `agent/fleet.py`, `agent/catalog.py`,
`agent/registry.py`, `service/app.py` (`/health` field), `tests/test_threat_intel.py`
(new), a fixture under `tests/fixtures/`.

---

## Non-negotiables (checked before every commit)

- [ ] `python3 -m pytest` green — especially `tests/test_determinism.py`; each new
      feature carries its own determinism assertion.
- [ ] No float and no black-box dependency in any sealed value. VT output is
      cached data sealed into the window, not a live dependency of the seal.
- [ ] Honest degradation for a missing VT key; posture surfaced on `/health`.
- [ ] English in-repo; forward-only git; commit messages say *why*.
