# annaconda / VIGÍA — Project Brief

> Mini-brief: what this repo is today, and the evolution we want to build.
> Hackathon / deadline: _(fill in)_

## What it is today

annaconda is **VIGÍA, a deterministic forensic engine**. You feed it DFIR
artifacts (disk images, memory dumps, event logs, PCAPs, registry, browser and
mobile data) and it returns a **sealed, reproducible, court-defensible verdict**
on whether there is malicious activity — mapped to MITRE ATT&CK, with full chain
of custody. 24 SIFT analyzers.

Core invariant: **the LLM is out of the decision path.** The deterministic engine
produces and seals the verdict *before* any model narrates it — swap the narrator
and the verdict never changes. No floats in the decision path; results are
SHA-256 reproducible. Today VIGÍA is **post-incident**: it analyzes evidence
*after* the fact.

## What we want to build (the evolution)

Turn VIGÍA from post-mortem into **live**, aimed at **Purple Team**.

- **Velociraptor as the live evidence source.** Instead of static artifacts,
  VIGÍA ingests real-time endpoint telemetry collected via Velociraptor (VQL
  hunts) and analyzes an attack **as it unfolds**. (Velociraptor is used as an
  independent AGPLv3 service via its API — not embedded — so it imposes no
  copyleft on VIGÍA's Apache-2.0 code.)
- **Purple Team loop.** Red team runs a technique; VIGÍA emits a **live, sealed,
  MITRE-mapped verdict + attribution**; red and blue both get one reproducible,
  tamper-evident readout of what happened and whether the detection held. Attack
  and defense share a single source of truth.
- **Memory + audit.** MNEME / raven-memory carry context across incidents;
  CRONOS records the tamper-evident audit trail of the investigation itself.
- **Invariant preserved:** determinism and sealed verdicts survive the move to
  real time — reproducible even under streaming, partial evidence.

## Why it's hard (honest)

Real time breaks assumptions: streaming and partial evidence, latency, holding a
deterministic sealed verdict when data arrives incrementally, Velociraptor VQL
integration, and a genuine Purple Team workflow. It is ambitious and risky — if
it does not place, it is a large time investment. That is the bet.

## Workstreams (so tasks can be divided)

1. **Deterministic forensic core + verdict** — sealed, no-float, MITRE-mapped.
   Owned tightly; this is the part that must never regress.
2. **Velociraptor live integration** — VQL collection to a streaming evidence
   adapter that feeds VIGÍA.
3. **Live Purple Team view / dashboard / UX** — real-time attack timeline,
   verdicts, red-vs-blue readout.
4. **ML / anomaly triage layer** — surface candidate events from live telemetry
   for the deterministic core to adjudicate (ML never decides; it only nominates).
5. **Memory + audit wiring** — MNEME / raven-memory context + CRONOS audit trail.

Core (1) stays deterministic and closely held. Workstreams **3 and 4** are the
natural pieces for a frontend- and ML-strong collaborator, with a clean interface
into the core.
