# VIGIA — Live Purple Team Evolution Plan

> Working plan for the hackathon evolution described in `PROJECT_BRIEF.md`:
> turn VIGIA from post-incident analysis into a live, Velociraptor-fed
> Purple Team tool, without ever compromising the sealed deterministic core.

## 1. Where we start (verified against the tree, 2026-08-11)

Mature and closely held (workstream 1): the deterministic core (~37.7 KLOC,
72 files) — 25 SIFT analyzers, CAIE v2, Daubert-compliant abductive reasoner
v2 (CCS > 1/2 gate), 8-state quadripartite verdict, SHA-256 sealing over
canonical v2 serialization, chain of custody, hallucination guard, and two
entry points (`vigia_agent.py` Mode 1, `vigia_scorer.py` Mode 2).

Not yet built: streaming ingestion, Velociraptor integration (only
`scripts/setup_velociraptor.sh` exists), dashboard, ML triage, CRONOS wiring.

## 2. The one design decision that shapes everything

**Windows, not streams, get sealed.** The live adapter freezes telemetry into
immutable, hashed *evidence windows*; the existing core scores each window
exactly as it scores static artifacts today; each verdict is sealed over
(`window_hash`, `prev_verdict_hash`, `sequence`), forming a tamper-evident
hash chain. Replaying the same window sequence reproduces every seal
bit-for-bit. Recorded windows double as (a) the live-determinism proof for
judges and (b) the demo fallback if the lab misbehaves.

The contracts in `contracts/` (evidence window, verdict stream entry, ML
nomination) are the frozen interfaces; parallel workstreams build against
them, never against core internals.

## 3. Phases

| Phase | What | Owner | Status |
|---|---|---|---|
| 0 | Hygiene: pyproject, pytest wrappers over inline self-tests, cross-process determinism check | core | done |
| 1 | Contracts: the three versioned schemas + fixtures | core | schemas done, fixtures pending |
| 2 | Velociraptor batch-first: lab as external service, adapter (REST/mTLS client + curated VQL templates) → evidence windows | core | adapter done against fixtures; live integration pending lab |
| 3 | Window manager + hash-chained sealed verdict stream + live-mode runner (poll → window → verdict → emit) | core | pending |
| 4 | Purple Team dashboard: consumes the sealed stream (SSE), MITRE timeline, red-vs-blue readout, ATT&CK Navigator heatmap | collaborator | can start now against fixtures |
| 5 | ML triage: surprisal-ensemble port (nominate-only, see contract) | collaborator | can start now against fixtures |
| 6 | CRONOS audit-trail wiring for the investigation itself | core | stretch |
| 7 | Demo script: scripted red scenarios, rehearsed end-to-end, recorded windows as fallback, replay finale | both | last 2 days, non-negotiable |

MVP: one Windows endpoint, batch-poll Velociraptor, chained sealed windows,
live MITRE timeline, deterministic replay demo. Stretch: ML nominator,
CRONOS, true streaming, multiple endpoints.

## 4. External repositories: what we take, and the license boundary

| Repo | License | Use | What we take |
|---|---|---|---|
| `rjonhaas/hunt_lab` | GPL-3.0 | **Service only — never copy code** | Turn-key lab: Velociraptor server (docker-compose) + Windows AD domain + Caldera + Atomic Red Team, scenarios with ground truth. VIGIA talks to it over the network only. `velo_collect.py` read as API reference, re-derived clean. |
| `rjonhaas/SIFTics` | MIT | Lift selectively | Velociraptor REST/mTLS client (`mcp_broker`); the curated-VQL-template pattern (parameters filled into pre-committed VQL, raw VQL forbidden); `tag_findings_mitre.py`; baseline-diff pattern. |
| `allisterb/Camel` | MIT (C#) | One targeted port | 5-detector surprisal ensemble (~855 LOC) reimplemented in stdlib Python as the nomination layer; SyntheticIntrusion injector for red-side eval; `ToolkitCoverage.md` as analyzer gap list (Hayabusa/Sigma). |
| `marlyocat/findevil` | MIT | Lift selectively | Linux persistence/memory/timeline detection logic (reworked to Fraction discipline); `ai_signatures.py` (LLM-operated-adversary detector); 29 ground-truth attack scenarios as demo/eval corpus; red-team scoring loop pattern. |
| `calebevans/mulder` | Apache-2.0 | Lift selectively | Composite behavioral detectors; ATT&CK Navigator layer export; evidence-ref validation (findings must cite existing tool calls); Dockerfile as SIFT toolchain recipe. |
| `tupils1/protocol-siftpp` | MIT | Reference + 2 pieces | Spoliation self-attack harness ("prove guardrails by attacking them") for the demo; live attack panel + audit replay UX as dashboard seed. |

Boundary rules:

1. Nothing GPL enters this tree. hunt_lab runs as an independent service,
   same posture as Velociraptor itself (documented in `ATTRIBUTIONS.md`).
2. Everything copied from MIT/Apache-2.0 sources gets an `ATTRIBUTIONS.md`
   entry with its license notice.
3. No peer project's agentic loop is adopted. Every one of them places the
   LLM in the decision path; VIGIA's differentiator is that it never does.

## 4b. Integration gaps (found empirically 2026-08-12; CLOSED same day)

Feeding a fixture-built window through the real scorer surfaced, and then
closed, four integration findings — kept here because each encodes a
convention the live path must not regress on:

1. Evidence vocabulary: template evidence types must be keys of BOTH CAIE
   vocabularies (`_DOMAIN_MAP` and `EVIDENCE_PROFILES` — different sets).
   A miss degrades to the `default` profile or triggers
   CAIE_INVALID_EVIDENCE_TYPE. Enforced by a lockstep test.
2. Custody metadata: artifacts carry `acquisition_tool=velociraptor` (added
   to CAIE's whitelist beside F-Response, its live-acquisition precedent),
   per-row `acquisition_hash`, the caller-supplied freeze timestamp, and
   `examiner_id`. `write_blocker_used` is honestly False — live telemetry
   reaches FORENSIC assurance (3/4 gates), never STRONG, by design.
3. Provenance chains: each artifact links its row-content hash and the
   source-file hash sealed in the window manifest; an empty chain hits the
   scorer's EPC floor (trust 1/10) — that degradation stays as designed for
   transports without file custody.
4. No-signal prior: `raw_score` means tool-reported suspicion, so the
   adapter declares the EBS v1 floor `1/20`, never a midpoint (a `1/2`
   prior flipped a benign window to MALICE_HIGH — regression-tested now).
   Real suspicion enters from analyzers and CAIE, never from collection.

## 5. Risks

1. Lab standup eats days → hunt_lab as service, batch-poll before streaming.
2. Live demo fragility → recorded windows are both fallback and the
   determinism argument.
3. Temptation to modify the core "for streaming" → unnecessary under the
   window design; any core change passes the determinism test in `tests/`.
