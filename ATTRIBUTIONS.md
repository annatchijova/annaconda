# Attributions

annaconda builds on pre-existing open-source work. This file discloses what was
incorporated, per the disclosure requirement of the All Things Agentic Hackathon
(Google/Gemini): pre-existing code may be used as a foundation provided the
submission discloses it and demonstrably builds upon it.

The line between pre-existing and new: the **deterministic forensic core** is
prior work (VIGÍA, below); everything that makes annaconda a live, agentic,
Google-Cloud purple-team tool was **built for this submission** and is listed
under "New in this submission".

---

## Prior work — the deterministic core (Apache-2.0)

### VIGÍA
<https://github.com/annatchijova/vigia-intent-analysis>

A deterministic forensic-intent engine (Peircean semiotics, Daubert-oriented),
originally built for the SANS FIND EVIL hackathon — pre-dates this submission.
annaconda uses it as its sealed decision core. Incorporated subsystems:

- The deterministic scorer (`vigia_scorer.py`) and its dependency closure:
  canonical serialization (`core/canonicalize.py`), evidence aggregation, the
  decision/risk-bounded layers, likelihood/calibration, bundle sealing, graph
  stability.
- **CAIE — the Cross-Artifact Incongruence Engine (`tools/caie.py`)**: the
  cross-artifact fracture detectors (temporal-causality, process-injection,
  log-vs-memory, etc.) that produce the sealed verdicts annaconda demonstrates,
  and the MITRE ATT&CK mapping (`tools/mitre_mapping.py`).
- The 8-state quadripartite verdict (`verdict/quadripartite.py`) and the
  abductive reasoner (`inference/`).
- The SIFT analyzer suite (`sift/`) and the compatibility shim
  (`sift_orchestrator_shim.py`).
- The security / Model Armor layer (`security/`): LLMShield (prompt-injection
  firewall), sandboxed subprocess execution, path/output boundary validation.
- The LLM hallucination guard (`core/hallucination_guard.py`) — narrative
  claims mechanically verified against the sealed motor output.

This is the majority of the ~38 KLOC in the repository. It is disclosed here in
full; annaconda's own new code is listed separately below so a reviewer can draw
the line without guessing.

Other prior projects (CRONOS, MNEME, raven-memory, MUTANTE) are **not** included
in this submission and are not imported by any module here.

---

## New in this submission (built for this hackathon)

Everything that turns the deterministic core into a live, agentic, cloud tool:

- **Two Google ADK + Gemini agents** (`agent/`): the investigator that drives
  the hunt loop (`purple_team_agent.py`, `tools.py`) and the mentor for junior
  examiners (`consult_agent.py`, `consult_tools.py`). Neither can alter a
  sealed verdict.
- **The Velociraptor adapter** (`tools/velociraptor/`): curated VQL templates,
  Mock/Rest/Query transports, and sealed evidence windows.
- **The hash-chained sealed verdict stream** (`core/verdict_stream.py`) — the
  tamper-evident chain that makes a case one continuing record.
- **The Cloud Run service** (`service/`): FastAPI backend, the Firestore-backed
  case store (`case_store.py`), the analyst console and court-exhibit UI, the
  prompt-injection defense demo, and the autonomous sweep
  (Cloud Scheduler → Pub/Sub → `/tasks/sweep`).
- **The ML triage nominator** (`ml/nominator.py`) — see the Camel attribution
  below.
- The ABSTAIN-as-memory / autonomous-reentry logic, and the determinism and
  contract test suites (`tests/`).

---

## Third-party open source

### Velociraptor — AGPLv3
<https://github.com/Velocidex/velociraptor>

DFIR endpoint platform (VQL hunts). Used as an **independent service reached
over its own API / binary** — never modified, embedded, or forked — so its
AGPLv3 copyleft does not extend to annaconda's Apache-2.0 code. The official
signed release binary is fetched and GPG-verified by
`scripts/setup_velociraptor.sh`.

### Camel — MIT
<https://github.com/allisterb/Camel>

`ml/nominator.py` is a stdlib-Python port of Camel's label-free surprisal
ensemble (C#, MIT, © 2026 Allister Beharry), adapted to endpoint telemetry
(rare-path, rare-destination, content-entropy detectors retained; the name/type
detectors dropped as noise for this data). The nominator **nominates only** — it
never produces a sealed value.

---

## Models

Gemini 3.5 (via Vertex AI) narrates and drives the agents; Gemma
(`gemma-4-26b-a4b-it`, via the Gemini Developer API) is the naive narrator in the
prompt-injection demo. No model is in the decision path — the verdict is sealed
by the deterministic core before any model runs.
