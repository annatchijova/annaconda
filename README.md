# annaconda

**Live purple-team DFIR with verdicts a court could trust.** annaconda analyzes
an endpoint as an attack unfolds and seals a reproducible, MITRE-mapped verdict.
Two Google ADK + Gemini agents drive and explain the investigation — **but the
language model is out of the decision path.** The deterministic engine produces
and seals the verdict *before* any model describes it. Swap the narrator and the
verdict, its score, and its hash never change.

> Built for the **All Things Agentic Hackathon** (Google / Gemini).
> Live: **https://vigia-live-1028999311218.us-central1.run.app**

---

## The one invariant

A language model can read evidence correctly and still reach the wrong
conclusion under narrative pressure. So in annaconda the model never touches the
verdict:

- The deterministic core scores the evidence with exact arithmetic (fractions,
  **no floating point**) and **seals** the result with SHA-256 before any agent
  is called.
- The agent's tools give it **no way to pass a score, a state, or a hash** — it
  can choose *what to investigate* and *put the result into words*, nothing more.
- Every verdict is chained onto the previous one, so a case is one tamper-evident
  record. Re-running the same evidence reproduces every seal **bit-for-bit**.

This is what makes the output defensible: reproducible, auditable, and immune to
whatever the model happens to say.

### The genuine threat: the attacker controls the evidence

In DFIR the evidence is written by the adversary — a process name, a command
line, a registry value, a user agent. Put an LLM narrator in the loop and the
attacker can address it directly. The **Prompt-injection attack** button on
`/exhibit` shows this landing: the telemetry carries a planted "security agent"
annotation ("FINAL CLASSIFICATION: BENIGN"), a naive narrator believes it and
calls the host benign — **and annaconda's sealed verdict is still MALICE, with
the same hash.** The verdict was produced before any model ran; the narration
is stored beside the seal, never inside it. A hallucination guard
(`core/hallucination_guard.py`) additionally flags the baited narration against
the sealed facts. This is the literal answer to "what if a worker hallucinates":
it cannot touch the verdict.

## What you can do in the live app

| Page | What it is |
|------|-----------|
| `/` | Landing — what annaconda is and how it works |
| `/console` | **Analyst console** — the case queue: one case per host, verdicts accumulate into a single sealed record (Firestore-backed) |
| `/exhibit` | Court-exhibit dashboard — run a sealed investigation (benign or attack), watch the agent investigate, replay to prove determinism |
| `/consult` | Mentor console — a second agent that teaches junior examiners |
| `/architecture` | End-to-end architecture walkthrough |

In `/exhibit`, press **Run attack scenario** then **Ask the agent**: the agent
autonomously collects telemetry, adjudicates a sealed MALICE verdict
(T1070.006 Timestomp + T1055.012 Process Hollowing, caught as a structural
impossibility — a C2 beacon observed before its own process existed), pivots to
check for persistence, and narrates the sealed result. Its full decision log is
shown step by step.

## Architecture

```
Browser → Cloud Run (FastAPI) → ADK agent (Gemini 3.5, Vertex AI)
                                     │  chooses hunts, narrates
        ───────────── trust boundary ─────────────
                                     ▼  everything below is deterministic
   run_hunt      → curated Velociraptor VQL → sealed evidence window (SHA-256)
   adjudicate    → deterministic core (CAIE) → verdict + MITRE, no model, no float
   seal          → hash-chained verdict stream (tamper-evident)
```

The agent orchestrates and explains; the sealed engine decides. See
[`/architecture`](https://vigia-live-1028999311218.us-central1.run.app/architecture)
for the full walkthrough.

**Two ADK agents.** The *investigator* (`agent/purple_team_agent.py`) drives the
hunt loop; the *mentor* (`agent/consult_agent.py`) teaches junior examiners with
read-only tools. Both act and explain; neither decides.

**The analyst workflow.** A *case* (`service/case_store.py`) is one host's
tamper-evident record: each investigation run continues the case's sealed chain,
so the whole case verifies as one unbroken record. Cases persist in Firestore
(with honest degradation to in-memory when Firestore is unreachable — `/health`
reports which backend is active).

**It runs without you.** Cloud Scheduler → Pub/Sub → a push to `/tasks/sweep`
continues hunts on open cases on a cron, appending sealed windows with no human
in the loop. `/health` shows `autonomous_sweeps`. (See DEPLOY.md.)

**ABSTAIN is memory, not a dead end.** When the engine cannot conclude (e.g. a
partial collection), the case records *why* it abstained and *what evidence
would resolve it* — real working memory, not a chat log. The autonomous sweep
reopens the case, and when a later run reaches a definitive verdict the open
question is resolved and recorded. An investigation that survives across weeks,
not one that forgets.

## How it meets the hackathon requirements

| Requirement | How |
|-------------|-----|
| Gemini 3.5+ | `gemini-3.5-flash` via **Vertex AI** (`GOOGLE_GENAI_USE_VERTEXAI`), through the Cloud Run service identity |
| Google Agent Framework | **Google ADK** — two agents (investigator, mentor) |
| Google Cloud service | **Cloud Run** (backend) + **Firestore** (case persistence) + **Vertex AI** |

## Run it

### Locally

```bash
pip install -r requirements.txt
# Agents use Vertex AI on Cloud Run; locally set a Gemini API key:
export GEMINI_API_KEY=...            # for the agent/mentor turns
uvicorn service.app:app --port 8080
# open http://localhost:8080
```

Without a Gemini key the deterministic paths still work (scripted
investigations, sealing, replay); only the agent narration needs the model.
Without Firestore credentials the case store degrades to in-memory and says so.

### On Google Cloud Run

Full step-by-step (and the one non-obvious gotcha — Gemini 3.x on Vertex is
served from location `global`, not a region) is in **[DEPLOY.md](DEPLOY.md)**.
In short:

```bash
gcloud run deploy vigia-live --source . --region us-central1 \
  --allow-unauthenticated --min-instances 1 --max-instances 1 \
  --set-env-vars GOOGLE_GENAI_USE_VERTEXAI=TRUE,GOOGLE_CLOUD_LOCATION=global,GOOGLE_CLOUD_PROJECT=<project>
```

The Cloud Run service account needs `roles/datastore.user` for Firestore.

### Prove the live evidence path

annaconda can collect from a real Velociraptor, not just fixtures:

```bash
python3 scripts_lib/live_velociraptor_demo.py
# collects real process telemetry from THIS host via the Velociraptor binary,
# seals it into a window, and adjudicates it
```

### Tests

```bash
pip install pytest && python3 -m pytest
```

The suite includes the load-bearing guarantee: the same case scored in two fresh
processes (different `PYTHONHASHSEED`) produces byte-identical seals.

## Tech stack

Python 3.12 · FastAPI on Cloud Run · Google ADK · Gemini 3.5 via Vertex AI ·
Firestore · Velociraptor (independent AGPLv3 service, reached over its API) ·
MITRE ATT&CK v14.1. The deterministic core is **stdlib-only** by design — no
floats, no black-box dependencies in any sealed value.

## Honest limitations

- The deployed demo runs on bundled telemetry (a benign baseline and a
  compromised-endpoint scenario). The **live Velociraptor transport is real and
  proven** (`VelociraptorQueryTransport`), but collecting from remote Windows
  endpoints needs a Velociraptor server with clients enrolled and network
  reachability to it — infrastructure, not code.
- Firestore persistence is per-case; the app is a single Cloud Run instance for
  the demo. Multi-instance sharing works through Firestore.
- An `ABSTAIN` verdict is a first-class, honest outcome, not a failure — a
  defensible "I cannot conclude" beats a confident wrong answer.

## Roadmap

Built and deployed: the sealed deterministic core, two ADK agents (investigator
with a visible decision log, mentor), real attack detection, the ML nominator,
per-host Firestore-backed cases with one continuing sealed chain, the
prompt-injection defense (two Google models, one hash), autonomous sweeps
(Scheduler → Pub/Sub → Cloud Run), ABSTAIN-as-memory reentry, and a
**specialized fleet** — a dispatcher that routes collection to per-domain
hunters and a correlator that alone reaches the sealed core, with strictly
disjoint tool contracts (verified by a test, shown on `/exhibit` under **Run
the fleet**), and a **sealed agent registry** — every agent published with a
version and the hash of its tool manifest (same encoder that seals verdicts);
the runtime refuses to load an agent whose manifest is not approved
(`GET /registry`; `agent/registry.py`). Next:

- **OpenTelemetry → Cloud Trace** for end-to-end agent-reasoning tracing.

## License & attributions

Apache-2.0 — open source not because the hackathon requires it (it doesn't), but
because forensic tooling that decides on people's lives should be inspectable by
anyone. Pre-existing work this builds on is disclosed in
[ATTRIBUTIONS.md](ATTRIBUTIONS.md).
