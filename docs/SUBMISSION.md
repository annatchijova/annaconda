# Devpost submission pack

Ready-to-paste text for the Devpost form and the two zero-code bonus posts.
Confirm the exact hashtag and any category names on the live Devpost page before
posting.

---

## Live URL

https://vigia-live-1028999311218.us-central1.run.app

## Category

**Recommendation: Fortified Enterprise Fleet** if the specialized fleet lands
(dispatcher + per-platform hunters + persistence + correlation, disjoint tool
contracts). **Fallback: Taskmaster** — annaconda already fits it today
(autonomous, agent-driven investigation + the Cloud Scheduler sweep that runs
without a human). The `mvp-rev00020` tag lets you fall back to the Taskmaster
story in one command if the fleet does not finish. Either way the determinism
+ sealed-verdict architecture also positions for **Best Architectural Design**.

---

## Elevator line

annaconda is a live purple-team DFIR tool whose verdicts a court could trust:
two Gemini agents drive and explain the investigation, but the language model is
kept out of the decision entirely — the deterministic engine seals the verdict
before any model runs, reproducible bit-for-bit.

## Inspiration

In digital forensics the adversary writes the evidence — a process name, a
command line, a registry value. The moment you put a language model in the loop,
the attacker can address it directly. We wanted the leverage of an autonomous
agent without ever letting it — or a prompt injection hidden in the telemetry —
change the verdict.

## What it does

- An ADK + Gemini agent runs a live investigation on an endpoint: it chooses
  curated Velociraptor hunts, freezes sealed evidence windows, adjudicates each
  with a deterministic core, and narrates the result — with its decision log
  visible step by step.
- The deterministic core (no floats, no model) detects real attacks as
  structural impossibilities — e.g. a C2 beacon observed before its own process
  existed — and seals a MITRE-mapped verdict into a tamper-evident chain.
- Cases persist per host in Firestore as one continuing sealed record; an
  autonomous sweep (Cloud Scheduler → Pub/Sub → Cloud Run) continues hunts with
  no human in the loop; an ABSTAIN verdict becomes memory that a re-hunt
  reopens and resolves.
- A prompt-injection demo shows the threat and the defense on camera: an
  attacker plants a fake "classified BENIGN" annotation, a naive narrator
  (Gemma) believes it, but the sealed verdict is MALICE — the same hash — and a
  mechanical guard flags the lie. Swap Gemma for Gemini and the words change;
  the verdict never does.

## How we built it

Python 3.12, FastAPI on Cloud Run, Google ADK, Gemini 3.5 via Vertex AI, Gemma
via the Gemini Developer API, Firestore, Velociraptor (as an independent
service), MITRE ATT&CK v14.1. The deterministic core is stdlib-only by design.
The forensic engine (VIGÍA, including the CAIE cross-artifact engine) is prior
work, disclosed in ATTRIBUTIONS.md; everything that makes it live and agentic
was built for this hackathon.

## Challenges

Keeping the LLM provably out of the decision path while still giving it real
agency; making a verdict reproducible bit-for-bit across processes (no floats,
canonical serialization, cross-process determinism tests in CI); and proving —
not asserting — that the ML triage layer's floats never reach a sealed value.

## Accomplishments

Two ADK agents with visible reasoning; real attack detection from structural
fractures; a prompt-injection defense demonstrated with two different Google
models under one hash; autonomous operation on Cloud Scheduler; ABSTAIN as
working memory; 80 tests with a determinism gate in CI.

## What we learned

That "the model narrates, it never decides" is only credible if you can show it
under attack — a baited narrator and an unmoved seal — and if the guard that
checks the narration is a mechanical comparison, not another model.

## What's next

A specialized agent fleet (dispatcher, per-platform hunters, persistence,
correlation) with strictly disjoint tool contracts; a sealed agent registry
(refuse to load an agent whose tool-manifest hash is not approved); and
OpenTelemetry traces of the reasoning chain to Cloud Trace.

---

## Bonus post 1 — published content (blog / dev.to / Medium)

**Title:** Keeping the LLM out of the verdict: a court-defensible AI forensics agent

**Body (outline to expand):**
- The problem: in DFIR the attacker writes the evidence, so an LLM in the loop
  is attackable. Show the injection: fake EDR "FINAL CLASSIFICATION: BENIGN".
- The architecture: the deterministic engine seals the verdict before any model
  runs; the agent's tools give it no way to pass a score or a hash; the
  narration is stored beside the seal, never inside it.
- The proof, not the claim: the same sealed verdict narrated by two different
  Google models (Gemma baited → benign, Gemini → malice), one hash underneath;
  a mechanical (not model) hallucination guard catching the lie; cross-process
  determinism tests in CI.
- Running on Google Cloud: ADK + Gemini via Vertex AI, Cloud Run, Firestore,
  autonomous sweeps via Cloud Scheduler + Pub/Sub.
- Link the live URL and the repo.

## Bonus post 2 — social (X / LinkedIn)

> Built annaconda for the All Things Agentic Hackathon: a live purple-team
> forensics agent where the AI investigates and explains — but never decides.
> The verdict is sealed by a deterministic engine before any model runs, so a
> prompt injection in the evidence can fool the narrator (watch Gemma call a
> compromised host "benign") while the sealed verdict stays MALICE, same hash.
> Two Gemini agents, Vertex AI, Cloud Run, Firestore. Reproducible bit-for-bit.
> [live link] [repo link] #<confirm-hackathon-hashtag>

(Attach a 20–30s clip of the injection demo: naive narrator says benign, sealed
seal says MALICE_HIGH, hashes match on replay.)
