# Demo video script — annaconda (≤ 4 minutes)

All Things Agentic Hackathon. The rules require the video to show the backend
running on Google Cloud. Record against the live service:
**https://vigia-live-1028999311218.us-central1.run.app**

**Before recording:** open `/console` and click **Reset demo**. This seeds three
stable showcase cases (benign, malice, and one stuck in ABSTAIN) that the
autonomous sweep will not touch — so the state is exactly what you expect.

Tone: calm, forensic. Let the hashes and the two narrators do the work. Times
are cumulative.

---

### 0:00–0:35 · The document that lies (open `/exhibit`)

No explanation yet. Click **Prompt-injection attack**. Let the panel land in
silence.

> "The attacker wrote this line into the endpoint's own telemetry. A model read
> it and told the analyst: this host is **benign**. And here is annaconda's
> verdict on the same host: **MALICE**, sealed."

Point at the planted EDR annotation, the naive narrator saying *benign*, and the
red sealed MALICE_HIGH beside it. Let the judge feel the contradiction before you
resolve it.

### 0:35–1:10 · The thesis (same panel)

> "In forensics the adversary writes the evidence. Put a language model in the
> loop and it can be addressed directly. So annaconda keeps the model out of the
> decision entirely: the deterministic engine produces and seals the verdict
> **before any model runs**, and the model has no tool that can change it. It
> narrates; it never decides."

Point at the trust-boundary line (or open `/architecture` briefly).

### 1:10–2:00 · Two narrators, one hash (same panel)

> "Here is the proof, not the claim. The same sealed verdict, narrated by two
> different Google models. **Gemma** — the naive one — swallowed the bait and
> said benign. **Gemini**, told the verdict is final, reported MALICE. Different
> models, different words — **the same hash underneath.**"

Then point at the guard line:

> "And a guard catches the baited narration — not a model judging a model, a
> mechanical comparison of the narrator's claims against the sealed fields. It
> flagged the false 'benign' automatically."

### 2:00–3:00 · Memory, and running without you (go to `/console`)

Open **DEMO-ABSTAIN**.

> "A real examiner's cases live here — one host, one tamper-evident record. This
> one couldn't conclude: the collection was partial, so annaconda returned an
> honest ABSTAIN instead of a false clean bill of health. And it remembers why,
> and what evidence would resolve it."

Read the open question. Then click **Investigate (benign)** (a complete
re-collection) — or mention the cron:

> "annaconda reopens ABSTAIN cases on its own — Cloud Scheduler to Pub/Sub to
> Cloud Run, no human in the loop. When the evidence arrives, the case resolves
> and the chain grows."

Show the open question flip to **resolved**, and the chain still verifies.

### 3:00–3:40 · Architecture & determinism (open `/architecture`, then `/health`)

> "Two ADK agents on Gemini via Vertex AI, cases in Firestore, all on Cloud Run.
> And the load-bearing claim is a test: the same case scored in two fresh
> processes produces byte-identical seals — with the ML triage layer running in
> the same pipeline. Reproducible in CI, not just in a slide."

`/health` shows `vertex_ai: true`, `case_store: firestore`,
`llm_in_decision_path: false`, `autonomous_sweeps`.

### 3:40–4:00 · Honest limitations (say these yourself)

> "What this is not, yet: the deployed demo runs on bundled telemetry — the live
> Velociraptor transport is real and tested, but pointing it at Windows
> endpoints needs a lab and network reach. It's a single Cloud Run instance. And
> ABSTAIN is a first-class outcome here, not a failure — a defensible 'I cannot
> conclude' beats a confident wrong answer. That last part is the whole point."

End on the red seal and "reproducible".

---

## Shot checklist (the required "backend on Google Cloud" proof)

- [ ] `Reset demo` clicked before recording.
- [ ] The live `*.run.app` URL visible throughout.
- [ ] `/health`: `vertex_ai: true`, `case_store: firestore`, `autonomous_sweeps`.
- [ ] The two-narrator panel: Gemma benign vs Gemini malice, one hash.
- [ ] The ABSTAIN open question resolving.
