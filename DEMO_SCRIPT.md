# Demo video script — annaconda (≤ 4 minutes)

Target: All Things Agentic Hackathon. The rules require the video to show the
backend running on Google Cloud. Record against the live service:
**https://vigia-live-1028999311218.us-central1.run.app**

Tone: calm, confident, forensic. Let the sealed hashes and the agent's visible
reasoning do the work. Times are cumulative.

---

### 0:00–0:20 · The thesis (open on `/`)

> "This is annaconda. It analyzes an endpoint as an attack unfolds and seals a
> court-defensible verdict. The twist: the AI agent runs the investigation, but
> it never decides the verdict. The deterministic engine seals the result before
> any model describes it — so the answer is reproducible, not persuadable."

Show the landing hero and the one-invariant callout.

### 0:20–1:15 · The agent investigates (go to `/exhibit`)

1. Click **Run attack scenario** → the seal turns red, **MALICE_HIGH**.
2. Click **Ask the agent**. As it runs, narrate:

> "The agent is autonomous. Watch its decision log."

Point at the **Agent investigation log** appearing step by step:

> "It collected processes and network together, adjudicated a sealed MALICE
> verdict — Timestomp and Process Hollowing — then, on its own, pivoted to check
> for persistence. Every step is a tool call; none of them can change the
> verdict."

Highlight the MITRE techniques (T1070.006, T1055.012) and the sealed entry hash.

### 1:15–1:45 · The differentiator: reproducible (still `/exhibit`)

Click **Replay & re-verify seals**.

> "Here's what nothing with an LLM in the decision path can show. We re-derive
> every seal from the recorded evidence — and the hashes match, bit for bit.
> Swap Gemini for any other model and the wording changes; the verdict, the
> score, the hash never do."

Let the "HASHES MATCH ✓" land on screen.

### 1:45–2:35 · The analyst's real workflow (go to `/console`)

> "This is how an examiner actually uses it. One case per host. Verdicts
> accumulate into a single tamper-evident record that reopens and defends later."

- Point at the queue: worst-verdict-first (what needs attention on top).
- Open a case: show its sealed verdicts, MITRE, and **chain of custody intact**.
- Click **Investigate (attack)** to append a run; show the chain still verifies.
- Note the `storage: firestore` badge:

> "Persisted in Firestore. And if storage ever degrades, it says so — it never
> pretends a record is durable when it isn't."

### 2:35–3:05 · The second agent: the mentor (go to `/consult`)

Ask: *"VIGIA gave me ABSTAIN_INSUFFICIENT and I'm worried I did something wrong."*

> "A second ADK agent mentors junior examiners. Notice it teaches that an honest
> ABSTAIN is scientific integrity, not a failure — grounded in the engine's real
> definitions, and it never decides the case for them."

### 3:05–3:35 · Running on Google Cloud (open `/architecture`, then `/health`)

Show the architecture walkthrough (the trust boundary), then hit `/health`:

> "The whole thing runs on Google Cloud: the backend on Cloud Run, Gemini 3.5
> through Vertex AI, two agents on Google's Agent Development Kit, cases in
> Firestore."

`/health` shows `vertex_ai: true`, `case_store: firestore`,
`llm_in_decision_path: false`.

### 3:35–4:00 · Close

> "annaconda: a live purple-team agent that hunts, maps to MITRE, and seals a
> reproducible verdict a court could trust — with the language model kept out of
> the decision entirely. Open source, Apache-2.0, because forensic tooling that
> decides on people's lives should be inspectable by anyone."

End on the red seal and "reproducible" tagline.

---

## Shot checklist (for the required "backend on Google Cloud" proof)

- [ ] The live `*.run.app` URL visible in the address bar throughout.
- [ ] `/health` showing `vertex_ai: true` and `case_store: firestore`.
- [ ] Optional: a glimpse of the Cloud Run service in the GCP console.
- [ ] The replay "HASHES MATCH" moment.
- [ ] The agent investigation log with its step-by-step reasons.
