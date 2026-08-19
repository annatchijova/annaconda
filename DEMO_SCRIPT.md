# Demo video script — annaconda (≤ 4 minutes)

All Things Agentic Hackathon · category: **Fortified Enterprise Fleet**.
Record against the live service:
**https://vigia-live-1028999311218.us-central1.run.app**

Rules confirmed against the official page (not carried over): **max 4 minutes**
(only the first 4 are evaluated if longer — front-load the strongest beats),
uploaded **public on YouTube or Vimeo**, **English or English subtitles**, must
**show the backend running on Google Cloud**, and **no third-party logos,
trademarks, or music**. Deadline **Aug 31, 5:00 PM Pacific**.

**Before recording:**
1. Open `/console` and click **Reset demo** — seeds three stable showcase cases
   (benign, malice, one stuck in ABSTAIN) that the sweep never touches.
2. Record in **dark mode** (the ◐ toggle) — it reads as the 3am instrument the
   product is, and the verdict colours carry better on video.
3. Keep the `*.run.app` URL visible in the address bar the whole time.

The category's own words are the outline. The judges ask three things of a
fleet: agents **cataloged for cross-department use**, **context maintained
safely across weeks of asynchronous operation**, and **production data without
violating compliance**. Every beat below answers one of them on camera.

Tone: calm, forensic. Let the hashes, the refusal, and the two narrators do the
work. Times are cumulative.

---

### 0:00–0:30 · The document that lies (open `/exhibit`)

No explanation yet. Click **Prompt-injection attack**. Let the panel land in
silence.

> "The attacker wrote this line into the endpoint's own telemetry. A language
> model read it and told the analyst: this host is **benign**. And here is
> annaconda's verdict on the same host: **MALICE — sealed**, with a hash."

Point at the planted EDR annotation, the naive narrator saying *benign*, the
sealed MALICE beside it. Let the judge feel the contradiction.

### 0:30–1:00 · The thesis

> "In forensics the adversary writes the evidence, so a model in the loop can be
> addressed directly. annaconda keeps the model out of the decision entirely:
> a deterministic engine — no model, no floating point — produces and **seals**
> the verdict before any model runs, and no agent has a tool that can change
> it. The agents investigate and explain. The engine decides. That rule is
> structural, and everything you're about to see runs on top of it."

### 1:00–2:10 · The fleet, working with nobody watching (open `/fleet-console`)

This is the category's main course. Two panels, two claims.

**The catalog** (top panel):

> "This is an enterprise fleet, so the agents are **published, not just
> deployed**. Each one is cataloged with the data classes it may touch, who it
> may delegate to, and the SHA-256 of its tool manifest — the runtime refuses
> to load an agent whose manifest wasn't approved."

Switch **Viewing as department** to `soc`:

> "And it's cross-department: this is the fleet as the SOC sees it. The
> correlator — the only agent that reaches the sealed core — isn't published to
> them at all."

**The cycle** (middle panel). Select **DEMO-MALICE**, leave `incident-response`,
click **Run a cycle**:

> "Cloud Scheduler wakes this fleet on a cron. Watch one cycle — the same code
> path that runs at 3am. The commander reads the case's memory, tasks a hunter
> to freeze a sealed evidence window, sends it to the correlator, and the
> engine seals **MALICE_HIGH** with its MITRE techniques. Then the commander
> escalates to a human — and look at the escalation: it carries the sealed
> verdict and entry hash it rests on, attached by the tool, not by the model.
> An agent here cannot claim a verdict it didn't get."

Now switch **Running as** to `soc` and run again:

> "Same cycle, run as the SOC — and the catalog **refuses the adjudication**.
> The collection they're cleared for proceeds; the verdict they're not cleared
> for never happens. Compliance here is a gate that says no, not a policy
> document."

### 2:10–2:50 · Memory across weeks (scroll to Mission memory)

> "What survives to the next cycle — days or weeks later — is this: the case's
> working memory. What was already collected, so the fleet doesn't repeat
> itself. The next wake-up **it scheduled for itself** — a compromised host
> gets an hour, a quiet one gets a day. And the whole memory is a hash chain,
> verified on every read, sealed with the same recipe as the verdicts: memory
> an autonomous fleet keeps for weeks is memory an attacker has weeks to edit."

Point at `CHAIN verified · head …`. Then click **Take this up** on the
escalation, type a note ("host isolated, ticket INC-4412"):

> "An escalation stops being shown because a named examiner took it up and said
> what they did — recorded into the sealed journal — never because something
> newer arrived."

### 2:50–3:25 · Two narrators, one hash (back on `/exhibit`, panel still there)

> "The proof of the whole design, not the claim. The same sealed verdict,
> narrated by two different Google models. **Gemma**, the naive one, swallowed
> the bait and said benign. **Gemini**, told the verdict is final, reported
> MALICE. Different models, different words — **the same hash underneath**.
> And a mechanical guard — not another model — flagged the false 'benign'
> against the sealed fields automatically."

### 3:25–3:45 · The Google Cloud proof (open `/health`)

> "All of it on Google Cloud: two-plus ADK agents on Gemini via Vertex AI,
> cases and memory in Firestore, cycles woken by Cloud Scheduler through
> Pub/Sub into Cloud Run. And the load-bearing claim is a CI test: the same
> case scored in two fresh processes produces **byte-identical seals**."

`/health` shows `vertex_ai: true`, `case_store: firestore`,
`llm_in_decision_path: false`, `autonomous_cycles`, `sweep_cycle_cap`.

### 3:45–4:00 · Honest limitations (say these yourself)

> "What this is not, yet: the demo runs on bundled telemetry — the live
> Velociraptor transport is real and tested, but enrolling Windows endpoints
> needs a lab. The catalog authorizes departments the demo doesn't yet
> authenticate — the production posture is one env var away, and every record
> says whether the identity was verified or asserted. And ABSTAIN is a
> first-class outcome here, not a failure — a defensible 'I cannot conclude'
> beats a confident wrong answer. That last part is the whole point."

End on the sealed MALICE readout and the word "reproducible".

---

## Shot checklist (the required "backend on Google Cloud" proof)

- [ ] `Reset demo` clicked before recording; dark mode on.
- [ ] The live `*.run.app` URL visible throughout.
- [ ] `/catalog` as `soc`: the correlator absent from their view.
- [ ] A cycle as `incident-response`: commander → hunter → correlator →
      sealed MALICE_HIGH → escalation **resting on** the entry hash.
- [ ] The same cycle as `soc`: `refused by the catalog` in red.
- [ ] Mission memory: `CHAIN verified`, already-collected, self-scheduled
      next cycle; the escalation taken up by a named examiner.
- [ ] The two-narrator panel: Gemma benign vs Gemini malice, one hash.
- [ ] `/health`: `vertex_ai: true`, `case_store: firestore`,
      `llm_in_decision_path: false`, `autonomous_cycles`.

## Fallbacks

- If the Gemini turn is slow or rate-limited on camera, the cycle falls back to
  the deterministic planner and **says so on screen** — that's honest, not
  broken; you can even point at the label.
- If the injection demo's Gemma call fails, the panel says the model is
  unavailable and that the sealed verdict is unaffected — the seal beat still
  lands.
- The `mvp-rev00020` tag remains the one-command fallback to the pre-fleet
  Taskmaster story if anything is on fire on demo day.
