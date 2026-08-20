# Devpost submission pack

Ready-to-paste text for the Devpost form and the two zero-code bonus posts.
Confirm the exact hashtag and any category names on the live Devpost page before
posting.

---

## Live URL

https://vigia-live-1028999311218.us-central1.run.app

## Category

**Fortified Enterprise Fleet.** The track asks for three things, and each is a
gate in code with a test behind it (see `docs/COMPLIANCE.md`):

| Track criterion | annaconda |
|---|---|
| Agents cataloged for cross-department use | `GET /catalog?department=soc` returns the fleet as that department sees it — publication, clearances, delegation graph, each entry naming the manifest hash the sealed registry approved |
| Context maintained safely across weeks of asynchronous operation | Per-case mission memory whose every mutation is sealed into a hash chain, plus a schedule the fleet sets for itself so cases are worked when due, not polled |
| Production data without violating compliance, sovereignty, security | Every delegation passes a catalog gate (department · data class · region), and no agent anywhere can reach the verdict |

The determinism + sealed-verdict architecture also positions for **Best
Architectural Design**. A **Taskmaster** fallback still fits (the unattended
end-to-end workflow, escalation included) if the fleet story is crowded.

## Elevator line

annaconda is a live purple-team DFIR fleet whose verdicts a court could trust: a
commander agent works cases unattended for weeks — choosing what to hunt,
carrying a tamper-evident memory, escalating to a human when one is needed — but
the language model is kept out of the decision entirely. The deterministic
engine seals the verdict before any model runs, reproducible bit-for-bit.

## Inspiration

In digital forensics the adversary writes the evidence — a process name, a
command line, a registry value. The moment you put a language model in the loop,
the attacker can address it directly. We wanted the leverage of an autonomous
agent without ever letting it — or a prompt injection hidden in the telemetry —
change the verdict.

## What it does

- **It works without you.** Cloud Scheduler wakes a fleet of ADK + Gemini agents
  on a cron. A commander reads what earlier cycles established, tasks the
  specialists it is *cleared* to task, adjudicates through a deterministic
  engine, and decides when to look again, when a human is needed, and when to
  stop. It sets its own per-case cadence, so a compromised host is re-checked in
  an hour and a quiet one in a day.
- **It cannot decide what the evidence means.** The commander holds no
  collection tool and no adjudication tool of its own — only the authority to
  task specialists who do, through a catalog gate checked on every call. The
  deterministic core (no floats, no model) detects real attacks as structural
  impossibilities — a C2 beacon observed before its own process existed — and
  seals a MITRE-mapped verdict before any model sees it.
- **Its memory is tamper-evident.** What one cycle leaves for the next — open
  hypotheses, collections already run, unresolved questions — is sealed into a
  hash chain with the same recipe that seals verdicts, and re-verified on every
  read. And it cannot reach the verdict: a test fills memory with the most
  persuasive lie available and shows every seal unmoved.
- **It is published, not merely deployed.** `GET /catalog?department=soc` shows
  the fleet as one department sees it. Run a cycle as the SOC and the
  adjudication request is refused — adjudication belongs to forensics — while
  the collection the SOC is cleared for proceeds.
- **A prompt-injection demo shows the threat and the defense on camera:** an
  attacker plants a fake "classified BENIGN" annotation, a naive narrator
  (Gemma) believes it, but the sealed verdict is MALICE — the same hash — and a
  mechanical guard flags the lie.

## How we built it

Python 3.12, FastAPI on Cloud Run, Google ADK, Gemini 3.5 via Vertex AI, Gemma
via the Gemini Developer API, Firestore, Velociraptor (as an independent
service), MITRE ATT&CK v14.1. The deterministic core is stdlib-only by design.
The forensic engine (VIGÍA, including the CAIE cross-artifact engine) is prior
work, disclosed in ATTRIBUTIONS.md; everything that makes it live and agentic
was built for this hackathon.

## Challenges

Giving an agent enough agency to run an investigation for weeks unattended
while keeping it provably out of the verdict — the answer was to put the
boundary in the tool contracts (the commander owns nothing that collects or
adjudicates) rather than in a prompt. Then: making memory that survives weeks
also survive an attacker with weeks to edit it; making a verdict reproducible
bit-for-bit across processes; and getting an unattended cycle to fail honestly —
a collection that fails has to be recorded as an unobserved host, never as one
that was looked at and found quiet.

## Accomplishments

A fleet that genuinely runs itself — agent-driven cycles, self-set schedules,
escalation with reasoning, and a decision to stand down — with the verdict still
untouchable; an enterprise catalog that refuses taskings by department, data
class and region; tamper-evident mission memory; a prompt-injection defense
demonstrated with two different Google models under one hash; 140 tests with a
determinism gate in CI.

## What we learned

That "the model narrates, it never decides" is only credible if you can show it
under attack — a baited narrator and an unmoved seal — and if the guard that
checks the narration is a mechanical comparison, not another model. And that
autonomy is the harder half: an agent that cannot decide to stop is a loop, and
an agent that reports a failed collection as a quiet host is worse than no agent
at all.

## What's next

Chunking the sealed chains across Firestore documents so a case worked daily for
years does not meet the per-document limit; authenticating the department so the
catalog's principal comes from a Cloud Run identity token rather than a request
body; and a regional model endpoint for organisations whose residency rules
cover the narration, not just the evidence.

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
