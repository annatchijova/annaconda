# Running a fleet on production data without giving it the keys

This is the enterprise question annaconda has to answer to be trusted with real
endpoint telemetry: *if these agents run unattended for weeks, what exactly can
they do, who authorised it, and what stops one of them — or a prompt injection
that reaches one — from doing something else?*

Three mechanisms answer it, and each one is a gate in code with a test behind
it, not a paragraph of intent.

---

## 1. Agents are published, not merely deployed

`agent/catalog.py` is the enterprise catalog. Every agent in the fleet is
published with:

| Field | What it constrains |
|---|---|
| `department` | who owns the agent |
| `available_to` | which departments may task it |
| `tools` | its exact tool contract |
| `manifest_hash` | the SHA-256 of that contract, as approved in the sealed registry |
| `data_classes` | the classes of data it is cleared to touch |
| `delegates_to` | which other agents it may task |
| `reaches_sealed_core` | whether it can reach the deterministic engine at all |
| `region` | where its data may be processed |

`GET /catalog?department=soc` returns the fleet *as that department sees it* —
a cross-department view, not a flat list.

**The gate.** `catalog.authorize(agent, department=…, data_classes=…, region=…)`
raises rather than returns for a tasking that is not published, not cleared, or
not in-region. It is called on every delegation the commander attempts, at the
tool boundary, on every call — not once at startup.

**Demonstrable least privilege.** Adjudication belongs to forensics. Run the
autonomous cycle as the SOC and watch the adjudication request get refused
while the collection it *is* cleared for proceeds:

```bash
curl -X POST "$URL/cases/CASE-1/cycle" -d '{"department":"soc"}'
# fleet_log: {"role":"correlator","action":"refused_by_catalog", …}
# verdicts: []
```

That refusal is `tests/test_autonomous_service.py::
test_a_cycle_run_as_the_soc_is_refused_the_adjudication`.

**One identity, checked twice.** A catalog entry names a manifest hash; the
sealed registry (`agent/registry.py`) refuses to *load* an agent whose manifest
is not approved. Add a tool to an agent out of band and its hash changes: the
registry will not build it, and the catalog entry no longer describes it.

---

## 2. Context across weeks, and proof it was not edited

`agent/mission.py` is the case's working memory: open hypotheses, collections
already run, unresolved questions, the schedule the fleet set for itself, and
the reasoning behind each. It is what one cycle leaves for the next, which may
be days later.

Memory an autonomous fleet keeps for weeks is memory an attacker has weeks to
edit. So every mutation appends a journal entry sealed over the previous one,
with the same canonical-v2 + SHA-256 recipe that seals verdicts. `GET
/cases/{id}/mission` re-verifies the chain on every read; editing, reordering,
dropping, or forging an entry is detected (four tests in
`tests/test_mission.py`).

**Pacing, not polling.** The fleet schedules its own next wake-up per case
(`schedule_next_cycle`), so `/tasks/sweep` works only the cases that are *due*.
A host adjudicated malicious is re-checked in an hour; a quiet one in a day;
one with nothing left to do gets a `stand_down` and is not touched again. Most
wake-ups on most cases correctly do nothing — `/health` reports
`cases_worked_last_sweep` against `cases_not_due_last_sweep`.

**Schema versioning.** Missions carry `schema_version`. A case opened months
ago under an older shape is migrated forward on read, and the migration is
recorded in its own journal. An unrecognised version is refused, not guessed.

---

## 3. The model cannot reach the decision, on any path

This is annaconda's founding invariant, and autonomy does not weaken it — it is
what makes autonomy defensible.

- The deterministic core scores the evidence with exact arithmetic (no floats)
  and **seals** the verdict with SHA-256 before any model sees the result.
- The commander's tool contract contains no collection tool and no adjudication
  tool. It cannot gather evidence and it cannot adjudicate; it can only task
  specialists who are cleared to. `tests/test_autonomy.py::
  test_the_commander_holds_no_collection_or_adjudication_tool_of_its_own`
  asserts its contract is disjoint from every specialist's.
- Nothing in mission memory is an input to the case's status or verdict.
  `service/case_store._apply_run` computes both from the sealed chain alone.
  The test for this fills memory with the most persuasive lie available — every
  hypothesis refuted, a stand-down declaring the host clean and quoting a
  fabricated hash — and shows the status and every seal unchanged.

So the blast radius of a compromised or manipulated agent is bounded to *what
gets investigated and when*. It cannot reach *what the evidence means*.

**And what it says is checked against what was sealed.** An agent working
unattended can escalate or narrate at any point in a cycle — including after a
collection failed and nothing was adjudicated at all. Two mechanical checks,
neither of them another model:

- Every escalation carries a `sealed_basis`: the verdict states and entry
  hashes the cycle actually sealed, read from the adjudicated record by the
  tool itself. The agent cannot supply, inflate, or suppress it. An escalation
  that rests on nothing is recorded with `unsupported_by_seal: true` rather
  than refused — refusing could strand a real incident; what it must not do is
  look supported.
- Escalation text and the closing narration are compared against the sealed
  verdict states of that cycle. A verdict named in prose but never sealed is
  reported as `unsealed_verdict_claims` and shown on the fleet console.

`tests/test_commander_loop.py` drives the real ADK loop with a scripted model to
exercise exactly this: a commander that escalates citing `MALICE_HIGH` after a
failed collection, and one that narrates `BENIGN_HIGH` over a sealed
`MALICE_HIGH`. Both are flagged; neither moves a seal.

---

## Data residency — what is and is not covered

**Covered.** Evidence windows, sealed verdicts, and case memory are processed by
the stdlib-only deterministic core inside the Cloud Run service and stored in
Firestore, both in `us-central1`. `catalog.HOME_REGION` is enforced by
`authorize`, so a second region cannot be introduced without an explicit
catalog change.

**Not covered.** The model round-trip. Gemini 3.x on Vertex AI is served from
location `global`, not a region — narration prompts leave `us-central1` by
design, and no configuration in this repo changes that. This is the reason the
commander is cleared for `case_memory` only and never for raw
`endpoint_telemetry`: what reaches the model is sealed results, the mission
brief, and its own instructions — not evidence rows it was not cleared for.

An organisation with a hard data-residency requirement on the *narration* would
need a regional model endpoint. That is a deployment change, not a code change,
but it is not done here and should not be claimed.

## Other honest limits

- **Firestore document size.** A case document holds its sealed entries and its
  mission journal, and both grow with every cycle. Firestore's 1 MiB per-document
  limit will eventually be reached on a long-running case. Truncating a hash
  chain to fit would break its verification — which is the chain working as
  designed — so the real fix is chunking the chain across documents. It is not
  implemented. A case worked daily has ample headroom for the review period;
  a multi-year deployment does not.
- **Rate limiting** on the paid endpoints is a coarse per-instance sliding
  window (`VIGIA_RATE_MAX`). It stops a hammer; it is not a quota system.
- **Authentication.** The catalog gate is only as good as the identity in front
  of it, so `agent/principal.py` resolves one on every tasking and names its
  confidence. A presented Google identity token is verified and mapped to a
  department through the deployment's roster (`VIGIA_DEPARTMENT_ROSTER`); a
  verified identity wins over whatever the request claims, so a caller cannot
  present a SOC token and ask to run as forensics. With no verified identity
  the department is **asserted**, and the principal — department, identity,
  `authenticated: false`, and how it was resolved — is sealed into the case's
  mission journal, so a record answers "who ran this cycle, and was that
  verified" months later.

  The deployed demo runs `--allow-unauthenticated` and therefore asserts. That
  is a posture, not a gap in the mechanism: set
  `VIGIA_REQUIRE_AUTHENTICATED_PRINCIPAL=true` and an asserted principal is
  refused with 403. `/health` reports which posture is live. What remains
  genuinely undone is the identity provider itself — a real deployment puts
  Cloud Run IAM or an IAP in front and populates the roster.
- **Gemini's own behaviour is not tested here.** The ADK loop is —
  `tests/test_commander_loop.py` runs it end to end against a scripted
  `BaseLlm` that reads real tool results from the transcript, so tool
  declarations, function-call dispatch, result feedback, fallback on model
  failure and the seal checks all run in CI. What no offline test can cover is
  whether the live model chooses well. The architecture is built so that a bad
  choice costs a wasted collection, not a wrong verdict.
- **The trust boundary of the evidence itself** is unchanged and examined in
  [RED_TEAM_AUDIT.md](RED_TEAM_AUDIT.md): a sealed verdict certifies
  reproducible adjudication of the *collected* evidence, not the truth of that
  evidence.
