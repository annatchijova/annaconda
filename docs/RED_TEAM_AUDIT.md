# Security Audit — annaconda

## Red Team Round 1–3
**Method:** Abductive Engineering (A–D–I) + Red-Team Auditing.
**Base:** `main` @ the rev deployed as Cloud Run `vigia-live-00024` (`aaa2bb3`),
audited before the fix in this report was applied.
**Runtime:** Python 3.12.
**Reproducible evidence:** the inductions are runnable scripts inlined below;
each states its prediction *before* the observation.

Certainty here is earned by induction, not asserted by confidence. Every finding
carries an explicit epistemic level, and two of the auditor's own hypotheses
were **falsified** — recorded as first-class results, because that is where the
method shows teeth.

## Threat model
- Attacker **CAN**: control the endpoint's reported telemetry (process names,
  command lines, image paths, timestamps, and the analyzer fields the adapter
  surfaces — `network_log_time`, `process_creation_time`, `injection_technique`,
  `pid_hidden`); call the public, unauthenticated HTTP endpoints.
- Attacker **CANNOT**: modify annaconda's code; hold GCP credentials; alter a
  window or verdict entry after it is sealed; write to Firestore directly.

## Epistemic legend
CODE FACT · PLAUSIBLE HYPOTHESIS · CONFIRMED BY INDUCTION · FALSIFIED

## Executive summary
| ID | Severity | Level | Bucket | Finding |
|----|----------|-------|--------|---------|
| RT-01 | Medium | CONFIRMED BY INDUCTION | threat-model boundary | A sealed MALICE verdict can be induced on a benign host by an attacker who controls the telemetry's structural fields; the golden-rule fractures bypass CAIE's spoofability weighting. |
| RT-02 | Low–Med | CONFIRMED BY INDUCTION | threat-model boundary | A real attack evades to a clean bill of health if the telemetry omits the correlating fields. |
| RT-03 | Medium | CONFIRMED BY INDUCTION | **vulnerability (fixed)** | A case whose worst verdict is MALICE displayed status `benign` after a later ABSTAIN resolved cleanly — hiding a real detection in the queue. Self-introduced this session; **fixed + regression test**. |
| RT-04 | Low | CODE FACT | hygiene | Several state-changing endpoints are public and unauthenticated; only `/injection-demo` and agent-mode `/investigate` are rate-limited. |
| RT-05 | Low–Med | CONFIRMED BY INDUCTION | vulnerability (detected, not silent) | `apply_run` is read-modify-write, so two runs on one case race and last-write-wins — but the resulting chain corruption is caught by `verify_stream` (fails loud), it is never silent. |

The core promise held under every attack aimed at it: **tamper-evidence and
bit-for-bit reproducibility did not break** (see Falsified / defended vectors).

---

## RT-01 — A wrong verdict can be sealed (frame via controlled telemetry)
**Severity:** Medium **Level:** CONFIRMED BY INDUCTION **Bucket:** threat-model boundary + design note

- **Expectation violated:** the sealed MALICE verdict reads as court-defensible
  ground truth. But it is computed from fields the attacker controls.
- **Abduction (ranked):** (1) the structural golden-rule fractures (TCV,
  process-injection) are computed purely from attacker-influenceable fields and
  are not down-weighted by CAIE's spoofability model; (2) the corroboration gate
  blocks it. Cheapest discriminating test: plant the fields on an all-benign host.
- **Deduction:** predict that attack-shaped telemetry, but with the malicious
  process renamed to a benign system binary (`lsass.exe` in `System32`), still
  seals MALICE, because CAIE keys on the structural fields, not the name/path.
- **Induction:** reproduced. All-benign process set + `network_log_time`
  (14:10) < `process_creation_time` (14:12) + `injection_technique`/`pid_hidden`
  planted on `lsass.exe` → **MALICE_HIGH, T1055.012 + T1070.006, sealed.**
- **Causal chain:**
  ```
  attacker-controlled telemetry fields
      ↓ adapter surfaces network_log_time / process_creation_time / injection_technique
  CAIE golden rules fire at fixed severity (TCV=1.0), bypassing spoofability weighting
      ↓ enough corroborating evidence present
  deterministic core seals MALICE on a benign host
  ```
- **Precondition:** the attacker controls the endpoint's reported telemetry.
  This is the inherent trust boundary of any DFIR tool — you can only analyze
  what you collect. The sharper, annaconda-specific note: CAIE's spoofability
  weighting exists precisely to discount attacker-controlled evidence, but the
  golden-rule *structural* verdicts do not benefit from it.
- **Not a code defect:** the sealing, the determinism, and CAIE all work as
  designed. The finding is that "sealed" certifies *the pipeline reached this
  verdict from this evidence, reproducibly* — never that the evidence was true.
- **Nuance (from the falsifications below):** this needs a corroborated
  telemetry picture; a thin planted fracture abstains rather than sealing MALICE.

## RT-02 — Evasion by field omission
**Severity:** Low–Medium **Level:** CONFIRMED BY INDUCTION **Bucket:** threat-model boundary

- **Deduction:** predict that stripping the promoted fields from real attack
  telemetry removes both fractures, so the host reads clean.
- **Induction:** reproduced. Attack fixtures with `network_log_time`,
  `process_creation_time`, `injection_technique`, `pid_hidden` removed →
  **NOISE / BENIGN_HIGH.** (Stripping only `network_log_time` did **not** evade —
  the injection fracture still fired MALICE; full omission was required.)
- **Precondition / bucket:** the inherent DFIR limit — a rootkit that hides from
  the collector hides from annaconda. Hygiene, not a breach; stated for honesty.

## RT-03 — A MALICE case could display "benign" (self-corrected)
**Severity:** Medium **Level:** CONFIRMED BY INDUCTION **Bucket:** vulnerability — **fixed**

- **Surprise:** the ABSTAIN-as-memory reentry logic (added this session) sets a
  case's status from the resolving verdict.
- **Deduction:** predict that a case sequence MALICE → ABSTAIN → BENIGN keeps
  `worst_verdict = MALICE_HIGH` (monotone) but sets `status = benign`.
- **Induction:** reproduced exactly — `worst_verdict = MALICE_HIGH`,
  `status = benign`. The queue still sorts by `worst_verdict`, so ordering was
  safe, but the status pill would show green on a red case — an analyst could
  dismiss a real detection.
- **Causal chain:** open-question resolution overrode `status` from the
  concluding BENIGN verdict without checking the case's worse history.
- **Fix:** `_update_open_question` now refuses to downgrade `status` below a case
  whose worst verdict is MALICE/ESCALATE. Confirmed by induction after the fix
  (`status = malice`), pinned by
  `test_a_malice_case_never_displays_benign_after_an_abstain_resolves`.

## RT-04 — Unauthenticated state-changing endpoints
**Severity:** Low **Level:** CODE FACT **Bucket:** hygiene

`/demo/seed`, `/fleet-investigate`, scripted `/investigate`, `POST /cases` and
`/cases/{id}/investigate` are public and unauthenticated; only `/injection-demo`
and agent-mode `/investigate` are rate-limited. A visitor can create junk cases
or spam deterministic runs (Firestore writes / cost). Acceptable for a scored
demo behind a budget alert; before any wider exposure, put the state-changing
endpoints behind auth or a shared token. Not an exploit — hygiene.

## RT-05 — Concurrent runs on one case race (detected, not silent)
**Severity:** Low–Medium **Level:** CONFIRMED BY INDUCTION **Bucket:** vulnerability — mitigated by detection

- **Surprise:** a case accumulates one continuing sealed chain, but two runs can
  hit it at once (e.g. the autonomous sweep and a manual investigation).
- **Deduction:** `apply_run` reads the case, appends, and writes back
  (read-modify-write, non-transactional in both the memory and Firestore
  backends). Predict that two runs from the same stale snapshot each start their
  sub-chain at the same sequence, so the merged chain has a sequence collision —
  and that `verify_stream` detects it rather than silently accepting it.
- **Induction:** reproduced. Two runs from one snapshot → merged case chain
  `chain_ok = False`, error `entry[1]: sequence 0 != 1 (gap, reorder, or
  truncation)`. The corruption is **detected**, not silent — the tamper-evident
  chain does its job even against an accidental race.
- **Precondition / impact:** requires two writes to one case to interleave. Demo
  showcase cases are excluded from the autonomous sweep, so the race window
  there is essentially nil; the exposure is a real deployment running the sweep
  concurrently with manual work on the same host.
- **Recommendation:** wrap `apply_run` in a Firestore transaction (read + write
  atomic) so concurrent runs serialize instead of racing. Not fixed here — the
  detection provides a safety net and the demo does not race.

---

## Falsified / defended vectors (the audit's teeth)
| Vector | Prediction | Result |
|--------|-----------|--------|
| Frame → sealed MALICE from a **thin** planted fracture (2 artifacts) | seals MALICE | **FALSIFIED** — verdict was ABSTAIN_INSUFFICIENT; the corroboration gate refused. Frame needs a full corroborated picture (RT-01). |
| Evade by stripping only `network_log_time` | evades to benign | **FALSIFIED** — PROCESS_INJECTION_ANTIFORENSIC still fired MALICE_HIGH. |
| Tamper a deep nested field of a sealed window | `verify_window` still True | **FALSIFIED (defense holds)** — original verifies True, tampered verifies False. Tamper-evidence covers the whole canonical form. |
| Break reproducibility with adversarial unicode (NFD, RTL override) in a command line | seal differs across processes | **FALSIFIED (defense holds)** — window hash identical across two `PYTHONHASHSEED` processes (canonical NFC normalization). |
| ML nominator floats reach a sealed value | sealed hash varies | **FALSIFIED (defense holds)** — sealed entry_hash byte-identical with the nominator in-pipeline; no nomination fields in the sealed stream (pinned in CI). |
| Canonicalization collision — two distinct objects, one hash (`int 1` vs `str "1"`) | one hash | **FALSIFIED (defense holds)** — v2 type-tagging hashes them distinctly. |
| Break the scorer with absurd timestamps (year 9999, year 1) | crash / bad seal | **FALSIFIED (defense holds)** — no crash; the window seals and scores NOISE. |
| Monotonicity — add 20 benign processes to an attack window to dilute it below MALICE | verdict drops | **FALSIFIED (defense holds)** — still MALICE_HIGH; adding benign evidence never lowers the verdict. |

The two central promises — **the LLM cannot change the verdict** and **the
verdict is reproducible and tamper-evident** — survived every direct attack.
The real findings live one layer out: the sealed verdict is only as trustworthy
as the telemetry it is computed from (RT-01/02), which is the honest, stated
boundary of the whole class of tool.

## Suspicions considered but not confirmed — capped at their honest level
These were reasoned about and deliberately not escalated. Recorded so the next
auditor does not re-walk them and so the certainty is not inflated past what was
actually done.

| Vector | Level | Why it stops here |
|--------|-------|-------------------|
| **Registry gate bypass by constructing an ADK `Agent(...)` directly**, skipping `require_approved` | PLAUSIBLE HYPOTHESIS · out of threat model | The gate lives in `build_agent` / `build_consult_agent` / `build_specialist`; nothing stops a *direct* `Agent(...)` call. But reaching that requires modifying code, which the threat model excludes. Every path in the deployed service routes through the gated builders. A defence-in-depth note, not a reachable exploit. |
| **Case/chain forgery by writing Firestore directly** | Out of threat model | Would let an attacker seat any verdict, but requires GCP credentials the model excludes. The chain is tamper-evident against *post-seal* edits (RT tamper test), not against someone who owns the datastore. |
| **`/demo/seed` reset during judging** | CODE FACT · hygiene | Public and unauthenticated; a visitor can reset the three showcase cases mid-review. Idempotent (recreates the same state), so it is self-healing, and demo cases are sweep-excluded. Annoyance, not a breach; folds into RT-04. |
| **Per-instance rate limiter under `max-instances 4`** | CODE FACT · hygiene | The `/injection-demo` limiter is per-instance in-memory, so the effective ceiling is ~4× the configured window across instances. Enough to stop a single hammer; a hard global cap would need a shared limiter. |
| **Mentor conversation continuity across instances** | CODE FACT · availability, not security | ADK mentor sessions are in-memory per instance; with `max-instances > 1` a follow-up turn can land on a different instance and lose context. A UX degradation, not a security finding. |
| **Audit-chain causality** | Boundary note | The sealed verdict chain proves insertion order and integrity, never that the sequence of verdicts is *causally* possible. Stated honestly; a hash certifies bytes, not truth. |
| **Cold start / Firestore quota** | Not a finding | Firestore free tier is ample for the demo load; `min-instances 1` keeps the service warm. No action. |

## Recommendations (record only; out of scope of the RT-03 fix)
- State RT-01/02 in the README's honest-limitations section: "a sealed verdict
  certifies reproducible adjudication of the collected evidence, not the truth of
  that evidence; annaconda inherits the collector's trust boundary."
- Consider extending CAIE's spoofability weighting to the golden-rule structural
  verdicts, or requiring a hard-to-spoof anchor before a structural rule can
  alone reach MALICE.
- Put the state-changing endpoints behind auth/a shared token before wider
  exposure (RT-04).
- Wrap `apply_run` in a Firestore transaction so concurrent runs on one case
  serialize instead of racing (RT-05).

---

# Red Team Round 4 — the autonomous fleet

**Method:** Abductive Engineering (A–D–I) + Red-Team Auditing.
**Scope:** the code built for autonomous operation — `agent/autonomy.py`,
`agent/mission.py`, `agent/catalog.py`, `agent/principal.py`,
`service/chain_store.py`, `service/case_store.py` and the service wiring.
**Base:** `claude/agentic-autonomous-project-d9y5u0` @ `f3d17a0`, audited
*before* the fixes in this round were applied.
**Runtime:** Python 3.11.15, `google-adk` 2.1.0.
**Reproducible evidence:** each finding below states its prediction before the
observation; the inductions are the tests named with each one, which fail on
`f3d17a0` and pass after the fix.

This round is Round 2–3 material on the escalation ladder: not "is this
function buggy" but "can the system reach a state its specification says is
impossible". All three confirmed findings are in code written during this
session — self-introduced, self-found, fixed.

## Threat model
Unchanged from Rounds 1–3, plus:
- Attacker **CAN**: influence what the commander does, in the limit — through a
  manipulated model, a prompt injection that reaches it, or simply a model that
  errs. The design position is that a bad *choice* must cost a wasted
  collection, never a wrong or an unwatched verdict.
- Attacker **CANNOT**: write to Firestore directly; alter a sealed entry.
- Not attacker-driven at all: **RT-06** and **RT-07** are ordinary defects.
  They are in this report because their consequence — destroying or corrupting
  the sealed record — is exactly what an attacker would want, and the system's
  guarantee does not care which cause produced it.

## Executive summary
| ID | Severity | Level | Bucket | Finding |
|----|----------|-------|--------|---------|
| RT-06 | **Critical** | CONFIRMED BY INDUCTION | **vulnerability (fixed)** | Every case written before chain segmentation loses its entire sealed chain, mission journal and audit trail on first read; the loss becomes permanent on the next write. |
| RT-07 | High | CONFIRMED BY INDUCTION | **vulnerability (fixed)** | Two cycles working one case silently drop one cycle's reasoning and leave the memory chain failing verification — the tamper-evidence mechanism reports tampering with no attacker present. |
| RT-08 | High | CONFIRMED BY INDUCTION | **vulnerability (fixed)** | The commander could stand down, or park for 30 days, a host the engine had just adjudicated `MALICE_HIGH` — with no human escalated to. |
| RT-09 | Medium | CONFIRMED BY INDUCTION | **vulnerability (fixed)** | Introduced by the RT-07 fix: a chain rejected part-way had already written its segment, so an uncommitted entry was readable as part of the record. |
| RT-10 | Low | CODE FACT | hygiene | The narration/escalation seal check compares verdict *tokens*; a claim that names a verdict the cycle did seal, but attaches it to the wrong host or window, is not caught. |

---

## RT-06 — A deploy erases the sealed chain of every existing case

**Severity:** Critical **Level:** CONFIRMED BY INDUCTION **Bucket:** vulnerability (fixed)

- **Surprise:** segmentation was added as a pure storage change, but storage
  changes have a migration, and this one had none.
- **Abduction (ranked):** (1) `_assemble` unconditionally replaces each chain
  field from its segment index, so a document with no index yields `[]`;
  (2) the arrays are left alone when absent from the index; (3) reads fail
  loudly on an unknown shape. (1) is cheapest to test and matches the code.
- **Deduction:** write a case document in the pre-segmentation shape — arrays
  inline, no `chain_index` — and read it. Predict `entries == []` where five
  were stored, and that the next write persists the emptiness.
- **Induction:** observed `entries 5 → 0`, `journal 1 → 0`, `audit 1 → 0`; after
  one further write the stored index reads `{'segments': 0, 'count': 0}`.
  Prediction holds.
- **Causal chain:** deploy → `get_case` → `_assemble` → `index.get(field)` is
  `None` → `read_all(None)` returns `[]` → `case[field] = []` → `_persist`
  writes the emptiness → the case's sealed history no longer exists.
- **Precondition:** any case in the database predating the segmentation commit.
  The live service runs pre-segmentation code, so *every* deployed case
  qualifies. Reachable by deploying, not by attacking.
- **Fix:** a field with no index has never been segmented and is left exactly
  as stored; the next write migrates it into segments.
  `tests/test_chain_segmentation.py::test_a_case_written_before_segmentation_keeps_its_history`

## RT-07 — Two cycles on one case corrupt the record they are meant to protect

**Severity:** High **Level:** CONFIRMED BY INDUCTION **Bucket:** vulnerability (fixed)

Round 1–3 recorded this class as RT-05: last-write-wins, "caught by
`verify_stream`, never silent". Segmentation changed that, for the worse.

- **Deduction (first attempt, FALSIFIED):** predicted that concurrent writers
  would lose sealed verdict entries. Observed `[0, 1, 100, 101]` — all four
  present. `apply_cycle` re-reads the case, so the verdict stream survives.
  The vector was wrong and is corrected below rather than quietly restated.
- **Deduction (corrected):** the new entries are computed as `chain[count:]`,
  which assumes the writer's chain is an *extension* of the stored one. Under
  two writers it is a divergent *branch* from the same point. Predict: the
  first writer's journal survives, the second writer's journal entries are
  absent, `memory_head` belongs to the second writer, and `verify_mission`
  reports tampering.
- **Induction:** observed exactly that — journal contains `A: beacon on port
  443`, the mission's hypotheses list contains `B: scheduled task
  persistence`, `memory_head` is B's, and `verify_mission` → `False,
  ['memory_head does not match the end of the journal']`. The record's summary
  and its tamper-evident log disagree, and the integrity signal fires with no
  attacker present.
- **Why that is worse than losing data:** a false tampering alarm on a
  legitimate record is not a smaller failure than data loss. It teaches an
  examiner to distrust the one mechanism that is supposed to be trustworthy.
- **Fix:** the index carries the chain's head; a writer whose entry at the
  stored position does not match it is refused with
  `ConcurrentModificationError` rather than written. The service returns 409;
  the sweep records `concurrent write` and moves on. The same guard catches the
  single-request version of the mistake (`apply_run` + `save_mission`), which
  is now refused instead of silently forking.
  `tests/test_chain_segmentation.py::test_two_cycles_racing_one_case_lose_the_race_rather_than_the_record`

## RT-08 — The fleet could abandon a host the engine called malicious

**Severity:** High **Level:** CONFIRMED BY INDUCTION **Bucket:** vulnerability (fixed)

- **Surprise:** the deterministic planner had just been fixed to keep a
  compromised host on a short interval. The agent path had the same rule only
  in its instruction — and this project's stated position is that guarantees
  are structural, not prompted.
- **Deduction:** `schedule_next_cycle` accepts any 1–720 hours with no
  reference to the sealed record, and `stand_down` accepts any rationale.
  Predict a commander that seals `MALICE_HIGH`, schedules 720 hours out and
  stands down: both succeed, `is_due` returns `False` forever, no escalation.
- **Induction:** ran it through the real ADK loop with a scripted model.
  Observed `sealed: ['MALICE_HIGH']`, `standing_down: "the situation is under
  control"`, `is_due: False`, `escalated: False`. Prediction holds — the host
  is never looked at again and nobody is told.
- **Precondition:** a commander that errs or is manipulated. Note the bucket:
  this is a vulnerability, not a threat-model assumption, precisely because
  the architecture's claim is that a bad model choice cannot produce a bad
  outcome. Here it could.
- **Fix, in three parts, all reading the SEALED record only (the case's worst
  verdict and what this session sealed — never mission memory, which the agent
  writes):** `stand_down` is refused on a compromised host; a schedule beyond
  two hours is refused; and a sealed `MALICE` verdict raises the escalation
  **mechanically, attributed to the engine**, when the cycle closes without
  one. The commander tried both refusals and the case ended escalated and
  scheduled two hours out.
  `tests/test_commander_loop.py::test_the_fleet_cannot_park_or_abandon_a_host_the_engine_called_malicious`

## RT-09 — The RT-07 fix wrote half an operation

**Severity:** Medium **Level:** CONFIRMED BY INDUCTION **Bucket:** vulnerability (fixed)

Found by the RT-07 regression test failing in an unexpected way — the second
writer's *sealed entry* appeared in the record although its write had been
refused.

- **Cause:** chains were validated and written in one pass over four fields.
  The verdict stream passed its check and was written; the journal then
  diverged and raised. The segment was on disk; the case document, which was
  never updated, still counted one fewer entry. `read_all` returned everything
  in the referenced segments, so an entry that was never committed was
  readable — one writer's verdict inside another writer's record.
- **Fix:** every chain is checked before any is written, so an abort writes
  nothing; segments are computed as slices of the writer's chain rather than
  read-modify-written, so a retry stores the same bytes instead of
  duplicating; and the case document's index is the single commit point —
  `read_all` returns exactly `count` entries, so anything a half-finished
  write left beyond it is invisible until an index commits it. A chain
  *shorter* than the index claims is refused, not read as a clean shorter
  history.
  `tests/test_chain_segmentation.py::test_an_uncommitted_segment_write_is_invisible_until_the_index_commits_it`

## RT-10 — The seal check compares verdicts, not their subjects

**Severity:** Low **Level:** CODE FACT **Bucket:** hygiene

`unsealed_verdict_claims` flags a verdict state named in an escalation or
narration that the cycle did not seal. It does not check what the claim is
*about*: "MALICE_HIGH on the domain controller" passes when `MALICE_HIGH` was
sealed on the workstation. Recorded, not fixed — the honest description of the
guard is "it cannot invent a verdict", not "it cannot say anything false", and
the escalation now carries the sealed basis (state, entry hash, sequence)
beside the prose for a human to compare.

## Falsified / defended vectors

| Vector | Result | Why |
|---|---|---|
| Concurrent writers lose sealed verdict entries | **FALSIFIED** | `apply_cycle` re-reads the case, so the verdict stream survives; the damage is to the journal (RT-07). |
| Mission memory can change a verdict or a case's status | **Defended** | `_apply_run` computes status from the sealed chain alone; the existing test fills memory with a stand-down declaring the host clean and every seal is unmoved. |
| The catalog gate can be bypassed on the agent path | **Defended** | The gate is at the tool boundary, so it fires whichever planner runs (`test_the_catalog_still_refuses_the_soc_on_the_agent_path`). |
| An agent can pass a score, verdict or hash | **Defended** | No tool in any approved manifest accepts one; the tool-schema tests pin every declaration to its signature. |
| An agent can add a tool out of band | **Defended** | The sealed registry refuses to build an agent whose manifest hash is not approved, on the build path. |

## Recommendations (record only)

- A Firestore transaction around read-modify-write would turn RT-07's refusal
  into a retry the caller never sees. The refusal is correct and honest; a
  transaction would also be *convenient*.
- `verdicts` and `audit_trail` carry no per-entry identity, so divergence
  between two writers cannot be detected for them — only the two hash chains
  are protected. Giving them an identity would close the gap.

---

# Red Team Round 5 — identity, growth, and what a human actually sees

**Method:** Abductive Engineering (A–D–I) + Red-Team Auditing.
**Base:** `claude/agentic-autonomous-project-d9y5u0` @ `cda8881`, audited before
the fixes in this round.
**Runtime:** Python 3.11.15, `google-auth` 2.56.3.
**Scope:** what Round 4 did not reach — the identity check itself, growth in the
parts left unsegmented, and whether an escalation survives to be read.

Round 4 was about the record being destroyed or corrupted. This round is about
the record being *correct and unread*: a token that authenticates the wrong
person, a document that fills up anyway, and an escalation that stops being
shown without anybody handling it.

## Executive summary
| ID | Severity | Level | Bucket | Finding |
|----|----------|-------|--------|---------|
| RT-11 | **High** | CONFIRMED BY INDUCTION | **vulnerability (fixed)** | The identity token's audience was not verified: a correctly signed token minted for a completely different service authenticated. |
| RT-12 | Medium | CONFIRMED BY INDUCTION | **vulnerability (fixed)** | Only the journal was segmented out of the mission; the working summary grew unbounded, filling a document in ~145 days at hourly cadence. |
| RT-13 | Medium | CONFIRMED BY INDUCTION | **vulnerability (fixed)** | An unacknowledged escalation for a sealed `MALICE_HIGH` was silently replaced by a later routine one — nobody handled it, it stopped being shown. |
| — | — | **DEFENDED** | — | Bit-for-bit sealing survives the autonomous path: two runs produce identical `entry_hash` and score. |

---

## RT-11 — A token for another service authenticated

**Severity:** High **Level:** CONFIRMED BY INDUCTION **Bucket:** vulnerability (fixed)

- **Surprise:** `agent/principal.py` states its own rule — "a token we could not
  verify is treated exactly like no token at all" — and then passes
  `audience=None` when `VIGIA_EXPECTED_AUDIENCE` is unset, which is the default.
- **CODE FACT (google-auth 2.56.3):** `jwt.decode` checks the `aud` claim only
  `if audience is not None`. Supplying `None` does not mean "any audience is
  acceptable" by policy; it means the claim is never looked at.
- **Deduction:** a correctly signed token whose `aud` names an unrelated service
  verifies when no audience is configured, and is rejected when one is.
- **Induction:** signed a Google-format ID token with a locally generated RSA
  key and injected its certificate, so the signature genuinely verifies and only
  the audience is in question. `aud =
  https://some-unrelated-service.example.com`. Observed: **audience unset →
  accepted**, `email: analyst@example.com`; audience set → `Token has wrong
  audience …`. Prediction holds.
- **Causal chain:** any service the analyst signs into can obtain an ID token
  for its own audience → presented to annaconda → signature valid, audience
  never checked → if the subject is in the roster, the request runs as that
  analyst, with that department's catalog privileges. Classic confused deputy.
- **Bounded by:** the roster. An identity annaconda has not rostered still gets
  nothing (Round 4's design). So the reachable case is a *rostered* analyst's
  token leaking through an unrelated service, not an arbitrary Google account.
- **Fix:** no configured audience means the token cannot be fully verified, so
  it does not authenticate — the module's own rule, now applied. The service
  keeps working; the principal is `asserted`, as it already is with no token at
  all. `DEPLOY.md` already sets `VIGIA_EXPECTED_AUDIENCE`.
  `tests/test_principal.py::test_a_token_cannot_authenticate_without_a_configured_audience`

## RT-12 — Segmenting the chains postponed the ceiling 13×, it did not remove it

**Severity:** Medium **Level:** CONFIRMED BY INDUCTION **Bucket:** vulnerability (fixed)

- **Surprise:** Round 4 segmented the two hash chains and the docs then read as
  though the 1 MiB problem was handled. But `hypotheses`, `tried_hunts` and
  `open_questions` live inside the mission, which stays in the case document.
- **Deduction:** each grows at least once per cycle, so the document still grows
  without bound — more slowly, which is worse for being less visible.
- **Induction:** 400 cycles against the size-limited double. Observed **~301
  bytes/cycle** in the unsegmented part → 1 MiB at ~3,482 cycles = **145 days**
  at hourly cadence (against 11 days before segmentation).
- **Fix:** those lists are a *working summary* of the journal — every entry was
  written to the journal first, and the journal is segmented and authoritative.
  Each list is capped, giving up settled entries before open ones and oldest
  before newest, and what was dropped is counted and reported in the brief
  (`older_entries_in_sealed_journal`) so no reader mistakes the view for the
  record. Re-measured: **~2 bytes/cycle**, flat at ~31 KB.
  `tests/test_mission.py::test_the_working_summary_is_bounded_and_says_what_it_dropped`
- **First fix attempt, corrected:** capping only *settled* entries left open
  hypotheses unbounded — an agent that opens a line every cycle and never
  settles one still filled the document (measured: still 144 bytes/cycle). The
  rule became "cap everything, give up settled first", which is bounded under
  every agent behaviour rather than under well-behaved ones.

## RT-13 — An escalation stopped being shown without being handled

**Severity:** Medium **Level:** CONFIRMED BY INDUCTION **Bucket:** vulnerability (fixed)

- **Surprise:** `mission["escalation"]` is a single slot, assigned on every
  `escalate()`.
- **Deduction:** a case escalated for a sealed `MALICE_HIGH`, then escalated
  again by a later cycle for something routine, shows only the later one on
  `/cases/{id}/mission` and on the console — which is where a human looks.
- **Induction:** observed exactly that; the malicious escalation survived only
  in the journal, and its `acknowledged` flag was never set. It was replaced,
  not handled.
- **Fix:** escalations accumulate in a bounded list. `mission["escalation"]` is
  now *derived* — the most severe unacknowledged one, ranked from its **sealed
  basis** only (an adjudicated malicious verdict outranks anything else; the
  agent's prose has no bearing on it). `POST
  /cases/{id}/escalations/{i}/acknowledge` closes the loop: an escalation stops
  being shown because a named examiner took it up and said what they did,
  recorded into the sealed journal — never because something newer arrived.
  `tests/test_mission.py::test_a_later_escalation_cannot_displace_an_unacknowledged_severe_one`

## Defended vectors

| Vector | Result | Evidence |
|---|---|---|
| The autonomous path breaks bit-for-bit sealing | **DEFENDED** | Two independent runs over the same evidence: identical `MALICE_HIGH`, `5569/10000`, `98224dab…`. Mission journal hashes differ (they seal a wall clock) and are not part of any verdict. |
| A verified identity can run as a department it does not hold | **DEFENDED** | The roster's department wins over the request's claim (Round 4). |
| Bounding the summary loses history | **DEFENDED** | Every trimmed entry remains in the segmented journal, and the brief reports the counts rather than presenting a truncated view as complete. |

## Recommendations (record only)

- `_rate_ok("cycle")` is one global bucket for every case and caller, not
  per-principal. It stops a hammer; it is not a quota system, and one busy
  operator can throttle another.
- The escalation ranking is coarse by design (malicious / other-sealed /
  unsealed). If escalation reasons multiply it will need a real severity field
  rather than an inference from the basis.

---

# Red Team Round 6 — the service boundary, after the sweep became expensive

**Method:** Abductive Engineering (A–D–I) + Red-Team Auditing.
**Base:** `claude/agentic-autonomous-project-d9y5u0` @ `5f14149`, audited before
the fixes in this round.
**Scope:** the public HTTP surface, re-examined because *this session changed
what it costs*. Rounds 1–3 recorded unauthenticated state-changing endpoints as
hygiene (RT-04) when `/tasks/sweep` ran a scripted collection. It now runs a
Gemini turn per due case, so the same endpoints are worth a second look at a
different severity.

## Executive summary
| ID | Severity | Level | Bucket | Finding |
|----|----------|-------|--------|---------|
| RT-14 | Medium | CONFIRMED BY INDUCTION | **vulnerability (fixed)** | One unauthenticated `POST /cases` buys one Gemini cycle on the next sweep, unbounded — 50 cases created by a stranger produced 50 cycles. |
| RT-15 | Medium | CONFIRMED BY INDUCTION | **vulnerability (fixed, introduced by the RT-14 fix)** | A cycle cap without priority lets a flood of new cases push a compromised host past it on every sweep. |
| RT-16 | Low–Med | CODE FACT | **vulnerability (fixed)** | Anyone could mark an escalation for a sealed `MALICE_HIGH` as handled by any named examiner, with no record of whether that identity was verified. |
| — | — | **FALSIFIED** | — | Hammering `/tasks/sweep` does *not* repeat the work: `is_due` defuses it after the first call. |

---

## RT-14 — One POST buys one Gemini turn

**Severity:** Medium **Level:** CONFIRMED BY INDUCTION **Bucket:** vulnerability (fixed)

- **Abduction, two rivals:** (H1) hammering `/tasks/sweep` burns quota, each
  call running cycles again; (H2) `is_due` defuses that, and the real lever is
  case *creation*, which is also unauthenticated and leaves every new case
  immediately due.
- **Induction:** three consecutive sweeps → `worked=3`, then `worked=0`,
  `worked=0`. **H1 FALSIFIED** — the sweep is self-limiting, and the schedule
  the fleet sets for itself is what limits it. Then 50 cases created by an
  unauthenticated caller → next sweep ran **50 cycles**, no rate limit hit.
  **H2 holds.**
- **Why it is worth a finding at all:** the cost of a wake-up was set by
  whoever created the most cases, on a demo URL with a real Vertex bill behind
  it.
- **Fix:** a sweep runs at most `VIGIA_SWEEP_MAX_CYCLES` cycles (default 10);
  the rest are **deferred and reported**, never silently dropped — a sweep that
  stopped part way in silence would read as "every case is up to date".
  `POST /cases` now carries the same rate limit as the other paid paths, so the
  cap bounds cost per wake-up and the limit bounds arrival.
  `tests/test_autonomous_service.py::test_a_sweep_caps_how_many_cycles_it_runs`

## RT-15 — The cost fix created an availability hole

**Severity:** Medium **Level:** CONFIRMED BY INDUCTION **Bucket:** vulnerability (fixed)

A cap bounds cost and creates a queue, and a queue can be gamed.

- **Deduction:** if the sweep takes cases in list order, a stranger who creates
  more cases than the cap pushes the one host under an adjudicated `MALICE`
  verdict past it — on every sweep, forever. The hourly re-check that Round 4
  made structural would never run.
- **Induction:** with priority ordering, a compromised host created *before* 30
  flood cases is worked **first** (`worked[0] == "AAA-VICTIM"`), 41 cases
  deferred. Without it the victim sorts by case id like everything else.
- **Fix:** the sweep orders by worst sealed verdict first, then most overdue.
  Cost is capped without starving the case the whole schedule exists to
  protect.
  `tests/test_autonomous_service.py::test_a_flood_of_new_cases_cannot_starve_a_compromised_host`

## RT-16 — Anyone could mark a malicious escalation as handled

**Severity:** Low–Medium **Level:** CODE FACT **Bucket:** vulnerability (fixed)

`POST /cases/{id}/escalations/{i}/acknowledge` took `examiner_id` from the
request body and wrote it as the person who took the escalation up. Since
acknowledging is precisely how a sealed malicious verdict stops demanding
attention (RT-13's fix), an unauthenticated caller could silence one under any
name, and the record would not say the name was unverified.

Not confirmed by induction: the endpoint is this session's own and the code
path is unambiguous, so this is recorded as a CODE FACT rather than dressed up
with an experiment that would only restate it.

**Fix:** the acknowledgement resolves a principal like every other tasking and
records `acknowledged_by_authenticated` beside the name — verified or asserted,
travelling together, and shown as such on the console. `/demo/seed`, which
deletes and rebuilds the showcase cases, is rate limited.

## Recommendations (record only)

- Case *storage* is still unbounded: the sweep cap limits cost per wake-up and
  the rate limit slows arrival, but a patient stranger can still fill the
  database. A case quota, or authentication on creation, is the real answer.
- The rate limiter remains one per-process bucket per key, not per principal.

---

# Red Team Round 7 — a code review of the whole branch, before it ships

**Method:** full-diff review of `main...HEAD` (33 files, ~7k lines) at high
effort, then A–D–I on each finding before touching anything.
**Base:** `claude/agentic-autonomous-project-d9y5u0` @ `84c499a`.
**Why:** none of this session's work had ever been merged or deployed. Reviewing
7k lines of unshipped changes *before* they reach production is cheaper than
after.

Four of the seven findings were reproduced. Two of them are corrections to
claims made in earlier rounds of this very document — recorded here rather than
edited away, because a claim that was too broad is a finding.

## Executive summary
| ID | Severity | Level | Bucket | Finding |
|----|----------|-------|--------|---------|
| RT-17 | **High** | CONFIRMED BY INDUCTION | **vulnerability (fixed)** | Round 4's concurrency defence did not cover the sealed *verdict* chain: two concurrent cycles stored entries with duplicate sequence numbers, and the chain's own verifier rejected the result. |
| RT-18 | **High** | CONFIRMED BY INDUCTION | **vulnerability (fixed)** | After a human acknowledged the first escalation, a later cycle sealing a fresh `MALICE_HIGH` reached nobody — RT-08's failure, reappearing through a derived field. |
| RT-19 | Medium | CONFIRMED BY INDUCTION | **vulnerability (fixed)** | Ids minted as `len(list)+1` collide once `_trim` caps the list; settling a line of inquiry then settled an older namesake. |
| RT-20 | Medium | PLAUSIBLE → fixed | vulnerability (fixed) | A cycle that left an already past-due plan untouched kept the case permanently due, so every wake-up ran a full Gemini cycle on it. |
| RT-21 | Low–Med | CODE FACT | vulnerability (fixed) | Escalations were acknowledged by position into a list `_trim` mutates, so a stale index could silence an escalation nobody handled. |
| RT-22 | Low | CODE FACT | hygiene (fixed) | `_run_cycle_on_case` built a session — and a `mkdtemp` never removed — before the due check, leaking a directory per case per sweep. |
| RT-23 | Low | CODE FACT | hygiene (fixed) | A rate-limit guard was inserted above `demo_seed`'s docstring, leaving the endpoint with no `__doc__`. |

---

## RT-17 — Round 4's concurrency claim was too broad

**Severity:** High **Level:** CONFIRMED BY INDUCTION **Bucket:** vulnerability (fixed)

Round 4 (RT-07) said two concurrent cycles are "detected and refused — the
record stays intact". That is true of the **mission journal** and was false of
the **sealed verdict stream**. The correction matters more than the fix.

- **Why the check missed it:** the divergence guard compares the writer's
  *prefix* against the stored head. But the verdict stream is minted by a
  `PurpleTeamSession` built from the case *as it was read*, so two concurrent
  cycles produce entries carrying the same `sequence` and the same
  `prev_entry_hash`. The second writer then re-reads the case before
  persisting — so its prefix is the first writer's entries and matches
  perfectly. The divergence is not in the prefix; it is in the entries being
  appended.
- **Induction:** two sessions built from the same snapshot, both adjudicating
  the attack fixture. Observed: second write **accepted**, stored sequences
  `[0, 0]`, both `prev_entry_hash` = genesis, and
  `verify_stream(...)["chain_ok"] == False` —
  `sequence 0 != 1` and `prev_entry_hash does not match previous entry`. The
  sealed chain was corrupted and nothing complained at write time.
- **Fix:** the check now also requires the **first new entry to chain onto the
  stored head** (`prev_of(chain[already]) == index["head"]`), reading
  `prev_entry_hash` or `prev_hash` so both chains are covered by one rule.
  `tests/test_chain_segmentation.py::test_entries_minted_against_a_stale_head_are_refused`
  drives it with genuinely sealed entries — the earlier synthetic fixtures
  could not have caught this, because `_entry(0)`'s hash is 64 zeros, which
  *is* the genesis hash.

## RT-18 — RT-08's failure, back through a derived field

**Severity:** High **Level:** CONFIRMED BY INDUCTION **Bucket:** vulnerability (fixed)

Round 4 made "a sealed MALICE must reach a human" structural. Round 5 then made
`mission["escalation"]` a *derived view* that falls back to the most recent
entry once everything is acknowledged — and the net still gated on
`mission["escalation"] is None`, which is never true again after the first
escalation.

- **Induction:** cycle 1 seals `MALICE_HIGH` and escalates; a human
  acknowledges it; cycle 2 seals `MALICE_HIGH` again with a commander that says
  nothing. Observed: escalations still 1, **unacknowledged 0**. A freshly
  sealed malicious verdict reached nobody.
- **Causal chain:** derived field never returns to None → net never fires →
  the only remaining path is the agent choosing to escalate, which is exactly
  the assumption RT-08 removed.
- **Fix:** `mission.has_open_escalation()` asks the real question — is any
  escalation still *unacknowledged* — and the net gates on that. The lesson is
  narrower than "check the right field": a derived convenience view was
  substituted for a predicate, and the substitution was invisible at the call
  site.

## RT-19 / RT-21 — capping a list broke the ids into it

**Severity:** Medium / Low–Medium **Level:** CONFIRMED BY INDUCTION / CODE FACT

RT-12's fix capped the working lists. Ids were minted as `len(list) + 1` and
escalations were acknowledged by position — both of which assume a list that
only grows.

- Reproduced duplicate `H101` / `Q51` once the cap was reached;
  `update_hypothesis` then settles whichever namesake it finds first.
- **Fix:** a monotonic per-mission counter (seeded from the highest id already
  present, so older missions keep handing out fresh ids), and escalations carry
  a stable `id` that `acknowledge_escalation` accepts in place of a position.
  `_trim` now runs *before* the derived view is recomputed, so the view can
  never point at an entry the cap just dropped.

## RT-20 / RT-22 / RT-23 — the smaller ones

- **RT-20:** the "never leave the case without a decision" net asked *is the
  plan absent?* when the question is *is this case still due?*. A cycle that
  left an already past-due plan in place kept `is_due` True, so every wake-up
  ran a full Gemini cycle on that case forever. Now gated on `mem.is_due`.
- **RT-22:** `_run_cycle_on_case` built a session — and a `mkdtemp` that is
  never cleaned — before checking whether the case was due. Since most
  wake-ups on most cases correctly skip, that leaked a directory per case per
  sweep. The due check moved ahead of the session build.
- **RT-23:** a rate-limit guard was inserted above `demo_seed`'s docstring,
  leaving the endpoint with no `__doc__` and no OpenAPI description.

## What this round says about the method

Two of seven findings are earlier rounds' claims being too broad, both in the
same shape: a guarantee was established, then a *later* refactor moved the thing
it depended on, and nothing re-checked the guarantee. The tests that would have
caught RT-17 existed — they just used synthetic entries whose hashes could not
express the failure. Fixtures that cannot represent the bug are not coverage.
