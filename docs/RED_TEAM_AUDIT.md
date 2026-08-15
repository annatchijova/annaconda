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

---

## Falsified / defended vectors (the audit's teeth)
| Vector | Prediction | Result |
|--------|-----------|--------|
| Frame → sealed MALICE from a **thin** planted fracture (2 artifacts) | seals MALICE | **FALSIFIED** — verdict was ABSTAIN_INSUFFICIENT; the corroboration gate refused. Frame needs a full corroborated picture (RT-01). |
| Evade by stripping only `network_log_time` | evades to benign | **FALSIFIED** — PROCESS_INJECTION_ANTIFORENSIC still fired MALICE_HIGH. |
| Tamper a deep nested field of a sealed window | `verify_window` still True | **FALSIFIED (defense holds)** — original verifies True, tampered verifies False. Tamper-evidence covers the whole canonical form. |
| Break reproducibility with adversarial unicode (NFD, RTL override) in a command line | seal differs across processes | **FALSIFIED (defense holds)** — window hash identical across two `PYTHONHASHSEED` processes (canonical NFC normalization). |
| ML nominator floats reach a sealed value | sealed hash varies | **FALSIFIED (defense holds)** — sealed entry_hash byte-identical with the nominator in-pipeline; no nomination fields in the sealed stream (pinned in CI). |

The two central promises — **the LLM cannot change the verdict** and **the
verdict is reproducible and tamper-evident** — survived every direct attack.
The real findings live one layer out: the sealed verdict is only as trustworthy
as the telemetry it is computed from (RT-01/02), which is the honest, stated
boundary of the whole class of tool.

## Recommendations (record only; out of scope of the RT-03 fix)
- State RT-01/02 in the README's honest-limitations section: "a sealed verdict
  certifies reproducible adjudication of the collected evidence, not the truth of
  that evidence; annaconda inherits the collector's trust boundary."
- Consider extending CAIE's spoofability weighting to the golden-rule structural
  verdicts, or requiring a hard-to-spoof anchor before a structural rule can
  alone reach MALICE.
- Put the state-changing endpoints behind auth/a shared token before wider
  exposure (RT-04).
