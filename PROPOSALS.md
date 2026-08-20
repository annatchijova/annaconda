# Proposals — where annaconda goes next for the DFIR community

annaconda's thesis is narrow and load-bearing: **a language model never touches
the verdict.** The deterministic core scores the evidence and seals a
reproducible, MITRE-mapped result *before* any agent runs; the model chooses what
to investigate and puts the sealed figures into words, nothing more. Every
proposal here is judged against that invariant first. A feature that would put the
model, a float, or a black-box dependency inside a sealed value does not ship, no
matter how good it looks in a demo.

Two of these have already shipped; the rest are the roadmap, ordered by value to a
working DFIR team over effort to build. Each names how it *keeps* the invariant,
because that is the hard part, not the integration.

---

## Shipped

### STIX 2.1 export of sealed verdicts — `GET /cases/{id}/stix`
A sealed case leaves annaconda as a standard STIX 2.1 bundle: the host as an
`identity`, each MITRE technique as an `attack-pattern` with its ATT&CK reference,
and each sealed entry as an `x-annaconda-sealed-verdict` SDO carrying the state,
the exact-fraction score, and the seal chain (`entry_hash` / `prev_entry_hash` /
`window_hash`). It is a pure projection of an already-sealed verdict — it
references the stored seal rather than recomputing it, ids are `uuid5` over the
seal, so re-exporting the same case is byte-identical.
- **Google value:** Google SecOps (Chronicle) ingests STIX; this is the on-ramp.
- **Community value:** the case travels to any TIP (MISP, OpenCTI) or court
  exhibit with its tamper-evidence intact.

### Threat-intel enrichment specialist (VirusTotal / Google Threat Intelligence)
A fleet specialist enriches a window's indicators (file hashes, IPs) with VT / GTI
reputation, sealed *into* the evidence window as cached, exact-integer evidence —
beside the scored artifacts, never among them, so it is tamper-evident and
replay-deterministic yet structurally unable to move a verdict. Honest degradation
when no key is configured; gated by the catalog for the `external_enrichment` data
class only.
- **Google value:** VirusTotal / GTI is a Google product analysts already trust.
- **Community value:** reputation context sealed alongside the evidence, with a
  provable "the reputation did not decide" property.

### Independent, stdlib-only bundle verifier — `annaconda-verify`
`tools/verify_bundle.py` re-derives every seal in an exported exhibit
(`GET /cases/{id}/exhibit`) and reports PASS / WARN / FAIL, catching any altered,
reordered, inserted, or dropped verdict — and, when the windows are included, any
tampered evidence. It is standard-library only and **imports nothing from
annaconda**: it keeps its own copy of the canonical encoder, held bit-for-bit in
lockstep with the producer by a test, so it cannot share a bug with the sealer.
A third party can run it on an air-gapped machine without trusting this service.
- **Google / community value:** the Daubert posture made runnable — the guarantee
  is worth more precisely because someone who distrusts you can check it themselves.

### Sigma rule synthesis from a sealed MALICE window
`verdict/sigma_export.py` turns a sealed MALICE/ESCALATE window into portable
Sigma draft rules: one per evidence type, tagged with the sealed verdict's MITRE
techniques, with selectors built only from stable identifying fields (Image,
ParentImage, User, DestinationIp, CommandLine, TargetFilename, EventID) — volatile
fields are dropped. It is a deterministic projection of the sealed evidence (no
model authors the logic; ids are uuid5 over the seal), and it ships behind an
honest draft posture: `status: experimental`, an author note, and a false-positive
line telling the analyst to review and generalize before deploying. A non-MALICE
verdict yields no rule. Exposed as the `detection-engineer` fleet specialist,
gated by the catalog like every other agent.
- **Google / community value:** Sigma is the community lingua franca for
  detections; this closes the loop from "we caught it here" to a shareable rule.

---

## Proposed

### C — CACAO 2.0 playbook export of an autonomous investigation
**What.** Turn one autonomous cycle (the commander's tasking → collection →
adjudication → escalation decisions) into an OASIS **CACAO 2.0** response playbook:
a portable, machine-readable record of *what the fleet did and why*, with the
sealed verdicts as the decision points.
**Why.** CACAO is the OASIS standard for security playbooks; SOAR platforms and
Google SecOps consume it. It makes annaconda's autonomy auditable and repeatable by
other tools, not just observable in its own console.
**Invariant.** Pure export, like STIX: derived from the sealed mission journal and
verdict chain, references the seals, no model in the path. A CACAO step *records* a
sealed decision; it never re-decides.
**Effort.** Small–medium. Reuses the STIX id/timestamp discipline.

### F — Sealed-verdict push to Google SecOps (Chronicle) over Pub/Sub
**What.** On each sealed escalation, publish the STIX bundle to a Pub/Sub topic a
Chronicle feed subscribes to, so annaconda's verdicts land in the enterprise SIEM
timeline automatically.
**Why.** Completes the Google-native loop: unattended detection → sealed verdict →
SecOps, with no human copy-paste. Reuses the autonomous sweep's existing Pub/Sub
wiring.
**Invariant.** Push is downstream of the seal; a delivery failure is a `WARN` that
never discards the sealed verdict (honest degradation — the persistence-failure
rule already in the codebase).
**Effort.** Small–medium. Mostly IAM + a topic + reusing the STIX export.

### G — MISP / OpenCTI ingestion to seed enrichment context
**What.** Pull an organization's own MISP / OpenCTI indicators to seed the
enrichment specialist, so a window is enriched against *the team's* threat picture,
not only the public VT verdict.
**Why.** Meets DFIR teams where their intel already lives; the community runs MISP.
**Invariant.** Same discipline as VT: ingested indicators are cached into the
sealed window as evidence at collection time; they inform context, never the score.
**Effort.** Medium. A read-only MISP client + the existing enrichment seam.

---

## What we are deliberately *not* proposing

- **Letting the model tune a score, weight, or threshold.** That is the one line
  the project exists not to cross. Any "smarter adjudication" work happens in the
  deterministic core (CAIE) with exact arithmetic, reviewed and re-sealed — never
  delegated to the narrator.
- **A float anywhere near a sealed value**, including "just for the confidence
  bar." Cosmetic rounding stays in the display layer.
- **Silent enrichment that moves the verdict.** If reputation is ever promoted from
  context to a suspicion signal, it will be an explicit, exact-integer step in the
  analysis layer, tested for determinism and documented — not a quiet dependency.

Honest scope beats an impressive metric: a known, documented limitation is an asset
in this domain, not a gap to paper over.
