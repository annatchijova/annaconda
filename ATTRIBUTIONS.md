# Attributions

annaconda is built by adapting and extending pre-existing open-source work.
This file discloses everything incorporated, per the "New Projects Only"
disclosure requirement of the All Things Agentic Hackathon (Google/Gemini)
official rules: pre-existing code may be used as a foundation as long as
the submission discloses it and demonstrably enhances and builds upon it.

The line between "pre-existing" and "new" is drawn at what was ported
versus what was built from scratch for this submission (Agent Runtime,
Agent Registry, Agent Identity, Agent Gateway, and the Gemini/ADK
orchestration tying everything below together).

---

## Own prior work (Apache 2.0), adapted and ported

### VIGÍA
<https://github.com/annatchijova/vigia-intent-analysis>

The primary source for annaconda's current codebase. A forensic
intentionality analysis engine (Peircean semiotics, Daubert-oriented),
originally built for the SANS FIND EVIL Hackathon. annaconda reframes its
reasoning core away from courtroom admissibility and toward SOC/incident-
response use, adapting the following subsystems (see full commit history
for the complete file-by-file breakdown):

- The deterministic Mode 1 core (`vigia_agent.py`, `vigia_scorer.py`) and
  its dependency closure — canonicalization, atomic I/O, evidence
  aggregation, decision layer, semiotic detection, likelihood/calibration,
  bundle sealing, risk-bounded scoring, graph stability, quadripartite
  verdict classification.
- The full Windows SIFT analyzer suite (MFT, registry, prefetch,
  shellbags, amcache/shimcache, USB, event logs, memory, network, browser,
  IOC management) plus multi-platform parsers (Android, iOS, macOS, Google
  Takeout, pcap, fsevents) and the orchestrator tying them together
  (`sift_orchestrator_shim.py`, adapted from vigia-repo's root-level
  compatibility shim).
- The security/Model Armor layer: LLMShield (prompt-injection firewall
  with Unicode NFKC normalization), sandboxed subprocess execution,
  path/output boundary validation, trust decay.
- CAIE v2.0 (Cross-Artifact Incongruence Engine) and MITRE ATT&CK mapping.
- DARVO pattern detection and the LLM hallucination guard (narrative
  claims verified against the deterministic motor's actual output).

Deliberately **not** ported: `hash_chain.py` / `tool_log_chain.py` and
`reasoning_trace.py` (VIGÍA's own agent-decision audit chain) — CRONOS
(below) is annaconda's single source of truth for that, so duplicating a
second hash-chain implementation would be redundant. A single helper
function (`_parse_iso_ts`) was extracted into `core/_time_utils.py`
instead of porting the whole module.

### CRONOS, MNEME, raven-memory, MUTANTE
<https://github.com/annatchijova/cronos> ·
<https://github.com/annatchijova/mneme> ·
<https://github.com/annatchijova/raven-memory> ·
(MUTANTE, local working copy — GitHub remote not yet published)

Planned integrations, not yet ported into this repository as of this
writing:

- **CRONOS** — black-box, SHA-256/HMAC hash-chained decision recorder for
  AI agents. Intended as annaconda's Agent Observability layer.
- **MNEME** — memory layer with verifiable, tamper-evident chain of
  custody per stored memory; designed against poisoned-RAG. Intended as
  part of the Memory Bank pillar.
- **raven-memory** — adaptive memory field (resonance/inhibition/decay
  dynamics) with cryptographically auditable recall, deterministic and
  offline-capable. Also Memory Bank. Built for the Qwen Cloud Hackathon.
- **MUTANTE** — adversarial LLM evaluator; Thompson Sampling bandit over
  known jailbreak corpora (HarmBench et al.), not a generator of novel
  attacks. Built for the Google Cloud Rapid Agent Hackathon (Elastic
  Track). Intended as an LLM-layer complement to Strix's application-layer
  red teaming (see below).

All four are Apache 2.0.

---

## Third-party open source, used as independent services (not embedded)

### Velociraptor
<https://github.com/Velocidex/velociraptor> — **AGPLv3**

DFIR and endpoint-monitoring platform (VQL hunts across a fleet). Used as
a standalone service reached over its own API — the official signed
release binary is fetched and GPG-verified by `scripts/setup_velociraptor.sh`
(signing key fingerprint `0572F28B4EF19A043F4CBBE0B22A7FB19CB6CFA1`, verified
against the officially documented fingerprint). Velociraptor's source is
never modified, embedded, or forked, so its AGPLv3 copyleft terms do not
extend to annaconda's own code.

### Strix
<https://github.com/usestrix/strix> — **Apache 2.0**
(fork: <https://github.com/annatchijova/strix>)

Open-source autonomous AI pentesting tool. Forked (currently in sync with
upstream, no edits yet) to cover the "red team attacks the application
itself" angle — distinct from MUTANTE, which attacks the LLM layer via
known prompt corpora rather than the application under test. Its four
Claude Code skills (`strix-pentest`, `strix-fix-findings`,
`strix-cloud-api`, `strix-ci-setup`) are installed and used as-is, not
copied into this repository.

**Caution:** the `strix-pentest` skill scored High Risk (Gen) / Critical
Risk (Snyk) in its own installer's security assessment — the only skill
installed so far that did not come back Safe/Low. Expected given it
launches real exploitation, but review before invoking for an actual
pentest.

---

## Third-party open source, under evaluation (cloned for reference, nothing ported yet)

### SIFTics
<https://github.com/rjonhaas/SIFTics> — **MIT**

SANS Find Evil! 2026 hackathon entry: Claude Code as an agentic DFIR
analyst over the SIFT Workstation, with architectural (not merely
prompted) guardrails — typed MCP functions, a schema-layer Safety Officer
hard-stop, HMAC-signed Incident Commander approval before any active
response (fleet hunt, host isolation, account disable), hash-chained
audit. Already integrates Velociraptor directly. Cloned locally
(`~/SIFTics`) for evaluation; candidate modules identified but not yet
copied:

- `mcp_ic_approval/` + `siftics/ic_approval.py` — HMAC-signed approval
  gate, a strong fit for the Agent Identity (zero-trust) pillar.
- `mcp_containment/` — real fleet response actions (host isolation,
  account disable) — Agent Runtime taking real action.
- `mcp_baseline/` — deterministic comparison against a known-good Windows
  baseline corpus (credits AndrewRathbun/VanillaWindowsReference +
  VanillaWindowsRegistryHives in its own README).
- `mcp_cti/` — threat-intel enrichment (URLhaus, MalwareBazaar, ThreatFox,
  OpenSourceMalware.com STIX feed).
- `mcp_rag/` — RAG over MITRE ATT&CK, LOLBAS, Atomic Red Team, SigmaHQ,
  explicitly framed as "explanatory enrichment... not ground truth" — the
  same epistemic discipline VIGÍA already applies.
- `phases/run_zircolite.sh` — Sigma rule application over EVTX, credits
  wagga40/Zircolite upstream.
- `skills/*.md` — NIMS Incident Command System roles as agent skills
  (Investigation Section Chief, Safety Officer, Legal Officer, Finance
  Officer, Public Information Officer) — a working model for genuinely
  specialized multi-agent roles, not just labeled sub-prompts.
- `siftics/audit.py` — a second hash-chain audit implementation, useful as
  a comparison point against CRONOS's design, not necessarily to import
  directly (see the hash_chain.py decision above — avoid duplicating audit
  trails without a clear reason).

### (pending) additional SANS hackathon DFIR repos
Mentioned but not yet identified/named as of this writing: at least one
more autonomous, tool-equipped DFIR project, MIT/Apache-2.0 licensed, that
already integrates with Velociraptor. To be added here once located
(deferred until after the separate Midnight ZK hackathon).

---

## How to keep this file honest

Every entry above should name: the license, whether the code was actually
copied/adapted (state what) or is only being used as an external
service/tool (state how), and — for anything copied — roughly what was
left out and why, so a reviewer never has to guess where annaconda's own
code ends and someone else's begins.
