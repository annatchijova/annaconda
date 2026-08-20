# Security Audit — annaconda

## Red Team Round 1 (external)

**Method:** Abductive engineering (Abduction–Deduction–Induction) + red-team auditing.
**Base reviewed:** `main` @ `2f5633c` · **Scope:** the whole repository (~191 files,
~50k lines), focused on the LLM/engine boundary, the seal, chain of custody,
persistence, and the HTTP surface.

> **Implementer's note (how to read this document).** This audit was produced by
> an independent external auditor (a separate model). Per this repo's discipline,
> an auditor's finding is a *claim* until it is verified against the live code, and
> only then acted on. Every finding below was re-verified against the live tree at
> `2f5633c` before any change: all eight are real, and none of the fixes existed in
> the repository yet. The fixes described here were then implemented and tested
> independently — they are not a blind application of the auditor's patch. Where a
> fix could not be exercised by the local test suite (the Firestore path), it was
> verified **inductively against the real Firestore backend**; see R3-1.

---

## Threat model

- The attacker **CAN**: control the endpoint telemetry (process names, command
  lines, timestamps), call any public HTTP endpoint, create cases, send prompts to
  the agent, and replay concurrent requests.
- The attacker **CANNOT**: modify the service code, write directly to Firestore, or
  learn secrets (HMAC key, Gemini API key).
- The guarantee under test: *"the sealed verdict is reproducible and no model can
  touch it."* That is what was attacked.

## Epistemic legend

`CODE FACT` · `PLAUSIBLE HYPOTHESIS` · `CONFIRMED BY INDUCTION` · `FALSIFIED`

## Executive summary

| ID | Severity | Level | Module | Finding | Disposition |
|----|----------|-------|--------|---------|-------------|
| R3-1 | P1 | CONFIRMED | `service/case_store.py` | TOCTOU check→commit in `_persist` (Firestore): two concurrent writers silently lose/swap sealed verdicts | **FIXED** (verified against real Firestore) |
| R3-2 | P1 | CONFIRMED | `MemoryCaseStore` | No concurrency guard: two parallel runs break a case's sealed chain permanently | **FIXED** (test) |
| R2-1 | P1 | CONFIRMED (CODE FACT) | `service/app.py` | `/consult` and `/tasks/sweep`: public endpoints that trigger paid Gemini calls with **no rate limit** | **FIXED** (test) |
| R1-1 | P2 | CONFIRMED | `core/canonicalize.py` | Canonicalization collision: `{1: "x"}` and `{"1": "x"}` seal to the same hash | **FIXED** (test) |
| R1-2 | P2 | CONFIRMED (CODE FACT) | `core/verdict_stream.py` | `append_entry`: no fsync (durability) and no continuity check against the file's tail | **FIXED** (test) |
| R1-3 | P3 | CODE FACT | `service/app.py` | Global (per-endpoint, not per-client) rate limiter: one user exhausts everyone's quota — judges included | **DOCUMENTED** (below + DEPLOY.md) |
| R1-4 | P3 | CODE FACT | `service/app.py` | `mkdtemp` per investigation without cleanup + unbounded in-memory `_STORE`: unbounded growth on Cloud Run | **DOCUMENTED** |
| R3-3 | Info | CODE FACT | `/cases/{id}/exhibit` | The exhibit omits the windows: external verification covers integrity, not verdict correctness | **FIXED** (docstring) |

**The core README claims hold — confirmed by induction, not by reading:**

- **Bit-for-bit determinism**: the same pipeline in 3 independent processes → an
  identical hash, verdict `MALICE_HIGH`, exact score `5569/10000`. CONFIRMED.
- **Tampered window**: change a single character of the evidence → `build_stream_entry`
  refuses it ("window hash does not verify"). CONFIRMED.
- **Numeric boundary**: `score = NaN`, `inf`, or text garbage → `StreamError` at
  sealing. CONFIRMED.
- **The model cannot pass a score/verdict/hash**: the tool signatures have no
  parameter for it; the boundary is structural, not a prompt. CODE FACT, verified
  against `agent/tools.py`.

The findings are on the operational periphery (concurrent persistence, public
endpoints), not in the sealed core.

---

## Findings

### R3-1 — Silent loss of sealed verdicts under a Firestore race (P1)

**Bucket:** vulnerability (atomicity). **Level:** CONFIRMED BY INDUCTION against the
real Firestore backend.

- **Surprise:** `chain_store.py` documents that "the case document is the single
  commit point" — but the commit (`doc.set()`) is not a compare-and-swap: the
  divergence `check()` runs *before* writing, against the index read at the start of
  the request.
- **Prediction:** two writers whose chains legitimately hang off the same head both
  pass the check, overwrite the same (deterministically-named) segment, and the last
  `set` wins.
- **Induction (live backend):** with two `case` objects read at the same base, writer
  A commits, then writer B — holding the now-stale base — is **rejected with
  `ConcurrentModificationError`**, and A's sealed entry survives intact (B does not
  overwrite it). Against the pre-fix code, B would have committed silently over A.
- **Causal chain (pre-fix):**
  ```
  requests A and B read the case (same chain_index)
      ↓ both check() OK against the old index
  A writes segment N; B writes the SAME segment N (deterministic ids)
      ↓ last doc.set() wins
  one sealed run vanishes — no ConcurrentModificationError, no verification error, no trace
  ```
- **Precondition:** two concurrent writers on the same case (operator + sweep, or two
  operators). Reachable via `POST /cases/{id}/investigate` ×2 in parallel.
- **Fix:** `_persist` now runs the segment writes and the case-document commit inside
  a **Firestore transaction** that re-reads the *current* stored `chain_index` and
  runs `SegmentedChain.check` against it — so a run minted against a head that has
  since advanced is refused, and the loser commits nothing (the segment writes join
  the transaction and are rolled back with it). A backend without a `transaction`
  primitive (the test double) takes the direct path: the same checks, no concurrency
  claim — stated in the code. **Not covered by the local suite** (needs the real
  backend); verified inductively against real Firestore as above.

### R3-2 — MemoryCaseStore with no concurrency guard (P1)

**Bucket:** vulnerability. **Level:** CONFIRMED BY INDUCTION.

The default backend when there is no `GOOGLE_CLOUD_PROJECT` (i.e. every local demo,
and potentially the one in front of judges if Firestore fails) had **no** protection:
two concurrent requests on the same case → `apply_run` extends blindly → a chain with
`sequence 0 != 1` and a broken `prev_entry_hash`, **permanently** (the case is broken
forever in that backend).

- **Fix:** a per-store lock plus a continuation check (`_check_continuation`): the
  first new entry must chain onto the stored tail and carry the contiguous sequence,
  equivalent to `SegmentedChain.check`. The loser is refused with
  `ConcurrentModificationError`; the chain stays `chain_ok: True`. Regression test in
  `tests/test_redteam_round1_fixes.py`.

### R2-1 — Public endpoints that burn paid quota with no rate limit (P1)

**Bucket:** vulnerability (cost/DoS). **Level:** CODE FACT.

- `POST /consult`: each call is a Gemini turn; public, unauthenticated, **no
  `_rate_ok`** — the only model-touching route with no limit.
- `POST /tasks/sweep`: public, no rate limit; triggers up to `SWEEP_MAX_CYCLES` paid
  agentic cycles. Combined with public case creation, an attacker fabricates "due"
  cases and wakes them at will.
- **Fix:** `_rate_ok("consult")` and `_rate_ok("sweep")` guard both routes (429 on
  exceed); the caller-controlled `session_id` is capped at 64 chars. The cron fires
  far below the cap, so the legitimate sweep is unaffected. Regression test asserts
  both routes 429.

### R1-1 — Canonicalization collision via non-string keys (P2)

**Bucket:** latent vulnerability. **Level:** CONFIRMED BY INDUCTION (collision),
FALSIFIED (reachable today).

- **Induction:** `_canonicalize({1: "x"})` and `_canonicalize({"1": "x"})` → the
  **same SHA-256**. `json.dumps` silently coerces int keys to strings.
- **Reachability:** FALSIFIED today — windows, manifests, and the journal all derive
  from JSON (keys always strings). It is a landmine for any future sealed payload with
  non-string keys.
- **Fix:** all three v2 encoder copies (`core/canonicalize.py`, `core/bundle_builder.py`,
  `tools/verify_bundle.py`) now reject non-string keys with `TypeError` — fail-loud,
  without changing the encoding of any existing seal (verified: a string-keyed seal is
  bit-identical before and after; the determinism test stays green). If non-string
  keys are ever needed, that is a v3 change, not a silent collision.

### R1-2 — `append_entry` without fsync or continuity (P2)

**Bucket:** vulnerability (durability) + missing defense. **Level:** CODE FACT.

The JSONL stream was written with a bare `open('a')`: (1) no fsync — a crash after the
append can lose the sealed verdict the caller believes is stored, exactly the guarantee
the stream exists to give; (2) nothing checked that the entry chained onto the file's
last one, so a caller with stale state wrote a break silently. **Fix:** mandatory
continuity when the file has entries (a fresh file accepts any `prev` — a session
continuing a case chains to the case head, not to this per-session file) + `fsync`
before returning. Regression test covers both the accepted continuation and the two
rejection modes.

### R1-3 — Global rate limiter, not per-client (P3)

**Bucket:** threat-model assumption / hardening. **Level:** CODE FACT.

`_RATE_HITS` is keyed by a constant per endpoint (`"agent"`, `"cycle"`…), not by
client: one user exhausts the quota **for everyone** — including a judge who arrives
right after a crawler. It is also per Cloud Run instance. **Disposition:** documented
(here and in `DEPLOY.md`) rather than changed — per-client keying changes visible
behavior and must be bounded (a cap on the number of client keys) to avoid a
memory-DoS; recommended for a hardening pass, not a hot-fix before the deadline.

### R1-4 — Unbounded resources: tempdirs and `_STORE` (P3)

**Bucket:** hygiene. **Level:** CODE FACT.

Each investigation calls `mkdtemp` that is never cleaned (on Cloud Run this is tmpfs —
it grows until the instance restarts), and `_STORE` / `_consult_sessions` grow without
bound in memory. **Disposition:** documented; suggested a reaper by age or an
LRU/TTL. (The `session_id` cap from R2-1 removes the one *attacker-controlled* growth
vector.)

### R3-3 — The exhibit verifies integrity, not correctness (Info)

**Bucket:** language precision / boundary of the guarantee. **Level:** CODE FACT.

`GET /cases/{id}/exhibit` includes `entries` but **not the evidence windows** (they
live in ephemeral collection storage). `annaconda-verify` can prove "nobody altered
anything after sealing", but not "this score is what the engine produces over this
evidence" — that would need the windows and a re-run of the scorer. This is the
universal property of hashes (integrity ≠ truth), not a bug. **Fix:** the endpoint
docstring now states this scope explicitly, so a hostile reviewer cannot present it as
an overclaim; the verifier already WARNs that window seals were not re-checked when the
windows are absent.

---

## Discarded vectors (attempted, not exploitable)

| Vector | Result | Why it failed |
|--------|--------|---------------|
| Tamper with evidence before sealing | FALSIFIED | `build_stream_entry` re-verifies `window_hash` and refuses |
| Forge an entry with an arbitrary score | FALSIFIED (as a model attack) | The agent tools have no score parameter; `build_stream_entry` is pure but unreachable from the model |
| bool/int/None collision in canonical v2 | FALSIFIED | v2's `s:` prefix already closes it (confirmed by experiment) |
| NaN/inf/garbage in a sealed score | FALSIFIED | `_exact_fraction_str` refuses anything not exact |
| Determinism broken across processes | FALSIFIED | 3 processes → a bit-identical hash |
| int/str key collision reachable from evidence | FALSIFIED | Every sealed input derives from JSON (string keys) — latent only |
| Prompt injection moving the verdict | FALSIFIED (by design + tests) | The verdict is sealed before the model is called; `/injection-demo` exhibits it |

---

## Fixes applied

| Fix | File | Verification |
|-----|------|--------------|
| Transactional commit with re-check | `service/case_store.py` (`FirestoreCaseStore._persist`) | Inductive against real Firestore: divergent second writer rejected, first survives |
| Lock + continuation check | `service/case_store.py` (`MemoryCaseStore`) | Race reproduced → now rejected, chain intact (test) |
| Rate limit + session_id cap | `service/app.py` (`/consult`, `/tasks/sweep`) | Both routes 429 after the cap (test) |
| Fail-loud rejection of non-string keys ×3 copies | `canonicalize.py`, `bundle_builder.py`, `verify_bundle.py` | Collision reproduced → now `TypeError`; string-keyed seal bit-identical (test) |
| Continuity + fsync in `append_entry` | `core/verdict_stream.py` | Divergent/non-contiguous append → `StreamError` (test) |
| Exhibit scope docstring | `service/app.py` (`/cases/{id}/exhibit`) | Integrity-vs-correctness stated |

Regression tests: `tests/test_redteam_round1_fixes.py`. Determinism preserved
bit-for-bit (`tests/test_determinism.py` green).

## Recommendations recorded (not actioned)

1. Per-client (IP) rate limiting with a bounded key map — R1-3.
2. A reaper for tempdirs and a TTL/LRU for `_STORE` — R1-4.
3. Set `VIGIA_REQUIRE_AUTHENTICATED_PRINCIPAL=true` + `VIGIA_EXPECTED_AUDIENCE` in the
   deployment if the catalog is to be a real gate rather than asserted — today
   `/health` reports this honestly (`requires_authenticated_principal`), which is
   correct; just confirm the deploy turns it on.
4. A smoke test against the Firestore emulator for the transactional `_persist` path
   (the concurrency guard is a property of the real backend; the test double does not
   exercise it — this round verified it inductively against real Firestore instead).
