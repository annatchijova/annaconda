# VIGIA live-mode contracts

Versioned JSON Schemas for the interfaces between the deterministic core and
the live (Purple Team) components. These contracts exist so that workstreams
can proceed in parallel against fixtures: the dashboard and the ML triage
layer depend only on these shapes, never on core internals.

| Schema | Producer | Consumer | Purpose |
|---|---|---|---|
| `evidence_window.schema.json` | Velociraptor adapter (or replay) | Deterministic core | A frozen, hashed snapshot of live telemetry for one time window |
| `verdict_stream_entry.schema.json` | Deterministic core | Dashboard, CRONOS, replay verifier | One sealed verdict in the hash-chained live stream |
| `ml_nomination.schema.json` | ML triage layer | Deterministic core | A candidate event the ML layer NOMINATES for adjudication |

## Design rules (binding)

1. **Windows, not streams, get sealed.** The adapter freezes telemetry into an
   immutable evidence window with a manifest and a SHA-256 `window_hash`. The
   core scores the window exactly as it scores static artifacts today.
2. **Verdicts form a hash chain.** Every stream entry commits to
   (`window_hash`, `prev_verdict_hash`, `sequence`). Replaying the same window
   sequence must reproduce every seal bit-for-bit.
3. **No floats in anything that gets sealed.** Ratios travel as `"num/den"`
   fraction strings or fixed-precision decimal strings. Floats are permitted
   only inside `ml_nomination` (nomination layer, never sealed) and cosmetic
   display fields.
4. **ML nominates, never decides.** A nomination is an input candidate. It
   carries no verdict semantics and its scores never enter a sealed payload.
   If a nominated event matters, the deterministic core re-derives its weight
   with exact arithmetic.
5. **Every schema instance carries `schema_version`.** Consumers must reject
   versions they do not know (fail loud, no best-effort parsing).

## Change control

These files are part of workstream 1 (closely held). Changes require a version
bump and a matching fixture update under `tests/`.
