"""ML triage — nominates, never decides.

A label-free, self-baselining surprisal ensemble that surfaces the events most
worth a human's (and the deterministic core's) attention. It produces
NOMINATIONS, not verdicts: its scores are advisory floats that never enter a
sealed payload. If a nominated event matters, the deterministic core re-derives
its weight with exact arithmetic and seals the result. See
contracts/ml_nomination.schema.json. (Ported from the surprisal ensemble in
allisterb/Camel, MIT — see ATTRIBUTIONS.md.)
"""
