"""
core/_time_utils.py — shared timestamp helper.

Extracted from VIGÍA's hash_chain.py (github.com/annatchijova/vigia-intent-analysis,
Apache 2.0) as a standalone utility, rather than porting the whole chain
module — annaconda uses CRONOS for its agent-decision audit trail, so
duplicating a second hash-chain implementation here would be redundant.
This single tolerant ISO-8601 parser is kept because other modules (CAIE)
depend on it for timestamp-plausibility checks.
"""
from __future__ import annotations
from datetime import datetime, timezone


def _parse_iso_ts(ts):
    """Tolerant ISO-8601 parsing for plausibility checks. Returns a
    tz-aware datetime (naive -> UTC) or None if not parseable/absent."""
    if not isinstance(ts, str) or not ts.strip():
        return None
    try:
        dt = datetime.fromisoformat(ts.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)
