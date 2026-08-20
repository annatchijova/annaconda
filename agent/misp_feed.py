"""MISP / OpenCTI feed ingestion — the team's own threat picture, as sealed evidence.

VirusTotal (agent/threat_intel.py) is the *public* reputation of an indicator.
This module adds the *organization's own* intelligence: indicators exported from a
MISP or OpenCTI instance (their attributes — threat level, tags, the event that
recorded them). A window's indicators are matched against that feed and the
matches are sealed into the window as evidence, exactly like the VirusTotal
enrichment and under the same invariant:

- Same discipline as VirusTotal. A match is written into the sealed evidence
  window at collection time, beside the scored artifacts (``window["enrichment"]``),
  never among them. It is tamper-evident and replay-deterministic, yet
  structurally incapable of moving a verdict — the scorer never reads it.
- Deterministic. The feed loaded at collection time is what gets sealed; matching
  is a pure lookup; observations are sorted; every field is a string or an exact
  integer. No float, no live call during adjudication or replay.
- Honest degradation. No feed configured (``MISP_FEED_PATH`` unset or unreadable)
  means an empty index and a ``/health`` posture of ``unavailable`` — never a
  fabricated match. An absent feed degrades the feature, not the core.

The feed file is a JSON document ``{"indicators": [ {type, value, ...}, ... ]}``
(a MISP attribute export or an OpenCTI observable export); it is the cached,
sealed-into-window source, refreshed out of band, so nothing here reaches the
network on the sealing path.
"""
from __future__ import annotations

import json
import os

from agent.threat_intel import extract_indicators

_FEED_ENV = "MISP_FEED_PATH"

# MISP/OpenCTI attribute type -> our indicator_type. Only unambiguous types map;
# anything else is ignored, so the index is stable.
_TYPE_MAP = {
    "ip-dst": "ip_address", "ip-src": "ip_address", "ip": "ip_address",
    "sha256": "file", "filename|sha256": "file",
    "domain": "domain", "hostname": "domain",
}

# MISP threat_level_id -> label (1 = high ... 4 = undefined).
_THREAT_LEVEL = {1: "high", 2: "medium", 3: "low", 4: "undefined"}


def _feed_path(path: str | None = None) -> str | None:
    return path or os.environ.get(_FEED_ENV, "").strip() or None


def load_feed(path: str | None = None) -> dict:
    """Load a MISP/OpenCTI export into an index ``{(indicator_type, value): entry}``.

    Honest degradation: a missing or unreadable feed yields an empty index rather
    than an error, so a window still collects and seals — just without this
    context.
    """
    resolved = _feed_path(path)
    if not resolved:
        return {}
    try:
        with open(resolved, "r", encoding="utf-8") as handle:
            doc = json.load(handle)
    except (OSError, ValueError):
        return {}
    index: dict = {}
    for raw in (doc.get("indicators") or []):
        if not isinstance(raw, dict):
            continue
        itype = _TYPE_MAP.get(str(raw.get("type", "")).lower())
        value = raw.get("value")
        if not itype or not isinstance(value, str) or not value:
            continue
        value = value.lower() if itype == "file" else value
        index[(itype, value)] = raw
    return index


def feed_size(feed: dict | None = None) -> int:
    return len(load_feed() if feed is None else feed)


def posture(feed: dict | None = None) -> str:
    """The honest posture for ``/health``: the feed size, or ``unavailable``."""
    if not _feed_path():
        return "unavailable"
    n = feed_size(feed)
    return f"misp:{n}" if n else "misp:empty"


def _observation(indicator_type: str, value: str, entry: dict) -> dict:
    tlid = entry.get("threat_level_id")
    tlid = tlid if isinstance(tlid, int) and not isinstance(tlid, bool) else None
    tags = entry.get("tags") or entry.get("Tag") or []
    if isinstance(tags, list):
        tags = sorted({t.get("name") if isinstance(t, dict) else str(t) for t in tags})
    else:
        tags = []
    return {
        "indicator": value,
        "indicator_type": indicator_type,
        "source": "misp",
        "matched": True,
        "threat_level_id": tlid,
        "threat_level": _THREAT_LEVEL.get(tlid, "unknown"),
        "tags": tags,
        "event_info": str(entry.get("event_info", "")) or None,
        "event_id": str(entry.get("event_id", "")) or None,
    }


def enrich(artifacts: list, *, feed: dict | None = None) -> list:
    """Match a window's indicators against the feed. Returns sorted observations
    for the MATCHES only (a non-match carries no signal). Deterministic given the
    feed; never a live call."""
    if feed is None:
        feed = load_feed()
    if not feed:
        return []
    records = []
    for indicator_type, value in extract_indicators(artifacts):
        entry = feed.get((indicator_type, value))
        if entry is not None:
            records.append(_observation(indicator_type, value, entry))
    return sorted(records, key=lambda r: (r["indicator_type"], r["indicator"]))


def make_enricher(*, feed: dict | None = None):
    """Build the ``(artifacts) -> observations`` callable the collect_window seam
    accepts; the observations seal into the window beside the scored artifacts."""
    resolved = load_feed() if feed is None else feed

    def _enricher(artifacts: list) -> list:
        return enrich(artifacts, feed=resolved)
    return _enricher


def summarize(records: list) -> dict:
    """A compact, read-only summary of the MISP matches for a window."""
    high = [r for r in records if r.get("threat_level") in ("high", "medium")]
    return {
        "source": "misp",
        "matches": len(records),
        "elevated": len(high),
        "records": records,
        "note": ("organization threat-intel matches, sealed beside the evidence; "
                 "they do not and cannot change the sealed verdict"),
    }
