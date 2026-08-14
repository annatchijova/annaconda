"""Surprisal-ensemble nominator.

Given a set of events (endpoint telemetry), it scores how *surprising* each one
is against the events themselves — no labels, no training, no fixed rules — and
returns a ranked shortlist of nominations for a human or the deterministic core
to adjudicate.

Surprisal is measured in bits: for a value v seen with empirical probability
p(v), its surprisal is -log2(p(v)). A value that appears once among many is
improbable, so it carries many bits — it stands out. Five detectors look at
different facets:

  rare-type    an unusual kind of event
  rare-name    an unusual process / object name
  rare-path    an executable in an unusual location (e.g. a user Temp dir)
  rare-dest    an unusual outbound network destination
  content      an unusually high-entropy command line (encoded payloads)

The ensemble takes each event's strongest signal, enforces a per-detector quota
so no single facet dominates the shortlist, and returns the top-K with a
plain-language reason.

CRITICAL: this layer NOMINATES. It never produces a verdict, a score that gets
sealed, or a decision. Floats live here by design and go no further.
"""

from __future__ import annotations

import math
import posixpath
from collections import Counter
from typing import Optional

NOMINATED_BY = "ml"


def _surprisal(counts: Counter, total: int, value) -> float:
    """Bits of surprisal for ``value`` given an empirical distribution."""
    c = counts.get(value, 0)
    if c <= 0 or total <= 0:
        return 0.0
    return -math.log2(c / total)


def _dirname(path: str) -> str:
    p = str(path).replace("\\", "/")
    d = posixpath.dirname(p)
    return d.lower() or "(none)"


def _shannon_bits(text: str) -> float:
    """Shannon entropy of a string in bits/char — high for encoded blobs."""
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def events_from_artifacts(artifacts: list) -> list:
    """Project core artifacts into the generic event shape the ensemble reads.

    Pulls from the raw collected row so the ensemble sees what the endpoint
    actually reported (process name, image path, destination, command line).
    """
    events = []
    for a in artifacts:
        row = (a.get("metadata") or {}).get("row") or {}
        dest = ((a.get("metadata") or {}).get("dst_ip")
                or row.get("dst_ip") or row.get("Raddr.IP"))
        events.append({
            "id": a.get("artifact_id"),
            "type": a.get("evidence_type"),
            "name": row.get("Name") or row.get("NewProcessName"),
            "path": row.get("Exe") or row.get("NewProcessName"),
            "dest": dest,
            "content": row.get("CommandLine"),
            "time": a.get("timestamp"),
        })
    return events


class SurprisalNominator:
    """Ranks events by how much they stand out. Nominates, never decides."""

    def __init__(self, top_k: int = 8, per_detector_quota: int = 4,
                 min_bits: float = 0.5):
        self.top_k = top_k
        self.per_detector_quota = per_detector_quota
        self.min_bits = min_bits

    # -- detectors: each returns {event_id: (bits, reason)} ------------------

    def _rare_categorical(self, events, key, label, fmt):
        vals = [(e["id"], e.get(key)) for e in events if e.get(key)]
        counts = Counter(v for _, v in vals)
        total = len(vals)
        # Surprisal only discriminates when there is repetition to be rare
        # against. If every value is unique, they all carry identical bits —
        # that is noise, not signal. Skip the detector entirely.
        if not counts or max(counts.values()) <= 1:
            return {}
        out = {}
        for eid, v in vals:
            bits = _surprisal(counts, total, v)
            out[eid] = (bits, fmt(v))
        return out

    def _rare_path(self, events):
        vals = [(e["id"], _dirname(e["path"])) for e in events if e.get("path")]
        counts = Counter(d for _, d in vals)
        total = len(vals)
        out = {}
        for e in events:
            if not e.get("path"):
                continue
            d = _dirname(e["path"])
            bits = _surprisal(counts, total, d)
            out[e["id"]] = (bits, f"executable in an unusual location: {e['path']}")
        return out

    def _content(self, events):
        out = {}
        for e in events:
            content = e.get("content")
            if not content:
                continue
            ent = _shannon_bits(content)
            # Only genuinely high-entropy, long command lines (encoded blobs)
            # surprise; ordinary long paths do not clear this bar.
            if ent >= 4.5 and len(content) >= 50:
                out[e["id"]] = (ent, "high-entropy command line "
                                     "(possible encoded payload)")
        return out

    # -- ensemble ------------------------------------------------------------

    def nominate(self, events: list, window_id: str = "") -> list:
        if not events:
            return []
        # Detectors chosen for endpoint process/network telemetry. Name- and
        # type-surprisal (from Camel's event-stream ensemble) are omitted here:
        # on a process snapshot a name that appears once is not "unusual
        # malware", it is just a process without a peer — noise, not signal.
        # These three discriminate for this data.
        detectors = {
            "rare-path": self._rare_path(events),
            "rare-dest": self._rare_categorical(
                events, "dest", "dest",
                lambda v: f"rare outbound destination: {v}"),
            "content": self._content(events),
        }
        # Each event keeps its single strongest signal.
        best: dict = {}
        for detector, scored in detectors.items():
            for eid, (bits, reason) in scored.items():
                if bits < self.min_bits:
                    continue
                if eid not in best or bits > best[eid][0]:
                    best[eid] = (bits, detector, reason)

        # Deterministic order: strongest first, ties broken by event id.
        ranked = sorted(best.items(), key=lambda kv: (-kv[1][0], str(kv[0])))

        nominations = []
        quota: Counter = Counter()
        for eid, (bits, detector, reason) in ranked:
            if len(nominations) >= self.top_k:
                break
            if quota[detector] >= self.per_detector_quota:
                continue
            quota[detector] += 1
            nominations.append({
                "schema_version": 1,
                "nomination_id": f"{window_id or 'w'}-nom-{len(nominations):03d}",
                "window_id": window_id,
                "nominated_by": NOMINATED_BY,
                "detector": detector,
                "event_ref": {"artifact_id": eid},
                "surprisal_bits": round(bits, 4),
                "rank": len(nominations) + 1,
                "reason": reason,
            })
        return nominations


def nominate_window(window: dict, top_k: int = 8) -> list:
    """Convenience: nominate over a sealed evidence window's artifacts."""
    events = events_from_artifacts(window.get("artifacts", []))
    return SurprisalNominator(top_k=top_k).nominate(
        events, window_id=window.get("window_id", ""))
