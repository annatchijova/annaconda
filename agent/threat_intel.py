"""External threat-intelligence enrichment — evidence for the record, never a decider.

VirusTotal / Google Threat Intelligence reputation is the enrichment DFIR analysts
actually rely on (file/IP/domain prevalence and detection counts). Here it is
treated as *evidence sealed beside the collected telemetry*, never as a live
dependency of a verdict. The founding invariant (CLAUDE.md 5.1 — no black-box in
the decision path) is preserved by three deliberate choices:

1. **Cached into the seal, read once.** Enrichment is computed at collection time
   and sealed INTO the evidence window (``window["enrichment"]``, covered by
   ``window_hash``). Adjudication and every replay read that frozen, cached value
   from the sealed window — never a live VirusTotal call — so the seal stays
   bit-for-bit reproducible across processes.

2. **Beside the scored artifacts, not among them.** The enrichment is sealed under
   its own window key; ``window_to_case`` (the scorer feed) does not read it. So
   the reputation is tamper-evident and STIX-exportable, yet it is *structurally
   incapable of moving the score* — VirusTotal is not even in the scorer's input.
   Promoting reputation to a suspicion signal would be a deliberate later step in
   the analysis layer (CAIE), done on exact integer counts; it is out of scope
   here, and that scope boundary is stated, not hidden (the Daubert posture).

3. **Honest degradation.** With no ``VT_API_KEY`` / ``GTI_API_KEY`` the enricher
   does not fabricate: it records ``available: False`` with the reason, ``/health``
   reports ``threat_intel: "unavailable"``, and the core path is untouched. An
   absent key degrades the feature, never the verdict.

All reputation figures are exact integers (detection counts, reputation score).
No float ever enters an enrichment record, so nothing here can taint a sealed value.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import urllib.error
import urllib.request

# Environment keys, in preference order. VirusTotal and Google Threat Intelligence
# share the same v3 API surface and key header.
_KEY_ENV = ("VT_API_KEY", "GTI_API_KEY")
_API_ROOT = "https://www.virustotal.com/api/v3"

# Indicator extraction. Deterministic and conservative: we only enrich indicators
# we can recognise unambiguously, so the set is stable across runs.
_SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
# Metadata keys whose value, when present, is treated as an indicator of that type.
_HASH_KEYS = ("sha256", "file_hash", "hash", "image_hash")
_IP_KEYS = ("dst", "dest_ip", "remote_addr", "remote_ip", "dst_ip", "raddr")

_STAT_FIELDS = ("malicious", "suspicious", "harmless", "undetected", "timeout")


def key_present() -> bool:
    """True iff a threat-intel API key is configured in the environment."""
    return any(os.environ.get(k, "").strip() for k in _KEY_ENV)


def posture() -> str:
    """The honest posture for ``/health``: which backend, or ``unavailable``."""
    if os.environ.get("VT_API_KEY", "").strip():
        return "virustotal"
    if os.environ.get("GTI_API_KEY", "").strip():
        return "google-threat-intelligence"
    return "unavailable"


def _api_key() -> str | None:
    for k in _KEY_ENV:
        v = os.environ.get(k, "").strip()
        if v:
            return v
    return None


# ---------------------------------------------------------------------------
# Indicator extraction (pure, deterministic)
# ---------------------------------------------------------------------------

def _walk_strings(value):
    """Yield every string leaf of a nested metadata value, in a stable order."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for k in sorted(value):
            yield from _walk_strings(value[k])
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _walk_strings(item)


def extract_indicators(artifacts: list) -> list:
    """Pull the enrichable indicators out of a window's artifacts.

    Returns a **sorted, de-duplicated** list of ``(indicator_type, value)`` pairs.
    Deterministic by construction: an indicator is recognised the same way in any
    run, so the enrichment set — and therefore the sealed window — is stable.
    """
    found: set[tuple[str, str]] = set()
    for art in artifacts:
        meta = art.get("metadata") or {}
        # Trust explicit typed keys first.
        for key in _HASH_KEYS:
            v = meta.get(key)
            if isinstance(v, str) and _SHA256_RE.fullmatch(v):
                found.add(("file", v.lower()))
        for key in _IP_KEYS:
            v = meta.get(key)
            if isinstance(v, str) and _IPV4_RE.fullmatch(v):
                found.add(("ip_address", v))
        # Then sweep every string leaf for unambiguous patterns.
        for s in _walk_strings(meta):
            for m in _SHA256_RE.findall(s):
                found.add(("file", m.lower()))
            for m in _IPV4_RE.findall(s):
                found.add(("ip_address", m))
    return sorted(found)


# ---------------------------------------------------------------------------
# Fetchers — the only place a live network call may happen
# ---------------------------------------------------------------------------

def _endpoint(indicator_type: str, value: str) -> str:
    path = {"file": "files", "ip_address": "ip_addresses",
            "domain": "domains"}[indicator_type]
    return f"{_API_ROOT}/{path}/{value}"


def live_virustotal_fetch(indicator_type: str, value: str) -> dict | None:
    """Query VirusTotal v3 for one indicator. Returns the raw ``attributes``
    dict, or ``None`` if not found / unreachable / no key. Used only on the live
    collection path — never during tests or replay (those inject a fetcher)."""
    key = _api_key()
    if not key:
        return None
    req = urllib.request.Request(
        _endpoint(indicator_type, value),
        headers={"x-apikey": key, "accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:  # noqa: S310 (fixed host)
            payload = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, ValueError, OSError):
        return None
    return (payload.get("data") or {}).get("attributes")


# ---------------------------------------------------------------------------
# Enrichment records (pure given a fetcher)
# ---------------------------------------------------------------------------

def _record(indicator_type: str, value: str, attributes, *, source: str) -> dict:
    """One enrichment observation. Reputation figures are exact integers only."""
    if attributes is None:
        return {
            "indicator": value,
            "indicator_type": indicator_type,
            "source": source,
            "available": False,
            "reason": "not found or enrichment unavailable",
        }
    stats = attributes.get("last_analysis_stats") or {}
    # Coerce to int defensively; a non-integer stat is dropped to 0 rather than
    # allowed to smuggle a float into a sealed record.
    counts = {}
    for f in _STAT_FIELDS:
        raw = stats.get(f, 0)
        counts[f] = raw if isinstance(raw, int) and not isinstance(raw, bool) else 0
    rep = attributes.get("reputation", 0)
    return {
        "indicator": value,
        "indicator_type": indicator_type,
        "source": source,
        "available": True,
        "stats": counts,
        "reputation": rep if isinstance(rep, int) and not isinstance(rep, bool) else 0,
    }


def enrich(artifacts: list, *, fetcher=None, source: str | None = None) -> list:
    """Enrich a window's indicators into sorted, deterministic observations.

    ``fetcher(indicator_type, value) -> attributes | None`` is injectable: the
    live path passes :func:`live_virustotal_fetch`; tests and replay pass a
    fixture so the result is reproducible. With no key and no injected fetcher,
    every observation degrades honestly to ``available: False`` — nothing is
    fabricated.
    """
    if source is None:
        source = posture()
    if fetcher is None:
        fetcher = live_virustotal_fetch if key_present() else (lambda t, v: None)
    records = []
    for indicator_type, value in extract_indicators(artifacts):
        try:
            attributes = fetcher(indicator_type, value)
        except Exception:  # a flaky lookup degrades to unavailable, never crashes
            attributes = None
        records.append(_record(indicator_type, value, attributes, source=source))
    # Stable order regardless of fetch timing.
    return sorted(records, key=lambda r: (r["indicator_type"], r["indicator"]))


def make_enricher(*, fetcher=None, source: str | None = None):
    """Build the callable ``collect_window``/``build_evidence_window`` accept as
    their ``enricher``: ``(artifacts) -> list[observation]``. The observations are
    sealed into the window under its own key, beside — never among — the scored
    artifacts."""
    def _enricher(artifacts: list) -> list:
        return enrich(artifacts, fetcher=fetcher, source=source)
    return _enricher


def summarize(records: list) -> dict:
    """A compact, human/agent-facing summary of an enrichment set (read-only)."""
    available = [r for r in records if r.get("available")]
    flagged = [r for r in available
               if (r.get("stats", {}).get("malicious", 0)
                   + r.get("stats", {}).get("suspicious", 0)) > 0]
    return {
        "indicators": len(records),
        "enriched": len(available),
        "unavailable": len(records) - len(available),
        "flagged": len(flagged),
        "records": records,
        "note": ("threat-intel is sealed evidence beside the telemetry; it does "
                 "not and cannot change the sealed verdict"),
    }
