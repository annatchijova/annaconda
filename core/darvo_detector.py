"""
annaconda/core/darvo_detector.py
DARVO Detector — contact-claim asymmetry between actor_a and actor_b.

Adapted from VIGÍA (github.com/annatchijova/vigia-intent-analysis,
Apache 2.0) for annaconda. Detects the DARVO pattern (Deny, Attack,
Reverse Victim and Offender): an actor claims "zero contact" with
another party while simultaneously operating surveillance
infrastructure against them. Structured detection with traceable
matched spans; no effect on any verdict by itself — this is a signal,
not a decision.

Design notes carried over from the original module:
  - Keyword matching uses word-boundary lookarounds on both edges,
    not a bare substring or `\\b`, so multi-word phrases ('php error',
    'zero contact') anchor correctly and short keywords like 'log'
    don't match inside 'logs'.
  - `pattern_present` requires the FULL asymmetry — both surveillance
    infrastructure AND a zero-contact claim. Surveillance keywords
    alone ('log', 'server'...) fire in many benign cases; annotating
    those alone as "DARVO" would be misleading.
  - The `penalty` field is kept only for traceability of the
    historical scoring formula; it has no consumer in this module and
    should not be wired into a verdict without an explicit design
    decision to do so.
"""
from __future__ import annotations
import re
from fractions import Fraction
from typing import Any, Dict, List

SURVEILLANCE_KEYWORDS = ('honeypot', 'access log', 'server', 'log', 'stalking', 'php error', 'trampoline')
ZERO_CONTACT_KEYWORDS = ('zero contact', 'no contact', 'blocked')
_SURVEILLANCE_TYPES = ('file_metadata', 'log_entry')


def _compile_keywords(keywords):
    """Word-boundary patterns on both edges.

    Lookarounds instead of `\\b` so multi-word phrases anchor
    correctly on both ends. This avoids 'no contact' matching inside
    "no contacts database" (a false positive from an English plural),
    and 'log' matching inside "logs". A standalone word like 'server'
    still matches normally (e.g. "4 S3 server list URLs").
    """
    return tuple(
        re.compile(r"(?<!\w)" + re.escape(k) + r"(?!\w)") for k in keywords
    )


_SURVEILLANCE_RES = _compile_keywords(SURVEILLANCE_KEYWORDS)
_ZERO_CONTACT_RES = _compile_keywords(ZERO_CONTACT_KEYWORDS)


def _field(artifact: Any, name: str, default: Any = None) -> Any:
    """Read a field from an artifact given as either an object or a dict.

    Some pipelines pass artifacts as plain dicts; falling back to
    getattr alone would leave the detector blind to that shape.
    """
    if isinstance(artifact, dict):
        return artifact.get(name, default)
    return getattr(artifact, name, default)


def detect_darvo_pattern(artifacts: List[Any]) -> Dict[str, Any]:
    """Structured detection of the DARVO contact-claim asymmetry.

    Returns counts, a Fraction-valued penalty (traceability only, see
    module docstring), and the ids of the artifacts that triggered a
    match, with the matched spans for auditability. Pure Fraction
    arithmetic, deterministic; tolerant of malformed fields (str()
    coercion, non-dict metadata treated as empty).
    """
    surveillance_count = 0
    zero_contact_count = 0
    matched: List[str] = []
    spans: List[Dict[str, str]] = []

    def _span(art_id: str, family: str, keyword: str, desc: str, m) -> Dict[str, str]:
        # Per-keyword traceability: family, keyword, and a context
        # window around the match. The keyword list is public in this
        # repo either way, so recording the exact span costs nothing
        # and helps auditability.
        return {
            "artifact_id": art_id,
            "family": family,
            "keyword": keyword,
            "context": desc[max(0, m.start() - 30):m.end() + 30],
        }

    for idx, a in enumerate(artifacts):
        desc = str(_field(a, 'description', '') or '').lower()
        meta = _field(a, 'metadata', None)
        if not isinstance(meta, dict):
            meta = {}
        etype = _field(a, 'evidence_type', None) or meta.get('evidence_type', '')
        art_id = str(_field(a, 'artifact_id', None) or f'#{idx}')

        hit = False
        if etype in _SURVEILLANCE_TYPES:
            surv_matches = [
                (kw, rx.search(desc))
                for kw, rx in zip(SURVEILLANCE_KEYWORDS, _SURVEILLANCE_RES)
            ]
            surv_matches = [(kw, m) for kw, m in surv_matches if m]
            if surv_matches:
                surveillance_count += 1
                hit = True
                for kw, m in surv_matches:
                    spans.append(_span(art_id, "surveillance", kw, desc, m))
        zc_matches = [
            (kw, rx.search(desc))
            for kw, rx in zip(ZERO_CONTACT_KEYWORDS, _ZERO_CONTACT_RES)
        ]
        zc_matches = [(kw, m) for kw, m in zc_matches if m]
        if zc_matches:
            zero_contact_count += 1
            hit = True
            for kw, m in zc_matches:
                spans.append(_span(art_id, "zero_contact", kw, desc, m))
        if hit:
            matched.append(art_id)

    if surveillance_count == 0:
        penalty = Fraction(0)
    elif zero_contact_count > 0:
        penalty = min(Fraction(8, 10), Fraction(surveillance_count * 3, 10))
    else:
        penalty = min(Fraction(8, 10), Fraction(surveillance_count, 10))

    return {
        "pattern_present": surveillance_count > 0 and zero_contact_count > 0,
        "penalty": penalty,
        "surveillance_count": surveillance_count,
        "zero_contact_count": zero_contact_count,
        "matched_artifacts": matched,
        "matched_spans": spans,
    }
