"""Hash-chained sealed verdict stream (contracts/verdict_stream_entry.schema.json).

One entry per adjudicated evidence window. Entry N commits to entry N-1
(``prev_entry_hash``), to the window it judged (``window_hash``) and to the
full scorer result (``bundle_sha256``), so the live stream is tamper-evident
end to end: altering any window, any verdict, or the order of events breaks
verification. Replaying the same window sequence reproduces every seal
bit-for-bit.

Uses the same canonical-v2 + SHA-256 recipe as core/bundle_builder — one
encoder, everywhere. Scores travel as exact fraction strings: the scorer's
deterministically-rounded decimal floats are converted via ``Fraction(str())``
(exact, not approximate) at this boundary so no float enters the sealed entry.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from fractions import Fraction
from typing import Optional

from core.canonicalize import CANONICALIZE_VERSION, _canonicalize

GENESIS_HASH = "0" * 64

_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
_MITRE_RE = re.compile(r"^T[0-9]{4}(\.[0-9]{3})?$")

_VALID_STATES = frozenset({
    "MALICE_HIGH", "MALICE_MEDIUM", "BENIGN_HIGH", "BENIGN_MEDIUM",
    "ABSTAIN_CONTRADICTION", "ABSTAIN_INSUFFICIENT", "ABSTAIN_DEGRADED",
    "ESCALATE",
})


class StreamError(ValueError):
    """Invalid input reached the verdict-stream boundary."""


def _sha256_canonical(obj) -> str:
    """Exact same recipe as core/bundle_builder._sha256_dict (v2 lockstep)."""
    serialized = json.dumps(
        _canonicalize(obj), sort_keys=True, ensure_ascii=True
    ).encode("utf-8")
    return hashlib.sha256(serialized).hexdigest()


def host_hash(host) -> str:
    """The identity of the machine a verdict is about, as one hash.

    A sealed verdict that does not name its host is only half an identity: the
    hostname beside it in an exhibit is then a free-text label anyone can
    rewrite, and the chain still verifies (red-team A-1). Sealing this hash into
    every entry makes the binding checkable by anyone holding the host record,
    with or without the evidence windows.

    Same canonical-v2 + SHA-256 recipe as everything else here.
    """
    if not isinstance(host, dict):
        raise StreamError(f"host must be a dict, got {type(host).__name__}")
    return _sha256_canonical(host)


def _exact_fraction_str(value, field: str) -> str:
    """Convert a scorer numeric (decimal-quantized float / int / Fraction)
    to an exact ``num/den`` string. ``Fraction(str(x))`` over a decimal
    representation is exact; anything unparseable fails loud."""
    try:
        frac = Fraction(str(value))
    except (ValueError, ZeroDivisionError, TypeError) as exc:
        raise StreamError(f"{field} is not an exact numeric: {value!r}") from exc
    return f"{frac.numerator}/{frac.denominator}"


def _extract_mitre(scorer_result: dict) -> list:
    """Deterministically collect valid ATT&CK technique ids mentioned in the
    CAIE fracture details. Sorted unique; invalid shapes ignored."""
    found = set()
    for detail in scorer_result.get("caie_fracture_details", []) or []:
        if not isinstance(detail, dict):
            continue
        for value in detail.values():
            if isinstance(value, str) and _MITRE_RE.fullmatch(value):
                found.add(value)
    return sorted(found)


def build_stream_entry(*, window: dict, scorer_result: dict,
                       prev_entry_hash: str) -> dict:
    """Seal one verdict-stream entry over an adjudicated window.

    Pure function of its inputs. The window must verify (its hash is
    recomputed here — a tampered window is refused, not chained), the
    scorer result must carry a quadripartite state, and ``prev_entry_hash``
    must be the previous entry's hash (GENESIS_HASH for sequence 0).
    """
    from tools.velociraptor.adapter import verify_window
    if not verify_window(window):
        raise StreamError("window hash does not verify — refusing to chain it")
    if not isinstance(prev_entry_hash, str) or not _SHA256_RE.fullmatch(prev_entry_hash):
        raise StreamError(f"prev_entry_hash is not a sha256 hex: {prev_entry_hash!r}")
    if window["sequence"] == 0 and prev_entry_hash != GENESIS_HASH:
        raise StreamError("sequence 0 must chain from GENESIS_HASH")

    quad = scorer_result.get("quadripartite_state")
    if not isinstance(quad, dict) or quad.get("verdict_state") not in _VALID_STATES:
        raise StreamError(
            f"scorer result carries no valid quadripartite state: {quad!r}"
        )

    bundle = {
        "window_hash": window["window_hash"],
        "scorer_result": scorer_result,
    }

    entry = {
        # v2 adds host_hash. Verification recomputes each entry's hash from its
        # own content, so a v1 entry sealed before this existed still verifies
        # unchanged; only the host binding is unavailable for it, and
        # verify_stream says so rather than passing it silently.
        "schema_version": 2,
        "case_id": window["case_id"],
        "sequence": window["sequence"],
        "window_hash": window["window_hash"],
        "host_hash": host_hash(window["host"]),
        "prev_entry_hash": prev_entry_hash,
        "verdict": {
            "state": quad["verdict_state"],
            "score": _exact_fraction_str(scorer_result.get("score"), "score"),
            "confidence": _exact_fraction_str(
                scorer_result.get("confidence"), "confidence"),
            "mitre_techniques": _extract_mitre(scorer_result),
            "determinism_level": "sealed",
        },
        "bundle_sha256": _sha256_canonical(bundle),
        "canonicalize_version": CANONICALIZE_VERSION,
    }
    entry["entry_hash"] = _sha256_canonical(entry)
    return entry


def verify_stream(entries: list, windows: Optional[dict] = None, *,
                  case_id: Optional[str] = None,
                  host: Optional[dict] = None) -> dict:
    """Verify a whole stream. Returns ``{"chain_ok": bool, "errors": [...],
    "warnings": [...]}`` — every violation found, never just the first, so an
    auditor sees the full damage.

    Three layers, and they answer different questions:

    - **integrity** — was any entry altered, inserted, reordered or dropped?
    - **identity** (red-team A-1) — is this chain the record of the case and
      host it is being presented as? A chain is sealed over its ``case_id`` and
      (from schema v2) its ``host_hash``, but nothing compared those to the
      envelope carrying them, so a MALICE chain could be presented as another
      machine's record and still verify. Pass ``case_id`` / ``host`` — whatever
      the caller is claiming this chain belongs to — and the claim is checked
      against the seals instead of taken on trust.
    - **evidence** — ``windows`` (optional) maps window_hash -> window dict to
      re-verify each referenced window's own seal, and to confirm the window
      belongs to the same case as the entry that cites it.

    A v1 entry, sealed before the host binding existed, cannot be checked
    against a host. That is reported as a WARNING, never as a pass: the reader
    learns exactly what was out of scope.
    """
    errors = []
    warnings = []
    prev_hash = GENESIS_HASH
    seen_case_ids = set()
    for position, entry in enumerate(entries):
        label = f"entry[{position}]"
        if not isinstance(entry, dict):
            errors.append(f"{label}: not a dict")
            prev_hash = None
            continue
        if entry.get("sequence") != position:
            errors.append(
                f"{label}: sequence {entry.get('sequence')!r} != {position} "
                f"(gap, reorder, or truncation)"
            )
        if prev_hash is not None and entry.get("prev_entry_hash") != prev_hash:
            errors.append(f"{label}: prev_entry_hash does not match previous entry")
        unsealed = {k: v for k, v in entry.items() if k != "entry_hash"}
        recomputed = _sha256_canonical(unsealed)
        if entry.get("entry_hash") != recomputed:
            errors.append(f"{label}: entry_hash does not match content (tampered)")

        # -- identity -------------------------------------------------------
        entry_case = entry.get("case_id")
        seen_case_ids.add(entry_case)
        if case_id is not None and entry_case != case_id:
            errors.append(
                f"{label}: sealed case_id {entry_case!r} is not the case this "
                f"chain is presented as ({case_id!r}) — identity substitution")
        if host is not None:
            sealed_host = entry.get("host_hash")
            if not sealed_host:
                warnings.append(
                    f"{label}: sealed before host binding existed "
                    f"(schema v{entry.get('schema_version')!r}), so the host it "
                    f"judged could NOT be checked against the one claimed")
            elif sealed_host != host_hash(host):
                errors.append(
                    f"{label}: sealed host does not match the host this chain "
                    f"is presented as ({host.get('hostname')!r}) — identity "
                    f"substitution")

        if windows is not None:
            from tools.velociraptor.adapter import verify_window
            window = windows.get(entry.get("window_hash"))
            if window is None:
                errors.append(f"{label}: referenced window not provided")
            elif not verify_window(window):
                errors.append(f"{label}: referenced window fails its own seal")
            elif window.get("case_id") != entry_case:
                errors.append(
                    f"{label}: referenced window belongs to case "
                    f"{window.get('case_id')!r}, not to this entry's case "
                    f"{entry_case!r}")
        prev_hash = entry.get("entry_hash")

    if len(seen_case_ids) > 1:
        errors.append(
            f"chain mixes entries whose sealed case_id differs "
            f"({sorted(str(c) for c in seen_case_ids)}) — a case's chain is the "
            f"record of ONE case")
    if host is None and entries:
        warnings.append(
            "no host was supplied, so the machine each verdict is about was not "
            "checked — the chain's integrity is verified, its subject is not")
    return {"chain_ok": not errors, "entries": len(entries), "errors": errors,
            "warnings": warnings}


def _last_entry(stream_path) -> Optional[dict]:
    """The last non-empty entry already in the stream file, or None if the file
    does not exist yet or is empty."""
    try:
        last = None
        with open(stream_path, "r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if line:
                    last = line
    except FileNotFoundError:
        return None
    return json.loads(last) if last else None


def append_entry(stream_path, entry: dict) -> None:
    """Append one entry to a JSONL stream file (one canonical-JSON line).

    Continuity and durability (red-team R1-2): when the file already holds
    entries, the new one must chain onto the last (matching ``prev_entry_hash``
    and a contiguous ``sequence``), so a caller holding stale state cannot write
    a silent break onto disk; and the append is flushed and ``fsync``'d before
    returning, so a crash cannot lose a verdict the caller believes is stored.
    A fresh/empty file accepts any entry — a session continuing an existing case
    chains to the case head, not to this per-session file.
    """
    last = _last_entry(stream_path)
    if last is not None:
        if entry.get("prev_entry_hash") != last.get("entry_hash"):
            raise StreamError(
                "append_entry: entry does not chain onto the file's last entry "
                "(stale state would write a break)")
        if entry.get("sequence") != (last.get("sequence", -1) + 1):
            raise StreamError(
                f"append_entry: non-contiguous sequence {entry.get('sequence')!r} "
                f"after {last.get('sequence')!r}")
    line = json.dumps(entry, sort_keys=True, ensure_ascii=True)
    with open(stream_path, "a", encoding="utf-8") as handle:
        handle.write(line + "\n")
        handle.flush()
        os.fsync(handle.fileno())


def read_stream(stream_path) -> list:
    """Read a JSONL stream file back into a list of entries."""
    entries = []
    with open(stream_path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                entries.append(json.loads(line))
    return entries
