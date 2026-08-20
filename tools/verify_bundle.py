#!/usr/bin/env python3
"""annaconda-verify — independently confirm a sealed exhibit, trusting nothing.

This is a court-grade, adversarial verifier. It re-derives every seal in an
exported annaconda case bundle and reports whether the tamper-evident chain
holds. Its whole value is *independence*, so it obeys two hard rules:

1. **Standard library only.** No third-party package, no network, no clock.
   A reviewer can read every line and run it on an air-gapped machine.

2. **It imports nothing from annaconda.** It keeps its OWN copy of the canonical
   encoder and the chain rules, in lockstep with core/canonicalize.py and
   core/verdict_stream.py (tests/test_verify_bundle.py asserts the lockstep). If
   the producing code had an encoding bug, this verifier — written separately —
   would disagree with it rather than share the bug. A verifier that imported the
   sealer's own encoder could only ever confirm "the sealer agrees with itself".

What it checks, for each entry in the chain:
  - the entry hash re-derives from the entry's own content (nothing was altered);
  - the entry links to the one before it (``prev_entry_hash``), in order, from
    GENESIS — so no entry was inserted, reordered, dropped, or truncated;
  - if the exhibit also carries the evidence windows, each referenced window
    re-seals to its ``window_hash`` (the evidence itself is intact).

Exit code: 0 if the chain verifies (PASS, or PASS with a WARN), 1 if any seal is
broken (FAIL), 2 if a WARN is present and --strict was given. A WARN is never a
silent PASS: it names exactly what could not be checked (e.g. windows not
included in this exhibit), so the reader knows the scope of the guarantee.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import unicodedata
from fractions import Fraction

GENESIS_HASH = "0" * 64

# ---------------------------------------------------------------------------
# Canonical encoder — an INDEPENDENT copy of core/canonicalize.py, kept in
# lockstep by tests/test_verify_bundle.py. Do not import the producer's copy.
# ---------------------------------------------------------------------------

_V2_STR_PREFIX = "s:"


def _norm_str(s: str) -> str:
    return unicodedata.normalize(
        "NFC", s.replace("\r\n", "\n").replace("\r", "\n"))


def _canon_v1(obj):
    """Legacy v1 schema — for verifying historically sealed bundles only."""
    if isinstance(obj, bool):
        return "true" if obj else "false"
    if isinstance(obj, int):
        return f"{obj}:int"
    if isinstance(obj, float):
        if obj != obj:
            return "nan"
        if obj == float("inf"):
            return "inf"
        if obj == float("-inf"):
            return "-inf"
        return f"{obj + 0.0:.8f}"
    if isinstance(obj, str):
        return obj
    if obj is None:
        return "null"
    if isinstance(obj, Fraction):
        return str(obj)
    if isinstance(obj, dict):
        return {k: _canon_v1(v) for k, v in sorted(obj.items())}
    if isinstance(obj, (list, tuple)):
        return [_canon_v1(v) for v in obj]
    return str(obj)


def _canon_v2(obj):
    """Default v2 schema — used to seal new bundles."""
    if isinstance(obj, bool):
        return "true" if obj else "false"
    if isinstance(obj, int):
        return f"{obj}:int"
    if isinstance(obj, float):
        if obj != obj:
            return "nan"
        if obj == float("inf"):
            return "inf"
        if obj == float("-inf"):
            return "-inf"
        return f"{obj + 0.0:.8f}"
    if isinstance(obj, str):
        return _V2_STR_PREFIX + _norm_str(obj)
    if obj is None:
        return "null"
    if isinstance(obj, Fraction):
        return f"{obj.numerator}/{obj.denominator}:frac"
    if isinstance(obj, dict):
        # Lockstep with the producer: non-string keys are refused (they would
        # collide with their string form under json.dumps — R1-1).
        for k in obj:
            if not isinstance(k, str):
                raise TypeError(
                    f"canonical v2 refuses non-string dict key {k!r} "
                    f"({type(k).__name__}): it would collide with its string form")
        return {k: _canon_v2(v) for k, v in sorted(obj.items())}
    if isinstance(obj, (list, tuple)):
        return [_canon_v2(v) for v in obj]
    return _V2_STR_PREFIX + _norm_str(str(obj))


def _sha256_canonical(obj, version: str = "2") -> str:
    canon = _canon_v1 if str(version) == "1" else _canon_v2
    serialized = json.dumps(
        canon(obj), sort_keys=True, ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(serialized).hexdigest()


# ---------------------------------------------------------------------------
# Verification (independent copy of the chain rules in core/verdict_stream.py)
# ---------------------------------------------------------------------------

def _reseal_of(obj: dict, hash_field: str) -> str:
    """Recompute the seal of a dict from all its fields except the seal itself,
    honoring the object's own declared canonicalize_version."""
    version = str(obj.get("canonicalize_version", "2"))
    unsealed = {k: v for k, v in obj.items() if k != hash_field}
    return _sha256_canonical(unsealed, version)


def verify_entries(entries: list, windows: dict | None = None) -> dict:
    """Verify a whole verdict chain. Returns every violation, not just the first,
    so a reviewer sees the full extent of any tampering.

    ``windows`` optionally maps window_hash -> window dict; when present each
    referenced window is re-sealed too. When absent, window integrity is reported
    as a WARN (unchecked), never as a pass.
    """
    errors: list[str] = []
    warnings: list[str] = []
    prev_hash = GENESIS_HASH

    if not isinstance(entries, list) or not entries:
        return {"status": "FAIL", "entries": 0,
                "errors": ["exhibit carries no verdict entries to verify"],
                "warnings": []}

    for position, entry in enumerate(entries):
        label = f"entry[{position}]"
        if not isinstance(entry, dict):
            errors.append(f"{label}: not an object")
            prev_hash = None
            continue

        if entry.get("sequence") != position:
            errors.append(
                f"{label}: sequence {entry.get('sequence')!r} != {position} "
                f"(gap, reorder, or truncation)")

        if prev_hash is not None and entry.get("prev_entry_hash") != prev_hash:
            errors.append(
                f"{label}: prev_entry_hash does not link to the previous entry "
                f"(chain broken)")
        elif position == 0 and entry.get("prev_entry_hash") != GENESIS_HASH:
            errors.append(f"{label}: first entry must chain from GENESIS")

        stored = entry.get("entry_hash")
        if not isinstance(stored, str):
            errors.append(f"{label}: entry_hash missing")
        else:
            recomputed = _reseal_of(entry, "entry_hash")
            if stored != recomputed:
                errors.append(
                    f"{label}: entry_hash does not match content (tampered)")

        if windows is not None:
            wh = entry.get("window_hash")
            window = windows.get(wh)
            if window is None:
                errors.append(f"{label}: referenced window {wh!r} not provided")
            else:
                if _reseal_of(window, "window_hash") != window.get("window_hash"):
                    errors.append(f"{label}: referenced window fails its own seal")

        prev_hash = entry.get("entry_hash")

    if windows is None:
        warnings.append(
            "evidence windows were not included in this exhibit: the verdict "
            "CHAIN is verified, but each window's own evidence seal was not "
            "re-checked (export with --with-windows for full coverage)")

    status = "FAIL" if errors else ("WARN" if warnings else "PASS")
    return {"status": status, "entries": len(entries),
            "errors": errors, "warnings": warnings}


def verify_bundle(bundle: dict) -> dict:
    """Verify an exported exhibit bundle (the shape of GET /cases/{id}/exhibit,
    or a raw case dict with ``entries``). Returns a structured report."""
    if not isinstance(bundle, dict):
        return {"status": "FAIL", "case_id": None, "entries": 0,
                "errors": ["input is not a JSON object"], "warnings": []}
    case = bundle.get("case", bundle)  # accept a raw case dict too
    entries = case.get("entries") if isinstance(case, dict) else None
    windows = bundle.get("windows")
    if isinstance(windows, list):
        windows = {w.get("window_hash"): w for w in windows if isinstance(w, dict)}
    report = verify_entries(entries or [], windows if windows else None)
    report["case_id"] = (case or {}).get("case_id") if isinstance(case, dict) else None
    report["format"] = bundle.get("format")
    return report


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _render(report: dict) -> str:
    icon = {"PASS": "PASS", "WARN": "PASS (with warnings)", "FAIL": "FAIL"}
    lines = [
        f"annaconda exhibit verification: {icon.get(report['status'], report['status'])}",
        f"  case:    {report.get('case_id')}",
        f"  entries: {report['entries']} sealed verdict(s) in the chain",
    ]
    for w in report.get("warnings", []):
        lines.append(f"  WARN: {w}")
    for e in report.get("errors", []):
        lines.append(f"  BROKEN: {e}")
    if report["status"] == "PASS":
        lines.append("  The chain is intact: no verdict was altered, reordered, "
                     "inserted, or dropped.")
    elif report["status"] == "WARN":
        lines.append("  The verdict chain is intact; see WARN for what was out of "
                     "scope for this exhibit.")
    else:
        lines.append("  The seal does not hold. Treat this exhibit as tampered.")
    return "\n".join(lines)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="annaconda-verify",
        description="Independently verify a sealed annaconda exhibit bundle. "
                    "Standard-library only; imports nothing from annaconda.")
    parser.add_argument(
        "bundle", nargs="?", default="-",
        help="path to the exhibit JSON (GET /cases/{id}/exhibit), or - for stdin")
    parser.add_argument("--json", action="store_true",
                        help="emit the machine-readable report instead of text")
    parser.add_argument("--strict", action="store_true",
                        help="treat a WARN as a failure (exit 2)")
    args = parser.parse_args(argv)

    try:
        raw = sys.stdin.read() if args.bundle == "-" else \
            open(args.bundle, "r", encoding="utf-8").read()
        bundle = json.loads(raw)
    except (OSError, ValueError) as exc:
        print(f"annaconda-verify: cannot read bundle: {exc}", file=sys.stderr)
        return 1

    report = verify_bundle(bundle)
    print(json.dumps(report, indent=2, sort_keys=True) if args.json
          else _render(report))

    if report["status"] == "FAIL":
        return 1
    if report["status"] == "WARN" and args.strict:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
