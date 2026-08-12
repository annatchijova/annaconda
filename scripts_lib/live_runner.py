"""Live-mode runner: poll -> evidence window -> sealed verdict -> chain.

The phase 3 loop. Each cycle freezes one evidence window through the
Velociraptor adapter, adjudicates it with the deterministic core, seals a
verdict-stream entry chained to the previous one, and persists both:

    <out_dir>/windows/window-<seq>.json   (the sealed evidence windows)
    <out_dir>/stream.jsonl                (the hash-chained verdict stream)

Recorded windows are simultaneously the demo fallback and the determinism
proof: ``replay`` re-scores them from disk and asserts every seal comes out
bit-for-bit identical to the recorded stream.

Clock discipline: wall time is read ONLY in live capture, where it enters
the window as recorded evidence data (then sealed, then replayable). Mock
capture derives all timestamps from --time-base, so it is deterministic by
construction and never touches the clock.

Exit codes: 0 ok / replay MATCH; 1 verification or replay mismatch; 2 usage
or runtime error.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from core.verdict_stream import (  # noqa: E402
    GENESIS_HASH, append_entry, build_stream_entry, read_stream, verify_stream,
)
from tools.velociraptor.adapter import (  # noqa: E402
    MockTransport, RestTransport, verify_window, window_to_case,
)

_TS_FMT = "%Y-%m-%dT%H:%M:%SZ"

DEFAULT_REQUESTS = [
    ("pslist", {}),
    ("netstat", {}),
    ("process_creation_evtx", {"Channel": "Security"}),
]


def _parse_ts(value: str) -> datetime:
    return datetime.strptime(value, _TS_FMT).replace(tzinfo=timezone.utc)


def _fmt_ts(value: datetime) -> str:
    return value.strftime(_TS_FMT)


def _score(case: dict) -> dict:
    from vigia_scorer import _vigia_score  # heavy import, deferred
    return _vigia_score(case)


def run_capture(transport, *, case_id: str, host: dict, examiner_id: str,
                out_dir: Path, cycles: int, interval_s: int,
                requests=None, source: str = "velociraptor",
                time_base: str | None = None,
                emit=print) -> list:
    """Capture ``cycles`` consecutive windows and chain their verdicts.

    With ``time_base`` set, window k spans
    [base + k*interval, base + (k+1)*interval) and the clock is never read
    (deterministic mock/demo capture). Without it, live wall time is
    recorded — and a real wait of ``interval_s`` happens between cycles.
    Returns the list of sealed stream entries.
    """
    from tools.velociraptor.adapter import collect_window
    windows_dir = out_dir / "windows"
    windows_dir.mkdir(parents=True, exist_ok=True)
    stream_path = out_dir / "stream.jsonl"
    if stream_path.exists():
        raise SystemExit(
            f"refusing to append to an existing stream: {stream_path} — "
            f"a verdict chain is append-only within one run; use a fresh "
            f"out_dir per capture session"
        )

    requests = requests if requests is not None else DEFAULT_REQUESTS
    base = _parse_ts(time_base) if time_base else None
    entries = []
    prev = GENESIS_HASH

    for sequence in range(cycles):
        if base is not None:
            start = base + timedelta(seconds=sequence * interval_s)
            end = start + timedelta(seconds=interval_s)
        else:
            import time as _time
            if sequence:
                _time.sleep(interval_s)
            now = datetime.now(timezone.utc)
            start, end = now - timedelta(seconds=interval_s), now

        window, reports = collect_window(
            transport, case_id=case_id, sequence=sequence, source=source,
            host=host, time_start_utc=_fmt_ts(start), time_end_utc=_fmt_ts(end),
            examiner_id=examiner_id, requests=requests,
        )
        result = _score(window_to_case(window))
        entry = build_stream_entry(
            window=window, scorer_result=result, prev_entry_hash=prev,
        )

        window_path = windows_dir / f"window-{sequence:06d}.json"
        window_path.write_text(
            json.dumps(window, sort_keys=True, ensure_ascii=True, indent=1),
            encoding="utf-8",
        )
        append_entry(stream_path, entry)

        dropped = sum(r.get("dropped_no_timestamp", 0) for r in reports)
        emit(
            f"[{sequence:06d}] {entry['verdict']['state']:<22} "
            f"score={entry['verdict']['score']:<10} "
            f"window={window['window_hash'][:12]} "
            f"entry={entry['entry_hash'][:12]}"
            + (f" dropped_rows={dropped}" if dropped else "")
        )
        entries.append(entry)
        prev = entry["entry_hash"]

    return entries


def run_replay(out_dir: Path, emit=print) -> dict:
    """Re-score recorded windows and compare against the recorded stream.

    The determinism demonstration: same windows in, bit-identical seals out.
    Returns {"match": bool, "entries": n, "errors": [...]}.
    """
    windows_dir = out_dir / "windows"
    stream_path = out_dir / "stream.jsonl"
    errors = []

    recorded = read_stream(stream_path)
    window_files = sorted(windows_dir.glob("window-*.json"))
    if len(recorded) != len(window_files):
        errors.append(
            f"{len(window_files)} windows vs {len(recorded)} stream entries"
        )

    windows = []
    bad_seals = set()
    for path in window_files:
        window = json.loads(path.read_text(encoding="utf-8"))
        if not verify_window(window):
            errors.append(f"{path.name}: window seal does not verify")
            bad_seals.add(window.get("window_hash"))
        windows.append(window)

    chain_report = verify_stream(
        recorded, windows={w["window_hash"]: w for w in windows},
    )
    if not chain_report["chain_ok"]:
        errors.extend(chain_report["errors"])

    prev = GENESIS_HASH
    for window, recorded_entry in zip(windows, recorded):
        # A window with a broken seal is already reported; re-scoring it
        # would only crash on the adapter's own integrity refusal. Skip it
        # and keep auditing the rest — the report must be complete.
        if window.get("window_hash") in bad_seals:
            prev = recorded_entry.get("entry_hash")
            continue
        result = _score(window_to_case(window))
        rebuilt = build_stream_entry(
            window=window, scorer_result=result, prev_entry_hash=prev,
        )
        if rebuilt["entry_hash"] != recorded_entry.get("entry_hash"):
            errors.append(
                f"entry[{window['sequence']}]: replay produced "
                f"{rebuilt['entry_hash'][:12]} but the record says "
                f"{str(recorded_entry.get('entry_hash'))[:12]} — "
                f"non-determinism or tampering"
            )
        prev = recorded_entry.get("entry_hash")

    match = not errors
    emit(
        f"REPLAY {'MATCH' if match else 'MISMATCH'} — "
        f"{len(recorded)} entries re-derived"
        + ("" if match else f"; {len(errors)} error(s)")
    )
    for error in errors:
        emit(f"  - {error}")
    return {"match": match, "entries": len(recorded), "errors": errors}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="live_runner",
        description="VIGIA live loop: window -> sealed verdict -> chain",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    cap = sub.add_parser("capture", help="capture windows and chain verdicts")
    cap.add_argument("--mode", choices=("mock", "live"), required=True)
    cap.add_argument("--out-dir", required=True)
    cap.add_argument("--case-id", required=True)
    cap.add_argument("--examiner-id", required=True)
    cap.add_argument("--cycles", type=int, default=3)
    cap.add_argument("--interval-s", type=int, default=30)
    cap.add_argument("--fixtures",
                     help="[mock] fixtures dir (default: tests/fixtures/velociraptor)")
    cap.add_argument("--time-base",
                     help="[mock] deterministic time base, e.g. 2026-08-12T14:00:00Z "
                          "(required in mock mode; forbidden in live mode)")
    cap.add_argument("--base-url", help="[live] Velociraptor https endpoint")
    cap.add_argument("--username", help="[live] GUI user")
    cap.add_argument("--password", help="[live] GUI password")
    cap.add_argument("--ca-path", help="[live] server CA certificate")
    cap.add_argument("--client-id", default="C.mock01")
    cap.add_argument("--hostname", default="WIN11-VICTIM")

    rep = sub.add_parser("replay", help="re-score recorded windows, compare seals")
    rep.add_argument("--out-dir", required=True)

    args = parser.parse_args(argv)

    if args.command == "replay":
        return 0 if run_replay(Path(args.out_dir))["match"] else 1

    if args.mode == "mock":
        if not args.time_base:
            parser.error("--time-base is required in mock mode (determinism)")
        fixtures = Path(args.fixtures) if args.fixtures else (
            REPO_ROOT / "tests" / "fixtures" / "velociraptor")
        transport = MockTransport(fixtures)
        source = "replay"
    else:
        if args.time_base:
            parser.error("--time-base is forbidden in live mode (wall time is "
                         "the recorded evidence)")
        for field in ("base_url", "username", "password"):
            if not getattr(args, field):
                parser.error(f"--{field.replace('_', '-')} is required in live mode")
        transport = RestTransport(
            args.base_url, args.username, args.password, ca_path=args.ca_path)
        source = "velociraptor"

    entries = run_capture(
        transport,
        case_id=args.case_id,
        host={"client_id": args.client_id, "hostname": args.hostname,
              "os": "windows"},
        examiner_id=args.examiner_id,
        out_dir=Path(args.out_dir),
        cycles=args.cycles,
        interval_s=args.interval_s,
        source=source,
        time_base=args.time_base,
    )
    report = verify_stream(entries)
    print(f"chain_ok={report['chain_ok']} entries={report['entries']}")
    return 0 if report["chain_ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
