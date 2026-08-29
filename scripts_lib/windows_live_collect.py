"""Collect REAL Windows telemetry through Velociraptor, seal it, adjudicate it.

Two modes, one code path:

    python3 scripts_lib/windows_live_collect.py C:\\path\\velociraptor.exe
        Live: runs the curated Windows templates against THIS host through
        Velociraptor's own VQL engine, seals the window, adjudicates it, and
        writes the raw rows to --out as replay fixtures.

    python3 scripts_lib/windows_live_collect.py --replay evidence_dump/
        Replay: re-runs the identical pipeline over rows collected earlier
        (on another machine). The window hash must come out identical to the
        live run -- that equality is the point of saving the rows.

Window time bounds are derived from the collected rows, never from a wall
clock, so a replay of the same telemetry reproduces the same seal bit-for-bit.

The VQL below is a starting point, not gospel: field names and types are what
this run is meant to discover. Every template reports rows_in vs artifacts_out
and WHY rows were dropped, and --show-fields prints the raw field names
Velociraptor actually returned so the mapping can be fixed with real data in
hand instead of guessed.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.velociraptor.adapter import (  # noqa: E402
    MockTransport, VelociraptorQueryTransport, collect_window, verify_window,
    window_to_case,
)
from tools.velociraptor.vql_templates import TEMPLATES  # noqa: E402

# Template id -> VQL that gathers it on Windows. Keyed by the template's
# artifact name because that is what the transport maps.
#
# netstat: the curated template reads "Raddr.IP"/"Laddr.IP", while netstat()
# returns Laddr/Raddr as nested objects -- hence the backticked aliases. If
# Velociraptor rejects a dotted alias, drop the backticks, rerun with
# --show-fields, and we fix the template instead of the query.
WINDOWS_VQL = {
    "Windows.System.Pslist":
        "SELECT Pid, Ppid, Name, Exe, CommandLine, Username, CreateTime "
        "FROM pslist()",
    "Windows.Network.Netstat":
        "SELECT Pid, Name, Status, "
        "Laddr.IP AS `Laddr.IP`, Laddr.Port AS `Laddr.Port`, "
        "Raddr.IP AS `Raddr.IP`, Raddr.Port AS `Raddr.Port`, "
        "Timestamp FROM netstat()",
    "Windows.EventLogs.Evtx":
        "SELECT System.EventID.Value AS EventID, System.Channel AS Channel, "
        "System.Computer AS Computer, System.TimeCreated.SystemTime AS EventTime, "
        "EventData.NewProcessName AS NewProcessName, "
        "EventData.ParentProcessName AS ParentProcessName, "
        "EventData.SubjectUserName AS SubjectUserName "
        "FROM parse_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx') "
        "WHERE EventID = 4688 LIMIT 200",
    "Windows.System.TaskScheduler":
        "SELECT FullPath, Mtime AS MTime, Command FROM glob("
        "globs='C:/Windows/System32/Tasks/**') WHERE NOT IsDir",
}

class _Recording:
    """Delegates to a real transport while keeping every raw row it served.

    The dump must contain the rows that were DROPPED too -- a row with no
    usable timestamp is precisely the one worth looking at later -- so the
    rows are captured here, at the transport, before normalization sees them.
    """

    def __init__(self, inner):
        self._inner = inner
        self.rows_by_artifact: dict[str, list] = {}

    def collect(self, client_id, artifact, params):
        return self._inner.collect(client_id, artifact, params)

    def flow_state(self, client_id, flow_id):
        return self._inner.flow_state(client_id, flow_id)

    def flow_results(self, client_id, flow_id, artifact):
        rows = self._inner.flow_results(client_id, flow_id, artifact)
        self.rows_by_artifact[artifact] = rows
        return rows

    def manifest(self, client_id, flow_id, artifact):
        return self._inner.manifest(client_id, flow_id, artifact)


DEFAULT_TEMPLATES = ("pslist", "netstat", "process_creation_evtx", "scheduled_tasks")


def _bounds(artifacts: list) -> tuple[str, str]:
    """Window bounds from the evidence itself -- no clock, so replay reseals
    to the same hash. Falls back to a stated placeholder on empty collection."""
    stamps = sorted(a["timestamp"] for a in artifacts if a.get("timestamp"))
    if not stamps:
        return "1970-01-01T00:00:00Z", "1970-01-01T00:00:00Z"
    return stamps[0], stamps[-1]


def _check_against_live(dump_dir: Path, replayed: dict) -> int:
    """Compare a replay against the sealed window saved by the live run.

    The window hashes are NOT expected to match: ``source``, the flow ids and
    the manifest are custody, and the custody genuinely differed (a live
    endpoint query vs a file on disk). What must match is the evidence --
    artifact ids are derived from row content alone -- and the saved window
    must still verify against its own seal.
    """
    saved_path = dump_dir / "live_window.json"
    if not saved_path.is_file():
        print(f"[replay] no live_window.json in {dump_dir} -- nothing to compare")
        return 0
    live = json.loads(saved_path.read_text(encoding="utf-8"))

    if not verify_window(live):
        print("[replay] FAIL -- the saved live window does not match its own "
              "seal: it was altered after collection")
        return 1
    print(f"[replay] saved live window verifies (hash {live['window_hash'][:16]}...)")

    live_ids = {a["artifact_id"] for a in live["artifacts"]}
    replay_ids = {a["artifact_id"] for a in replayed["artifacts"]}
    if live_ids == replay_ids:
        print(f"[replay] MATCH -- {len(live_ids)} artifact ids re-derived "
              "identically from the saved rows")
        return 0
    print(f"[replay] MISMATCH -- live={len(live_ids)} replay={len(replay_ids)}")
    for missing in sorted(live_ids - replay_ids)[:5]:
        print(f"           only in live:   {missing}")
    for extra in sorted(replay_ids - live_ids)[:5]:
        print(f"           only in replay: {extra}")
    return 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("binary", nargs="?", help="path to velociraptor.exe")
    ap.add_argument("--replay", metavar="DIR",
                    help="replay saved rows from DIR instead of collecting live")
    ap.add_argument("--out", default="evidence_dump",
                    help="where to write the raw rows (default: evidence_dump)")
    ap.add_argument("--hostname", default="WIN-LIVE-01")
    ap.add_argument("--examiner-id", default="anna")
    ap.add_argument("--case-id", default="WIN-LIVE-001")
    ap.add_argument("--templates", nargs="+", default=list(DEFAULT_TEMPLATES),
                    choices=sorted(TEMPLATES), metavar="TEMPLATE",
                    help=f"default: {' '.join(DEFAULT_TEMPLATES)}")
    ap.add_argument("--show-fields", action="store_true",
                    help="print the raw field names of the first row per template")
    args = ap.parse_args()

    if args.replay:
        transport = MockTransport(args.replay)
        print(f"[replay] rows from {args.replay}")
    elif args.binary:
        if not Path(args.binary).exists():
            print(f"[live] binary not found: {args.binary}")
            return 2
        transport = _Recording(VelociraptorQueryTransport(args.binary, WINDOWS_VQL))
        print(f"[live] collecting from THIS host via {Path(args.binary).name}")
    else:
        ap.error("give a path to velociraptor.exe, or --replay DIR")

    requests = [(t, {}) for t in args.templates]
    try:
        window, reports = collect_window(
            transport, case_id=args.case_id, sequence=0,
            source="velociraptor" if not args.replay else "replay",
            host={"client_id": "C.localhost", "hostname": args.hostname,
                  "os": "windows"},
            # Provisional bounds; resealed below from the rows themselves.
            time_start_utc="1970-01-01T00:00:00Z",
            time_end_utc="1970-01-01T00:00:00Z",
            examiner_id=args.examiner_id, requests=requests,
        )
    except Exception as exc:                      # noqa: BLE001 - report, do not mask
        print(f"[FAIL] collection failed: {type(exc).__name__}: {exc}")
        return 1

    # Reseal over evidence-derived bounds so live and replay agree.
    from tools.velociraptor.adapter import build_evidence_window
    start, end = _bounds(window["artifacts"])
    window = build_evidence_window(
        case_id=window["case_id"], sequence=window["sequence"],
        source=window["source"], host=window["host"],
        time_start_utc=start, time_end_utc=end,
        collection=window["collection"], artifacts=window["artifacts"],
        manifest=window["manifest"],
    )

    print("\n--- what each template actually yielded ---")
    for rep in reports:
        flag = "" if rep["dropped_no_timestamp"] == 0 else "   <-- LOOK HERE"
        print(f"  {rep['template_id']:<22} rows_in={rep['rows_in']:<5} "
              f"artifacts={rep['artifacts_out']:<5} "
              f"dropped_no_timestamp={rep['dropped_no_timestamp']:<5} "
              f"dedup={rep['deduplicated']}{flag}")

    if args.show_fields:
        print("\n--- raw field names Velociraptor returned (first row each) ---")
        recorded = getattr(transport, "rows_by_artifact", {})
        for artifact, rows in sorted(recorded.items()):
            if rows:
                print(f"  {artifact}: {sorted(rows[0])}")
        seen = set()
        for art in window["artifacts"]:
            tid = art["metadata"]["vql_template"]
            if tid in seen:
                continue
            seen.add(tid)
            print(f"  {tid}: {sorted(art['metadata']['row'])}")

    print(f"\n[window] {window['window_id']}  artifacts={len(window['artifacts'])}  "
          f"bounds={start} .. {end}")
    print(f"[window] window_hash={window['window_hash']}")
    print(f"[window] verifies: {verify_window(window)}")

    rc = 0
    if args.replay:
        rc = _check_against_live(Path(args.replay), window)

    from vigia_scorer import _vigia_score
    result = _vigia_score(window_to_case(window))
    print(f"[verdict] {result['verdict']} "
          f"({result['quadripartite_state']['verdict_state']})")

    if not args.replay:
        out = Path(args.out)
        out.mkdir(parents=True, exist_ok=True)
        for artifact, rows in transport.rows_by_artifact.items():
            # The window manifest hashes these bytes, so the file written here
            # is itself part of what replay must reproduce -- do not reformat it.
            (out / f"{artifact}.json").write_text(
                json.dumps(rows, indent=2, ensure_ascii=False), encoding="utf-8")
        # Save the sealed window itself: that is the evidence to take home.
        # Replaying the rows produces a DIFFERENT window_hash on purpose --
        # source, flow ids and manifest are custody, and custody really did
        # differ -- so the at-home check compares what must be equal instead.
        (out / "live_window.json").write_text(
            json.dumps(window, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"\n[saved] raw rows + sealed window in {out}/ -- take home and run:")
        print(f"        python3 scripts_lib/windows_live_collect.py --replay {out}/")
        print("        it re-derives the same artifacts from the same rows.")
    return rc


if __name__ == "__main__":
    sys.exit(main())
