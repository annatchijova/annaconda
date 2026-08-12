"""Tests for the hash-chained sealed verdict stream (phase 3)."""

import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

from core.verdict_stream import (
    GENESIS_HASH,
    StreamError,
    append_entry,
    build_stream_entry,
    read_stream,
    verify_stream,
)
from tools.velociraptor.adapter import MockTransport, collect_window, window_to_case

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURES = REPO_ROOT / "tests" / "fixtures" / "velociraptor"
HOST = {"client_id": "C.mock01", "hostname": "WIN11-VICTIM", "os": "windows"}

WINDOW_SPECS = [
    (0, "2026-08-12T14:00:00Z", "2026-08-12T14:05:00Z",
     [("pslist", {}), ("netstat", {})]),
    (1, "2026-08-12T14:05:00Z", "2026-08-12T14:10:00Z",
     [("process_creation_evtx", {"Channel": "Security"})]),
]

_FRACTION_RE = re.compile(r"^-?(0|[1-9][0-9]*)/([1-9][0-9]*)$")


@pytest.fixture(scope="module")
def chain():
    """A real two-window chain: collect -> seal -> score -> chain."""
    from vigia_scorer import _vigia_score
    transport = MockTransport(FIXTURES)
    windows, entries = [], []
    prev = GENESIS_HASH
    for sequence, start, end, requests in WINDOW_SPECS:
        window, _ = collect_window(
            transport, case_id="STREAM-TEST-001", sequence=sequence,
            source="replay", host=HOST, time_start_utc=start,
            time_end_utc=end, examiner_id="purple-op-01", requests=requests,
        )
        result = _vigia_score(window_to_case(window))
        entry = build_stream_entry(
            window=window, scorer_result=result, prev_entry_hash=prev,
        )
        windows.append(window)
        entries.append(entry)
        prev = entry["entry_hash"]
    return windows, entries


def test_chain_verifies_end_to_end(chain):
    windows, entries = chain
    verdict = verify_stream(
        entries, windows={w["window_hash"]: w for w in windows},
    )
    assert verdict["chain_ok"], verdict["errors"]
    assert verdict["entries"] == 2


def test_entries_conform_to_contract(chain):
    _, entries = chain
    for entry in entries:
        assert entry["schema_version"] == 1
        assert entry["canonicalize_version"] == "2"
        assert entry["verdict"]["determinism_level"] == "sealed"
        # No floats in a sealed entry: exact fraction strings only.
        assert _FRACTION_RE.fullmatch(entry["verdict"]["score"])
        assert _FRACTION_RE.fullmatch(entry["verdict"]["confidence"])
        assert isinstance(entry["verdict"]["mitre_techniques"], list)


def test_tampered_entry_detected(chain):
    _, entries = chain
    tampered = json.loads(json.dumps(entries))
    tampered[0]["verdict"]["state"] = "MALICE_HIGH"
    verdict = verify_stream(tampered)
    assert not verdict["chain_ok"]
    assert any("entry[0]" in e and "tampered" in e for e in verdict["errors"])


def test_reordered_entries_detected(chain):
    _, entries = chain
    verdict = verify_stream(list(reversed(entries)))
    assert not verdict["chain_ok"]


def test_truncated_stream_detected(chain):
    _, entries = chain
    # Dropping the first entry breaks both sequence and genesis linkage.
    verdict = verify_stream(entries[1:])
    assert not verdict["chain_ok"]


def test_sequence_zero_requires_genesis(chain):
    windows, _ = chain
    from vigia_scorer import _vigia_score
    result = _vigia_score(window_to_case(windows[0]))
    with pytest.raises(StreamError, match="GENESIS"):
        build_stream_entry(
            window=windows[0], scorer_result=result, prev_entry_hash="a" * 64,
        )


def test_tampered_window_refused_at_chain_time(chain):
    windows, _ = chain
    from vigia_scorer import _vigia_score
    result = _vigia_score(window_to_case(windows[0]))
    tampered = json.loads(json.dumps(windows[0]))
    tampered["artifacts"][0]["evidence_type"] = "cryptographic_hash"
    with pytest.raises(StreamError, match="refusing to chain"):
        build_stream_entry(
            window=tampered, scorer_result=result, prev_entry_hash=GENESIS_HASH,
        )


def test_jsonl_roundtrip(chain, tmp_path):
    _, entries = chain
    stream_path = tmp_path / "stream.jsonl"
    for entry in entries:
        append_entry(stream_path, entry)
    assert read_stream(stream_path) == entries
    assert verify_stream(read_stream(stream_path))["chain_ok"]


def test_full_pipeline_reproducible_across_processes():
    """The flagship guarantee: collect -> seal -> score -> chain, twice, in
    fresh interpreters with different hash seeds -> identical final seal."""
    child = REPO_ROOT / "tests" / "_stream_child.py"
    digests = []
    for hashseed in ("0", "31337"):
        proc = subprocess.run(
            [sys.executable, str(child)],
            cwd=REPO_ROOT, capture_output=True, text=True, timeout=300,
            env={"PYTHONHASHSEED": hashseed, "PATH": "/usr/bin:/bin"},
        )
        assert proc.returncode == 0, proc.stderr[-2000:]
        digests.append(proc.stdout.strip().splitlines()[-1])
    assert digests[0] == digests[1], (
        "live pipeline is not reproducible: "
        f"{digests[0][:12]}… vs {digests[1][:12]}…"
    )
