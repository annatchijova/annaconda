"""Tests for the live-mode runner (capture -> chain -> replay)."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

from core.verdict_stream import read_stream, verify_stream
from scripts_lib.live_runner import main as runner_main

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURES = REPO_ROOT / "tests" / "fixtures" / "velociraptor"


def _capture(out_dir, cycles=2):
    return runner_main([
        "capture", "--mode", "mock",
        "--out-dir", str(out_dir),
        "--case-id", "RUNNER-TEST-001",
        "--examiner-id", "purple-op-01",
        "--cycles", str(cycles),
        "--interval-s", "30",
        "--time-base", "2026-08-12T14:00:00Z",
        "--fixtures", str(FIXTURES),
    ])


def test_capture_produces_verified_chain_and_recordings(tmp_path):
    assert _capture(tmp_path) == 0
    entries = read_stream(tmp_path / "stream.jsonl")
    windows = [
        json.loads(p.read_text(encoding="utf-8"))
        for p in sorted((tmp_path / "windows").glob("window-*.json"))
    ]
    assert len(entries) == len(windows) == 2
    report = verify_stream(entries, windows={w["window_hash"]: w for w in windows})
    assert report["chain_ok"], report["errors"]
    # Consecutive windows tile time with no gap.
    assert windows[0]["time_end_utc"] == windows[1]["time_start_utc"]


def test_capture_refuses_to_append_to_existing_stream(tmp_path):
    assert _capture(tmp_path) == 0
    with pytest.raises(SystemExit, match="append-only"):
        _capture(tmp_path)


def test_replay_matches_recorded_seals(tmp_path):
    assert _capture(tmp_path) == 0
    assert runner_main(["replay", "--out-dir", str(tmp_path)]) == 0


def test_replay_detects_tampered_recorded_window(tmp_path):
    assert _capture(tmp_path) == 0
    window_path = tmp_path / "windows" / "window-000000.json"
    window = json.loads(window_path.read_text(encoding="utf-8"))
    window["artifacts"][0]["raw_score"] = "9/10"
    window_path.write_text(json.dumps(window), encoding="utf-8")
    assert runner_main(["replay", "--out-dir", str(tmp_path)]) == 1


def test_replay_detects_tampered_stream_entry(tmp_path):
    assert _capture(tmp_path) == 0
    stream_path = tmp_path / "stream.jsonl"
    entries = read_stream(stream_path)
    entries[0]["verdict"]["state"] = "MALICE_HIGH"
    stream_path.write_text(
        "\n".join(json.dumps(e, sort_keys=True) for e in entries) + "\n",
        encoding="utf-8",
    )
    assert runner_main(["replay", "--out-dir", str(tmp_path)]) == 1


def test_mock_capture_is_deterministic_across_processes(tmp_path):
    """Two full CLI captures in fresh interpreters, different hash seeds,
    same time base -> byte-identical stream files."""
    streams = []
    for tag, hashseed in (("a", "0"), ("b", "98765")):
        out_dir = tmp_path / tag
        proc = subprocess.run(
            [sys.executable, str(REPO_ROOT / "scripts_lib" / "live_runner.py"),
             "capture", "--mode", "mock",
             "--out-dir", str(out_dir),
             "--case-id", "RUNNER-DET-001",
             "--examiner-id", "purple-op-01",
             "--cycles", "2", "--interval-s", "30",
             "--time-base", "2026-08-12T14:00:00Z",
             "--fixtures", str(FIXTURES)],
            cwd=REPO_ROOT, capture_output=True, text=True, timeout=300,
            env={"PYTHONHASHSEED": hashseed, "PATH": "/usr/bin:/bin"},
        )
        assert proc.returncode == 0, proc.stderr[-2000:]
        streams.append((out_dir / "stream.jsonl").read_bytes())
    assert streams[0] == streams[1], "mock capture is not deterministic"
