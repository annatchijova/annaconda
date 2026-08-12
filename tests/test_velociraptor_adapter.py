"""Tests for the Velociraptor adapter (curated templates -> sealed windows)."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

from tools.velociraptor.adapter import (
    AdapterError,
    MockTransport,
    build_evidence_window,
    collect_window,
    normalize_rows,
    verify_window,
)
from tools.velociraptor.vql_templates import TemplateError, validate_request

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURES = REPO_ROOT / "tests" / "fixtures" / "velociraptor"

HOST = {"client_id": "C.mock01", "hostname": "WIN11-VICTIM", "os": "windows"}
REQUESTS = [
    ("pslist", {}),
    ("netstat", {}),
    ("process_creation_evtx", {"Channel": "Security", "IdFilter": "4688"}),
]


def _collect(sequence=0):
    return collect_window(
        MockTransport(FIXTURES),
        case_id="WINDOW-TEST-001",
        sequence=sequence,
        source="replay",
        host=HOST,
        time_start_utc="2026-08-12T14:00:00Z",
        time_end_utc="2026-08-12T14:05:00Z",
        requests=REQUESTS,
    )


# -- curated-template contract ----------------------------------------------

def test_unknown_template_rejected():
    with pytest.raises(TemplateError, match="unknown VQL template"):
        validate_request("raw_vql", {})


def test_unknown_parameter_rejected():
    with pytest.raises(TemplateError, match="does not accept parameters"):
        validate_request("pslist", {"Query": "SELECT * FROM pslist()"})


@pytest.mark.parametrize("value", [
    "Security' OR 1=1",
    "} LET x = SELECT * FROM glob(globs='C:/**')",
    "Security\nSELECT",
])
def test_injection_shaped_value_rejected(value):
    with pytest.raises(TemplateError, match="does not match"):
        validate_request("process_creation_evtx", {"Channel": value})


def test_non_string_parameter_rejected():
    with pytest.raises(TemplateError, match="must be a string"):
        validate_request("process_creation_evtx", {"IdFilter": 4688})


# -- normalization -----------------------------------------------------------

def test_normalize_reports_dropped_rows_honestly():
    rows = json.loads((FIXTURES / "Windows.EventLogs.Evtx.json").read_text())
    artifacts, report = normalize_rows("process_creation_evtx", rows)
    # The 1102 fixture row has no EventTime on purpose.
    assert report["dropped_no_timestamp"] == 1
    assert report["artifacts_out"] == len(artifacts) == 2
    assert report["rows_in"] == 3


def test_normalize_is_row_order_independent():
    rows = json.loads((FIXTURES / "Windows.System.Pslist.json").read_text())
    a_fwd, _ = normalize_rows("pslist", rows)
    a_rev, _ = normalize_rows("pslist", list(reversed(rows)))
    assert a_fwd == a_rev


def test_adapter_assigns_no_scores():
    rows = json.loads((FIXTURES / "Windows.System.Pslist.json").read_text())
    artifacts, _ = normalize_rows("pslist", rows)
    assert artifacts, "fixture produced no artifacts"
    for artifact in artifacts:
        assert "raw_score" not in artifact, (
            "the adapter must not score evidence — that is decision-path work"
        )


# -- window sealing ----------------------------------------------------------

def test_collect_window_end_to_end():
    window, reports = _collect()
    for field in ("window_id", "case_id", "sequence", "source", "host",
                  "time_start_utc", "time_end_utc", "collection", "artifacts",
                  "manifest", "canonicalize_version", "window_hash"):
        assert field in window, field
    assert window["canonicalize_version"] == "2"
    assert verify_window(window)
    assert len(window["manifest"]) == 3  # one fixture file per template
    assert len(reports) == 3
    ids = [a["artifact_id"] for a in window["artifacts"]]
    assert ids == sorted(ids)


def test_window_hash_independent_of_artifact_order():
    window, _ = _collect()
    unsealed = {k: v for k, v in window.items() if k != "window_hash"}
    rebuilt = build_evidence_window(
        case_id=unsealed["case_id"],
        sequence=unsealed["sequence"],
        source=unsealed["source"],
        host=unsealed["host"],
        time_start_utc=unsealed["time_start_utc"],
        time_end_utc=unsealed["time_end_utc"],
        collection=unsealed["collection"],
        artifacts=list(reversed(unsealed["artifacts"])),
        manifest=list(reversed(unsealed["manifest"])),
    )
    assert rebuilt["window_hash"] == window["window_hash"]


def test_verify_window_detects_tampering():
    window, _ = _collect()
    tampered = json.loads(json.dumps(window))
    tampered["artifacts"][0]["metadata"]["row"]["CommandLine"] = "notepad.exe"
    assert not verify_window(tampered)


def test_window_hash_reproducible_across_processes():
    child = REPO_ROOT / "tests" / "_window_child.py"
    digests = []
    for hashseed in ("0", "424242"):
        proc = subprocess.run(
            [sys.executable, str(child)],
            cwd=REPO_ROOT, capture_output=True, text=True, timeout=120,
            env={"PYTHONHASHSEED": hashseed, "PATH": "/usr/bin:/bin"},
        )
        assert proc.returncode == 0, proc.stderr[-2000:]
        digests.append(proc.stdout.strip())
    assert digests[0] == digests[1], (
        "window seal is not reproducible across processes: "
        f"{digests[0][:12]}… vs {digests[1][:12]}…"
    )


# -- boundary validation -----------------------------------------------------

def test_boundary_rejects_bad_inputs():
    good = dict(case_id="OK-1", sequence=0, source="replay", host=HOST,
                time_start_utc="2026-08-12T14:00:00Z",
                time_end_utc="2026-08-12T14:05:00Z",
                collection={}, artifacts=[], manifest=[])
    with pytest.raises(AdapterError):
        build_evidence_window(**{**good, "case_id": "../evil"})
    with pytest.raises(AdapterError):
        build_evidence_window(**{**good, "sequence": True})
    with pytest.raises(AdapterError):
        build_evidence_window(**{**good, "sequence": -1})
    with pytest.raises(AdapterError):
        build_evidence_window(**{**good, "source": "live_feed"})
    with pytest.raises(AdapterError):
        build_evidence_window(**{**good, "host": {"client_id": "C.1"}})
