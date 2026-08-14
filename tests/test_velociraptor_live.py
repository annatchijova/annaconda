"""Live Velociraptor integration — real telemetry through the sealed pipeline.

Skipped when the Velociraptor binary is absent, so CI never depends on it.
When present, it proves workstream A: annaconda can collect from a real
Velociraptor and seal a verdict from real telemetry — not fixtures.
"""

from pathlib import Path

import pytest

from tools.velociraptor.adapter import (
    VelociraptorQueryTransport, collect_window, verify_window, window_to_case,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
BINARY = REPO_ROOT / "tools" / "velociraptor" / "velociraptor-v0.77.1-linux-amd64"

pytestmark = pytest.mark.skipif(
    not BINARY.exists(),
    reason="Velociraptor binary not present (run scripts/setup_velociraptor.sh)")

LIVE_VQL = {"Windows.System.Pslist":
            "SELECT Pid, Name, CommandLine, Exe, CreateTime FROM pslist()"}


def _collect_live():
    transport = VelociraptorQueryTransport(str(BINARY), LIVE_VQL)
    return collect_window(
        transport, case_id="LIVE-TEST-001", sequence=0, source="velociraptor",
        host={"client_id": "C.localhost", "hostname": "dev", "os": "linux"},
        time_start_utc="2026-08-14T00:00:00Z", time_end_utc="2026-08-14T23:59:59Z",
        examiner_id="op", requests=[("pslist", {})],
    )


def test_live_collection_produces_a_sealed_verifiable_window():
    window, reports = _collect_live()
    assert window["source"] == "velociraptor"
    assert window["artifacts"], "no real processes collected"
    assert verify_window(window)
    # Custody manifest records a hash of the raw collected rows.
    assert window["manifest"] and window["manifest"][0]["sha256"]
    # Real process names came through into the artifact rows.
    names = {a["metadata"]["row"].get("Name") for a in window["artifacts"]}
    assert any(names), "process rows carry no Name field"


def test_live_telemetry_feeds_the_deterministic_core():
    from vigia_scorer import _vigia_score
    window, _ = _collect_live()
    result = _vigia_score(window_to_case(window))
    # A normal dev host is benign; the point is the real pipeline runs and
    # seals, not the specific verdict.
    assert result["verdict"] != "ERROR"
    assert result["caie_fractures_source"] == "live_caie"


def test_unmapped_artifact_fails_loud():
    from tools.velociraptor.adapter import AdapterError
    transport = VelociraptorQueryTransport(str(BINARY), {})
    with pytest.raises(AdapterError, match="no VQL mapped"):
        transport.collect("C.localhost", "Windows.System.Pslist", {})
