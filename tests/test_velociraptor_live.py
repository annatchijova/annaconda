"""Live Velociraptor integration — real telemetry through the sealed pipeline.

Three different facts about the host are kept distinct, and only the first is
an absence: the binary is missing, the binary is present but this shell may not
start it, or the collection ran. Collapsing the middle case into "not present"
is what made a platform look untested when nothing had looked at it; turning it
into a hard failure would be the opposite error, permanent red on every
unelevated Windows runner for an environment fact rather than a defect. A skip
that names its own cause is the honest third state.

When it does run, it proves workstream A: annaconda can collect from a real
Velociraptor and seal a verdict from real telemetry — not fixtures.
"""

import subprocess

import pytest

from tools.velociraptor.adapter import (
    VelociraptorQueryTransport, collect_window, verify_window, window_to_case,
)
from tools.velociraptor.release import default_binary_path, host_block

BINARY = default_binary_path()

#: Windows refuses to start a binary whose manifest asks for elevation the
#: current shell does not hold. Velociraptor's Windows release embeds
#: requestedExecutionLevel="highestAvailable", so an unelevated shell gets this.
ERROR_ELEVATION_REQUIRED = 740


def _cannot_start_reason() -> "str | None":
    """Why this shell cannot START the binary, or None when it can.

    Elevation is OBSERVED, not inferred. Reading the process token is not
    equivalent: with "highestAvailable" a genuine standard user runs the binary
    at their own level and never sees 740, so "not an administrator" does not
    imply the collection would fail. Asking the binary for its version is cheap
    and answers the question that actually matters — can THIS shell start THIS
    binary.
    """
    if not BINARY.exists():
        return None  # absence is covered by the module-level mark
    try:
        subprocess.run([str(BINARY), "version"], capture_output=True, timeout=60)
    except OSError as exc:
        if getattr(exc, "winerror", None) == ERROR_ELEVATION_REQUIRED:
            return (f"{BINARY.name} is present but this shell may not start it: "
                    'the Windows release embeds requestedExecutionLevel='
                    f'"highestAvailable" and Windows returned '
                    f"ERROR_ELEVATION_REQUIRED ({ERROR_ELEVATION_REQUIRED}). "
                    "Run this suite from an elevated (Administrator) terminal.")
        # An unanticipated state, named in full rather than folded into one of
        # the known ones, so it can never read as a precondition we understood.
        return f"{BINARY.name} could not be started: {exc!r}"
    except subprocess.TimeoutExpired:
        return f"{BINARY.name} did not answer `version` within 60s"
    return None


BINARY_ABSENT_REASON = None if BINARY.exists() else (
    f"Velociraptor binary not present at {BINARY.name} "
    "(run scripts/setup_velociraptor.sh)")
CANNOT_START_REASON = _cannot_start_reason()

# Every test in this file needs the binary on disk...
pytestmark = pytest.mark.skipif(
    BINARY_ABSENT_REASON is not None, reason=BINARY_ABSENT_REASON or "")

# ...but only the two that actually collect need to be able to RUN it.
# test_unmapped_artifact_fails_loud asserts the adapter refuses an unmapped
# artifact BEFORE it ever spawns a process, so it stays honest — and green — on
# an unelevated shell. Skipping it with the others would be the same mistake in
# the other direction: silencing a test that can run.
requires_running_binary = pytest.mark.skipif(
    CANNOT_START_REASON is not None, reason=CANNOT_START_REASON or "")

LIVE_VQL = {"Windows.System.Pslist":
            "SELECT Pid, Name, CommandLine, Exe, CreateTime FROM pslist()"}


def _collect_live():
    transport = VelociraptorQueryTransport(str(BINARY), LIVE_VQL)
    return collect_window(
        transport, case_id="LIVE-TEST-001", sequence=0, source="velociraptor",
        # Custody, not decoration: this block is sealed into the window and
        # travels with the evidence. Hardcoded "linux" meant a collection taken
        # on Windows carried a sealed claim its own machine contradicts.
        host=host_block(),
        time_start_utc="2026-08-14T00:00:00Z", time_end_utc="2026-08-14T23:59:59Z",
        examiner_id="op", requests=[("pslist", {})],
    )


@requires_running_binary
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


@requires_running_binary
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
