"""The reasoning chain reaches the tracer.

The README claims OpenTelemetry traces "the reasoning chain, not just the HTTP
request". Until now that was true only of the old deterministic /fleet path —
the autonomous cycle, which is what actually runs unattended, emitted nothing.
So the claim is a test: run a real cycle against an in-memory exporter and read
back the spans a Cloud Trace user would see.
"""

import asyncio
import tempfile
from pathlib import Path

import pytest

pytest.importorskip("opentelemetry.sdk")

from opentelemetry import trace  # noqa: E402
from opentelemetry.sdk.trace import TracerProvider  # noqa: E402
from opentelemetry.sdk.trace.export import SimpleSpanProcessor  # noqa: E402
from opentelemetry.sdk.trace.export.in_memory_span_exporter import (  # noqa: E402
    InMemorySpanExporter,
)

from agent.tools import PurpleTeamSession  # noqa: E402
from tools.velociraptor.adapter import MockTransport  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
HOST = {"client_id": "C.1", "hostname": "WIN11-VICTIM", "os": "windows"}


@pytest.fixture(scope="module")
def exporter():
    """Install a real tracer provider once, then re-import the span helper so it
    binds to it (the module caches its tracer at import time)."""
    exp = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exp))
    try:
        trace.set_tracer_provider(provider)
    except Exception:  # noqa: BLE001 — already set by another test run
        pass

    import importlib
    import agent._tracing
    import agent.autonomy
    import agent.fleet
    importlib.reload(agent._tracing)
    importlib.reload(agent.fleet)
    importlib.reload(agent.autonomy)
    yield exp


def _session(fixtures="attack", case_id="TRACE"):
    return PurpleTeamSession(
        MockTransport(REPO / "tests" / "fixtures" / fixtures), case_id=case_id,
        host=HOST, examiner_id="op", out_dir=tempfile.mkdtemp(),
        source="replay", time_base="2026-08-12T14:10:00Z")


def _case(case_id="TRACE"):
    return {"case_id": case_id, "host": HOST, "status": "open",
            "worst_verdict": None, "entries": [], "verdicts": [],
            "audit_trail": [], "runs": 0}


def _spans_by_name(exporter):
    return {s.name: s for s in exporter.get_finished_spans()}


def test_an_autonomous_cycle_emits_the_shape_of_the_investigation(exporter):
    import agent.autonomy as autonomy
    exporter.clear()
    asyncio.run(autonomy.run_cycle(_session(), _case(), trigger="test"))
    spans = _spans_by_name(exporter)

    assert "fleet.cycle" in spans, sorted(spans)
    assert "windows-hunter.collect" in spans
    assert "correlator.adjudicate" in spans
    assert "commander.escalate" in spans


def test_the_cycle_span_carries_what_a_reviewer_needs(exporter):
    import agent.autonomy as autonomy
    exporter.clear()
    asyncio.run(autonomy.run_cycle(_session(case_id="TRACE-2"), _case("TRACE-2"),
                                   trigger="cloud-scheduler"))
    root = _spans_by_name(exporter)["fleet.cycle"].attributes
    assert root["case.id"] == "TRACE-2"
    assert root["cycle.number"] == 1
    assert root["cycle.trigger"] == "cloud-scheduler"
    assert root["fleet.department"] == "incident-response"
    assert root["cycle.planner"] == "deterministic-fallback"
    assert root["cycle.escalated"] is True
    assert root["principal.authenticated"] is False


def test_the_sealed_verdict_appears_on_the_adjudication_span(exporter):
    """A trace is worth reading only if it shows what the engine concluded."""
    import agent.autonomy as autonomy
    exporter.clear()
    asyncio.run(autonomy.run_cycle(_session(case_id="TRACE-3"), _case("TRACE-3"),
                                   trigger="test"))
    adj = _spans_by_name(exporter)["correlator.adjudicate"].attributes
    assert adj["verdict.state"] == "MALICE_HIGH"
    assert adj["verdict.sealed"] is True
    assert len(adj["verdict.entry_hash"]) == 64
    assert "T1055.012" in adj["verdict.mitre"]


def test_a_catalog_refusal_is_visible_in_the_trace(exporter):
    """The compliance gate firing has to be findable in Cloud Trace, not only
    in a response body somebody happened to read."""
    import agent.autonomy as autonomy
    exporter.clear()
    asyncio.run(autonomy.run_cycle(_session(case_id="TRACE-4"), _case("TRACE-4"),
                                   department="soc", trigger="test"))
    adj = _spans_by_name(exporter)["correlator.adjudicate"].attributes
    assert adj["catalog.refused"] is True
    assert "not published to department 'soc'" in adj["catalog.reason"]


def test_tracing_is_a_no_op_when_no_provider_is_configured():
    """A span that cannot be recorded must never break a cycle."""
    from agent._tracing import annotate, span
    with span("whatever", key="value") as sp:
        annotate(sp, other="value")   # must not raise even when sp is None
