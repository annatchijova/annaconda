"""OpenTelemetry tracing of the agent reasoning chain, exported to Cloud Trace.

The spans are the REASONING, not just the HTTP request: the fleet dispatch and
each specialist's step become spans, so Cloud Trace shows the shape of the
investigation — which agent did what, in what order, and the sealed verdict —
not merely a request timeline.

Honest degradation: if the Cloud Trace exporter cannot be configured (no GCP
credentials, package missing), tracing becomes a no-op and the service runs
normally. `setup_tracing()` returns which mode is active.
"""

from __future__ import annotations

import logging
import os

log = logging.getLogger("annaconda.tracing")

_MODE = "uninitialized"


def setup_tracing() -> str:
    global _MODE
    if _MODE != "uninitialized":
        return _MODE
    try:
        from opentelemetry import trace
        from opentelemetry.exporter.cloud_trace import CloudTraceSpanExporter
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor

        project = os.environ.get("GOOGLE_CLOUD_PROJECT")
        provider = TracerProvider(
            resource=Resource.create({"service.name": "annaconda"}))
        provider.add_span_processor(
            BatchSpanProcessor(CloudTraceSpanExporter(project_id=project)))
        trace.set_tracer_provider(provider)
        _MODE = "cloud-trace"
        log.info("tracing: Cloud Trace exporter active (project %s)", project)
    except Exception as exc:  # noqa: BLE001 — honest degradation
        _MODE = "disabled"
        log.warning("tracing: disabled (%s) — service runs without traces", exc)
    return _MODE


def tracing_mode() -> str:
    return _MODE


def flush_tracing() -> None:
    """Force-export buffered spans now. Cloud Run throttles CPU between requests,
    so the batch exporter's background thread may not run; flushing at the end of
    a traced request exports the spans while CPU is still allocated."""
    if _MODE != "cloud-trace":
        return
    try:
        from opentelemetry import trace
        provider = trace.get_tracer_provider()
        if hasattr(provider, "force_flush"):
            provider.force_flush()
    except Exception:  # noqa: BLE001
        pass
