"""One reasoning-chain span helper, shared by the fleet and the autonomous cycle.

The spans are the REASONING, not the HTTP request: which agent did what, in what
order, what the catalog allowed, and what the engine sealed. Cloud Trace then
shows the shape of an unattended investigation that nobody watched happen.

No-op unless a tracer provider is configured, so tests and local runs are
unaffected — and a span that cannot be recorded never breaks a cycle.
"""

from __future__ import annotations

from contextlib import contextmanager

try:
    from opentelemetry import trace as _otel
    _TRACER = _otel.get_tracer("annaconda.fleet")
except Exception:  # noqa: BLE001 — tracing is optional
    _TRACER = None


@contextmanager
def span(name: str, **attrs):
    if _TRACER is None:
        yield None
        return
    with _TRACER.start_as_current_span(name) as sp:
        for k, v in attrs.items():
            if v is None:
                continue
            try:
                sp.set_attribute(k, v if isinstance(v, (str, int, float, bool))
                                 else str(v))
            except Exception:  # noqa: BLE001
                pass
        yield sp


def annotate(sp, **attrs) -> None:
    """Add attributes to a span already open. Safe when tracing is off."""
    if sp is None:
        return
    for k, v in attrs.items():
        if v is None:
            continue
        try:
            sp.set_attribute(k, v if isinstance(v, (str, int, float, bool))
                             else str(v))
        except Exception:  # noqa: BLE001
            pass
