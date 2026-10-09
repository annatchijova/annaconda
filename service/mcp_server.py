"""Curated, read-only MCP bridge for annaconda's already-running service.

This process does not re-implement any annaconda logic and holds no state
of its own. It is a thin stdio MCP wrapper around a subset of
`service/app.py`'s existing GET routes on an annaconda instance that is
already running (locally via uvicorn, or deployed) — the same pattern
vigia-repo and zaynor use for their own curated bridges, generalized to an
HTTP backend here because annaconda's live/fleet state genuinely lives in
that running process (sweep counters, Firestore vs. memory case-store
backend), not in anything a second process could safely reconstruct.

By construction, every route that creates a case, starts a live
investigation (/investigate, /cases/{id}/investigate, /fleet-investigate),
pushes to an external system (/cases/{id}/push-to-secops), or runs a
scripted demo (/injection-demo, /tasks/sweep) is excluded. This is not an
allowlist that happens to be short — it is the boundary: this bridge can
only ever grow more read-only tools, never gain a write/trigger one,
without a deliberate, separately-reviewed decision (same posture as
zaynor's docs/adr/0001-separate-mcp-capability-planes.md).

No new runtime dependency: HTTP calls use stdlib `urllib.request` only,
consistent with this repo's own stated preference for keeping anything
outside the stdlib-only forensic core to a minimum (requirements.txt's own
comment: "the deterministic forensic CORE is stdlib-only by design").
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from typing import Optional

from mcp.server.fastmcp import FastMCP

BASE_URL = os.environ.get("ANNACONDA_BASE_URL", "http://127.0.0.1:8080").rstrip("/")
TIMEOUT_SECONDS = float(os.environ.get("ANNACONDA_MCP_TIMEOUT", "10"))

mcp = FastMCP("annaconda")


def _get(path: str, params: Optional[dict] = None) -> dict:
    """GET against the live annaconda service. Never raises to the caller:
    a connection failure or non-2xx response degrades to an explicit error
    field rather than crashing the MCP tool call (honest degradation, same
    posture as case_store.py's backend fallback)."""
    url = BASE_URL + path
    if params:
        clean = {k: v for k, v in params.items() if v is not None}
        if clean:
            url += "?" + urllib.parse.urlencode(clean)
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS) as resp:
            body = resp.read()
            return json.loads(body)
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        return {"error": f"HTTP {exc.code} from annaconda at {url}", "detail": detail}
    except urllib.error.URLError as exc:
        return {
            "error": f"could not reach annaconda at {url}: {exc.reason}",
            "hint": "is the annaconda service running? "
            "ANNACONDA_BASE_URL defaults to http://127.0.0.1:8080",
        }


@mcp.tool()
def annaconda_health() -> dict:
    """Service health and posture: backend in use, whether sealed verdicts
    and determinism invariants are active, autonomous-sweep counters."""
    return _get("/health")


@mcp.tool()
def annaconda_registry() -> dict:
    """The sealed agent registry: every published agent, its version, and
    the hash of its approved tool manifest."""
    return _get("/registry")


@mcp.tool()
def annaconda_catalog(department: Optional[str] = None) -> dict:
    """The enterprise catalog of which department may task which agent.
    Pass department to see the fleet as that department sees it."""
    return _get("/catalog", {"department": department})


@mcp.tool()
def annaconda_hunts() -> dict:
    """Catalog of hunt templates (what each one collects, evidence type)."""
    return _get("/hunts")


@mcp.tool()
def annaconda_list_cases() -> dict:
    """The case queue, worst-verdict first. Read-only — does not create,
    modify, or re-score any case."""
    return _get("/cases")


@mcp.tool()
def annaconda_get_case(case_id: str) -> dict:
    """A single case's sealed verdict chain and custody-chain verification
    result. Read-only."""
    return _get(f"/cases/{urllib.parse.quote(case_id, safe='')}")


@mcp.tool()
def annaconda_get_case_stix(case_id: str) -> dict:
    """A case's sealed verdict exported as STIX. Read-only."""
    return _get(f"/cases/{urllib.parse.quote(case_id, safe='')}/stix")


@mcp.tool()
def annaconda_get_case_cacao(case_id: str) -> dict:
    """A case's sealed verdict exported as CACAO. Read-only."""
    return _get(f"/cases/{urllib.parse.quote(case_id, safe='')}/cacao")


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
