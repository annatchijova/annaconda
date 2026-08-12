"""Velociraptor adapter: VQL hunt results -> sealed evidence windows.

Boundary layer between the live evidence source (Velociraptor, independent
AGPLv3 service reached over its API) and the deterministic core. It does
three things, and deliberately nothing more:

1. Collect: run curated VQL templates (vql_templates.py) through a transport.
2. Normalize: turn result rows into the artifact shape the core scorer
   already consumes. The adapter assigns NO scores — ``raw_score`` is left
   absent so the core applies its own defaults; scoring is decision-path
   work and the adapter is not on the decision path for values, only for
   evidence custody.
3. Freeze: build an immutable evidence window (contracts/
   evidence_window.schema.json) whose ``window_hash`` uses the same
   canonical-v2 + SHA-256 recipe as the core bundle seal.

Determinism rules honored here:
- No wall clock anywhere in a hashed payload: the caller supplies the
  window time bounds; artifact timestamps come from the collected rows.
- Artifact ids derive from row content (SHA-256), so window hashes are
  independent of row arrival order.
- Same fixtures in, bit-identical window out, in any process.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from pathlib import Path
from typing import Iterable, Optional, Protocol

from core.canonicalize import CANONICALIZE_VERSION, _canonicalize
from tools.velociraptor.vql_templates import TEMPLATES, validate_request

GENESIS_HASH = "0" * 64
_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_SOURCES = ("velociraptor", "replay")


def _sha256_canonical(obj) -> str:
    """Exact same recipe as core/bundle_builder._sha256_dict (v2 lockstep)."""
    serialized = json.dumps(
        _canonicalize(obj), sort_keys=True, ensure_ascii=True
    ).encode("utf-8")
    return hashlib.sha256(serialized).hexdigest()


class AdapterError(ValueError):
    """Invalid input reached the adapter boundary."""


# ---------------------------------------------------------------------------
# Transports
# ---------------------------------------------------------------------------

class Transport(Protocol):
    """Minimal surface the adapter needs from a Velociraptor endpoint."""

    def collect(self, client_id: str, artifact: str, params: dict) -> str:
        """Schedule a collection; return a flow id."""

    def flow_state(self, client_id: str, flow_id: str) -> str:
        """Return the flow state (e.g. RUNNING / FINISHED / ERROR)."""

    def flow_results(self, client_id: str, flow_id: str, artifact: str) -> list:
        """Return the result rows of a finished flow."""

    def manifest(self, client_id: str, flow_id: str, artifact: str) -> list:
        """Return chain-of-custody entries (path, sha256, size_bytes) for the
        raw files backing this flow. May be empty when the transport has no
        file-level artifacts (then the window's custody rests on the rows)."""


class MockTransport:
    """Fixture-backed transport for development, tests, and demo replay.

    Maps artifact name -> ``<fixtures_dir>/<artifact>.json`` (a JSON list of
    rows). Deterministic by construction: flow ids derive from the artifact
    name, results and manifest derive from the fixture bytes.
    """

    def __init__(self, fixtures_dir: str | Path):
        self._dir = Path(fixtures_dir)
        if not self._dir.is_dir():
            raise AdapterError(f"fixtures dir not found: {self._dir}")

    def _fixture(self, artifact: str) -> Path:
        path = self._dir / f"{artifact}.json"
        if not path.is_file():
            raise AdapterError(f"no fixture for artifact {artifact!r} at {path}")
        return path

    def collect(self, client_id: str, artifact: str, params: dict) -> str:
        self._fixture(artifact)  # fail loud at schedule time, like a real 404
        return f"F.mock.{artifact}"

    def flow_state(self, client_id: str, flow_id: str) -> str:
        return "FINISHED"

    def flow_results(self, client_id: str, flow_id: str, artifact: str) -> list:
        rows = json.loads(self._fixture(artifact).read_text(encoding="utf-8"))
        if not isinstance(rows, list):
            raise AdapterError(f"fixture {artifact!r} must be a JSON list of rows")
        return rows

    def manifest(self, client_id: str, flow_id: str, artifact: str) -> list:
        path = self._fixture(artifact)
        data = path.read_bytes()
        return [{
            "path": f"fixtures/{path.name}",
            "sha256": hashlib.sha256(data).hexdigest(),
            "size_bytes": len(data),
        }]


class RestTransport:
    """Transport against Velociraptor's HTTP API.

    STATUS: written for Phase 2 integration but NOT yet exercised against a
    live server — treat every call as unverified until the lab is up
    (PLAN.md phase 2). Endpoints and payloads follow the v0.7x API surface;
    expect to adjust field names during integration, not the adapter above.

    Auth: HTTP basic (GUI user) over TLS. ``ca_path`` pins the server CA;
    with a self-signed lab CA this is mandatory, not optional.
    """

    def __init__(self, base_url: str, username: str, password: str,
                 ca_path: Optional[str] = None):
        import base64
        import ssl
        if not base_url.startswith("https://"):
            raise AdapterError("RestTransport requires an https:// base_url")
        self._base = base_url.rstrip("/")
        token = base64.b64encode(f"{username}:{password}".encode()).decode()
        self._auth_header = f"Basic {token}"
        self._ctx = ssl.create_default_context(cafile=ca_path)

    def _post(self, endpoint: str, payload: dict) -> dict:
        import urllib.request
        req = urllib.request.Request(
            f"{self._base}{endpoint}",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Authorization": self._auth_header,
                "Content-Type": "application/json",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, context=self._ctx, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def collect(self, client_id: str, artifact: str, params: dict) -> str:
        result = self._post("/api/v1/CollectArtifact", {
            "client_id": client_id,
            "artifacts": [artifact],
            "parameters": {"env": [
                {"key": k, "value": v} for k, v in sorted(params.items())
            ]},
        })
        flow_id = result.get("flow_id")
        if not flow_id:
            raise AdapterError(f"CollectArtifact returned no flow_id: {result}")
        return flow_id

    def flow_state(self, client_id: str, flow_id: str) -> str:
        result = self._post("/api/v1/GetFlowDetails", {
            "client_id": client_id, "flow_id": flow_id,
        })
        return result.get("context", {}).get("state", "UNKNOWN")

    def flow_results(self, client_id: str, flow_id: str, artifact: str) -> list:
        result = self._post("/api/v1/GetTable", {
            "client_id": client_id,
            "flow_id": flow_id,
            "artifact": artifact,
            "rows": 10000,
        })
        columns = result.get("columns", [])
        return [dict(zip(columns, row.get("cell", [])))
                for row in result.get("rows", [])]

    def manifest(self, client_id: str, flow_id: str, artifact: str) -> list:
        # File-level custody (uploaded raw files) lands in Phase 2
        # integration; until then the window's custody rests on the rows.
        return []


# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------

def normalize_rows(template_id: str, rows: Iterable[dict]) -> tuple[list, dict]:
    """Turn raw VQL result rows into core-scorer artifacts.

    Returns ``(artifacts, report)``. ``report`` states honestly what was
    dropped and why (rows without the template's timestamp field, duplicate
    row content) — the caller must surface it, not swallow it.

    Artifact ids are content-derived (``<template>-<sha256(row)[:16]>``), so
    the output is independent of row order and stable across runs.
    """
    template = TEMPLATES[template_id]
    ts_field = template["timestamp_field"]
    artifacts = {}
    dropped_no_timestamp = 0
    duplicates = 0
    for row in rows:
        if not isinstance(row, dict):
            raise AdapterError(f"row must be a dict, got {type(row).__name__}")
        timestamp = row.get(ts_field)
        if not isinstance(timestamp, str) or not timestamp:
            dropped_no_timestamp += 1
            continue
        artifact_id = f"{template_id}-{_sha256_canonical(row)[:16]}"
        if artifact_id in artifacts:
            duplicates += 1
            continue
        artifacts[artifact_id] = {
            "artifact_id": artifact_id,
            "evidence_type": template["evidence_type"],
            "timestamp": timestamp,
            "metadata": {
                "tool": "velociraptor",
                "vql_template": template_id,
                "row": row,
            },
        }
    report = {
        "template_id": template_id,
        "rows_in": dropped_no_timestamp + duplicates + len(artifacts),
        "artifacts_out": len(artifacts),
        "dropped_no_timestamp": dropped_no_timestamp,
        "deduplicated": duplicates,
    }
    return [artifacts[k] for k in sorted(artifacts)], report


# ---------------------------------------------------------------------------
# Window building and verification
# ---------------------------------------------------------------------------

def build_evidence_window(*, case_id: str, sequence: int, source: str,
                          host: dict, time_start_utc: str, time_end_utc: str,
                          collection: dict, artifacts: list,
                          manifest: list) -> dict:
    """Freeze one immutable evidence window and seal its hash.

    Pure function of its inputs — no clock, no randomness, no I/O — so the
    same inputs produce a bit-identical window in any process.
    """
    if not _ID_RE.fullmatch(case_id or ""):
        raise AdapterError(f"invalid case_id: {case_id!r}")
    if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 0:
        raise AdapterError(f"sequence must be a non-negative int, got {sequence!r}")
    if source not in _SOURCES:
        raise AdapterError(f"source must be one of {_SOURCES}, got {source!r}")
    for field in ("client_id", "hostname"):
        if not isinstance(host.get(field), str) or not host[field]:
            raise AdapterError(f"host.{field} is required and must be a string")
    for name, value in (("time_start_utc", time_start_utc),
                        ("time_end_utc", time_end_utc)):
        if not isinstance(value, str) or not value:
            raise AdapterError(f"{name} is required and must be an ISO 8601 string")

    window = {
        "schema_version": 1,
        "window_id": f"{case_id}-w{sequence:06d}",
        "case_id": case_id,
        "sequence": sequence,
        "source": source,
        "host": dict(host),
        "time_start_utc": time_start_utc,
        "time_end_utc": time_end_utc,
        "collection": {
            "hunt_ids": sorted(collection.get("hunt_ids", [])),
            "flow_ids": sorted(collection.get("flow_ids", [])),
            "vql_template_ids": sorted(collection.get("vql_template_ids", [])),
            "velociraptor_version": collection.get("velociraptor_version", ""),
        },
        "artifacts": sorted(artifacts, key=lambda a: a["artifact_id"]),
        "manifest": sorted(manifest, key=lambda m: (m["path"], m["sha256"])),
        "canonicalize_version": CANONICALIZE_VERSION,
    }
    window["window_hash"] = _sha256_canonical(window)
    return window


def verify_window(window: dict) -> bool:
    """Recompute the window hash from content. True iff it matches."""
    if not isinstance(window, dict) or "window_hash" not in window:
        return False
    unsealed = {k: v for k, v in window.items() if k != "window_hash"}
    return _sha256_canonical(unsealed) == window["window_hash"]


# ---------------------------------------------------------------------------
# Collection orchestration
# ---------------------------------------------------------------------------

def collect_window(transport: Transport, *, case_id: str, sequence: int,
                   source: str, host: dict, time_start_utc: str,
                   time_end_utc: str, requests: list,
                   poll_interval_s: float = 2.0,
                   timeout_s: float = 300.0) -> tuple[dict, list]:
    """Run curated collections through a transport and freeze the window.

    ``requests`` is a list of ``(template_id, params)`` pairs; every pair is
    validated against the registry before anything runs. Returns
    ``(window, reports)`` where ``reports`` are the normalization reports —
    surface them, they are the honest record of what was dropped.
    """
    validated = [
        (template_id, validate_request(template_id, params))
        for template_id, params in requests
    ]

    artifacts: list = []
    manifest: list = []
    flow_ids: list = []
    reports: list = []
    client_id = host.get("client_id", "")

    for template_id, params in validated:
        artifact_name = TEMPLATES[template_id]["artifact"]
        flow_id = transport.collect(client_id, artifact_name, params)
        flow_ids.append(flow_id)

        deadline = time.monotonic() + timeout_s
        state = transport.flow_state(client_id, flow_id)
        while state not in ("FINISHED", "ERROR"):
            if time.monotonic() >= deadline:
                raise AdapterError(
                    f"flow {flow_id} ({template_id}) did not finish within "
                    f"{timeout_s}s (last state: {state})"
                )
            time.sleep(poll_interval_s)
            state = transport.flow_state(client_id, flow_id)
        if state == "ERROR":
            raise AdapterError(f"flow {flow_id} ({template_id}) failed on the endpoint")

        rows = transport.flow_results(client_id, flow_id, artifact_name)
        normalized, report = normalize_rows(template_id, rows)
        artifacts.extend(normalized)
        manifest.extend(transport.manifest(client_id, flow_id, artifact_name))
        reports.append(report)

    window = build_evidence_window(
        case_id=case_id,
        sequence=sequence,
        source=source,
        host=host,
        time_start_utc=time_start_utc,
        time_end_utc=time_end_utc,
        collection={
            "hunt_ids": [],
            "flow_ids": flow_ids,
            "vql_template_ids": [t for t, _ in validated],
        },
        artifacts=artifacts,
        manifest=manifest,
    )
    return window, reports
