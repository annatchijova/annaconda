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
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional, Protocol

from core.canonicalize import CANONICALIZE_VERSION, _canonicalize
from tools.velociraptor.vql_templates import TEMPLATES, validate_request

GENESIS_HASH = "0" * 64
_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_SOURCES = ("velociraptor", "replay")

# Fields the deterministic engine (CAIE) reads at artifact metadata top level
# to detect cross-artifact fractures. The adapter surfaces these from the raw
# row when present (normalization). It never invents them: benign telemetry
# has none, so no fracture fires. See CAIE fracture detectors in tools/caie.py.
_ENGINE_METADATA_FIELDS = (
    "network_log_time",       # network event time (TEMPORAL_CAUSALITY_VIOLATION)
    "process_creation_time",  # process creation time (TEMPORAL_CAUSALITY_VIOLATION)
    "injection_technique",    # PROCESS_INJECTION_ANTIFORENSIC
    "pid_hidden",             # PROCESS_INJECTION_ANTIFORENSIC
    "pid",                    # cross-artifact process correlation
    "dst_ip",                 # network destination
    "status",                 # collection/analysis state (intake-abstain gate)
    "analysis_status",        # PENDING -> the honest verdict is ABSTAIN
)


# Sentinel epochs that mean "this row carries no event time", not a time.
# Windows FILETIME zero surfaces as 1601-01-01 (observed: 59% of a real
# netstat collection -- TIME_WAIT sockets with no owning process), and Unix
# epoch zero as 1970-01-01. Both are syntactically valid ISO-8601 and both are
# lies about when something happened.
#
# The deterministic engine already refuses these inside its temporal-causality
# rule (tools/caie.py, guard R3-1, which names the FILETIME 1601 case by hand).
# That guard sits in ONE consumer, so every other consumer of the same
# timestamps had to rediscover the problem -- and one did: the sealed window's
# own time bounds took the minimum over all artifacts and adopted 1601 as the
# start of the collection, making the window assert temporal coverage of four
# centuries it never had. Custody claims belong at the boundary, so the
# predicate lives here, where evidence enters.
PLAUSIBLE_EVENT_TIME_MIN = datetime(2000, 1, 1, tzinfo=timezone.utc)
PLAUSIBLE_EVENT_TIME_MAX = datetime(2038, 1, 19, 3, 14, 7, tzinfo=timezone.utc)


def is_plausible_event_time(timestamp) -> bool:
    """True when ``timestamp`` can be read as a real event time.

    Deliberately narrow: this answers "may this value be used as a claim about
    when something happened", not "is this row worth keeping". A TIME_WAIT
    socket with no recorded time is still evidence that the socket exists; it
    just cannot date anything.
    """
    if not isinstance(timestamp, str) or not timestamp.strip():
        return False
    try:
        parsed = datetime.fromisoformat(timestamp.strip().replace("Z", "+00:00"))
    except ValueError:
        return False
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return PLAUSIBLE_EVENT_TIME_MIN <= parsed < PLAUSIBLE_EVENT_TIME_MAX


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


class VelociraptorQueryTransport:
    """Real transport backed by the Velociraptor binary's own VQL engine.

    This is the working live-evidence path (RestTransport above was a first
    sketch and stays unverified). Two modes, same code:

    - Local (no api_config): runs VQL against THIS host. Real telemetry from a
      real endpoint — used to prove the live pipeline without a lab.
    - Remote (api_config set): runs VQL through a Velociraptor server's API to
      reach enrolled clients, e.g. collect_client(client_id=..., artifacts=...).
      Point this at the lab's api.config.yaml and annaconda investigates real
      Windows endpoints.

    ``vql_map`` maps a collection name (the template's ``artifact``) to the VQL
    that gathers it. Velociraptor runs as an independent AGPLv3 service reached
    over its own interface; nothing from it is embedded.
    """

    def __init__(self, binary: str, vql_map: dict, *,
                 api_config: Optional[str] = None, timeout_s: int = 120):
        self._binary = binary
        self._vql_map = dict(vql_map)
        self._api_config = api_config
        self._timeout = timeout_s
        self._flows: dict[str, list] = {}

    def _run_vql(self, vql: str) -> list:
        cmd = [self._binary]
        if self._api_config:
            cmd += ["--api_config", self._api_config]
        # JSONL (one row per line), not JSON: Velociraptor streams results in
        # batches and emits one JSON array PER batch, so a large result is
        # several arrays concatenated — not parseable as a single document.
        # JSONL sidesteps the batching entirely.
        cmd += ["query", vql, "--format", "jsonl"]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=self._timeout)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise AdapterError(f"velociraptor query failed to run: {exc}") from exc
        if proc.returncode != 0:
            raise AdapterError(
                f"velociraptor query exited {proc.returncode}: "
                f"{proc.stderr.strip()[:400]}")
        rows = []
        for line in proc.stdout.splitlines():
            line = line.strip()
            if line:
                rows.append(json.loads(line))
        return rows

    def collect(self, client_id: str, artifact: str, params: dict) -> str:
        vql = self._vql_map.get(artifact)
        if vql is None:
            raise AdapterError(
                f"no VQL mapped for artifact {artifact!r}; add it to vql_map")
        rows = self._run_vql(vql)
        flow_id = f"Q.{artifact}.{len(self._flows)}"
        self._flows[flow_id] = rows
        return flow_id

    def flow_state(self, client_id: str, flow_id: str) -> str:
        return "FINISHED" if flow_id in self._flows else "ERROR"

    def flow_results(self, client_id: str, flow_id: str, artifact: str) -> list:
        return self._flows.get(flow_id, [])

    def manifest(self, client_id: str, flow_id: str, artifact: str) -> list:
        rows = self._flows.get(flow_id, [])
        data = json.dumps(rows, sort_keys=True, ensure_ascii=True).encode("utf-8")
        return [{
            "path": f"velociraptor/{artifact}.json",
            "sha256": hashlib.sha256(data).hexdigest(),
            "size_bytes": len(data),
        }]


# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------

def normalize_rows(template_id: str, rows: Iterable[dict],
                   custody: Optional[dict] = None,
                   source_hashes: tuple = ()) -> tuple[list, dict]:
    """Turn raw VQL result rows into core-scorer artifacts.

    Returns ``(artifacts, report)``. ``report`` states honestly what was
    dropped and why (rows without the template's timestamp field, duplicate
    row content) — the caller must surface it, not swallow it.

    Artifact ids are content-derived (``<template>-<sha256(row)[:16]>``), so
    the output is independent of row order and stable across runs.

    ``custody`` carries the Daubert chain-of-custody fields CAIE audits
    (NIST SP 800-86 4.3): ``examiner_id`` (operator identity) and
    ``acquisition_timestamp`` (ISO 8601 with timezone — the window freeze
    time supplied by the caller, never a wall clock read here). Each
    artifact additionally gets ``acquisition_tool: "velociraptor"``,
    a per-row ``acquisition_hash`` (sha256 of the canonical row), and
    ``write_blocker_used: False`` — honestly False: live endpoint telemetry
    has no write blocker, so CAIE's G4 gate must not pass; the reachable
    assurance tier for live collection is FORENSIC (3/4), not STRONG, by
    design. Passing ``custody=None`` omits the operator fields and CAIE
    degrades base_trust, audited; the report says so.

    ``source_hashes`` are the sha256 digests of the raw collected files
    backing these rows (the window manifest entries). Each artifact's
    ``provenance_chain`` is then [row content hash] + source hashes — every
    link independently verifiable: the row hash is recomputable from the row,
    the source hashes appear in the sealed window manifest. An empty chain is
    honest for a transport without file custody, and the scorer's EPC factor
    degrades trust accordingly (1/10) — that degradation is the system
    working, not a bug to silence.
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
        row_sha256 = _sha256_canonical(row)
        artifact_id = f"{template_id}-{row_sha256[:16]}"
        if artifact_id in artifacts:
            duplicates += 1
            continue
        summary = ", ".join(
            f"{f}={row[f]}" for f in template.get("summary_fields", ())
            if f in row and row[f] not in ("", None)
        )
        metadata = {
            "tool": "velociraptor",
            "vql_template": template_id,
            "row": row,
            "acquisition_tool": "velociraptor",
            "acquisition_hash": f"sha256:{row_sha256}",
            "write_blocker_used": False,
        }
        if custody is not None:
            for field in ("examiner_id", "acquisition_timestamp"):
                value = custody.get(field)
                if not isinstance(value, str) or not value:
                    raise AdapterError(
                        f"custody.{field} is required and must be a "
                        f"non-empty string when custody is supplied"
                    )
                metadata[field] = value
        # Surface analyzer-extracted fields the deterministic engine reads for
        # cross-artifact fracture detection (CAIE). This is normalization, not
        # scoring: the adapter only makes a field the tool already recorded
        # visible at the metadata top level; whether it constitutes a fracture
        # is the engine's decision. Benign telemetry simply lacks these fields,
        # so no fracture fires — the value is never fabricated here.
        for field in _ENGINE_METADATA_FIELDS:
            if field in row and row[field] not in ("", None):
                metadata[field] = row[field]
        # Velociraptor names the process id "Pid"; the engine reads "pid".
        # Surfacing it under the name the engine reads is normalization -- the
        # tool already recorded the value -- and it is load-bearing: the
        # temporal-causality rule uses the pid to tell one execution from
        # another, and an artifact without it is treated as an unevaluable
        # pair rather than a comparable one.
        if "pid" not in metadata:
            for alias in ("Pid", "PID", "ProcessId"):
                if row.get(alias) not in ("", None):
                    metadata["pid"] = row[alias]
                    break
        artifacts[artifact_id] = {
            "artifact_id": artifact_id,
            "evidence_type": template["evidence_type"],
            "source_tool": "velociraptor",
            # Duplicated from metadata on purpose: the integration bridge
            # detects acquisition custody at artifact TOP level and, when it
            # sees none, synthesizes legacy custody INto metadata — including
            # a fabricated write_blocker_used=True, which would dishonestly
            # inflate live telemetry to STRONG assurance. Present here, the
            # bridge leaves our honest custody untouched.
            "acquisition_tool": "velociraptor",
            # No-suspicion prior, exact fraction string. raw_score means
            # "suspicion reported by the producing tool" [0,1]; the adapter
            # collects, it does not analyze, so it declares the EBS v1
            # no-signal floor (1/20 = 0.05, the bridge clamp floor and the
            # legacy-import convention). A midpoint like 1/2 would read as
            # "moderate suspicion" per artifact and flip benign windows to
            # MALICE. Real suspicion enters later, from analyzers and CAIE,
            # never from the collection layer.
            "raw_score": "1/20",
            "description": f"velociraptor {template_id}: {summary}" if summary
                           else f"velociraptor {template_id} row {row_sha256[:16]}",
            "timestamp": timestamp,
            "provenance_chain": [f"sha256:{row_sha256}"]
                                + [f"sha256:{h}" for h in source_hashes],
            "metadata": metadata,
        }
    report = {
        "template_id": template_id,
        "rows_in": dropped_no_timestamp + duplicates + len(artifacts),
        "artifacts_out": len(artifacts),
        "dropped_no_timestamp": dropped_no_timestamp,
        "deduplicated": duplicates,
        "custody": "present" if custody is not None else
                   "absent — CAIE will degrade base_trust, audited",
    }
    return [artifacts[k] for k in sorted(artifacts)], report


def window_to_case(window: dict) -> dict:
    """Convert a sealed evidence window into the case dict the core scorer
    consumes.

    This is the one sanctioned float boundary: windows store ``raw_score``
    as an exact fraction string (nothing sealed carries a float), while the
    scorer's canonical EBS v1 artifact schema expects a numeric raw_score
    under its own P0 deterministic-rounding protocol. The conversion happens
    here, at the feed boundary, in one place — never inside a sealed payload.
    """
    if not verify_window(window):
        raise AdapterError(
            "refusing to feed a window whose hash does not verify — "
            "evidence integrity comes before scoring"
        )
    from fractions import Fraction
    case_artifacts = []
    for artifact in window["artifacts"]:
        # Deep copy, not dict(): downstream consumers (the integration
        # bridge, CAIE) mutate artifact internals in place, and a shared
        # nested dict would let them silently corrupt the sealed window.
        converted = json.loads(json.dumps(artifact))
        if isinstance(artifact.get("raw_score"), str):
            converted["raw_score"] = float(Fraction(artifact["raw_score"]))
        case_artifacts.append(converted)
    return {
        "case_id": window["case_id"],
        "artifacts": case_artifacts,
        "temporal_violations": [],
        "provenance_analysis": {},
    }


# ---------------------------------------------------------------------------
# Window building and verification
# ---------------------------------------------------------------------------

def build_evidence_window(*, case_id: str, sequence: int, source: str,
                          host: dict, time_start_utc: str, time_end_utc: str,
                          collection: dict, artifacts: list,
                          manifest: list, enrichment: list | None = None) -> dict:
    """Freeze one immutable evidence window and seal its hash.

    Pure function of its inputs — no clock, no randomness, no I/O — so the
    same inputs produce a bit-identical window in any process.

    ``enrichment`` is optional external threat-intel context (see
    agent/threat_intel.py). It is sealed under its own key, *beside* the scored
    artifacts and never among them: it is covered by ``window_hash`` (so it is
    tamper-evident and reproducible), but ``window_to_case`` does not feed it to
    the scorer, so it is structurally incapable of changing a verdict. Omitted
    when empty, so a window with no enrichment is byte-identical to before.
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
    if enrichment:
        # Sorted for a stable seal regardless of fetch order; sealed beside the
        # artifacts, outside the scorer feed.
        window["enrichment"] = sorted(
            enrichment,
            key=lambda r: (r.get("indicator_type", ""), r.get("indicator", "")),
        )
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
                   time_end_utc: str, requests: list, examiner_id: str,
                   poll_interval_s: float = 2.0,
                   timeout_s: float = 300.0, enricher=None) -> tuple[dict, list]:
    """Run curated collections through a transport and freeze the window.

    ``requests`` is a list of ``(template_id, params)`` pairs; every pair is
    validated against the registry before anything runs. ``examiner_id``
    identifies the operator responsible for this collection (chain of
    custody; CAIE audits its absence). The acquisition timestamp recorded on
    every artifact is ``time_end_utc`` — the window freeze instant supplied
    by the caller — keeping the window a pure function of its inputs.
    Returns ``(window, reports)`` where ``reports`` are the normalization
    reports — surface them, they are the honest record of what was dropped.
    """
    if not isinstance(examiner_id, str) or not examiner_id.strip():
        raise AdapterError("examiner_id is required (chain of custody)")
    validated = [
        (template_id, validate_request(template_id, params))
        for template_id, params in requests
    ]
    custody = {
        "examiner_id": examiner_id.strip(),
        "acquisition_timestamp": time_end_utc,
    }

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
        flow_manifest = transport.manifest(client_id, flow_id, artifact_name)
        normalized, report = normalize_rows(
            template_id, rows, custody=custody,
            source_hashes=tuple(m["sha256"] for m in flow_manifest),
        )
        artifacts.extend(normalized)
        manifest.extend(flow_manifest)
        reports.append(report)

    # Enrich BEFORE sealing so the reputation is cached into the sealed window;
    # a failing enricher must never lose a valid collection, so it degrades to
    # no enrichment rather than raising out of the collection.
    enrichment = None
    if enricher is not None:
        try:
            enrichment = enricher(artifacts)
        except Exception:
            enrichment = None

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
        enrichment=enrichment,
    )
    return window, reports
