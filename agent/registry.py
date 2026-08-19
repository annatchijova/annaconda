"""Sealed agent registry: registry, identity, and gateway in one mechanism.

Every agent is published with a version and the SHA-256 hash of its tool
manifest (its name, version, and the sorted names of the tools it may call).
The hash is computed with the SAME canonical encoder that seals verdicts — one
sealing discipline across the system. At load time the runtime recomputes an
agent's manifest hash and refuses to build it unless that hash is in the
approved set. So:

- registry: the approved set is the list of published agents.
- identity: an agent IS its manifest hash — change its tools and it is a
  different, unapproved agent.
- gateway: the runtime will not load an agent whose manifest was not approved.

Re-approving is deliberate: after a reviewed change to an agent's tools, add its
new manifest to the approved set below. An out-of-band tool added to an agent
changes its hash and is refused until re-approved.
"""

from __future__ import annotations

import hashlib
import json

from core.canonicalize import _canonicalize

REGISTRY_VERSION = "1.0.0"


class UnapprovedAgentError(RuntimeError):
    """Raised when the runtime is asked to load an agent whose tool manifest is
    not in the sealed registry."""


def manifest(name: str, version: str, tool_names) -> dict:
    return {"name": name, "version": version, "tools": sorted(tool_names)}


def manifest_hash(m: dict) -> str:
    """Same canonical-v2 + SHA-256 recipe used to seal verdicts."""
    serialized = json.dumps(
        _canonicalize(m), sort_keys=True, ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(serialized).hexdigest()


# The approved snapshot — the ONLY agent manifests the runtime will load.
_APPROVED_MANIFESTS = [
    manifest("dispatcher", REGISTRY_VERSION, ["list_hunts"]),
    manifest("windows-hunter", REGISTRY_VERSION, ["survey_running_state"]),
    manifest("persistence-agent", REGISTRY_VERSION, ["survey_persistence"]),
    manifest("correlator", REGISTRY_VERSION, ["adjudicate_window", "verify_custody"]),
    manifest("vigia_purple_team", REGISTRY_VERSION,
             ["list_available_hunts", "run_hunt", "adjudicate", "verify_chain"]),
    manifest("fleet-commander", REGISTRY_VERSION,
             ["read_mission_brief", "task_hunter", "request_adjudication",
              "open_line_of_inquiry", "settle_line_of_inquiry",
              "schedule_next_cycle", "escalate_to_human", "stand_down"]),
    manifest("vigia_mentor", REGISTRY_VERSION,
             ["explain_mitre_technique", "explain_verdict_state",
              "list_verdict_states", "list_available_hunts", "explain_investigation"]),
]

APPROVED: dict[str, dict] = {manifest_hash(m): m for m in _APPROVED_MANIFESTS}


def require_approved(name: str, version: str, tool_names) -> str:
    """Gate: return the manifest hash if approved, else refuse to load."""
    m = manifest(name, version, tool_names)
    h = manifest_hash(m)
    if h not in APPROVED:
        raise UnapprovedAgentError(
            f"agent {name!r} v{version} with tools {sorted(tool_names)} is not "
            f"in the sealed registry (manifest {h[:16]}… not approved) — "
            f"refusing to load")
    return h


def approved_registry() -> list:
    """The published registry: each approved agent with its version and hash."""
    return [{"name": m["name"], "version": m["version"], "tools": m["tools"],
             "manifest_hash": manifest_hash(m)}
            for m in _APPROVED_MANIFESTS]
