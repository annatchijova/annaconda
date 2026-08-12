"""Curated VQL template registry.

Design rule (contracts/README.md, binding): raw ad-hoc VQL never runs. Every
collection names a pre-committed template from this registry and supplies only
whitelisted, pattern-validated parameter values. This is the live-hunt
application of VIGIA's core invariant — no free-form instruction from any
model or caller can reach the evidence source. (Pattern after SIFTics'
template-driven VQL broker, MIT; no code copied.)

Each template declares:
- ``artifact``        : the Velociraptor artifact name to collect
- ``evidence_type``   : the evidence class the core scorer understands
- ``timestamp_field`` : which row field carries the event/observation time
- ``parameters``      : allowed parameter slots, each with a fullmatch regex

Adding a template is a reviewed change to workstream 1, not runtime data.
"""

from __future__ import annotations

import re
from typing import Dict

# Conservative slot patterns. Deny-by-default: anything not matching fails.
_P_EVENT_ID = r"[0-9]{1,6}"
_P_CHANNEL = r"[A-Za-z0-9 ._/-]{1,128}"
_P_GLOB = r"[A-Za-z0-9 ._:\\/*?-]{1,256}"

TEMPLATES: Dict[str, dict] = {
    "pslist": {
        "artifact": "Windows.System.Pslist",
        "evidence_type": "memory",
        "timestamp_field": "CreateTime",
        "description": "Running processes with command line and binary path.",
        "parameters": {},
    },
    "netstat": {
        "artifact": "Windows.Network.Netstat",
        "evidence_type": "network",
        "timestamp_field": "Timestamp",
        "description": "Active network connections with owning process.",
        "parameters": {},
    },
    "process_creation_evtx": {
        "artifact": "Windows.EventLogs.Evtx",
        "evidence_type": "event_log",
        "timestamp_field": "EventTime",
        "description": "Windows event log records (e.g. 4688 process creation).",
        "parameters": {
            "Channel": _P_CHANNEL,
            "IdFilter": _P_EVENT_ID,
        },
    },
    "scheduled_tasks": {
        "artifact": "Windows.System.TaskScheduler",
        "evidence_type": "registry",
        "timestamp_field": "MTime",
        "description": "Scheduled tasks (persistence surface, T1053).",
        "parameters": {
            "TasksPath": _P_GLOB,
        },
    },
}


class TemplateError(ValueError):
    """A collection request violated the curated-template contract."""


def validate_request(template_id: str, params: dict) -> dict:
    """Validate one collection request against the registry.

    Returns the validated parameter dict (only whitelisted keys, only values
    that fullmatch their slot pattern). Raises TemplateError otherwise —
    fail loud at the boundary, never best-effort.
    """
    if template_id not in TEMPLATES:
        raise TemplateError(
            f"unknown VQL template {template_id!r} — raw or unregistered "
            f"collections are forbidden by contract"
        )
    if not isinstance(params, dict):
        raise TemplateError(
            f"params must be a dict, got {type(params).__name__}"
        )
    allowed = TEMPLATES[template_id]["parameters"]
    unknown = sorted(set(params) - set(allowed))
    if unknown:
        raise TemplateError(
            f"template {template_id!r} does not accept parameters {unknown}; "
            f"allowed: {sorted(allowed)}"
        )
    validated = {}
    for key, value in sorted(params.items()):
        if not isinstance(value, str):
            raise TemplateError(
                f"parameter {key!r} must be a string, got "
                f"{type(value).__name__}"
            )
        if re.fullmatch(allowed[key], value) is None:
            raise TemplateError(
                f"parameter {key!r} value {value!r} does not match the "
                f"allowed pattern for template {template_id!r}"
            )
        validated[key] = value
    return validated
