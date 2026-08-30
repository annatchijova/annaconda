"""Curated VQL template registry.

Design rule (contracts/README.md, binding): raw ad-hoc VQL never runs. Every
collection names a pre-committed template from this registry and supplies only
whitelisted, pattern-validated parameter values. This is the live-hunt
application of VIGIA's core invariant — no free-form instruction from any
model or caller can reach the evidence source. (Pattern after SIFTics'
template-driven VQL broker, MIT; no code copied.)

Each template declares:
- ``artifact``        : the Velociraptor artifact name to collect
- ``evidence_type``   : a key of CAIE's _DOMAIN_MAP taxonomy (tools/caie.py) —
  never a free-form label; tests/test_velociraptor_adapter.py enforces the
  lockstep so a typo cannot silently degrade to the "default" profile
- ``timestamp_field`` : which row field carries the event/observation time
- ``parameters``      : allowed parameter slots, each with a fullmatch regex

Adding a template is a reviewed change to workstream 1, not runtime data.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Dict

# Conservative slot patterns. Deny-by-default: anything not matching fails.
_P_EVENT_ID = r"[0-9]{1,6}"
_P_CHANNEL = r"[A-Za-z0-9 ._/-]{1,128}"
_P_GLOB = r"[A-Za-z0-9 ._:\\/*?-]{1,256}"
# A committed ruleset FILENAME, never rule text. See the YARA templates below.
_P_RULESET = r"[A-Za-z0-9_-]{1,64}"

TEMPLATES: Dict[str, dict] = {
    "pslist": {
        "artifact": "Windows.System.Pslist",
        "evidence_type": "memory_process",
        "timestamp_field": "CreateTime",
        "summary_fields": ("Name", "Pid", "Username"),
        "description": "Running processes with command line and binary path.",
        "parameters": {},
    },
    "netstat": {
        "artifact": "Windows.Network.Netstat",
        "evidence_type": "network_flow",
        "timestamp_field": "Timestamp",
        "summary_fields": ("Name", "Pid", "Raddr.IP", "Raddr.Port", "Status"),
        "description": "Active network connections with owning process.",
        "parameters": {},
    },
    "process_creation_evtx": {
        "artifact": "Windows.EventLogs.Evtx",
        "evidence_type": "windows_event_log",
        "timestamp_field": "EventTime",
        "summary_fields": ("EventID", "Computer", "NewProcessName", "SubjectUserName"),
        "description": "Windows event log records (e.g. 4688 process creation).",
        "parameters": {
            "Channel": _P_CHANNEL,
            "IdFilter": _P_EVENT_ID,
        },
    },
    "scheduled_tasks": {
        "artifact": "Windows.System.TaskScheduler",
        "evidence_type": "filesystem_artifact",
        "timestamp_field": "MTime",
        "summary_fields": ("FullPath", "Command"),
        "description": "Scheduled tasks (persistence surface, T1053).",
        "parameters": {
            "TasksPath": _P_GLOB,
        },
    },
    # -----------------------------------------------------------------------
    # Malware detection: Velociraptor's own YARA engine.
    #
    # Detection lives on the collector's side of the boundary, which is the
    # point: Velociraptor already knows how to match rules against process
    # memory and files, so annaconda collects and SEALS those matches instead
    # of reimplementing a scanner.
    #
    # Two constraints hold here, and neither is incidental:
    #
    # 1. Rules are NEVER a caller-supplied value. ``RuleSet`` names a file
    #    committed to tools/velociraptor/yara_rules/ and validated against
    #    _P_RULESET; rule TEXT is not accepted from anyone. A YARA rule is
    #    executable matching logic, so accepting it as a parameter would be
    #    exactly the free-form instruction reaching the evidence source that
    #    this registry exists to prevent -- and an expensive rule is a denial
    #    of service against the endpoint being investigated.
    #
    # 2. A match collected here carries NO verdict weight. The adapter assigns
    #    every collected artifact the EBS no-signal floor because collecting
    #    is not analyzing, and that is left deliberately unchanged: a hit is
    #    sealed, exportable and visible, and it does not move the verdict.
    #    Whether a signature match SHOULD weigh on a sealed verdict -- and how
    #    much, given that the adversary picks the bytes -- is an open decision,
    #    recorded rather than silently answered by a default.
    #    tests/test_yara_collection.py pins both halves of that claim.
    "yara_process": {
        "artifact": "Windows.Detection.Yara.Process",
        "evidence_type": "malware_static_analysis",
        "timestamp_field": "ScanTime",
        "summary_fields": ("Rule", "Tags", "ProcessName", "Pid"),
        "description": ("YARA matches in process memory (sealed as evidence; "
                        "carries no verdict weight by design)."),
        "parameters": {
            "RuleSet": _P_RULESET,
        },
    },
    "yara_file": {
        "artifact": "Generic.Detection.Yara.Glob",
        "evidence_type": "malware_static_analysis",
        "timestamp_field": "ScanTime",
        "summary_fields": ("Rule", "Tags", "FullPath"),
        "description": ("YARA matches in files under a target glob (sealed as "
                        "evidence; carries no verdict weight by design)."),
        "parameters": {
            "RuleSet": _P_RULESET,
            "TargetGlob": _P_GLOB,
        },
    },
}

# Where committed rulesets live. A RuleSet parameter names a file in here;
# resolve_ruleset() is the only way a rule file reaches a collection.
RULES_DIR = Path(__file__).resolve().parent / "yara_rules"


def resolve_ruleset(name: str) -> Path:
    """Resolve a validated RuleSet name to a committed rule file.

    Deny by default: the name must fullmatch _P_RULESET (no separators, so no
    traversal is expressible), and the resolved path must still sit inside
    RULES_DIR after resolution. Missing files fail loud rather than scanning
    with no rules and reporting a clean result.
    """
    if not isinstance(name, str) or re.fullmatch(_P_RULESET, name) is None:
        raise TemplateError(
            f"invalid ruleset name {name!r}; committed rulesets match "
            f"{_P_RULESET} and rule TEXT is never accepted")
    path = (RULES_DIR / f"{name}.yar").resolve()
    if path.parent != RULES_DIR.resolve():
        raise TemplateError(f"ruleset {name!r} resolves outside {RULES_DIR}")
    if not path.is_file():
        raise TemplateError(
            f"ruleset {name!r} is not committed at {path}; a scan with no "
            f"rules would report a clean host it never examined")
    return path


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
