"""Deterministic Sigma-rule synthesis from a sealed MALICE window.

When the deterministic core seals a MALICE (or ESCALATE) verdict, the evidence
that earned it can be turned into a portable Sigma detection so the catch on one
host becomes a rule the whole community can deploy. Like the STIX export, this is
*output of an already-sealed verdict*, never an input to one:

- No model authors detection logic. The rule is a deterministic template over the
  SEALED window's fields and the sealed verdict's MITRE techniques. Swapping the
  narrator cannot change a selector.
- No float, no clock, no I/O. Rule ids are ``uuid5`` over the seal; the date comes
  from the sealed window. Re-synthesizing the same window is byte-identical.
- Honest posture. A machine-suggested rule is a DRAFT: ``status: experimental``,
  an author note saying so, and a false-positive line telling the analyst to
  review and generalize before deploying. Only stable, identifying fields become
  selectors (Image, ParentImage, User, DestinationIp, CommandLine, TargetFilename,
  EventID); volatile ones (timestamps, PIDs, ports, ephemeral ports) are dropped,
  so the draft is a starting point, not noise. A non-MALICE verdict yields no rule
  — there is nothing to share, and we say nothing rather than invent a detection.
"""
from __future__ import annotations

import uuid

_NS = uuid.uuid5(uuid.NAMESPACE_URL, "https://annaconda.dev/sigma")

# evidence_type -> Sigma logsource category (product windows for this fleet).
_CATEGORY = {
    "windows_event_log": "process_creation",
    "memory_process": "process_creation",
    "network_flow": "network_connection",
    "filesystem_artifact": "file_event",
}

# evidence_type -> {raw row field: Sigma field}. Only stable, identifying fields
# are mapped; anything not here (timestamps, pids, ports, status) is dropped.
_FIELD_MAP = {
    "windows_event_log": {
        "NewProcessName": "Image", "ParentProcessName": "ParentImage",
        "SubjectUserName": "User", "EventID": "EventID"},
    "memory_process": {
        "Name": "Image", "Exe": "Image", "CommandLine": "CommandLine"},
    "network_flow": {
        "Raddr.IP": "DestinationIp", "dst_ip": "DestinationIp",
        "Raddr.Port": "DestinationPort", "Name": "Image"},
    "filesystem_artifact": {
        "FullPath": "TargetFilename", "Command": "CommandLine"},
}

_LEVEL = {"MALICE_HIGH": "high", "MALICE_MEDIUM": "medium", "ESCALATE": "high"}

# Ports are dropped as selectors even though mapped above: a destination port is
# rarely a stable IoC on its own and inflates false positives. Kept out here.
_DROP_SIGMA_FIELDS = {"DestinationPort"}

_MAX_VALUES = 20  # cap a selector's value list; truncation is annotated, never silent.


def _seals_a_detection(verdict: dict | None) -> bool:
    state = (verdict or {}).get("state") or (verdict or {}).get("verdict_state")
    return isinstance(state, str) and (state.startswith("MALICE") or state == "ESCALATE")


def _technique_tags(techniques: list) -> list:
    """Sigma ``attack.*`` tags: the technique ids plus their tactics (looked up
    from the master dictionary; unknown techniques still get their id tag)."""
    tags = []
    try:
        from tools.mitre_mapping import MASTER_TTP_DICTIONARY
    except Exception:
        MASTER_TTP_DICTIONARY = {}
    tactics = set()
    for tid in techniques:
        tags.append("attack." + tid.lower())
        meta = MASTER_TTP_DICTIONARY.get(tid)
        for t in (getattr(meta, "tactics", None) or ()):
            tactics.add("attack." + t.name.lower())
    return sorted(dict.fromkeys(tags)) + sorted(tactics)


def _selection_for(artifacts: list, evidence_type: str) -> tuple[dict, bool]:
    """Build the Sigma ``selection`` map for one evidence_type group from the
    sealed rows. Returns (selection, truncated)."""
    field_map = _FIELD_MAP[evidence_type]
    collected: dict[str, set] = {}
    for art in artifacts:
        row = (art.get("metadata") or {}).get("row") or {}
        for raw_field, sigma_field in field_map.items():
            if sigma_field in _DROP_SIGMA_FIELDS:
                continue
            value = row.get(raw_field)
            if value in (None, ""):
                continue
            collected.setdefault(sigma_field, set()).add(str(value))
    selection = {}
    truncated = False
    for sigma_field in sorted(collected):
        values = sorted(collected[sigma_field])
        if len(values) > _MAX_VALUES:
            values = values[:_MAX_VALUES]
            truncated = True
        # a single value stays a scalar; multiple become an OR list — Sigma idiom.
        selection[sigma_field] = values[0] if len(values) == 1 else values
    return selection, truncated


def window_to_sigma_rules(window: dict, *, verdict: dict | None = None) -> list:
    """Synthesize Sigma draft rules from a sealed window and its sealed verdict.

    One rule per evidence_type that carries mappable selectors. Returns an empty
    list for a non-MALICE verdict (nothing to share) — deterministic and honest.
    """
    if not _seals_a_detection(verdict):
        return []
    case_id = window.get("case_id", "")
    window_hash = window.get("window_hash", "")
    date = (window.get("time_end_utc") or "")[:10].replace("-", "/")
    state = verdict.get("state") or verdict.get("verdict_state")
    techniques = sorted(verdict.get("mitre_techniques") or [])
    tags = _technique_tags(techniques)
    references = ["https://attack.mitre.org/techniques/" + t.replace(".", "/")
                 for t in techniques]

    by_type: dict[str, list] = {}
    for art in window.get("artifacts", []):
        et = art.get("evidence_type")
        if et in _CATEGORY:
            by_type.setdefault(et, []).append(art)

    rules = []
    for evidence_type in sorted(by_type):
        selection, truncated = _selection_for(by_type[evidence_type], evidence_type)
        if not selection:
            continue
        rule_seed = f"{case_id}:{window_hash}:{evidence_type}"
        fp = ("Machine-suggested DRAFT synthesized from a single sealed window; "
              "review and generalize the selectors before deploying.")
        if truncated:
            fp += (f" Selector value lists were capped at {_MAX_VALUES}; widen from "
                   f"the full sealed window if needed.")
        rules.append({
            "title": f"annaconda draft: {state} on {evidence_type} ({case_id})",
            "id": str(uuid.uuid5(_NS, rule_seed)),
            "status": "experimental",
            "description": (f"Draft detection derived from an annaconda sealed "
                            f"{state} verdict over {evidence_type} evidence. "
                            f"Not authored by a model; a deterministic projection "
                            f"of the sealed window {window_hash[:16]}."),
            "references": references,
            "author": "annaconda (machine-suggested; requires human review)",
            "date": date,
            "tags": tags,
            "logsource": {"product": "windows", "category": _CATEGORY[evidence_type]},
            "detection": {"selection": selection, "condition": "selection"},
            "falsepositives": [fp],
            "level": _LEVEL.get(state, "medium"),
        })
    return rules


# ---------------------------------------------------------------------------
# Deterministic minimal YAML emitter for the fixed Sigma schema (stdlib-only).
# ---------------------------------------------------------------------------

# Conventional Sigma key order — fixed, so output is stable and reads like a
# hand-written rule rather than a sorted dump.
_KEY_ORDER = ["title", "id", "status", "description", "references", "author",
              "date", "tags", "logsource", "detection", "falsepositives", "level"]


def _scalar(value) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    s = str(value)
    escaped = s.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _emit(value, indent: int) -> list:
    pad = "  " * indent
    lines = []
    if isinstance(value, dict):
        for k in value:
            v = value[k]
            if isinstance(v, (dict, list)) and v:
                lines.append(f"{pad}{k}:")
                lines.extend(_emit(v, indent + 1))
            elif isinstance(v, (dict, list)):
                lines.append(f"{pad}{k}: {{}}" if isinstance(v, dict) else f"{pad}{k}: []")
            else:
                lines.append(f"{pad}{k}: {_scalar(v)}")
    elif isinstance(value, list):
        for item in value:
            if isinstance(item, (dict, list)):
                lines.append(f"{pad}-")
                lines.extend(_emit(item, indent + 1))
            else:
                lines.append(f"{pad}- {_scalar(item)}")
    return lines


def to_yaml(rule: dict) -> str:
    """Serialize one synthesized rule to Sigma-conventional YAML, deterministically."""
    ordered = {k: rule[k] for k in _KEY_ORDER if k in rule}
    ordered.update({k: v for k, v in rule.items() if k not in ordered})
    return "\n".join(_emit(ordered, 0)) + "\n"
