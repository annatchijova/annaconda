"""The enterprise catalog: which department may task which agent, over what data.

The sealed registry (agent/registry.py) answers *is this agent the one we
approved* — it is identity and a load gate. It does not answer the questions an
enterprise asks before letting a fleet loose on production telemetry:

- Who may task this agent? (cross-department publication)
- What class of data is it allowed to touch? (least privilege)
- Where may that data be processed? (residency)
- Can it reach the deterministic core, and can it write the case's memory?

This module is that layer, and it is a gate, not documentation: ``authorize``
refuses a tasking that the catalog does not permit, and the refusal is the
mechanism, not a prompt instruction the model could talk itself out of.

Catalog entries are keyed by the same agent names the registry approves, and
each carries its manifest hash, so a catalog entry always names a specific,
approved tool contract. Change an agent's tools and its manifest hash changes:
the registry refuses to load it, and the catalog entry no longer matches — one
identity, checked twice.

Honest scope of the residency rule: it governs where *evidence, seals and case
memory* are processed and stored (the deterministic core and Firestore, both in
the service's region). It does not cover the model round-trip: Gemini 3.x on
Vertex AI is served from location ``global``, so narration text leaves the
region by design. That is why no agent is granted a data class the narration
carries — the model sees sealed results and its own prompt, never raw evidence
it was not cleared for. See docs/COMPLIANCE.md.
"""

from __future__ import annotations

from agent.registry import REGISTRY_VERSION, manifest, manifest_hash

# Data classes a fleet agent can be cleared for. Least privilege is expressed
# by which of these an agent is granted — a hunter that collects process state
# has no business reading the case's sealed verdicts.
DATA_CLASSES = frozenset({
    "endpoint_telemetry",     # raw collected rows from the endpoint
    "persistence_artifacts",  # scheduled tasks, execution logs
    "sealed_verdicts",        # adjudicated, sealed results
    "case_memory",            # the fleet's own working memory
    "reference_material",     # MITRE mappings, verdict-state definitions
    "external_enrichment",    # third-party reputation (VirusTotal / GTI) as sealed evidence
})

# The departments this deployment publishes to.
DEPARTMENTS = frozenset({"soc", "incident-response", "forensics", "training",
                         "compliance"})

# Where evidence, seals and case memory may be processed. A single region for
# this deployment; the check exists so a second region cannot be added without
# an explicit catalog change.
HOME_REGION = "us-central1"


class NotPublishedError(PermissionError):
    """A department tried to task an agent that is not published to it."""


class ClearanceError(PermissionError):
    """An agent was tasked with a data class it is not cleared for, or in a
    region where that data may not be processed."""


# name -> publication. ``tools`` must match the registry's approved manifest.
_CATALOG = {
    "dispatcher": {
        "department": "soc",
        "purpose": "Triages a case and routes collection to the specialists.",
        "available_to": ["soc", "incident-response", "forensics"],
        "tools": ["list_hunts"],
        "data_classes": ["case_memory"],
        "reaches_sealed_core": False,
        "writes_case_memory": True,
    },
    "windows-hunter": {
        "department": "soc",
        "purpose": "Collects running process and network state as a sealed window.",
        "available_to": ["soc", "incident-response"],
        "tools": ["survey_running_state"],
        "data_classes": ["endpoint_telemetry"],
        "reaches_sealed_core": False,
        "writes_case_memory": False,
    },
    "persistence-agent": {
        "department": "incident-response",
        "purpose": "Collects the persistence surface as a sealed window.",
        "available_to": ["soc", "incident-response"],
        "tools": ["survey_persistence"],
        "data_classes": ["persistence_artifacts"],
        "reaches_sealed_core": False,
        "writes_case_memory": False,
    },
    "threat-intel": {
        "department": "soc",
        "purpose": ("Enriches a window's indicators with external threat-intel "
                    "(VirusTotal / Google Threat Intelligence) reputation, sealed "
                    "beside the evidence as context — never a verdict input."),
        "available_to": ["soc", "incident-response", "forensics"],
        "tools": ["enrich_indicators"],
        # It reads external reputation only; it is cleared for neither raw
        # telemetry nor sealed verdicts, and it cannot reach the core.
        "data_classes": ["external_enrichment"],
        "reaches_sealed_core": False,
        "writes_case_memory": False,
    },
    "correlator": {
        "department": "forensics",
        "purpose": "Adjudicates frozen windows and verifies the sealed chain.",
        # Forensics owns adjudication; IR may request it, the SOC may not.
        "available_to": ["forensics", "incident-response"],
        "tools": ["adjudicate_window", "verify_custody"],
        "data_classes": ["endpoint_telemetry", "persistence_artifacts",
                         "sealed_verdicts"],
        "reaches_sealed_core": True,
        "writes_case_memory": False,
    },
    "vigia_purple_team": {
        "department": "forensics",
        "purpose": "Single-operator investigator: drives hunts end to end.",
        "available_to": ["forensics", "incident-response"],
        "tools": ["list_available_hunts", "run_hunt", "adjudicate", "verify_chain"],
        "data_classes": ["endpoint_telemetry", "persistence_artifacts",
                         "sealed_verdicts"],
        "reaches_sealed_core": True,
        "writes_case_memory": False,
    },
    "fleet-commander": {
        "department": "incident-response",
        "purpose": ("Works a case autonomously across cycles: tasks the "
                    "specialists, carries the investigation's memory, decides "
                    "when to look again, escalate, or stand down."),
        # Published widely because any department may want unattended cover of
        # its hosts; what it may actually *do* is bounded by the taskings the
        # catalog authorizes for its running department, not by who launched it.
        "available_to": ["soc", "incident-response", "forensics"],
        "tools": ["read_mission_brief", "task_hunter", "request_adjudication",
                  "open_line_of_inquiry", "settle_line_of_inquiry",
                  "schedule_next_cycle", "escalate_to_human", "stand_down"],
        "data_classes": ["case_memory"],
        "reaches_sealed_core": False,
        "writes_case_memory": True,
        "delegates_to": ["windows-hunter", "persistence-agent", "correlator"],
    },
    "vigia_mentor": {
        "department": "training",
        "purpose": "Teaches junior examiners; read-only, no collection.",
        "available_to": ["training", "soc", "incident-response", "forensics"],
        "tools": ["explain_mitre_technique", "explain_verdict_state",
                  "list_verdict_states", "list_available_hunts",
                  "explain_investigation"],
        "data_classes": ["reference_material"],
        "reaches_sealed_core": False,
        "writes_case_memory": False,
    },
}


def _entry(name: str) -> dict:
    entry = _CATALOG.get(name)
    if entry is None:
        raise NotPublishedError(f"agent {name!r} is not in the enterprise catalog")
    return dict(entry, delegates_to=entry.get("delegates_to", []))


def publication(name: str) -> dict:
    """The catalog record for one agent, including its approved manifest hash."""
    entry = _entry(name)
    m = manifest(name, REGISTRY_VERSION, entry["tools"])
    return dict(entry, name=name, version=REGISTRY_VERSION,
                manifest_hash=manifest_hash(m), region=HOME_REGION)


def catalog(department: str | None = None) -> list:
    """The published catalog, optionally as one department sees it.

    This is the cross-department view: a SOC analyst browsing the catalog sees
    the agents the SOC may task, not the whole fleet.
    """
    names = sorted(_CATALOG)
    if department is None:
        return [publication(n) for n in names]
    dept = _norm_department(department)
    return [publication(n) for n in names
            if dept in _CATALOG[n]["available_to"]]


def _norm_department(department: str) -> str:
    dept = (department or "").strip().lower()
    if dept not in DEPARTMENTS:
        raise NotPublishedError(
            f"unknown department {department!r}; published departments are "
            f"{sorted(DEPARTMENTS)}")
    return dept


def authorize(name: str, *, department: str, data_classes=(),
              region: str = HOME_REGION) -> dict:
    """Gate one tasking. Returns the publication, or refuses.

    Three checks, in the order an enterprise cares about:
    1. Is the agent published to the department doing the tasking?
    2. Is every data class in the request within the agent's clearance?
    3. Is the processing region one this deployment permits?
    """
    entry = _entry(name)
    dept = _norm_department(department)
    if dept not in entry["available_to"]:
        raise NotPublishedError(
            f"agent {name!r} is not published to department {dept!r} "
            f"(published to {sorted(entry['available_to'])})")

    requested = {str(c) for c in data_classes}
    unknown = requested - DATA_CLASSES
    if unknown:
        raise ClearanceError(f"unknown data class(es) {sorted(unknown)}")
    beyond = requested - set(entry["data_classes"])
    if beyond:
        raise ClearanceError(
            f"agent {name!r} is not cleared for {sorted(beyond)} "
            f"(cleared for {sorted(entry['data_classes'])})")

    if region != HOME_REGION:
        raise ClearanceError(
            f"evidence and case memory may only be processed in "
            f"{HOME_REGION!r}, not {region!r}")
    return publication(name)


def catalog_matches_registry() -> list:
    """Every catalog entry must name an approved manifest. Returns the list of
    mismatches — empty means catalog and registry agree."""
    from agent.registry import APPROVED
    problems = []
    for name, entry in sorted(_CATALOG.items()):
        h = manifest_hash(manifest(name, REGISTRY_VERSION, entry["tools"]))
        if h not in APPROVED:
            problems.append(f"catalog entry {name!r} names a tool contract that "
                            f"the sealed registry has not approved")
    return problems
