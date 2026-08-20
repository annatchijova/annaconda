"""A specialized agent fleet with strictly disjoint tool contracts.

Where the single investigator (agent/purple_team_agent.py) holds every tool,
the fleet splits the work across specialists, each owning a bounded set of
tools that no other specialist shares. That separation of responsibilities is
the thing a fleet is judged on, and it is enforced structurally — a test
asserts the contracts are pairwise disjoint — not just asserted in prose.

Roles:
  dispatcher        triages the case and routes work (sees the hunt catalogue)
  windows-hunter    collects running process + network state
  persistence-agent collects the persistence surface (scheduled tasks, exec logs)
  correlator        adjudicates frozen windows and verifies the sealed chain

Only the correlator's tools reach the deterministic core, and even they cannot
change a verdict — adjudicate runs the sealed engine. The invariant holds across
the fleet: agents act and divide the labour; the engine decides.

The single-investigator route is untouched; the fleet is additive.
"""

from __future__ import annotations

from agent.purple_team_agent import model_id
from agent.tools import PurpleTeamSession

from agent._tracing import span as _span


# --- disjoint tool contracts -------------------------------------------------
# Each factory returns the tools that role — and only that role — may call.
# The function names are the contract; tests verify no name appears in two.

def dispatcher_tools(session: PurpleTeamSession) -> list:
    def list_hunts() -> dict:
        """[dispatcher] List the curated hunts available to assign to specialists."""
        return session.list_available_hunts()
    return [list_hunts]


def windows_hunter_tools(session: PurpleTeamSession) -> list:
    def survey_running_state(reason: str) -> dict:
        """[windows-hunter] Collect running processes and their network
        connections together as one sealed evidence window."""
        return session.run_hunt(["pslist", "netstat"], reason=reason)
    return [survey_running_state]


def persistence_tools(session: PurpleTeamSession) -> list:
    def survey_persistence(reason: str) -> dict:
        """[persistence-agent] Collect scheduled tasks and process-creation logs
        as one sealed evidence window."""
        return session.run_hunt(["scheduled_tasks", "process_creation_evtx"],
                                reason=reason)
    return [survey_persistence]


def threat_intel_tools(session: PurpleTeamSession) -> list:
    def enrich_indicators(window_id: str) -> dict:
        """[threat-intel] Surface external threat-intel (VirusTotal / Google
        Threat Intelligence) reputation for the indicators in a frozen window.
        Read-only context sealed beside the evidence; it never changes a verdict."""
        return session.enrich_indicators(window_id)
    return [enrich_indicators]


def detection_engineer_tools(session: PurpleTeamSession) -> list:
    def synthesize_detection(window_id: str) -> dict:
        """[detection-engineer] Turn a sealed MALICE window into portable Sigma
        draft rules (status: experimental). Derived deterministically from the
        sealed evidence; a model never authors the detection logic."""
        return session.synthesize_detection(window_id)
    return [synthesize_detection]


def correlator_tools(session: PurpleTeamSession) -> list:
    def adjudicate_window(window_id: str) -> dict:
        """[correlator] Adjudicate a frozen evidence window into a SEALED verdict
        from the deterministic engine. Report it exactly; you cannot change it."""
        return session.adjudicate(window_id)

    def verify_custody() -> dict:
        """[correlator] Verify the sealed verdict chain is intact end to end."""
        return session.verify_chain()
    return [adjudicate_window, verify_custody]


FLEET = {
    "dispatcher": {"role": "triages the case and routes work",
                   "tools": dispatcher_tools},
    "windows-hunter": {"role": "collects running process and network state",
                       "tools": windows_hunter_tools},
    "persistence-agent": {"role": "collects the persistence surface",
                          "tools": persistence_tools},
    "threat-intel": {"role": "enriches window indicators with external "
                             "threat-intel reputation (evidence, not a decider)",
                     "tools": threat_intel_tools},
    "correlator": {"role": "adjudicates windows and verifies the sealed chain",
                   "tools": correlator_tools},
    "detection-engineer": {"role": "turns a sealed MALICE window into portable "
                                   "Sigma draft rules",
                           "tools": detection_engineer_tools},
}

_SPECIALIST_INSTRUCTION = (
    "You are the {name} in annaconda's forensic fleet: you {role}. Use only your "
    "tools, do your part, and report what you found — briefly and factually. You "
    "do not decide verdicts; the deterministic engine does. Never invent a score, "
    "a technique, or a hash.")


def contract_names(session: PurpleTeamSession) -> dict:
    """The tool-name set each specialist owns — the material for the disjointness
    check and the UI."""
    return {name: [t.__name__ for t in spec["tools"](session)]
            for name, spec in FLEET.items()}


def build_specialist(name: str, session: PurpleTeamSession, *, model=None):
    """Build one specialist ADK agent bound to only its disjoint tool contract.
    The sealed registry gates the load: a specialist whose tools do not match its
    approved manifest is refused."""
    from google.adk.agents import Agent
    from agent.registry import REGISTRY_VERSION, require_approved
    spec = FLEET[name]
    tools = spec["tools"](session)
    require_approved(name, REGISTRY_VERSION, [t.__name__ for t in tools])
    return Agent(
        name=f"vigia_{name.replace('-', '_')}",
        model=model or model_id(),
        description=f"annaconda fleet · {name}: {spec['role']}",
        instruction=_SPECIALIST_INSTRUCTION.format(name=name, role=spec["role"]),
        tools=tools,
    )


def dispatch_investigation(session: PurpleTeamSession) -> dict:
    """The dispatcher runs the fleet over a case: the hunters collect (each its
    own disjoint window), the correlator adjudicates and seals. Deterministic
    orchestration — reliable for a live demo — with every step attributed to the
    specialist that owns that tool contract."""
    dispatch = dispatcher_tools(session)[0]
    hunt_windows = windows_hunter_tools(session)[0]
    hunt_persistence = persistence_tools(session)[0]
    enrich = threat_intel_tools(session)[0]
    synthesize = detection_engineer_tools(session)[0]
    adjudicate, verify = correlator_tools(session)

    log = []
    with _span("fleet.investigate", **{"case_id": session.case_id}):
        with _span("dispatcher.triage") as _:
            catalogue = dispatch()
        log.append({"role": "dispatcher", "action": "triage",
                    "detail": f"{len(catalogue['hunts'])} curated hunts; "
                              f"assigning collection to the hunters"})

        verdicts = []
        for role, tool, reason in (
            ("windows-hunter", hunt_windows, "baseline running state"),
            ("persistence-agent", hunt_persistence, "persistence surface"),
        ):
            with _span(f"{role}.collect", **{"fleet.role": role}):
                summary = tool(reason)
            if "error" in summary:
                log.append({"role": role, "action": "collect",
                            "error": summary["error"]})
                continue
            log.append({"role": role, "action": "collect",
                        "window_id": summary["window_id"],
                        "artifacts": summary.get("artifacts")})
            with _span("threat-intel.enrich",
                       **{"fleet.role": "threat-intel",
                          "window_id": summary["window_id"]}):
                enrichment = enrich(summary["window_id"])
            log.append({"role": "threat-intel", "action": "enrich",
                        "window_id": summary["window_id"],
                        "indicators": enrichment.get("indicators"),
                        "flagged": enrichment.get("flagged"),
                        "misp_matches": (enrichment.get("misp") or {}).get("matches", 0),
                        "sealed_into_window": enrichment.get("sealed_into_window")})
            with _span("correlator.adjudicate",
                       **{"fleet.role": "correlator",
                          "window_id": summary["window_id"]}) as sp:
                verdict = adjudicate(summary["window_id"])
                if sp is not None and "error" not in verdict:
                    sp.set_attribute("verdict.state", verdict["verdict_state"])
            if "error" not in verdict:
                verdicts.append(verdict)
                log.append({"role": "correlator", "action": "adjudicate",
                            "window_id": summary["window_id"],
                            "verdict_state": verdict["verdict_state"],
                            "mitre_techniques": verdict.get("mitre_techniques", [])})
                # A sealed MALICE window becomes a shareable detection draft; a
                # benign window yields none (honest — nothing to share).
                with _span("detection-engineer.synthesize",
                           **{"fleet.role": "detection-engineer",
                              "window_id": summary["window_id"]}):
                    detection = synthesize(summary["window_id"])
                log.append({"role": "detection-engineer", "action": "synthesize",
                            "window_id": summary["window_id"],
                            "sigma_rules": detection.get("count", 0)})

        with _span("correlator.verify_custody"):
            chain = verify()
        log.append({"role": "correlator", "action": "verify_custody",
                    "chain_ok": chain.get("chain_ok")})

    worst = None
    from service.case_store import verdict_rank
    for v in verdicts:
        if verdict_rank(v["verdict_state"]) > verdict_rank(worst):
            worst = v["verdict_state"]
    return {"fleet_log": log, "verdicts": verdicts, "chain": chain,
            "worst_verdict": worst}
