"""Consultation tools for the junior-examiner mentor agent.

Grounded, read-only lookups so the mentor agent teaches from the repo's real
knowledge instead of inventing forensic facts:
- MITRE ATT&CK technique metadata (tools/mitre_mapping.py)
- the meaning, recommended action, and Daubert note of each verdict state
  (verdict/quadripartite.py)
- the curated hunts available (tools/velociraptor/vql_templates.py)
- a plain-language read of a stored investigation's SEALED verdicts

Nothing here decides anything: the mentor explains and guides. Verdicts come
only from the sealed engine; these tools report them, never produce them.
"""

from __future__ import annotations

from typing import Optional

from tools.mitre_mapping import MASTER_TTP_DICTIONARY, get_ttp_metadata
from tools.velociraptor.vql_templates import TEMPLATES
from verdict.quadripartite import VERDICT_STATE_CONFIGS, VerdictState


def _state_config_by_name(name: str):
    key = (name or "").strip().upper()
    for state, config in VERDICT_STATE_CONFIGS.items():
        if state.value == key:
            return config
    return None


class ConsultTools:
    """Read-only mentor tools. ``store`` is the service's investigation store
    (a dict investigation_id -> record); omit it in contexts with no cases."""

    def __init__(self, store: Optional[dict] = None):
        self._store = store if store is not None else {}

    def explain_mitre_technique(self, technique_id: str) -> dict:
        """Explain a MITRE ATT&CK technique to a junior examiner.

        Returns its name, the tactics it serves, a description, the official
        ATT&CK URL, and — useful for weighing evidence — how spoofable it is.
        Pass an id like "T1059.001".
        """
        meta = get_ttp_metadata((technique_id or "").strip())
        if meta is None:
            return {
                "found": False,
                "message": f"{technique_id!r} is not in annaconda's ATT&CK map. "
                           f"Known techniques include: "
                           f"{', '.join(sorted(MASTER_TTP_DICTIONARY)[:12])}…",
            }
        return {
            "found": True,
            "technique_id": meta.technique_id,
            "name": meta.name,
            "tactics": list(meta.tactics),
            "platforms": list(meta.platforms),
            "description": meta.description,
            "attack_url": meta.url,
            "base_severity": meta.base_severity,
            "spoofability_score": meta.spoofability_score,
            "maps_from_evidence_types": list(meta.evidence_types),
            "attack_version": meta.version,
        }

    def explain_verdict_state(self, state: str) -> dict:
        """Explain what one of annaconda's eight verdict states means.

        Returns the human label, the action a examiner should take, the
        confidence range, and the Daubert/admissibility note — so a junior
        knows not just the label but what to DO and why it holds up in court.
        """
        config = _state_config_by_name(state)
        if config is None:
            return {
                "found": False,
                "message": f"{state!r} is not a recognized verdict state. Valid "
                           f"states: {', '.join(s.value for s in VerdictState)}",
            }
        return {
            "found": True,
            "state": config.state.value,
            "label": config.display_label,
            "recommended_action": config.action.value,
            "confidence_range": config.confidence_range,
            "daubert_note": config.daubert_note,
        }

    def list_verdict_states(self) -> dict:
        """List all eight verdict states with their recommended action.

        Use this to give a junior the map of possible outcomes — including the
        ABSTAIN states, which are honest 'I cannot conclude' outcomes, not
        failures.
        """
        return {
            "states": [
                {
                    "state": s.value,
                    "label": c.display_label,
                    "action": c.action.value,
                    "confidence_range": c.confidence_range,
                }
                for s, c in VERDICT_STATE_CONFIGS.items()
            ]
        }

    def list_available_hunts(self) -> dict:
        """List the curated telemetry hunts an examiner can run on an endpoint."""
        return {
            "hunts": {
                tid: {"collects": t["description"], "evidence_type": t["evidence_type"]}
                for tid, t in sorted(TEMPLATES.items())
            }
        }

    def explain_investigation(self, investigation_id: str) -> dict:
        """Summarize a stored investigation's SEALED verdicts in plain language.

        Reports exactly what the engine sealed — verdict state, exact score,
        confidence, MITRE techniques, and whether the custody chain is intact.
        Use this to help a junior read a real case. You must report these
        sealed facts as-is; you cannot change or reinterpret the verdict.
        """
        record = self._store.get((investigation_id or "").strip())
        if record is None:
            return {"found": False,
                    "message": f"No investigation {investigation_id!r} on record."}
        return {
            "found": True,
            "investigation_id": record["investigation_id"],
            "case_id": record.get("case_id"),
            "mode": record.get("mode"),
            "chain_intact": record.get("chain", {}).get("chain_ok"),
            "sealed_verdicts": [
                {
                    "sequence": v["sequence"],
                    "verdict_state": v["verdict_state"],
                    "score": v["score"],
                    "confidence": v["confidence"],
                    "mitre_techniques": v.get("mitre_techniques", []),
                    "entry_hash": v["entry_hash"][:16] + "…",
                }
                for v in record.get("verdicts", [])
            ],
        }
