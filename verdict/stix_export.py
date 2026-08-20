"""Deterministic STIX 2.1 export of a sealed annaconda case.

This is *output* of an already-sealed verdict, never an input to one: no model,
no float, no wall clock, no I/O. The sealed ``entry_hash`` chain is referenced,
never recomputed, so the exported bundle carries its own tamper-evidence and a
consumer can re-verify it against the case.

Determinism is a forensic requirement here, not a nicety: STIX object ids are
``uuid5`` over the seal (never a random ``uuid4``), and every ``created`` /
``modified`` timestamp comes from the sealed record. Re-exporting the same
stored case is therefore byte-for-byte identical.

A verdict maps to STIX like this:
  host                -> identity (the analyzed endpoint)
  each MITRE technique -> attack-pattern (with the MITRE external_reference)
  each sealed entry    -> x-annaconda-sealed-verdict (state, score, seals)
  + relationships (sealed-verdict `targets` host, `uses` each technique)
"""
from __future__ import annotations

import uuid

# A fixed namespace so every id is reproducible across processes and machines.
_NS = uuid.uuid5(uuid.NAMESPACE_URL, "https://annaconda.dev/stix")
_MITRE = "mitre-attack"


def _sid(kind: str, seed: str) -> str:
    """A deterministic STIX id: ``<kind>--<uuid5(namespace, kind:seed)>``."""
    return f"{kind}--{uuid.uuid5(_NS, kind + ':' + seed)}"


def _technique_url(tid: str) -> str:
    # T1070.006 -> https://attack.mitre.org/techniques/T1070/006
    return "https://attack.mitre.org/techniques/" + tid.replace(".", "/")


def _attack_pattern(tid: str, created: str, modified: str) -> dict:
    # The master dictionary enriches the name/tactic/description; a technique it
    # does not carry still gets a valid attack-pattern with a derived MITRE URL,
    # so an unknown technique is never silently dropped.
    from tools.mitre_mapping import MASTER_TTP_DICTIONARY

    meta = MASTER_TTP_DICTIONARY.get(tid)
    obj: dict = {
        "type": "attack-pattern",
        "spec_version": "2.1",
        "id": _sid("attack-pattern", tid),
        "created": created,
        "modified": modified,
        "name": meta.name if meta else tid,
        "external_references": [{
            "source_name": _MITRE,
            "external_id": tid,
            "url": (meta.url if (meta and meta.url) else _technique_url(tid)),
        }],
    }
    if meta and getattr(meta, "description", None):
        obj["description"] = meta.description
    if meta and getattr(meta, "tactics", None):
        obj["kill_chain_phases"] = [
            {"kill_chain_name": _MITRE,
             "phase_name": t.name.lower().replace("_", "-")}
            for t in meta.tactics
        ]
    return obj


def case_to_stix(case: dict, *, chain_ok: bool | None = None) -> dict:
    """Map a sealed case (the ``case`` object from ``GET /cases/{id}``) to a
    STIX 2.1 bundle. Pure and deterministic; does not touch the seal path."""
    case_id = case["case_id"]
    host = case.get("host") or {}
    created = case.get("created_utc")
    modified = case.get("updated_utc") or created
    entries = case.get("entries") or []

    objects: list[dict] = []

    # The analyzed endpoint.
    host_id = _sid("identity", f"{case_id}:{host.get('client_id', '')}:{host.get('hostname', '')}")
    objects.append({
        "type": "identity",
        "spec_version": "2.1",
        "id": host_id,
        "created": created,
        "modified": modified,
        "name": host.get("hostname") or host.get("client_id") or case_id,
        "identity_class": "system",
        "description": f"Analyzed endpoint — client {host.get('client_id', '?')}, os {host.get('os', '?')}.",
    })

    # One attack-pattern per unique technique across the case (sorted -> stable).
    techniques = sorted({
        t for e in entries for t in (e.get("verdict", {}).get("mitre_techniques") or [])
    })
    tech_id = {}
    for tid in techniques:
        ap = _attack_pattern(tid, created, modified)
        tech_id[tid] = ap["id"]
        objects.append(ap)

    # One sealed-verdict SDO per sealed entry, referencing the seal (never recomputed).
    for e in entries:
        v = e.get("verdict", {})
        seal = e["entry_hash"]
        sv_id = _sid("x-annaconda-sealed-verdict", seal)
        objects.append({
            "type": "x-annaconda-sealed-verdict",
            "spec_version": "2.1",
            "id": sv_id,
            "created": created,
            "modified": modified,
            "case_id": case_id,
            "sequence": e.get("sequence"),
            "verdict_state": v.get("state"),
            "score": v.get("score"),            # exact fraction string, never a float
            "confidence": v.get("confidence"),  # exact fraction string
            "determinism_level": v.get("determinism_level"),
            "mitre_techniques": v.get("mitre_techniques") or [],
            "entry_hash": seal,
            "prev_entry_hash": e.get("prev_entry_hash"),
            "window_hash": e.get("window_hash"),
            "bundle_sha256": e.get("bundle_sha256"),
            "canonicalize_version": e.get("canonicalize_version"),
            # Surfaced honestly (not part of the seal): did the chain verify on read?
            "chain_verified_on_read": chain_ok,
        })
        objects.append({
            "type": "relationship", "spec_version": "2.1",
            "id": _sid("relationship", f"{seal}:targets:{host_id}"),
            "created": created, "modified": modified,
            "relationship_type": "targets",
            "source_ref": sv_id, "target_ref": host_id,
        })
        for tid in (v.get("mitre_techniques") or []):
            objects.append({
                "type": "relationship", "spec_version": "2.1",
                "id": _sid("relationship", f"{seal}:uses:{tid}"),
                "created": created, "modified": modified,
                "relationship_type": "uses",
                "source_ref": sv_id, "target_ref": tech_id[tid],
            })

    return {
        "type": "bundle",
        "id": _sid("bundle", f"{case_id}:{modified or ''}"),
        "objects": objects,
    }
