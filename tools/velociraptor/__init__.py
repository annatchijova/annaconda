"""Velociraptor live-evidence adapter (workstream 2).

Turns VQL hunt results into sealed evidence windows (contracts/
evidence_window.schema.json) that the deterministic core scores exactly like
static artifacts. Velociraptor itself runs as an independent AGPLv3 service
reached over its API; nothing from it is embedded here.
"""
