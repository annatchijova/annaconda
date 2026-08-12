"""Sanity checks for the live-mode contract schemas.

Stdlib-only (no jsonschema dependency): verifies the schemas parse, are
internally consistent, and encode the binding design rules from
contracts/README.md — most importantly that nothing sealed admits floats
and that the nomination layer is the only place a float is allowed.
"""

import json
from pathlib import Path

CONTRACTS = Path(__file__).resolve().parent.parent / "contracts"

FRACTION_PATTERN_FRAGMENT = "/([1-9][0-9]*)$"


def _load(name):
    return json.loads((CONTRACTS / name).read_text(encoding="utf-8"))


def test_all_schemas_parse_and_are_versioned():
    for name in (
        "evidence_window.schema.json",
        "verdict_stream_entry.schema.json",
        "ml_nomination.schema.json",
    ):
        schema = _load(name)
        assert schema["properties"]["schema_version"]["const"] == 1, name
        assert "schema_version" in schema["required"], name
        assert schema["additionalProperties"] is False, name


def test_sealed_schemas_admit_no_float_scores():
    window = _load("evidence_window.schema.json")
    raw_score = window["properties"]["artifacts"]["items"]["properties"]["raw_score"]
    assert raw_score["type"] == "string"
    assert FRACTION_PATTERN_FRAGMENT in raw_score["pattern"]

    entry = _load("verdict_stream_entry.schema.json")
    verdict_props = entry["properties"]["verdict"]["properties"]
    for field in ("score", "confidence"):
        assert verdict_props[field]["type"] == "string", field
        assert FRACTION_PATTERN_FRAGMENT in verdict_props[field]["pattern"], field


def test_nomination_is_marked_and_advisory():
    nomination = _load("ml_nomination.schema.json")
    props = nomination["properties"]
    assert props["nominated_by"]["const"] == "ml"
    assert "nominated_by" in nomination["required"]
    # surprisal_bits is the one deliberate float in the contract set —
    # advisory only, never sealed.
    assert props["surprisal_bits"]["type"] == "number"


def test_chain_fields_are_sha256_shaped():
    entry = _load("verdict_stream_entry.schema.json")
    props = entry["properties"]
    for field in ("window_hash", "prev_entry_hash", "bundle_sha256", "entry_hash"):
        assert props[field]["pattern"] == "^[a-f0-9]{64}$", field
