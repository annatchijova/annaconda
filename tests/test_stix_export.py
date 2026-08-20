"""STIX 2.1 export is a pure, deterministic projection of a sealed case.

It must never introduce a float or touch the seal path, and re-exporting the
same stored case must be byte-for-byte identical.
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from verdict.stix_export import case_to_stix  # noqa: E402

# A minimal sealed case shaped exactly like the `case` object from GET /cases/{id}.
CASE = {
    "case_id": "TEST-STIX-01",
    "host": {"client_id": "C.demo01", "os": "windows", "hostname": "WIN11-VICTIM"},
    "created_utc": "2026-08-20T01:29:36Z",
    "updated_utc": "2026-08-20T01:30:03Z",
    "examiner_id": "purple-op-01",
    "entries": [
        {
            "case_id": "TEST-STIX-01",
            "sequence": 0,
            "canonicalize_version": "2",
            "bundle_sha256": "ce76d7b1f1e64efb06c940cac346eb487a3570f2e9f29ec994ef6bd0bcf265b2",
            "window_hash": "4cf944f32b0e3919ddd97e1ca2978788e5a0b1c861e398cdebdd841693e6936e",
            "entry_hash": "a8453fc04bb6c523fb71fe4b8db450bb4a5975f9af9079aa587fecc6d9b2342b",
            "prev_entry_hash": "0" * 64,
            "verdict": {
                "state": "MALICE_HIGH",
                "score": "5569/10000",
                "confidence": "19/20",
                "determinism_level": "sealed",
                "mitre_techniques": ["T1055.012", "T1070.006"],
            },
        }
    ],
}


def _objs(bundle, stix_type):
    return [o for o in bundle["objects"] if o["type"] == stix_type]


def _walk_no_float(obj):
    if isinstance(obj, float):
        raise AssertionError("a float reached the STIX bundle")
    if isinstance(obj, dict):
        for v in obj.values():
            _walk_no_float(v)
    elif isinstance(obj, list):
        for v in obj:
            _walk_no_float(v)


def test_bundle_shape():
    b = case_to_stix(CASE, chain_ok=True)
    assert b["type"] == "bundle"
    assert b["id"].startswith("bundle--")
    assert _objs(b, "identity"), "the analyzed host is an identity SDO"
    aps = _objs(b, "attack-pattern")
    assert {a["external_references"][0]["external_id"] for a in aps} == {"T1055.012", "T1070.006"}
    sv = _objs(b, "x-annaconda-sealed-verdict")
    assert len(sv) == 1
    assert _objs(b, "relationship"), "verdict is related to host and techniques"


def test_seal_is_referenced_not_recomputed():
    b = case_to_stix(CASE, chain_ok=True)
    sv = _objs(b, "x-annaconda-sealed-verdict")[0]
    assert sv["entry_hash"] == CASE["entries"][0]["entry_hash"]
    assert sv["prev_entry_hash"] == "0" * 64
    assert sv["verdict_state"] == "MALICE_HIGH"
    # scores stay exact fraction strings — never converted to a float
    assert sv["score"] == "5569/10000"
    assert sv["confidence"] == "19/20"
    assert sv["chain_verified_on_read"] is True


def test_export_is_deterministic():
    a = json.dumps(case_to_stix(CASE, chain_ok=True), sort_keys=True)
    b = json.dumps(case_to_stix(CASE, chain_ok=True), sort_keys=True)
    assert a == b, "re-exporting the same sealed case must be byte-identical"
    # ids are uuid5 over the seal, so they are stable, not random
    assert "bundle--" in a


def test_no_float_anywhere():
    _walk_no_float(case_to_stix(CASE, chain_ok=True))


def test_unknown_technique_is_still_exported():
    # T1055.012 is not in the master dictionary; it must still get a valid
    # attack-pattern with a MITRE external reference, never be dropped.
    b = case_to_stix(CASE, chain_ok=True)
    ap = next(a for a in _objs(b, "attack-pattern")
              if a["external_references"][0]["external_id"] == "T1055.012")
    assert ap["external_references"][0]["url"].endswith("/techniques/T1055/012")
    assert ap["name"]  # non-empty (falls back to the technique id)


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_"):
            fn()
            print("ok  ", name)
    print("all passed")
