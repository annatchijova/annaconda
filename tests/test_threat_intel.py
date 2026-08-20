"""External threat-intel enrichment is sealed evidence, never a decider.

These tests hold the enrichment to the founding invariant: the reputation is
sealed INTO the window (tamper-evident, reproducible) but sits beside the scored
artifacts, so it cannot reach the scorer and cannot move a verdict; with no key
it degrades honestly; and the specialist is gated by the catalog like any other.
"""
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from agent import catalog, threat_intel  # noqa: E402
from agent.registry import REGISTRY_VERSION, require_approved  # noqa: E402
from tools.velociraptor.adapter import (  # noqa: E402
    build_evidence_window, verify_window, window_to_case,
)

_SHA = "a" * 64
ARTIFACTS = [
    {"artifact_id": "a-net-1", "evidence_type": "network_flow",
     "source_tool": "velociraptor", "acquisition_tool": "velociraptor",
     "raw_score": "1/20", "description": "netstat", "timestamp": "2026-08-19T00:00:30Z",
     "provenance_chain": ["sha256:" + "0" * 64],
     "metadata": {"tool": "velociraptor", "dst": "198.51.100.7"}},
    {"artifact_id": "a-file-1", "evidence_type": "filesystem_artifact",
     "source_tool": "velociraptor", "acquisition_tool": "velociraptor",
     "raw_score": "1/20", "description": "dropped file", "timestamp": "2026-08-19T00:00:45Z",
     "provenance_chain": ["sha256:" + "1" * 64],
     "metadata": {"tool": "velociraptor", "sha256": _SHA}},
]


def fixture_fetch(indicator_type, value):
    """A frozen VirusTotal-shaped response — the stand-in for a live call, so the
    result is reproducible and no network is touched."""
    db = {
        ("ip_address", "198.51.100.7"): {
            "last_analysis_stats": {"malicious": 8, "suspicious": 1,
                                    "harmless": 60, "undetected": 5},
            "reputation": -14},
        ("file", _SHA): {
            "last_analysis_stats": {"malicious": 45, "suspicious": 2,
                                    "harmless": 0, "undetected": 20},
            "reputation": -30},
    }
    return db.get((indicator_type, value))


def _has_float(obj):
    if isinstance(obj, bool):
        return False
    if isinstance(obj, float):
        return True
    if isinstance(obj, dict):
        return any(_has_float(v) for v in obj.values())
    if isinstance(obj, (list, tuple)):
        return any(_has_float(v) for v in obj)
    return False


def test_indicators_extracted_and_enriched_with_fixture():
    inds = threat_intel.extract_indicators(ARTIFACTS)
    assert inds == [("file", _SHA), ("ip_address", "198.51.100.7")]
    records = threat_intel.enrich(ARTIFACTS, fetcher=fixture_fetch, source="virustotal")
    assert len(records) == 2
    ip = next(r for r in records if r["indicator_type"] == "ip_address")
    assert ip["available"] is True
    assert ip["stats"]["malicious"] == 8 and ip["reputation"] == -14
    # counts are exact integers — nothing here can smuggle a float into a seal
    assert not _has_float(records)


def test_enrichment_seals_into_window_but_never_reaches_the_scorer():
    enrichment = threat_intel.enrich(ARTIFACTS, fetcher=fixture_fetch, source="virustotal")
    window = build_evidence_window(
        case_id="TI-01", sequence=0, source="velociraptor",
        host={"client_id": "C.demo", "hostname": "WIN11"},
        time_start_utc="2026-08-19T00:00:00Z", time_end_utc="2026-08-19T00:01:00Z",
        collection={}, artifacts=ARTIFACTS, manifest=[], enrichment=enrichment)
    # sealed into the window and tamper-evident
    assert verify_window(window)
    assert len(window["enrichment"]) == 2
    # ...but the scorer's feed does not carry it — VT is structurally out of the
    # decision path, not merely asked nicely to stay out.
    case = window_to_case(window)
    assert "enrichment" not in case
    assert all("enrichment" not in a for a in case["artifacts"])
    # a window built from the SAME artifacts without enrichment feeds the scorer
    # an identical case: enrichment changes the sealed record, never the verdict.
    bare = build_evidence_window(
        case_id="TI-01", sequence=0, source="velociraptor",
        host={"client_id": "C.demo", "hostname": "WIN11"},
        time_start_utc="2026-08-19T00:00:00Z", time_end_utc="2026-08-19T00:01:00Z",
        collection={}, artifacts=ARTIFACTS, manifest=[])
    assert window_to_case(bare) == case
    assert "enrichment" not in bare  # empty enrichment leaves the window unchanged


_CHILD = r'''
import sys
sys.path.insert(0, sys.argv[1])
from agent import threat_intel
from tools.velociraptor.adapter import build_evidence_window
SHA = "a" * 64
ARTIFACTS = [
    {"artifact_id": "a-net-1", "evidence_type": "network_flow",
     "raw_score": "1/20", "timestamp": "2026-08-19T00:00:30Z",
     "metadata": {"tool": "v", "dst": "198.51.100.7"}},
    {"artifact_id": "a-file-1", "evidence_type": "filesystem_artifact",
     "raw_score": "1/20", "timestamp": "2026-08-19T00:00:45Z",
     "metadata": {"tool": "v", "sha256": SHA}},
]
def fetch(t, v):
    db = {("ip_address", "198.51.100.7"): {"last_analysis_stats":
             {"malicious": 8, "suspicious": 1, "harmless": 60, "undetected": 5},
             "reputation": -14},
          ("file", SHA): {"last_analysis_stats":
             {"malicious": 45, "suspicious": 2, "harmless": 0, "undetected": 20},
             "reputation": -30}}
    return db.get((t, v))
enr = threat_intel.enrich(ARTIFACTS, fetcher=fetch, source="virustotal")
w = build_evidence_window(case_id="TI-01", sequence=0, source="velociraptor",
    host={"client_id": "C.demo", "hostname": "WIN11"},
    time_start_utc="2026-08-19T00:00:00Z", time_end_utc="2026-08-19T00:01:00Z",
    collection={}, artifacts=ARTIFACTS, manifest=[], enrichment=enr)
print(w["window_hash"])
'''


def _seal_once(tmp_path, hashseed):
    child = tmp_path / "child.py"
    child.write_text(_CHILD, encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, str(child), str(REPO_ROOT)],
        capture_output=True, text=True, timeout=120,
        env={"PYTHONHASHSEED": hashseed, "PATH": "/usr/bin:/bin"})
    assert proc.returncode == 0, proc.stderr[-2000:]
    return proc.stdout.strip()


def test_sealed_enrichment_is_deterministic_across_processes(tmp_path):
    # Two fresh interpreters, different hash seeds: the enriched, sealed window
    # must hash byte-identically — the cached reputation replays exactly.
    a = _seal_once(tmp_path, "0")
    b = _seal_once(tmp_path, "12345")
    assert len(a) == 64 and a == b


def test_no_key_degrades_honestly(monkeypatch):
    monkeypatch.delenv("VT_API_KEY", raising=False)
    monkeypatch.delenv("GTI_API_KEY", raising=False)
    assert threat_intel.posture() == "unavailable"
    records = threat_intel.enrich(ARTIFACTS)  # no fetcher, no key
    assert len(records) == 2
    assert all(r["available"] is False and r["reason"] for r in records)
    # honest degradation must never fabricate a reputation figure
    assert all("stats" not in r for r in records)


def test_specialist_is_approved_and_catalog_gated():
    # registry approves the exact tool contract
    h = require_approved("threat-intel", REGISTRY_VERSION, ["enrich_indicators"])
    assert len(h) == 64
    assert catalog.catalog_matches_registry() == []
    # published to the SOC over external enrichment only
    pub = catalog.authorize("threat-intel", department="soc",
                            data_classes=["external_enrichment"])
    assert pub["name"] == "threat-intel"
    # a department it is not published to is refused
    with pytest.raises(catalog.NotPublishedError):
        catalog.authorize("threat-intel", department="training",
                          data_classes=["external_enrichment"])
    # and it is not cleared to touch sealed verdicts or raw telemetry
    with pytest.raises(catalog.ClearanceError):
        catalog.authorize("threat-intel", department="soc",
                          data_classes=["sealed_verdicts"])
