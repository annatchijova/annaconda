"""MISP/OpenCTI matches are sealed evidence, never a decider.

The feed loads deterministically, a window's indicators match the team's own
intel, the matches carry no float, and they seal beside the scored artifacts —
so they are tamper-evident and reproducible yet structurally unable to move a
verdict. No feed configured degrades honestly to nothing.
"""
from pathlib import Path

from agent import misp_feed, threat_intel
from tools.velociraptor.adapter import build_evidence_window, verify_window, window_to_case

FEED = str(Path(__file__).resolve().parent / "fixtures" / "misp_feed.json")
_SHA = "a" * 64

ARTIFACTS = [
    {"artifact_id": "a-net", "evidence_type": "network_flow", "raw_score": "1/20",
     "timestamp": "2026-08-20T00:00:30Z",
     "metadata": {"tool": "velociraptor", "dst": "198.51.100.7"}},
    {"artifact_id": "a-file", "evidence_type": "filesystem_artifact", "raw_score": "1/20",
     "timestamp": "2026-08-20T00:00:45Z",
     "metadata": {"tool": "velociraptor", "sha256": _SHA}},
    {"artifact_id": "a-clean", "evidence_type": "network_flow", "raw_score": "1/20",
     "timestamp": "2026-08-20T00:00:50Z",
     "metadata": {"tool": "velociraptor", "dst": "10.0.0.9"}},  # not in the feed
]


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


def test_feed_loads_and_indexes():
    feed = misp_feed.load_feed(FEED)
    assert misp_feed.feed_size(feed) == 3
    assert ("ip_address", "198.51.100.7") in feed
    assert ("file", _SHA) in feed  # sha256 lower-cased on both sides


def test_matches_the_teams_own_indicators_only():
    feed = misp_feed.load_feed(FEED)
    records = misp_feed.enrich(ARTIFACTS, feed=feed)
    matched = {(r["indicator_type"], r["indicator"]) for r in records}
    assert matched == {("file", _SHA), ("ip_address", "198.51.100.7")}
    ip = next(r for r in records if r["indicator_type"] == "ip_address")
    assert ip["threat_level"] == "high" and ip["threat_level_id"] == 1
    assert "apt29" in ip["tags"]
    # a MISP Tag given as {"name": ...} is normalized to the tag string
    fh = next(r for r in records if r["indicator_type"] == "file")
    assert fh["tags"] == ["ransomware"]
    assert not _has_float(records)


def test_no_feed_degrades_honestly(monkeypatch):
    monkeypatch.delenv("MISP_FEED_PATH", raising=False)
    assert misp_feed.posture() == "unavailable"
    assert misp_feed.load_feed() == {}
    assert misp_feed.enrich(ARTIFACTS) == []          # no feed -> no fabricated match


def test_posture_reports_feed_size(monkeypatch):
    monkeypatch.setenv("MISP_FEED_PATH", FEED)
    assert misp_feed.posture() == "misp:3"


def test_enrichment_is_deterministic():
    feed = misp_feed.load_feed(FEED)
    assert misp_feed.enrich(ARTIFACTS, feed=feed) == misp_feed.enrich(ARTIFACTS, feed=feed)


def test_misp_seals_beside_the_artifacts_and_stays_out_of_the_scorer():
    feed = misp_feed.load_feed(FEED)
    enricher = misp_feed.make_enricher(feed=feed)
    window = build_evidence_window(
        case_id="MISP-01", sequence=0, source="velociraptor",
        host={"client_id": "C.1", "hostname": "WIN11"},
        time_start_utc="2026-08-20T00:00:00Z", time_end_utc="2026-08-20T00:01:00Z",
        collection={}, artifacts=ARTIFACTS, manifest=[], enrichment=enricher(ARTIFACTS))
    assert verify_window(window)
    assert len(window["enrichment"]) == 2 and all(
        r["source"] == "misp" for r in window["enrichment"])
    # the scorer feed never sees the enrichment: MISP cannot move a verdict
    case = window_to_case(window)
    assert "enrichment" not in case
    assert all("enrichment" not in a for a in case["artifacts"])


def test_combined_with_virustotal_seals_both_sources():
    feed = misp_feed.load_feed(FEED)

    def vt_fetch(indicator_type, value):
        if (indicator_type, value) == ("ip_address", "198.51.100.7"):
            return {"last_analysis_stats": {"malicious": 8, "suspicious": 0,
                    "harmless": 60, "undetected": 5}, "reputation": -14}
        return None

    combined = threat_intel.combine_enrichers([
        threat_intel.make_enricher(fetcher=vt_fetch, source="virustotal"),
        misp_feed.make_enricher(feed=feed),
    ])
    records = combined(ARTIFACTS)
    sources = {r["source"] for r in records}
    assert sources == {"virustotal", "misp"}  # both sealed, each tagged by source
