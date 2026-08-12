"""Tests for the Velociraptor adapter (curated templates -> sealed windows)."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

from tools.velociraptor.adapter import (
    AdapterError,
    MockTransport,
    build_evidence_window,
    collect_window,
    normalize_rows,
    verify_window,
)
from tools.velociraptor.vql_templates import TemplateError, validate_request

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURES = REPO_ROOT / "tests" / "fixtures" / "velociraptor"

HOST = {"client_id": "C.mock01", "hostname": "WIN11-VICTIM", "os": "windows"}
REQUESTS = [
    ("pslist", {}),
    ("netstat", {}),
    ("process_creation_evtx", {"Channel": "Security", "IdFilter": "4688"}),
]


def _collect(sequence=0):
    return collect_window(
        MockTransport(FIXTURES),
        case_id="WINDOW-TEST-001",
        sequence=sequence,
        source="replay",
        host=HOST,
        time_start_utc="2026-08-12T14:00:00Z",
        time_end_utc="2026-08-12T14:05:00Z",
        examiner_id="purple-op-01",
        requests=REQUESTS,
    )


# -- curated-template contract ----------------------------------------------

def test_unknown_template_rejected():
    with pytest.raises(TemplateError, match="unknown VQL template"):
        validate_request("raw_vql", {})


def test_unknown_parameter_rejected():
    with pytest.raises(TemplateError, match="does not accept parameters"):
        validate_request("pslist", {"Query": "SELECT * FROM pslist()"})


@pytest.mark.parametrize("value", [
    "Security' OR 1=1",
    "} LET x = SELECT * FROM glob(globs='C:/**')",
    "Security\nSELECT",
])
def test_injection_shaped_value_rejected(value):
    with pytest.raises(TemplateError, match="does not match"):
        validate_request("process_creation_evtx", {"Channel": value})


def test_non_string_parameter_rejected():
    with pytest.raises(TemplateError, match="must be a string"):
        validate_request("process_creation_evtx", {"IdFilter": 4688})


# -- normalization -----------------------------------------------------------

def test_normalize_reports_dropped_rows_honestly():
    rows = json.loads((FIXTURES / "Windows.EventLogs.Evtx.json").read_text())
    artifacts, report = normalize_rows("process_creation_evtx", rows)
    # The 1102 fixture row has no EventTime on purpose.
    assert report["dropped_no_timestamp"] == 1
    assert report["artifacts_out"] == len(artifacts) == 2
    assert report["rows_in"] == 3


def test_normalize_is_row_order_independent():
    rows = json.loads((FIXTURES / "Windows.System.Pslist.json").read_text())
    a_fwd, _ = normalize_rows("pslist", rows)
    a_rev, _ = normalize_rows("pslist", list(reversed(rows)))
    assert a_fwd == a_rev


def test_adapter_scores_are_neutral_priors_only():
    """The adapter must not weigh evidence: every artifact carries exactly
    the neutral prior "1/2" (schema compliance so the bridge keeps our
    evidence_type), never a content-derived value."""
    rows = json.loads((FIXTURES / "Windows.System.Pslist.json").read_text())
    artifacts, _ = normalize_rows("pslist", rows)
    assert artifacts, "fixture produced no artifacts"
    for artifact in artifacts:
        assert artifact["raw_score"] == "1/20", (
            "the adapter must not score evidence — that is decision-path "
            "work; 1/20 is the EBS v1 no-signal floor, not an assessment"
        )
        assert artifact["source_tool"] == "velociraptor"
        assert artifact["description"].startswith("velociraptor pslist")


def test_evidence_types_are_caie_taxonomy_keys():
    """Lockstep with BOTH CAIE vocabularies: _DOMAIN_MAP (domain/sub-band
    classification) and EVIDENCE_PROFILES (add_artifact whitelist +
    spoofability). They are different sets — being in one but not the other
    triggers CAIE_INVALID_EVIDENCE_TYPE security alerts at scoring time."""
    from tools.caie import _DOMAIN_MAP, EVIDENCE_PROFILES
    from tools.velociraptor.vql_templates import TEMPLATES
    for template_id, template in TEMPLATES.items():
        evidence_type = template["evidence_type"]
        assert evidence_type in _DOMAIN_MAP, (
            f"template {template_id!r}: {evidence_type!r} not in _DOMAIN_MAP"
        )
        assert evidence_type in EVIDENCE_PROFILES, (
            f"template {template_id!r}: {evidence_type!r} not in "
            f"EVIDENCE_PROFILES (add_artifact would reject it)"
        )


def test_custody_metadata_reaches_forensic_assurance_tier():
    """Live collection must pass CAIE gates G1+G2+G3 and honestly fail G4
    (no write blocker exists for live telemetry) — FORENSIC tier, 3/4."""
    from fractions import Fraction
    from tools.caie import _compute_acquisition_assurance
    rows = json.loads((FIXTURES / "Windows.System.Pslist.json").read_text())
    artifacts, report = normalize_rows("pslist", rows, custody={
        "examiner_id": "purple-op-01",
        "acquisition_timestamp": "2026-08-12T14:05:00Z",
    })
    assert report["custody"] == "present"
    for artifact in artifacts:
        assurance = _compute_acquisition_assurance(artifact["metadata"])
        assert assurance == Fraction(3, 4), (
            f"expected FORENSIC (3/4) for {artifact['artifact_id']}, "
            f"got {assurance}"
        )
        assert artifact["metadata"]["write_blocker_used"] is False


def test_custody_absence_is_reported_not_hidden():
    rows = json.loads((FIXTURES / "Windows.System.Pslist.json").read_text())
    _, report = normalize_rows("pslist", rows, custody=None)
    assert report["custody"].startswith("absent")


# -- window sealing ----------------------------------------------------------

def test_collect_window_end_to_end():
    window, reports = _collect()
    for field in ("window_id", "case_id", "sequence", "source", "host",
                  "time_start_utc", "time_end_utc", "collection", "artifacts",
                  "manifest", "canonicalize_version", "window_hash"):
        assert field in window, field
    assert window["canonicalize_version"] == "2"
    assert verify_window(window)
    assert len(window["manifest"]) == 3  # one fixture file per template
    assert len(reports) == 3
    ids = [a["artifact_id"] for a in window["artifacts"]]
    assert ids == sorted(ids)


def test_window_hash_independent_of_artifact_order():
    window, _ = _collect()
    unsealed = {k: v for k, v in window.items() if k != "window_hash"}
    rebuilt = build_evidence_window(
        case_id=unsealed["case_id"],
        sequence=unsealed["sequence"],
        source=unsealed["source"],
        host=unsealed["host"],
        time_start_utc=unsealed["time_start_utc"],
        time_end_utc=unsealed["time_end_utc"],
        collection=unsealed["collection"],
        artifacts=list(reversed(unsealed["artifacts"])),
        manifest=list(reversed(unsealed["manifest"])),
    )
    assert rebuilt["window_hash"] == window["window_hash"]


def test_verify_window_detects_tampering():
    window, _ = _collect()
    tampered = json.loads(json.dumps(window))
    tampered["artifacts"][0]["metadata"]["row"]["CommandLine"] = "notepad.exe"
    assert not verify_window(tampered)


def test_window_hash_reproducible_across_processes():
    child = REPO_ROOT / "tests" / "_window_child.py"
    digests = []
    for hashseed in ("0", "424242"):
        proc = subprocess.run(
            [sys.executable, str(child)],
            cwd=REPO_ROOT, capture_output=True, text=True, timeout=120,
            env={"PYTHONHASHSEED": hashseed, "PATH": "/usr/bin:/bin"},
        )
        assert proc.returncode == 0, proc.stderr[-2000:]
        digests.append(proc.stdout.strip())
    assert digests[0] == digests[1], (
        "window seal is not reproducible across processes: "
        f"{digests[0][:12]}… vs {digests[1][:12]}…"
    )


# -- core integration --------------------------------------------------------

def test_window_feeds_core_scorer_with_full_taxonomy():
    """End-to-end: a sealed window flows through the real scorer with live
    CAIE, keeping our evidence types (no 'default' degradation) and without
    CAIE schema-validation skips."""
    from tools.velociraptor.adapter import window_to_case
    from vigia_scorer import _vigia_score

    window, _ = _collect()
    result = _vigia_score(window_to_case(window))

    assert result["verdict"] != "ERROR"
    # Regression guard for the no-signal prior semantics: telemetry with no
    # tool-assigned suspicion must never score as malice by construction.
    # (With a midpoint prior this exact window produced MALICE_HIGH.)
    assert result["verdict"] == "NOISE", (
        f"unscored telemetry produced {result['verdict']} — the adapter is "
        f"leaking suspicion into the decision path"
    )
    assert result["caie_fractures_source"] == "live_caie"
    seen_types = {et["evidence_type"] for et in result["effective_trusts"]}
    assert "default" not in seen_types, (
        f"some artifact degraded to the default profile: {seen_types}"
    )
    assert {"memory_process", "network_flow",
            "windows_event_log"} <= seen_types
    domains = set(result["r43_active_domains"])
    assert not any(d.startswith("UNKNOWN") for d in domains), domains
    # Provenance chains (row hash + source-file hash) must clear the EPC
    # degradation floor: full trust, not the 1/10 empty-chain penalty.
    for et in result["effective_trusts"]:
        assert et["effective_trust"] > 0.5, (
            f"{et['artifact_id']} trust {et['effective_trust']} — "
            f"provenance chain not honored"
        )


def test_artifacts_carry_verifiable_provenance_chains():
    window, _ = _collect()
    manifest_hashes = {m["sha256"] for m in window["manifest"]}
    for artifact in window["artifacts"]:
        chain = artifact["provenance_chain"]
        assert len(chain) == 2, artifact["artifact_id"]
        assert all(link.startswith("sha256:") for link in chain)
        # Second link must reference a file sealed in the window manifest.
        assert chain[1][len("sha256:"):] in manifest_hashes


def test_scoring_cannot_mutate_the_sealed_window():
    """The bridge/CAIE mutate artifact internals in place; the sealed window
    must be immune (deep copy at the feed boundary), and our honest custody
    (write_blocker_used=False) must survive scoring instead of being
    replaced by synthesized legacy custody."""
    from tools.velociraptor.adapter import window_to_case
    from vigia_scorer import _vigia_score

    window, _ = _collect()
    case = window_to_case(window)
    _vigia_score(case)

    assert verify_window(window), (
        "scoring mutated the sealed window through a shared reference"
    )
    for artifact in case["artifacts"]:
        md = artifact["metadata"]
        assert md["acquisition_tool"] == "velociraptor", (
            "bridge replaced live custody with synthesized legacy custody"
        )
        assert md["write_blocker_used"] is False, (
            "a write blocker was fabricated for live telemetry"
        )


def test_window_to_case_refuses_tampered_window():
    from tools.velociraptor.adapter import window_to_case
    window, _ = _collect()
    tampered = json.loads(json.dumps(window))
    tampered["artifacts"][0]["raw_score"] = "9/10"
    with pytest.raises(AdapterError, match="hash does not verify"):
        window_to_case(tampered)


# -- boundary validation -----------------------------------------------------

def test_boundary_rejects_bad_inputs():
    good = dict(case_id="OK-1", sequence=0, source="replay", host=HOST,
                time_start_utc="2026-08-12T14:00:00Z",
                time_end_utc="2026-08-12T14:05:00Z",
                collection={}, artifacts=[], manifest=[])
    with pytest.raises(AdapterError):
        build_evidence_window(**{**good, "case_id": "../evil"})
    with pytest.raises(AdapterError):
        build_evidence_window(**{**good, "sequence": True})
    with pytest.raises(AdapterError):
        build_evidence_window(**{**good, "sequence": -1})
    with pytest.raises(AdapterError):
        build_evidence_window(**{**good, "source": "live_feed"})
    with pytest.raises(AdapterError):
        build_evidence_window(**{**good, "host": {"client_id": "C.1"}})
