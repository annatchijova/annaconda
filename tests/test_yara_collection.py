"""YARA collection: Velociraptor detects, annaconda seals, nothing decides.

Malware detection enters annaconda the same way every other signal does --
through a curated template, normalized, frozen into the sealed window -- and
stops there. Two properties are pinned here because both are load-bearing and
neither is self-evident from reading the code:

1. rule TEXT never reaches the evidence source: a caller names a committed
   ruleset, and nothing else is accepted;
2. a match changes NOTHING about the verdict. The adapter gives every
   collected artifact the no-signal floor, so a sealed window with a YARA hit
   scores exactly like the same window without it.

(2) is not a limitation to be fixed quietly later. Whether a signature match
should weigh on a sealed verdict -- when the adversary chooses the bytes being
matched -- is an open decision. Until it is made deliberately, this test is
what stops it from being made by accident.
"""

import json

import pytest

from tools.velociraptor.adapter import (
    MockTransport, build_evidence_window, collect_window, normalize_rows,
    verify_window, window_to_case,
)
from tools.velociraptor.vql_templates import (
    TemplateError, resolve_ruleset, validate_request,
)
from vigia_scorer import _vigia_score

CUSTODY = {"examiner_id": "anna", "acquisition_timestamp": "2026-08-12T15:00:00Z"}

CLEAN_PROCESSES = [
    {"Pid": 612, "Name": "svchost.exe", "Exe": "C:\\W\\svchost.exe",
     "CommandLine": "svchost -k netsvcs", "Username": "SYSTEM",
     "CreateTime": "2026-08-12T08:00:05Z"},
    {"Pid": 4212, "Name": "notepad.exe", "Exe": "C:\\W\\notepad.exe",
     "CommandLine": "notepad", "Username": "LAB\\jdoe",
     "CreateTime": "2026-08-12T14:00:00Z"},
]

YARA_HITS = [
    {"Rule": "credential_dumper_strings", "Tags": "T1003.001",
     "ProcessName": "notepad.exe", "Pid": 4212,
     "ScanTime": "2026-08-12T14:59:00Z"},
]


def _window(artifacts):
    return build_evidence_window(
        case_id="YARA-T", sequence=0, source="velociraptor",
        host={"client_id": "C.x", "hostname": "box", "os": "windows"},
        time_start_utc="2026-08-12T08:00:00Z", time_end_utc="2026-08-12T15:00:00Z",
        collection={"hunt_ids": [], "flow_ids": [], "vql_template_ids": []},
        artifacts=artifacts, manifest=[])


def _artifacts(*pairs):
    out = []
    for template_id, rows in pairs:
        normalized, _ = normalize_rows(template_id, rows, custody=CUSTODY)
        out += normalized
    return out


# --------------------------------------------------------------------------
# Collection
# --------------------------------------------------------------------------

def test_a_yara_hit_is_collected_sealed_and_verifiable():
    artifacts = _artifacts(("yara_process", YARA_HITS))
    assert len(artifacts) == 1
    hit = artifacts[0]
    assert hit["evidence_type"] == "malware_static_analysis"
    assert "credential_dumper_strings" in hit["description"]
    # The pid links the hit to the process it was found in, the same way the
    # temporal rule links a connection to its process.
    assert hit["metadata"]["pid"] == 4212
    assert verify_window(_window(artifacts))


def test_rows_without_a_scan_time_are_dropped_and_reported():
    rows = YARA_HITS + [{"Rule": "no_time", "Pid": 1}]
    artifacts, report = normalize_rows("yara_process", rows, custody=CUSTODY)
    assert len(artifacts) == 1
    assert report["dropped_no_timestamp"] == 1, (
        "a hit with no scan time must be reported as dropped, never counted "
        "as a scan that found nothing")


def test_the_templates_are_reachable_through_the_curated_registry():
    for template_id in ("yara_process", "yara_file"):
        assert validate_request(template_id, {}) == {}
    with pytest.raises(TemplateError):
        validate_request("yara_freeform", {})


# --------------------------------------------------------------------------
# Rules are committed, never supplied
# --------------------------------------------------------------------------

def test_rule_text_is_never_accepted_as_a_parameter():
    rule_text = 'rule everything { condition: true }'
    with pytest.raises(TemplateError):
        validate_request("yara_process", {"RuleSet": rule_text})
    with pytest.raises(TemplateError):
        resolve_ruleset(rule_text)


def test_a_ruleset_outside_the_committed_directory_is_refused():
    for name in ("../../etc/passwd", "..\\..\\secrets", "/etc/passwd"):
        with pytest.raises(TemplateError):
            resolve_ruleset(name)


def test_a_missing_ruleset_fails_loud_rather_than_scanning_with_no_rules():
    with pytest.raises(TemplateError, match="not committed"):
        resolve_ruleset("ruleset_that_does_not_exist")


def test_the_committed_baseline_resolves():
    path = resolve_ruleset("purple_team_baseline")
    assert path.is_file()
    text = path.read_text(encoding="utf-8")
    assert "annaconda_purple_team_marker" in text


def test_the_selftest_marker_matches_utf16_as_well_as_ascii():
    """The marker exists to prove the collection path works on a real host.

    Windows keeps strings in memory as UTF-16 and Windows PowerShell 5.1
    writes UTF-16LE files by default, so an ascii-only marker misses the two
    most likely ways somebody produces the test data -- and the miss looks
    like a broken pipeline rather than a rule that did not match.
    """
    text = resolve_ruleset("purple_team_baseline").read_text(encoding="utf-8")
    marker_line = next(line for line in text.splitlines()
                       if "$marker" in line and "=" in line)
    assert "ascii" in marker_line and "wide" in marker_line, marker_line


# --------------------------------------------------------------------------
# The load-bearing one: collection does not decide
# --------------------------------------------------------------------------

def test_a_yara_hit_does_not_move_the_verdict():
    """The same clean host, scored with and without a YARA match on it.

    If this ever fails, a signature match has acquired verdict weight. That
    may well be desirable -- but it must be a decision someone made on
    purpose, with the adversary-controls-the-bytes problem answered, not a
    default that arrived with a template.
    """
    without = _vigia_score(window_to_case(_window(
        _artifacts(("pslist", CLEAN_PROCESSES)))))
    with_hit = _vigia_score(window_to_case(_window(
        _artifacts(("pslist", CLEAN_PROCESSES), ("yara_process", YARA_HITS)))))

    assert without["verdict"] == with_hit["verdict"], (
        f"a YARA hit moved the verdict {without['verdict']} -> "
        f"{with_hit['verdict']}")
    assert (without["quadripartite_state"]["verdict_state"]
            == with_hit["quadripartite_state"]["verdict_state"])


def test_the_hit_is_nonetheless_present_in_the_sealed_record():
    """Not deciding is not the same as not recording."""
    window = _window(_artifacts(("pslist", CLEAN_PROCESSES),
                                ("yara_process", YARA_HITS)))
    hits = [a for a in window["artifacts"]
            if a["evidence_type"] == "malware_static_analysis"]
    assert len(hits) == 1, "the match was collected but not sealed"
    assert window["window_hash"], "the hit must be covered by the seal"


def test_collection_through_a_transport_end_to_end(tmp_path):
    (tmp_path / "Windows.Detection.Yara.Process.json").write_text(
        json.dumps(YARA_HITS), encoding="utf-8")
    window, reports = collect_window(
        MockTransport(tmp_path), case_id="YARA-E2E", sequence=0, source="replay",
        host={"client_id": "C.x", "hostname": "box", "os": "windows"},
        time_start_utc="2026-08-12T08:00:00Z", time_end_utc="2026-08-12T15:00:00Z",
        examiner_id="anna", requests=[("yara_process", {})])
    assert verify_window(window)
    assert reports[0]["artifacts_out"] == 1
    assert window["collection"]["vql_template_ids"] == ["yara_process"]
