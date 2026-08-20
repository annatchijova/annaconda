"""Sigma synthesis is a deterministic projection of a sealed MALICE verdict.

No model authors the detection: the rule is a template over the sealed window's
fields and the sealed verdict's techniques. Only stable, identifying fields become
selectors; volatile ones are dropped; a non-MALICE verdict yields nothing; and
re-synthesizing the same window is byte-identical.
"""
import pytest

from agent import catalog
from agent.registry import REGISTRY_VERSION, require_approved
from tools.velociraptor.adapter import build_evidence_window
from verdict.sigma_export import to_yaml, window_to_sigma_rules

WINDOW = build_evidence_window(
    case_id="SIG-01", sequence=0, source="velociraptor",
    host={"client_id": "C.1", "hostname": "WIN11"},
    time_start_utc="2026-08-12T14:10:00Z", time_end_utc="2026-08-12T14:11:00Z",
    collection={}, manifest=[],
    artifacts=[
        {"artifact_id": "a-evt", "evidence_type": "windows_event_log",
         "raw_score": "1/20", "timestamp": "2026-08-12T14:10:30Z",
         "metadata": {"row": {
             "NewProcessName": "C:\\Users\\v\\evil.exe",
             "ParentProcessName": "C:\\Windows\\System32\\cmd.exe",
             "SubjectUserName": "victim", "EventID": 4688,
             "EventTime": "2026-08-12T14:10:30Z", "Computer": "WIN11"}}},
        {"artifact_id": "a-net", "evidence_type": "network_flow",
         "raw_score": "1/20", "timestamp": "2026-08-12T14:10:40Z",
         "metadata": {"row": {
             "Raddr.IP": "198.51.100.7", "Raddr.Port": 4444,
             "Laddr.IP": "10.0.0.5", "Name": "evil.exe",
             "Timestamp": "2026-08-12T14:10:40Z", "Pid": 1337,
             "Status": "ESTABLISHED"}}},
    ])

MALICE = {"state": "MALICE_HIGH", "mitre_techniques": ["T1055.012", "T1071.001"]}


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


def test_malice_window_yields_one_rule_per_evidence_type():
    rules = window_to_sigma_rules(WINDOW, verdict=MALICE)
    cats = {r["logsource"]["category"] for r in rules}
    assert cats == {"process_creation", "network_connection"}
    assert not _has_float(rules)


def test_only_stable_identifying_fields_become_selectors():
    rules = {r["logsource"]["category"]: r for r in window_to_sigma_rules(WINDOW, verdict=MALICE)}
    proc = rules["process_creation"]["detection"]["selection"]
    assert proc["Image"] == "C:\\Users\\v\\evil.exe"
    assert proc["ParentImage"] == "C:\\Windows\\System32\\cmd.exe"
    assert proc["User"] == "victim"
    assert proc["EventID"] == "4688"          # coerced to string, not a raw int
    assert "EventTime" not in proc and "Computer" not in proc  # volatile dropped
    net = rules["network_connection"]["detection"]["selection"]
    assert net["DestinationIp"] == "198.51.100.7"
    assert net["Image"] == "evil.exe"
    # ports, pids, timestamps and source addr are not stable IoCs -> dropped
    assert "DestinationPort" not in net and "SourcePort" not in net
    assert "Pid" not in net and "Status" not in net and "Timestamp" not in net


def test_draft_posture_is_explicit():
    rule = window_to_sigma_rules(WINDOW, verdict=MALICE)[0]
    assert rule["status"] == "experimental"
    assert "review" in rule["author"].lower()
    assert any("DRAFT" in fp for fp in rule["falsepositives"])
    assert rule["level"] == "high"
    assert "attack.t1055.012" in rule["tags"] and "attack.t1071.001" in rule["tags"]


def test_non_malice_yields_no_rule():
    assert window_to_sigma_rules(WINDOW, verdict={"state": "BENIGN_HIGH"}) == []
    assert window_to_sigma_rules(WINDOW, verdict={"state": "ABSTAIN_INSUFFICIENT"}) == []
    assert window_to_sigma_rules(WINDOW, verdict=None) == []


def test_synthesis_is_deterministic():
    a = window_to_sigma_rules(WINDOW, verdict=MALICE)
    b = window_to_sigma_rules(WINDOW, verdict=MALICE)
    assert a == b
    assert [to_yaml(r) for r in a] == [to_yaml(r) for r in b]
    # ids are uuid5 over the seal, so stable across calls
    assert a[0]["id"] == b[0]["id"]


def test_yaml_is_valid_and_ordered():
    rule = window_to_sigma_rules(WINDOW, verdict=MALICE)[0]
    text = to_yaml(rule)
    assert text.startswith("title:")
    for key in ("id:", "status:", "logsource:", "detection:", "condition:", "level:"):
        assert key in text
    yaml = pytest.importorskip("yaml", reason="PyYAML not installed; skip parse check")
    parsed = yaml.safe_load(text)
    assert parsed["detection"]["condition"] == "selection"
    assert parsed["logsource"]["product"] == "windows"
    assert parsed["status"] == "experimental"


def test_specialist_is_approved_and_catalog_gated():
    assert len(require_approved("detection-engineer", REGISTRY_VERSION,
                                ["synthesize_detection"])) == 64
    assert catalog.catalog_matches_registry() == []
    pub = catalog.authorize("detection-engineer", department="forensics",
                            data_classes=["sealed_verdicts", "endpoint_telemetry"])
    assert pub["name"] == "detection-engineer"
    with pytest.raises(catalog.NotPublishedError):
        catalog.authorize("detection-engineer", department="training",
                          data_classes=["sealed_verdicts"])
