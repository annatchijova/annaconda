"""The enterprise catalog: publication, least privilege, and residency.

An enterprise fleet is not a set of agents that happen to run; it is a set of
agents somebody published, to somebody, for some data. These tests hold the
catalog to that: every published agent names a tool contract the sealed
registry approved, departments see only what they may task, and clearance and
residency are refusals rather than documentation.
"""

import pytest

from agent import catalog
from agent.registry import APPROVED, REGISTRY_VERSION, manifest, manifest_hash


def test_every_catalog_entry_names_an_approved_tool_contract():
    assert catalog.catalog_matches_registry() == []


def test_a_catalog_entry_carries_the_agents_manifest_hash():
    pub = catalog.publication("correlator")
    expected = manifest_hash(manifest("correlator", REGISTRY_VERSION, pub["tools"]))
    assert pub["manifest_hash"] == expected
    assert expected in APPROVED


def test_changing_an_agents_tools_breaks_its_catalog_identity():
    """One identity, checked twice: the catalog names a manifest hash, so an
    agent whose tools drifted is no longer the agent that was published."""
    drifted = manifest_hash(manifest("correlator", REGISTRY_VERSION,
                                     ["adjudicate_window", "verify_custody",
                                      "delete_the_chain"]))
    assert drifted != catalog.publication("correlator")["manifest_hash"]
    assert drifted not in APPROVED


def test_each_department_sees_only_what_it_may_task():
    soc = {p["name"] for p in catalog.catalog("soc")}
    forensics = {p["name"] for p in catalog.catalog("forensics")}
    training = {p["name"] for p in catalog.catalog("training")}
    assert "correlator" not in soc and "correlator" in forensics
    assert training == {"vigia_mentor"}
    assert soc < {p["name"] for p in catalog.catalog()}


def test_the_full_catalog_is_the_union_of_the_departments():
    everything = {p["name"] for p in catalog.catalog()}
    union = set()
    for dept in catalog.DEPARTMENTS:
        union |= {p["name"] for p in catalog.catalog(dept)}
    assert union == everything


def test_an_agent_is_refused_a_data_class_it_is_not_cleared_for():
    with pytest.raises(catalog.ClearanceError):
        catalog.authorize("windows-hunter", department="soc",
                          data_classes=["sealed_verdicts"])
    catalog.authorize("windows-hunter", department="soc",
                      data_classes=["endpoint_telemetry"])


def test_an_unpublished_department_cannot_task_an_agent():
    with pytest.raises(catalog.NotPublishedError):
        catalog.authorize("correlator", department="soc",
                          data_classes=["sealed_verdicts"])


def test_an_unknown_department_or_agent_is_refused():
    with pytest.raises(catalog.NotPublishedError):
        catalog.authorize("correlator", department="marketing")
    with pytest.raises(catalog.NotPublishedError):
        catalog.authorize("shadow-agent", department="forensics")


def test_an_unknown_data_class_is_refused_rather_than_ignored():
    with pytest.raises(catalog.ClearanceError):
        catalog.authorize("correlator", department="forensics",
                          data_classes=["whatever_i_want"])


def test_evidence_may_not_be_processed_outside_the_home_region():
    with pytest.raises(catalog.ClearanceError):
        catalog.authorize("correlator", department="forensics",
                          data_classes=["sealed_verdicts"], region="eu-west1")


def test_only_the_core_reaching_agents_are_marked_as_such():
    reaching = {p["name"] for p in catalog.catalog() if p["reaches_sealed_core"]}
    assert reaching == {"correlator", "vigia_purple_team"}


def test_the_commander_reaches_the_core_only_by_delegation():
    pub = catalog.publication("fleet-commander")
    assert pub["reaches_sealed_core"] is False
    assert "correlator" in pub["delegates_to"]
    assert pub["data_classes"] == ["case_memory"]
