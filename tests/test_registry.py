"""Sealed agent registry: the runtime refuses to load an unapproved agent."""

import tempfile
from pathlib import Path

import pytest

from agent.registry import (
    UnapprovedAgentError, approved_registry, manifest, manifest_hash,
    require_approved,
)

REPO = Path(__file__).resolve().parent.parent


def _session():
    from agent.tools import PurpleTeamSession
    from tools.velociraptor.adapter import MockTransport
    return PurpleTeamSession(
        MockTransport(REPO / "tests" / "fixtures" / "attack"), case_id="R",
        host={"client_id": "C.1", "hostname": "H", "os": "windows"},
        examiner_id="op", out_dir=tempfile.mkdtemp(), source="replay",
        time_base="2026-08-12T14:10:00Z")


def test_manifest_hash_is_order_independent_and_sealed():
    # Tools are sorted, so hashing is order-independent — same sealing encoder.
    assert manifest_hash(manifest("x", "1.0.0", ["b", "a"])) == \
           manifest_hash(manifest("x", "1.0.0", ["a", "b"]))
    assert len(manifest_hash(manifest("x", "1.0.0", ["a"]))) == 64


def test_every_published_agent_is_approved():
    for entry in approved_registry():
        assert require_approved(entry["name"], entry["version"], entry["tools"])


def test_an_agent_with_an_extra_tool_is_refused():
    # An out-of-band tool added to a specialist changes its identity -> refused.
    with pytest.raises(UnapprovedAgentError, match="not in the sealed registry"):
        require_approved("windows-hunter", "1.0.0",
                         ["survey_running_state", "exfiltrate_everything"])


def test_a_wrong_version_is_refused():
    with pytest.raises(UnapprovedAgentError):
        require_approved("windows-hunter", "9.9.9", ["survey_running_state"])


def test_building_the_real_specialists_passes_the_gate():
    from agent.fleet import FLEET, build_specialist
    session = _session()
    for role in FLEET:
        build_specialist(role, session)  # raises UnapprovedAgentError if not approved


def test_a_specialist_with_a_tampered_contract_is_refused_at_build():
    from agent import fleet
    session = _session()

    def rogue_tools(_s):
        def survey_running_state(reason: str) -> dict:  # same name...
            return {}
        def exfiltrate(reason: str) -> dict:            # ...plus an extra tool
            return {}
        return [survey_running_state, exfiltrate]

    original = fleet.FLEET["windows-hunter"]["tools"]
    fleet.FLEET["windows-hunter"]["tools"] = rogue_tools
    try:
        with pytest.raises(UnapprovedAgentError):
            fleet.build_specialist("windows-hunter", session)
    finally:
        fleet.FLEET["windows-hunter"]["tools"] = original
