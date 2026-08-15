"""The specialized fleet: strictly disjoint tool contracts, verified.

Separation of responsibilities is the thing a fleet is judged on, so it is a
test, not a claim: no tool belongs to two specialists, only the correlator can
reach the sealed core, and the dispatcher orchestrates a real end-to-end
investigation whose verdict the deterministic engine (not any agent) decides.
"""

from pathlib import Path

from agent.fleet import FLEET, contract_names, dispatch_investigation
from agent.tools import PurpleTeamSession
from tools.velociraptor.adapter import MockTransport

REPO = Path(__file__).resolve().parent.parent
ATTACK = REPO / "tests" / "fixtures" / "attack"
HOST = {"client_id": "C.1", "hostname": "WIN11-VICTIM", "os": "windows"}


def _session(fixtures=ATTACK, out=None, time_base="2026-08-12T14:10:00Z"):
    import tempfile
    return PurpleTeamSession(
        MockTransport(fixtures), case_id="FLEET-T", host=HOST, examiner_id="op",
        out_dir=out or tempfile.mkdtemp(), source="replay", time_base=time_base)


def test_fleet_tool_contracts_are_pairwise_disjoint():
    contracts = {k: set(v) for k, v in contract_names(_session()).items()}
    names = list(contracts)
    for i in range(len(names)):
        for j in range(i + 1, len(names)):
            shared = contracts[names[i]] & contracts[names[j]]
            assert not shared, (
                f"{names[i]} and {names[j]} share tools {shared} — the fleet's "
                f"tool contracts must be disjoint")
    # every role owns at least one tool
    assert all(contracts.values())


def test_only_the_correlator_reaches_the_sealed_core():
    contracts = contract_names(_session())
    # adjudication (the only path to the sealed engine) belongs to the correlator
    # alone; the hunters and dispatcher cannot adjudicate.
    for role in ("dispatcher", "windows-hunter", "persistence-agent"):
        assert not any("adjudicate" in t for t in contracts[role]), role
    assert any("adjudicate" in t for t in contracts["correlator"])


def test_dispatch_runs_the_fleet_end_to_end_and_seals():
    report = dispatch_investigation(_session())
    # the correlator sealed a MALICE verdict from the windows hunter's window
    assert any(v["verdict_state"].startswith("MALICE") for v in report["verdicts"])
    assert report["worst_verdict"].startswith("MALICE")
    assert report["chain"]["chain_ok"]
    # every step is attributed to a real fleet role, and all four participated
    roles = {e["role"] for e in report["fleet_log"]}
    assert roles == set(FLEET), roles


def test_fleet_windows_are_two_distinct_sealed_collections():
    report = dispatch_investigation(_session())
    windows = [e["window_id"] for e in report["fleet_log"]
               if e.get("action") == "collect" and "window_id" in e]
    assert len(windows) == 2 and windows[0] != windows[1]
