"""The unattended path through the service, end to end.

What a judge (or a 3am cron) actually hits: create a case, wake the fleet, and
find that the case moved on its own — a sealed verdict appended, a human
escalated to, a next cycle scheduled, and a chain-verified memory of why.

These run with no model reachable, so the commander's decisions come from the
deterministic fallback planner. The service path, the persistence, the catalog
gate and the sealed chain are the same either way.
"""

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from service.app import app  # noqa: E402


@pytest.fixture(autouse=True)
def _fresh_rate_limit():
    """The rate limiter is a per-process sliding window shared by every cycle
    request, so a suite that runs more than a few of them throttles itself.
    Cleared per test; the limiter's own behaviour is asserted separately."""
    from service.app import _RATE_HITS
    _RATE_HITS.clear()
    yield


@pytest.fixture()
def client():
    with TestClient(app) as c:
        yield c


def test_the_cycle_endpoint_is_rate_limited(client):
    """An agentic cycle calls Gemini, so a public demo URL must not be a way to
    burn the quota."""
    from service.app import _RATE_HITS, _RATE_MAX
    _new_case(client, "SVC-RATE")
    codes = [client.post("/cases/SVC-RATE/cycle", json={}).status_code
             for _ in range(_RATE_MAX + 2)]
    assert 429 in codes, codes
    _RATE_HITS.clear()


def _new_case(client, case_id, scenario="attack"):
    r = client.post("/cases", json={"case_id": case_id, "examiner_id": "perito-01",
                                    "hostname": "WIN11-AUTO", "scenario": scenario})
    assert r.status_code == 200, r.text
    return r.json()


def test_a_swept_case_advances_with_no_human_in_the_loop(client):
    _new_case(client, "SVC-AUTO-1")
    before = client.get("/cases/SVC-AUTO-1").json()["case"]
    assert before["status"] == "open" and not before["entries"]

    swept = client.post("/tasks/sweep", json={}).json()
    worked = {c["case_id"]: c for c in swept["cases"]}
    assert "SVC-AUTO-1" in worked, swept

    after = client.get("/cases/SVC-AUTO-1").json()["case"]
    assert after["status"] == "malice"
    assert after["entries"], "the fleet sealed nothing"
    assert worked["SVC-AUTO-1"]["escalated"] is True
    assert worked["SVC-AUTO-1"]["memory_ok"] is True


def test_the_second_sweep_leaves_a_case_the_fleet_scheduled_for_later(client):
    _new_case(client, "SVC-AUTO-2")
    client.post("/tasks/sweep", json={})
    second = client.post("/tasks/sweep", json={}).json()
    not_due = {c["case_id"]: c for c in second["not_due"]}
    assert "SVC-AUTO-2" in not_due
    assert not_due["SVC-AUTO-2"]["reason"] == "not due"
    assert not_due["SVC-AUTO-2"]["next_due_utc"]


def test_the_mission_endpoint_shows_the_reasoning_and_verifies_its_chain(client):
    _new_case(client, "SVC-AUTO-3")
    client.post("/cases/SVC-AUTO-3/cycle", json={}).raise_for_status()
    mission = client.get("/cases/SVC-AUTO-3/mission").json()
    assert mission["verification"]["memory_ok"]
    assert mission["journal"], "the cycle recorded nothing"
    assert mission["escalation"]["what_to_check"]
    assert mission["next_action"]["due_utc"]
    assert mission["tried_hunts"]


def test_memory_persists_between_cycles_and_is_not_repeated(client):
    _new_case(client, "SVC-AUTO-4")
    client.post("/cases/SVC-AUTO-4/cycle", json={})
    client.post("/cases/SVC-AUTO-4/cycle", json={})
    mission = client.get("/cases/SVC-AUTO-4/mission").json()
    tried = [t["hunts"] for t in mission["tried_hunts"]]
    assert len(tried) == 2 and tried[0] != tried[1]
    assert mission["brief"]["cycles_so_far"] == 2
    assert mission["verification"]["memory_ok"]


def test_a_cycle_run_as_the_soc_is_refused_the_adjudication(client):
    """The compliance gate, over HTTP: the SOC may collect but not adjudicate.
    The cycle completes, records the refusal, and seals nothing."""
    _new_case(client, "SVC-AUTO-5")
    body = client.post("/cases/SVC-AUTO-5/cycle",
                       json={"department": "soc"}).json()
    log = body["cycle"]["fleet_log"]
    assert any(e["action"] == "refused_by_catalog" and e["role"] == "correlator"
               for e in log), log
    assert any(e["action"] == "collect" for e in log)
    assert not body["cycle"]["verdicts"]
    assert client.get("/cases/SVC-AUTO-5").json()["case"]["status"] == "open"


def test_the_queue_shows_what_the_fleet_is_doing(client):
    _new_case(client, "SVC-AUTO-6")
    client.post("/cases/SVC-AUTO-6/cycle", json={})
    rows = {c["case_id"]: c for c in client.get("/cases").json()["cases"]}
    autonomy_row = rows["SVC-AUTO-6"]["autonomy"]
    assert autonomy_row["cycles"] == 1
    assert autonomy_row["escalated"] is True
    assert autonomy_row["next_due_utc"]


def test_demo_cases_are_not_moved_by_the_sweep(client):
    client.post("/demo/seed")
    before = client.get("/cases/DEMO-MALICE").json()["case"]
    client.post("/tasks/sweep", json={})
    after = client.get("/cases/DEMO-MALICE").json()["case"]
    assert after["entries"] == before["entries"]
    assert after["mission"]["cycles"] == before["mission"]["cycles"]


def test_the_catalog_endpoint_publishes_per_department(client):
    everything = client.get("/catalog").json()
    assert everything["registry_agreement"] == "ok"
    soc = {a["name"] for a in client.get("/catalog?department=soc").json()["agents"]}
    assert "correlator" not in soc and "fleet-commander" in soc
    assert client.get("/catalog?department=marketing").status_code == 400


def test_health_reports_the_fleets_unattended_work(client):
    _new_case(client, "SVC-AUTO-7")
    client.post("/tasks/sweep", json={})
    health = client.get("/health").json()
    assert health["autonomous_sweeps"] >= 1
    assert health["autonomous_cycles"] >= 1
    assert health["commander_planner"] in ("gemini", "deterministic-fallback")
    assert health["llm_in_decision_path"] is False


def test_a_cycle_on_a_missing_case_is_a_404(client):
    assert client.post("/cases/NOPE/cycle", json={}).status_code == 404
    assert client.get("/cases/NOPE/mission").status_code == 404


def test_a_human_can_take_up_an_escalation_over_http(client):
    """The other half of escalation: it stops being shown because somebody
    handled it, never because something newer arrived."""
    _new_case(client, "SVC-ACK")
    client.post("/cases/SVC-ACK/cycle", json={})
    mission = client.get("/cases/SVC-ACK/mission").json()
    assert mission["escalations"], "the cycle raised nothing to acknowledge"
    assert "MALICE" in mission["escalation"]["why"]

    r = client.post("/cases/SVC-ACK/escalations/0/acknowledge",
                    json={"note": "host isolated, ticket INC-4412",
                          "examiner_id": "perito-01"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["acknowledged"]["acknowledged_by"] == "perito-01"

    after = client.get("/cases/SVC-ACK/mission").json()
    assert after["escalations"][0]["acknowledged"] is True
    assert after["verification"]["memory_ok"]


def test_acknowledging_an_escalation_that_does_not_exist_is_a_404(client):
    _new_case(client, "SVC-ACK2")
    client.post("/cases/SVC-ACK2/cycle", json={})
    assert client.post("/cases/SVC-ACK2/escalations/9/acknowledge",
                       json={"note": "n", "examiner_id": "p"}).status_code == 404
    assert client.post("/cases/NOPE/escalations/0/acknowledge",
                       json={"note": "n", "examiner_id": "p"}).status_code == 404


def _force_due(case_id):
    from service.app import _CASE_STORE
    case = _CASE_STORE.get_case(case_id)
    case["mission"]["next_action"]["due_utc"] = "2020-01-01T00:00:00Z"
    _CASE_STORE.save_mission(case_id, case["mission"])


def test_a_sweep_caps_how_many_cycles_it_runs(client):
    """Every cycle is a Gemini turn and case creation is unauthenticated on the
    public demo, so without a cap the cost of a wake-up is set by whoever
    created the most cases."""
    from service.app import SWEEP_MAX_CYCLES, _RATE_HITS
    for i in range(SWEEP_MAX_CYCLES + 5):
        _RATE_HITS.clear()
        _new_case(client, f"CAP-{i}", scenario="benign")
    body = client.post("/tasks/sweep", json={}).json()
    assert body["worked"] == SWEEP_MAX_CYCLES
    assert body["deferred"] >= 5
    assert body["cycle_cap"] == SWEEP_MAX_CYCLES


def test_deferred_cases_are_reported_rather_than_silently_dropped(client):
    """A sweep that stopped part way without saying so would read as 'every
    case is up to date'."""
    from service.app import SWEEP_MAX_CYCLES, _RATE_HITS
    for i in range(SWEEP_MAX_CYCLES + 3):
        _RATE_HITS.clear()
        _new_case(client, f"DEFER-{i}", scenario="benign")
    body = client.post("/tasks/sweep", json={}).json()
    assert body["deferred_cases"], body
    assert client.get("/health").json()["cases_deferred_last_sweep"] >= 3


def test_a_flood_of_new_cases_cannot_starve_a_compromised_host(client):
    """The cap bounds cost — and creates a queue, which can be gamed. Without
    priority ordering a stranger's fifty new cases would push the one host
    under an adjudicated malicious verdict past the cap on every sweep."""
    from service.app import SWEEP_MAX_CYCLES, _RATE_HITS
    _new_case(client, "AAA-VICTIM", scenario="attack")
    _RATE_HITS.clear()
    client.post("/cases/AAA-VICTIM/cycle", json={})
    assert client.get("/cases/AAA-VICTIM").json()["case"]["status"] == "malice"

    for i in range(SWEEP_MAX_CYCLES * 3):
        _RATE_HITS.clear()
        _new_case(client, f"ZZZ-FLOOD-{i}", scenario="benign")
    _force_due("AAA-VICTIM")

    body = client.post("/tasks/sweep", json={}).json()
    worked = [w["case_id"] for w in body["cases"]]
    assert worked[0] == "AAA-VICTIM", worked[:3]
    assert body["deferred"] > 0


def test_creating_a_case_is_rate_limited(client):
    """A created case is due immediately, so one POST here buys one Gemini turn
    on the next sweep."""
    from service.app import _RATE_HITS, _RATE_MAX
    _RATE_HITS.clear()
    codes = [client.post("/cases", json={"case_id": f"RL-{i}",
                                         "examiner_id": "x"}).status_code
             for i in range(_RATE_MAX + 2)]
    assert 429 in codes, codes
    _RATE_HITS.clear()


def test_the_injection_demo_surfaces_the_planted_line_and_a_sealed_malice(client):
    """The opening beat of the demo: point at what the attacker planted, next to
    the sealed MALICE verdict. The planted-line extractor once looked for
    "ignore instructions" while the fixture plants a forged EDR annotation, so
    the panel showed nothing — pinned here so it can't go stale silently.
    Model-independent: the seal and the planted line do not need a live model."""
    body = client.post("/injection-demo").json()
    planted = body.get("planted_instruction") or ""
    assert planted, "the planted-instruction line came back empty"
    assert "CLASSIFICATION" in planted.upper() or "EDR-ANNOTATION" in planted.upper()
    assert body["sealed_verdict"]["state"] == "MALICE_HIGH"
    assert body.get("invariant")
