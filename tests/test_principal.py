"""Who is asking, and whether we actually know.

The catalog gate was only ever as good as the identity in front of it: a
department arriving in a request body is a claim, not a fact. These tests hold
the distinction — an asserted department is allowed by default and recorded as
asserted, a verified identity wins over anything the request claims, and a
deployment can require verification with one env var.
"""

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from agent import mission as mem, principal as pr  # noqa: E402
from service.app import app  # noqa: E402


@pytest.fixture()
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture(autouse=True)
def _fresh_rate_limit():
    from service.app import _RATE_HITS
    _RATE_HITS.clear()
    yield


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    monkeypatch.delenv(pr.REQUIRE_AUTH_ENV, raising=False)
    monkeypatch.delenv(pr.ROSTER_ENV, raising=False)


def test_a_claimed_department_is_recorded_as_asserted():
    p = pr.resolve(claimed_department="forensics")
    assert p["department"] == "forensics"
    assert p["authenticated"] is False
    assert "no verified identity" in p["how"]


def test_an_unverifiable_token_never_upgrades_the_principal():
    """A token we could not check is treated exactly like no token at all."""
    p = pr.resolve(authorization_header="Bearer not-a-real-token",
                   claimed_department="soc")
    assert p["authenticated"] is False
    assert p["department"] == "soc"


def test_a_verified_identity_wins_over_what_the_request_claims(monkeypatch):
    """A caller cannot present a SOC identity and ask to run as forensics."""
    monkeypatch.setenv(pr.ROSTER_ENV, "analyst@example.com:soc")
    monkeypatch.setattr(pr, "verify_identity_token",
                        lambda token: "analyst@example.com")
    p = pr.resolve(authorization_header="Bearer x",
                   claimed_department="forensics")
    assert p["department"] == "soc"
    assert p["authenticated"] is True
    assert p["identity"] == "analyst@example.com"


def test_a_verified_identity_that_is_not_rostered_gets_nothing(monkeypatch):
    """Not an anonymous caller, and not granted what it asked for either."""
    monkeypatch.setenv(pr.ROSTER_ENV, "someone@example.com:soc")
    monkeypatch.setattr(pr, "verify_identity_token",
                        lambda token: "stranger@example.com")
    p = pr.resolve(authorization_header="Bearer x", claimed_department="forensics")
    assert p["department"] is None
    assert p["authenticated"] is False
    assert p["identity"] == "stranger@example.com"
    with pytest.raises(pr.UnauthenticatedPrincipalError):
        pr.enforce(p)


def test_a_roster_entry_naming_an_unknown_department_is_ignored(monkeypatch):
    monkeypatch.setenv(pr.ROSTER_ENV, "a@example.com:marketing")
    monkeypatch.setattr(pr, "verify_identity_token", lambda token: "a@example.com")
    assert pr.resolve(authorization_header="Bearer x")["department"] is None


def test_the_production_posture_refuses_an_asserted_principal(monkeypatch):
    monkeypatch.setenv(pr.REQUIRE_AUTH_ENV, "true")
    assert pr.require_authenticated()
    with pytest.raises(pr.UnauthenticatedPrincipalError):
        pr.enforce(pr.resolve(claimed_department="forensics"))


def test_the_cycle_seals_who_asked_into_the_case_memory(client):
    client.post("/cases", json={"case_id": "PRIN-1", "examiner_id": "perito-01",
                                "scenario": "attack"})
    client.post("/cases/PRIN-1/cycle", json={"department": "incident-response"})
    journal = client.get("/cases/PRIN-1/mission").json()["journal"]
    begun = next(e for e in journal if e["action"] == "begin_cycle")
    recorded = begun["detail"]["principal"]
    assert recorded["department"] == "incident-response"
    assert recorded["authenticated"] is False
    assert "asserted" in recorded["how"]


def test_the_sealed_record_of_who_asked_is_tamper_evident(client):
    """Rewriting the principal after the fact breaks the memory chain."""
    client.post("/cases", json={"case_id": "PRIN-2", "examiner_id": "perito-01"})
    client.post("/cases/PRIN-2/cycle", json={})
    from service.app import _CASE_STORE
    mission = _CASE_STORE.get_case("PRIN-2")["mission"]
    assert mem.verify_mission(mission)["memory_ok"]
    begun = next(e for e in mission["journal"] if e["action"] == "begin_cycle")
    begun["detail"]["principal"]["authenticated"] = True
    assert not mem.verify_mission(mission)["memory_ok"]


def test_a_deployment_requiring_authentication_refuses_over_http(client, monkeypatch):
    monkeypatch.setenv(pr.REQUIRE_AUTH_ENV, "true")
    client.post("/cases", json={"case_id": "PRIN-3", "examiner_id": "perito-01"})
    r = client.post("/cases/PRIN-3/cycle", json={"department": "forensics"})
    assert r.status_code == 403
    assert "verified identity" in r.json()["detail"]


def test_health_reports_the_posture(client, monkeypatch):
    assert client.get("/health").json()["requires_authenticated_principal"] is False
    monkeypatch.setenv(pr.REQUIRE_AUTH_ENV, "true")
    assert client.get("/health").json()["requires_authenticated_principal"] is True


def test_a_token_cannot_authenticate_without_a_configured_audience(monkeypatch):
    """google-auth checks 'aud' only when an audience is supplied. With none
    configured, a correctly signed token minted for a completely different
    service verifies — the confused-deputy case. An unverifiable token is
    treated as no token, per this module's own rule."""
    monkeypatch.delenv(pr.AUDIENCE_ENV, raising=False)
    called = []
    monkeypatch.setattr(
        "google.oauth2.id_token.verify_oauth2_token",
        lambda *a, **k: called.append(a) or {"email": "analyst@example.com"})
    assert pr.verify_identity_token("a.real.token") is None
    assert not called, "the token was verified without an audience check"


def test_a_configured_audience_is_passed_to_the_verifier(monkeypatch):
    monkeypatch.setenv(pr.AUDIENCE_ENV, "https://vigia-live.example.com")
    seen = {}

    def _verify(token, request, audience):
        seen["audience"] = audience
        return {"email": "analyst@example.com", "email_verified": True}

    monkeypatch.setattr("google.oauth2.id_token.verify_oauth2_token", _verify)
    assert pr.verify_identity_token("a.real.token") == "analyst@example.com"
    assert seen["audience"] == "https://vigia-live.example.com"


def test_an_unconfigured_audience_leaves_the_principal_asserted(monkeypatch):
    """End to end: the request still works, it is just not authenticated."""
    monkeypatch.delenv(pr.AUDIENCE_ENV, raising=False)
    monkeypatch.setenv(pr.ROSTER_ENV, "analyst@example.com:soc")
    p = pr.resolve(authorization_header="Bearer some.token",
                   claimed_department="forensics")
    assert p["authenticated"] is False
    assert p["department"] == "forensics"


def test_an_acknowledgement_records_whether_the_examiner_was_verified(client):
    """Acknowledging is how a malicious verdict stops demanding attention. Who
    claims to have handled it, and whether we know that, must travel together."""
    client.post("/cases", json={"case_id": "ACK-P", "examiner_id": "perito-01",
                                "scenario": "attack"})
    client.post("/cases/ACK-P/cycle", json={})
    client.post("/cases/ACK-P/escalations/0/acknowledge",
                json={"note": "isolated", "examiner_id": "perito-01"})
    entry = client.get("/cases/ACK-P/mission").json()["escalations"][0]
    assert entry["acknowledged"] is True
    assert entry["acknowledged_by_authenticated"] is False
    assert entry["acknowledged_by"] == "perito-01"
