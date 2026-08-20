"""Pushing a sealed verdict to SecOps is downstream of the seal, and honest.

The pusher never touches the verdict, never raises into a cycle, and degrades to
a first-class 'unavailable' when no sink is configured. The published payload is
exactly the deterministic STIX bundle.
"""
import json

from service.secops_push import SecOpsPusher, build_pusher, stix_attributes

BUNDLE = {"type": "bundle", "id": "bundle--x",
          "objects": [{"type": "identity", "id": "identity--a"},
                      {"type": "x-annaconda-sealed-verdict", "id": "x--1",
                       "score": "5569/10000"}]}


def test_publishes_the_exact_bundle_with_attributes():
    captured = {}

    def publish_fn(topic, data, attributes):
        captured["topic"] = topic
        captured["data"] = data
        captured["attributes"] = attributes
        return "msg-123"

    pusher = SecOpsPusher(publish_fn=publish_fn, topic="annaconda-verdicts")
    assert pusher.available and pusher.posture() == "pubsub:annaconda-verdicts"
    result = pusher.push(BUNDLE, attributes=stix_attributes(
        BUNDLE, case_id="C-1", worst_verdict="MALICE_HIGH", chain_ok=True))
    assert result["status"] == "published" and result["message_id"] == "msg-123"
    # the published bytes deserialize back to exactly the bundle — push does not
    # mutate or re-score anything.
    assert json.loads(captured["data"].decode("utf-8")) == BUNDLE
    assert captured["attributes"]["case_id"] == "C-1"
    assert captured["attributes"]["format"] == "stix-2.1"
    assert captured["attributes"]["chain_verified"] == "True"  # attrs are strings


def test_no_sink_is_unavailable_not_an_error():
    pusher = SecOpsPusher(publish_fn=None, topic=None)
    assert not pusher.available and pusher.posture() == "unavailable"
    result = pusher.push(BUNDLE)
    assert result["status"] == "unavailable" and "reason" in result


def test_delivery_failure_is_reported_never_raised():
    def boom(topic, data, attributes):
        raise RuntimeError("pubsub unreachable")

    pusher = SecOpsPusher(publish_fn=boom, topic="t")
    result = pusher.push(BUNDLE)  # must not raise — the sealed verdict is retained
    assert result["status"] == "failed"
    assert "pubsub unreachable" in result["reason"]


def test_build_pusher_without_a_topic_env_degrades(monkeypatch):
    monkeypatch.delenv("SECOPS_PUBSUB_TOPIC", raising=False)
    pusher = build_pusher()
    assert not pusher.available
    assert pusher.push(BUNDLE)["status"] == "unavailable"


def test_published_bytes_are_stable_for_a_bundle():
    seen = []
    pusher = SecOpsPusher(publish_fn=lambda t, d, a: seen.append(d) or "id", topic="t")
    pusher.push(BUNDLE)
    pusher.push(BUNDLE)
    assert seen[0] == seen[1]  # sort_keys -> deterministic payload bytes
