"""Push a sealed verdict to Google SecOps (Chronicle) over Pub/Sub.

Strictly downstream of the seal, never upstream. By the time this runs the
verdict is already sealed; the payload is the deterministic STIX bundle; and a
delivery failure is a WARN that keeps the sealed verdict rather than discarding
it. The invariant is preserved because the sink is not in the decision path at
all — it is told the result, it cannot change it.

Honest degradation, mirroring service/case_store.py: with no topic configured (or
the Pub/Sub client absent) the pusher does not fabricate a delivery — it reports
``unavailable`` and ``/health`` says so. An absent sink degrades the feature, not
the core; a push that fails is recorded, never raised into the autonomous cycle.
"""
from __future__ import annotations

import json
import os

_TOPIC_ENV = "SECOPS_PUBSUB_TOPIC"      # short name or projects/<p>/topics/<t>
_PROJECT_ENV = "GOOGLE_CLOUD_PROJECT"


def _configured_topic() -> str | None:
    topic = os.environ.get(_TOPIC_ENV, "").strip()
    return topic or None


class SecOpsPusher:
    """Publishes a STIX bundle to a Pub/Sub topic a Chronicle feed subscribes to.

    ``publish_fn(topic, data: bytes, attributes: dict) -> str`` is injectable so
    the whole path is testable offline; the live path binds a Pub/Sub client. A
    pusher with no ``publish_fn`` and no topic is a first-class 'unavailable'
    state, not an error.
    """

    def __init__(self, *, publish_fn=None, topic: str | None = None):
        self._publish_fn = publish_fn
        self._topic = topic

    @property
    def available(self) -> bool:
        return self._publish_fn is not None and bool(self._topic)

    def posture(self) -> str:
        return f"pubsub:{self._topic}" if self.available else "unavailable"

    def push(self, bundle: dict, *, attributes: dict | None = None) -> dict:
        """Publish one bundle. Never raises: a delivery problem is returned as a
        status, so the caller's already-sealed verdict is never lost to it."""
        if not self.available:
            return {"status": "unavailable",
                    "reason": f"no Pub/Sub sink configured (set {_TOPIC_ENV})"}
        # sort_keys so the published bytes are stable for a given bundle.
        data = json.dumps(bundle, sort_keys=True, ensure_ascii=True).encode("utf-8")
        attrs = {k: str(v) for k, v in (attributes or {}).items() if v is not None}
        try:
            message_id = self._publish_fn(self._topic, data, attrs)
        except Exception as exc:  # noqa: BLE001 — delivery must never break a cycle
            return {"status": "failed", "reason": str(exc), "topic": self._topic}
        return {"status": "published", "message_id": message_id,
                "topic": self._topic, "bytes": len(data)}


def _live_publish_fn():
    """Bind a real Pub/Sub publisher, or None if the client/config is absent."""
    topic = _configured_topic()
    project = os.environ.get(_PROJECT_ENV, "").strip()
    if not topic:
        return None, None
    try:
        from google.cloud import pubsub_v1
    except Exception:  # noqa: BLE001 — client not installed: degrade honestly
        return None, topic
    client = pubsub_v1.PublisherClient()
    topic_path = topic if topic.startswith("projects/") \
        else client.topic_path(project, topic)

    def _publish(_topic, data: bytes, attributes: dict) -> str:
        future = client.publish(topic_path, data=data, **attributes)
        return future.result(timeout=30)

    return _publish, topic


def build_pusher(*, publish_fn=None, topic: str | None = None) -> SecOpsPusher:
    """Construct the pusher used by the service. Explicit args win (tests);
    otherwise bind the live Pub/Sub client, degrading honestly if it is absent."""
    if publish_fn is not None:
        return SecOpsPusher(publish_fn=publish_fn, topic=topic or _configured_topic())
    fn, resolved_topic = _live_publish_fn()
    return SecOpsPusher(publish_fn=fn, topic=resolved_topic)


def stix_attributes(bundle: dict, *, case_id: str, worst_verdict=None,
                    chain_ok=None) -> dict:
    """Pub/Sub message attributes a Chronicle feed can route on, without opening
    the payload."""
    return {
        "format": "stix-2.1",
        "source": "annaconda",
        "case_id": case_id,
        "worst_verdict": worst_verdict,
        "chain_verified": chain_ok,
        "objects": len(bundle.get("objects", [])),
    }
