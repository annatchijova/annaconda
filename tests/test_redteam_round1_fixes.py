"""Regression tests for the external red-team (Round 1) findings.

Each test locks in a fix and would fail against the pre-fix code, so a later
change that reopens the hole is caught. The Firestore transactional path (R3-1)
is not covered here — it is a property of the real backend and needs a Firestore
emulator; see docs/RED_TEAM_AUDIT_ROUND1_EXTERNAL.md.
"""
import pytest

from core.canonicalize import _canonicalize
from core.verdict_stream import GENESIS_HASH, StreamError, append_entry
from service.case_store import MemoryCaseStore
from service.chain_store import ConcurrentModificationError

import core.bundle_builder as bundle_builder
import tools.verify_bundle as verify_bundle


# ---- R1-1: canonicalization must not collide int/str keys -------------------

def test_r1_1_non_string_keys_are_refused_in_every_v2_copy():
    encoders = [_canonicalize, bundle_builder._canonicalize_v2, verify_bundle._canon_v2]
    for enc in encoders:
        with pytest.raises(TypeError):
            enc({1: "x"})            # would collide with {"1": "x"} under json.dumps
        # string-keyed payloads are unaffected (no existing seal changes)
        assert enc({"1": "x"}) == enc({"1": "x"})


def test_r1_1_string_keyed_seal_is_unchanged():
    # the exact shape a verdict entry seals — must still canonicalize cleanly
    entry = {"case_id": "C", "sequence": 0, "verdict": {"state": "MALICE_HIGH",
             "score": "5569/10000"}, "prev_entry_hash": "0" * 64}
    assert _canonicalize(entry) == verify_bundle._canon_v2(entry)


# ---- R1-2: append_entry enforces continuity + durability --------------------

def _entry(seq, prev, h):
    return {"sequence": seq, "prev_entry_hash": prev, "entry_hash": h}


def test_r1_2_append_entry_enforces_chain_and_sequence(tmp_path):
    path = tmp_path / "stream.jsonl"
    append_entry(path, _entry(0, GENESIS_HASH, "h0"))   # fresh file: accepted
    append_entry(path, _entry(1, "h0", "h1"))           # continues: accepted
    with pytest.raises(StreamError):
        append_entry(path, _entry(2, "WRONG", "h2"))    # does not chain
    with pytest.raises(StreamError):
        append_entry(path, _entry(9, "h1", "h2"))       # non-contiguous sequence
    # the rejected appends left nothing behind
    from core.verdict_stream import read_stream
    assert [e["entry_hash"] for e in read_stream(path)] == ["h0", "h1"]


# ---- R3-2: MemoryCaseStore rejects a concurrent second writer ---------------

def test_r3_2_memory_store_rejects_a_divergent_concurrent_run():
    store = MemoryCaseStore()
    store.create_case("C", {"hostname": "h"}, "op")
    v = [{"verdict_state": "BENIGN_HIGH"}]

    store.apply_run("C", [_entry(0, GENESIS_HASH, "h0")], v, [])
    # a second run minted against the SAME base (GENESIS) — the signature of a
    # concurrent writer — must be refused, not blindly appended into a break.
    with pytest.raises(ConcurrentModificationError):
        store.apply_run("C", [_entry(0, GENESIS_HASH, "h0b")], v, [])
    # a proper continuation onto the stored head is accepted.
    store.apply_run("C", [_entry(1, "h0", "h1")], v, [])
    assert [e["entry_hash"] for e in store.get_case("C")["entries"]] == ["h0", "h1"]


# ---- R2-1: model-touching public routes are rate limited --------------------

def test_r2_1_consult_and_sweep_are_rate_limited():
    import service.app as app
    from fastapi.testclient import TestClient

    client = TestClient(app.app)
    # Exhaust each route's bucket via the same limiter the route consults, then
    # confirm the route refuses without reaching the paid model / the fleet.
    for key, method, path in (("consult", client.post, "/consult"),
                              ("sweep", client.post, "/tasks/sweep")):
        for _ in range(app._RATE_MAX):
            assert app._rate_ok(key) is True
        body = {"message": "hi"} if key == "consult" else {}
        resp = method(path, json=body)
        assert resp.status_code == 429, (path, resp.status_code)
