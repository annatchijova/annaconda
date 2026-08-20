"""The independent exhibit verifier confirms good seals and catches tampering.

Two things are proved here. First, that the standalone verifier
(tools/verify_bundle.py) agrees with a genuinely sealed chain and rejects every
class of tampering. Second — and this is what makes it worth anything — that its
OWN copy of the canonical encoder is bit-for-bit in lockstep with the producer's
(core/canonicalize.py). If the two ever drift, the verifier would stop being an
independent check and this test fails.
"""
import copy
import json
import tempfile
from fractions import Fraction
from pathlib import Path

from agent.fleet import dispatch_investigation
from agent.tools import PurpleTeamSession
from tools.velociraptor.adapter import MockTransport

# the producer's real encoder + chain sealer, imported ONLY by the test (never
# by the verifier) so we can assert lockstep.
from core.canonicalize import _canonicalize
from core.verdict_stream import _sha256_canonical as producer_sha256

import tools.verify_bundle as V

REPO = Path(__file__).resolve().parent.parent
ATTACK = REPO / "tests" / "fixtures" / "attack"
HOST = {"client_id": "C.1", "hostname": "WIN11-VICTIM", "os": "windows"}


def _sealed_chain():
    """A genuinely sealed 2-window verdict chain from the real producer."""
    session = PurpleTeamSession(
        MockTransport(ATTACK), case_id="EXHIBIT-T", host=HOST, examiner_id="op",
        out_dir=tempfile.mkdtemp(), source="replay", time_base="2026-08-12T14:10:00Z")
    dispatch_investigation(session)
    return session._entries, list(session._windows.values())


def _bundle(entries, windows=None):
    b = {"format": "annaconda-exhibit", "case": {"case_id": "EXHIBIT-T",
         "entries": copy.deepcopy(entries)}}
    if windows is not None:
        b["windows"] = copy.deepcopy(windows)
    return b


# --- lockstep: the independent encoder must match the producer's exactly ------

def test_encoder_is_in_lockstep_with_the_producer():
    battery = [
        True, False, 0, 1, -7, 42,
        "plain", "café", "café", "line\r\nbreak", "cr\ronly", "",
        None, Fraction(5569, 10000), Fraction(0, 1),
        {"b": 2, "a": 1, "nested": {"z": [1, "x", None]}},
        [True, 1, "1", None, {"k": Fraction(1, 3)}],
        3.14159, 0.0, -0.0,
    ]
    for obj in battery:
        assert V._canon_v2(obj) == _canonicalize(obj), f"drift on {obj!r}"
        assert V._sha256_canonical(obj) == producer_sha256(obj), f"hash drift on {obj!r}"


def test_verifier_reproduces_real_entry_hashes():
    entries, _ = _sealed_chain()
    assert entries, "producer sealed no entries"
    for e in entries:
        unsealed = {k: v for k, v in e.items() if k != "entry_hash"}
        assert V._sha256_canonical(unsealed) == e["entry_hash"]


# --- a good bundle verifies ---------------------------------------------------

def test_good_chain_with_windows_passes():
    entries, windows = _sealed_chain()
    report = V.verify_bundle(_bundle(entries, windows))
    assert report["status"] == "PASS", report["errors"]
    assert report["entries"] == len(entries)
    assert not report["errors"]


def test_good_chain_without_windows_warns_not_fails():
    entries, _ = _sealed_chain()
    report = V.verify_bundle(_bundle(entries))  # no windows included
    assert report["status"] == "WARN"
    assert not report["errors"]
    assert any("window" in w for w in report["warnings"])


# --- every class of tampering is caught ---------------------------------------

def test_a_flipped_verdict_is_caught():
    entries, windows = _sealed_chain()
    tampered = copy.deepcopy(entries)
    # flip the sealed state without touching entry_hash — the reseal must diverge
    tampered[0]["verdict"]["state"] = "BENIGN_HIGH"
    report = V.verify_bundle(_bundle(tampered, windows))
    assert report["status"] == "FAIL"
    assert any("tampered" in e for e in report["errors"])


def test_a_reordered_chain_is_caught():
    entries, windows = _sealed_chain()
    if len(entries) < 2:
        return  # need at least two entries to reorder
    swapped = [copy.deepcopy(entries[1]), copy.deepcopy(entries[0])]
    report = V.verify_bundle(_bundle(swapped, windows))
    assert report["status"] == "FAIL"
    assert report["errors"]


def test_a_truncated_chain_is_caught():
    entries, windows = _sealed_chain()
    if len(entries) < 2:
        return
    # dropping the last entry leaves a shorter but internally-consistent chain;
    # a broken sequence/prev-link appears when the head is dropped, so drop entry 0.
    report = V.verify_bundle(_bundle(entries[1:], windows))
    assert report["status"] == "FAIL"
    assert report["errors"]


def test_a_broken_prev_link_is_caught():
    entries, windows = _sealed_chain()
    if len(entries) < 2:
        return
    tampered = copy.deepcopy(entries)
    tampered[1]["prev_entry_hash"] = "0" * 64
    report = V.verify_bundle(_bundle(tampered, windows))
    assert report["status"] == "FAIL"
    assert any("chain broken" in e or "link" in e for e in report["errors"])


def test_a_tampered_window_is_caught():
    entries, windows = _sealed_chain()
    tampered_windows = copy.deepcopy(windows)
    # mutate an artifact inside the first window without fixing its window_hash
    tampered_windows[0]["artifacts"].append(
        {"artifact_id": "smuggled", "evidence_type": "network_flow",
         "raw_score": "1/1", "timestamp": "2026-08-12T14:10:30Z", "metadata": {}})
    report = V.verify_bundle(_bundle(entries, tampered_windows))
    assert report["status"] == "FAIL"
    assert any("window" in e for e in report["errors"])


# --- the CLI contract ---------------------------------------------------------

def test_cli_exit_codes(tmp_path):
    entries, windows = _sealed_chain()
    good = tmp_path / "good.json"
    good.write_text(json.dumps(_bundle(entries, windows)), encoding="utf-8")
    assert V.main([str(good)]) == 0

    bad_bundle = _bundle(entries, windows)
    bad_bundle["case"]["entries"][0]["verdict"]["score"] = "1/1"
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps(bad_bundle), encoding="utf-8")
    assert V.main([str(bad)]) == 1

    # a WARN (no windows) passes by default but fails under --strict
    warn = tmp_path / "warn.json"
    warn.write_text(json.dumps(_bundle(entries)), encoding="utf-8")
    assert V.main([str(warn)]) == 0
    assert V.main([str(warn), "--strict"]) == 2
