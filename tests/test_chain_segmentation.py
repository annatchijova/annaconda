"""A case that outlives one document.

Measured on this build a cycle adds about 4 KB to a case, so a Firestore
document holding the sealed stream and the mission journal reaches the 1 MiB
per-document limit at roughly 270 cycles. The case that reaches it first is the
one that matters most: a host under an adjudicated malicious verdict is
re-checked hourly, which is about eleven days.

Truncating a hash chain to fit is not an option, so the chains are segmented.
These tests run the real FirestoreCaseStore against a double that enforces the
same 1 MiB limit — a store that would have failed in production fails here.
"""

import json

import pytest

from agent import mission as mem
from core.verdict_stream import verify_stream
from service import chain_store


FIRESTORE_DOC_LIMIT = 1024 * 1024


class DocumentTooLarge(Exception):
    """What Firestore raises past 1 MiB, and what this double raises."""


class _Snapshot:
    def __init__(self, doc_id, data):
        self.id = doc_id
        self._data = data

    @property
    def exists(self):
        return self._data is not None

    def to_dict(self):
        return json.loads(json.dumps(self._data)) if self._data else None


class _Ref:
    def __init__(self, doc_id):
        self.id = doc_id


class FakeDocument:
    def __init__(self, store, path):
        self._store = store
        self._path = path

    def get(self):
        return _Snapshot(self._path.split("/")[-1], self._store.docs.get(self._path))

    def set(self, data):
        size = len(json.dumps(data, default=str).encode())
        if size > FIRESTORE_DOC_LIMIT:
            raise DocumentTooLarge(
                f"document {self._path} is {size} bytes, over the 1 MiB limit")
        self._store.docs[self._path] = json.loads(json.dumps(data, default=str))
        self._store.max_seen = max(self._store.max_seen, size)

    def delete(self):
        self._store.docs.pop(self._path, None)

    def collection(self, name):
        return FakeCollection(self._store, f"{self._path}/{name}")


class FakeCollection:
    def __init__(self, store, path, _limit=None):
        self._store = store
        self._path = path
        self._limit = _limit

    def document(self, doc_id):
        return FakeDocument(self._store, f"{self._path}/{doc_id}")

    def _children(self):
        prefix = self._path + "/"
        return sorted(k for k in self._store.docs
                      if k.startswith(prefix) and "/" not in k[len(prefix):])

    def stream(self):
        keys = self._children()
        if self._limit is not None:
            keys = keys[:self._limit]
        return [_Snapshot(k.split("/")[-1], self._store.docs[k]) for k in keys]

    def limit(self, n):
        return FakeCollection(self._store, self._path, _limit=n)

    def list_documents(self):
        return [_Ref(k.split("/")[-1]) for k in self._children()]


class FakeFirestore:
    def __init__(self):
        self.docs = {}
        self.max_seen = 0

    def collection(self, name):
        return FakeCollection(self, name)


@pytest.fixture()
def store(monkeypatch):
    fake = FakeFirestore()

    class _ClientFactory:
        def __init__(self, project=None):
            pass

        def collection(self, name):
            return fake.collection(name)

    import google.cloud.firestore as real
    monkeypatch.setattr(real, "Client", _ClientFactory)

    from service.case_store import FirestoreCaseStore
    st = FirestoreCaseStore("test-project")
    st.fake = fake
    return st


def _entry(i):
    """A sealed stream entry the size real ones run to."""
    return {"sequence": i, "entry_hash": f"{i:064x}", "prev_entry_hash": f"{i-1:064x}",
            "window_hash": f"{i:064x}", "bundle_sha256": f"{i:064x}",
            "verdict": {"state": "MALICE_HIGH", "score": "3/4",
                        "confidence": "9/10", "mitre_techniques": ["T1055.012"],
                        "determinism_level": "FORENSIC"},
            "padding": "x" * 600}


def test_a_case_survives_far_past_the_single_document_limit(store):
    """The regression this exists for. 1200 cycles' worth of chain is roughly
    four times what one document holds; before segmentation this raised."""
    store.create_case("LONG", {"hostname": "WIN11"}, "perito")
    for batch in range(12):
        entries = [_entry(batch * 100 + i) for i in range(100)]
        store.apply_run("LONG", entries,
                        [{"verdict_state": "MALICE_HIGH"}], [])

    case = store.get_case("LONG")
    assert len(case["entries"]) == 1200
    assert case["status"] == "malice"
    # No single stored document ever came close to the limit.
    assert store.fake.max_seen < FIRESTORE_DOC_LIMIT, store.fake.max_seen
    assert store.fake.max_seen < chain_store.SEGMENT_MAX_BYTES * 1.5


def test_the_reassembled_chain_is_the_same_list_in_the_same_order(store):
    store.create_case("ORDER", {"hostname": "H"}, "perito")
    written = [_entry(i) for i in range(500)]
    for i in range(0, 500, 50):
        store.apply_run("ORDER", written[i:i + 50], [], [])
    assert store.get_case("ORDER")["entries"] == written


def test_the_chain_spans_segments_and_still_verifies(store):
    """Segmentation must not break the guarantee it exists to preserve: the
    verifier sees one unbroken chain across every segment boundary."""
    from agent.tools import PurpleTeamSession
    from tools.velociraptor.adapter import MockTransport
    from pathlib import Path
    import tempfile

    repo = Path(__file__).resolve().parent.parent
    session = PurpleTeamSession(
        MockTransport(repo / "tests" / "fixtures" / "attack"), case_id="VERIFY",
        host={"client_id": "C.1", "hostname": "H", "os": "windows"},
        examiner_id="op", out_dir=tempfile.mkdtemp(), source="replay",
        time_base="2026-08-12T14:10:00Z")
    session.adjudicate(session.run_hunt(["pslist", "netstat"], "r")["window_id"])

    store.create_case("VERIFY", {"hostname": "H"}, "perito")
    # Force a segment boundary by shrinking the budget for this test.
    original = chain_store.SEGMENT_MAX_BYTES
    chain_store.SEGMENT_MAX_BYTES = 4000
    try:
        for entry in session._entries:
            store.apply_run("VERIFY", [entry], [], [])
        case = store.get_case("VERIFY")
    finally:
        chain_store.SEGMENT_MAX_BYTES = original

    assert case["chain_index"]["entries"]["segments"] >= 1
    assert verify_stream(case["entries"])["chain_ok"]


def test_the_mission_journal_is_segmented_and_still_tamper_evident(store):
    case = store.create_case("MEM", {"hostname": "H"}, "perito")
    original = chain_store.SEGMENT_MAX_BYTES
    chain_store.SEGMENT_MAX_BYTES = 3000
    try:
        for i in range(60):
            mission = store.get_case("MEM")["mission"]
            mem.add_hypothesis(mission, actor="fleet-commander",
                               text=f"line of inquiry {i}")
            store.save_mission("MEM", mission)
        loaded = store.get_case("MEM")["mission"]
    finally:
        chain_store.SEGMENT_MAX_BYTES = original

    assert len(loaded["journal"]) == 60
    assert mem.verify_mission(loaded)["memory_ok"]
    # and an edit inside a segment is still caught after reassembly
    loaded["journal"][30]["detail"]["text"] = "forged"
    assert not mem.verify_mission(loaded)["memory_ok"]


def test_listing_cases_does_not_read_their_histories(store):
    """The queue must render from the case documents alone — otherwise every
    page load costs one read per segment per case."""
    store.create_case("L1", {"hostname": "A"}, "perito")
    store.apply_run("L1", [_entry(i) for i in range(300)],
                    [{"verdict_state": "MALICE_HIGH"}], [])

    reads = []
    original_read = chain_store.SegmentedChain.read_all
    chain_store.SegmentedChain.read_all = lambda self, index: (
        reads.append(self.field) or original_read(self, index))
    try:
        rows = store.list_cases()
    finally:
        chain_store.SegmentedChain.read_all = original_read

    assert reads == [], f"list_cases loaded chains: {reads}"
    assert rows[0]["sealed_verdicts"] == 300


def test_a_missing_segment_is_refused_rather_than_verified_as_whole(store):
    """A verifier handed a silently short list would report a clean chain over
    incomplete history — the worst possible failure for this system."""
    store.create_case("HOLE", {"hostname": "H"}, "perito")
    original = chain_store.SEGMENT_MAX_BYTES
    chain_store.SEGMENT_MAX_BYTES = 3000
    try:
        store.apply_run("HOLE", [_entry(i) for i in range(20)], [], [])
    finally:
        chain_store.SEGMENT_MAX_BYTES = original

    segments = [k for k in store.fake.docs if "/chain/entries-" in k]
    assert len(segments) > 1, "test needs more than one segment to remove one"
    del store.fake.docs[sorted(segments)[0]]

    with pytest.raises(chain_store.ChainStoreError, match="incomplete"):
        store.get_case("HOLE")


def test_an_entry_too_large_for_any_segment_is_refused_at_the_boundary():
    index = chain_store.new_index()
    with pytest.raises(chain_store.ChainStoreError, match="exceeds"):
        chain_store.plan_appends(index, [{"x": "y" * (chain_store.MAX_ENTRY_BYTES + 10)}])


def test_deleting_a_case_removes_its_segments(store):
    store.create_case("DEL", {"hostname": "H"}, "perito")
    store.apply_run("DEL", [_entry(i) for i in range(50)], [], [])
    assert any("/chain/" in k for k in store.fake.docs)
    store.delete_case("DEL")
    assert not any(k.startswith("cases/DEL") for k in store.fake.docs)


def test_one_cycle_writes_one_mission_not_two(store):
    """A cycle that both seals a verdict and reasons must not produce two
    divergent copies of the case's memory.

    The service reads a case, runs a cycle against it, then persists — first
    the sealed run, then the memory. On a durable backend each of those calls
    re-reads the stored case, so the run's own mission mutations (an ABSTAIN
    question, say) land on a *different* mission object than the cycle's. Two
    objects appending to one hash chain is a broken chain: the entries written
    second chain onto a head the entries written first never had.
    """
    store.create_case("SPLIT", {"hostname": "H"}, "perito")

    # What a cycle does: take the case in hand, reason into its memory.
    case = store.get_case("SPLIT")
    mission = case["mission"]
    mem.begin_cycle(mission, actor="fleet-commander", trigger="test")
    mem.add_hypothesis(mission, actor="fleet-commander", text="a lead")

    # ...and what the service then does: persist both in one write. The run
    # abstains, so _apply_run writes an open question into the memory too —
    # into the *same* mission, which is the whole point.
    store.apply_cycle("SPLIT", [], [{"verdict_state": "ABSTAIN_INSUFFICIENT"}],
                      [], mission)

    stored = store.get_case("SPLIT")["mission"]
    assert mem.verify_mission(stored)["memory_ok"], (
        f"the case's memory chain is broken after one cycle: "
        f"{mem.verify_mission(stored)['errors']}")
    # both the cycle's reasoning and the run's own question are on one chain
    actions = [e["action"] for e in stored["journal"]]
    assert "add_hypothesis" in actions and "note_open_question" in actions


def test_persisting_a_cycle_in_two_writes_is_what_forks_the_memory(store):
    """The bug this API exists to prevent, pinned so it cannot come back by
    someone reaching for apply_run + save_mission on a cycle again."""
    store.create_case("FORK", {"hostname": "H"}, "perito")
    mission = store.get_case("FORK")["mission"]
    mem.begin_cycle(mission, actor="fleet-commander", trigger="test")

    store.apply_run("FORK", [], [{"verdict_state": "ABSTAIN_INSUFFICIENT"}], [])
    store.save_mission("FORK", mission)

    broken = mem.verify_mission(store.get_case("FORK")["mission"])
    assert not broken["memory_ok"], (
        "two separate writes no longer fork the memory — if that is "
        "deliberate, this test should be deleted along with apply_cycle")
