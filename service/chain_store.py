"""Append-only chains that outgrow a single document.

A case accumulates two chains that never stop growing: the sealed verdict
stream and the mission journal. Measured on this build, a cycle adds about
4 KB between them, so a Firestore document holding both reaches the 1 MiB
per-document limit at roughly 270 cycles. That sounds distant until you notice
which case runs most often: a host under an adjudicated malicious verdict is
re-checked every hour, which is **about eleven days**. The case that matters
most is the one that breaks first.

Truncating a hash chain to fit is not an option — a chain you can shorten is a
chain an attacker can shorten, and the whole point of these two structures is
that they cannot be. So the chains are stored in *segments*: bounded documents
holding consecutive runs of entries, with the case document keeping only an
index. Reading concatenates the segments in order, which reproduces exactly the
list the verifiers already consume, so every existing check (verify_stream,
verify_mission) works unchanged and still spans the whole history.

This module is storage-shaped, not Firestore-shaped: it talks to a minimal
document-collection interface, so the segmentation logic is exercised in tests
against a double that enforces the same 1 MiB limit, rather than only in
production.
"""

from __future__ import annotations

import json
from typing import Iterable, Optional, Protocol

# Firestore's hard limit is 1 MiB per document, including keys, overhead and
# index entries. Segments are capped well below it: the cost of a smaller
# segment is one more read, and the cost of a segment that does not fit is a
# case that cannot be written at all.
SEGMENT_MAX_BYTES = 200_000

# A single entry larger than this cannot be stored by any segmentation and is
# refused at the boundary rather than silently dropped or written to fail.
MAX_ENTRY_BYTES = SEGMENT_MAX_BYTES


class ChainStoreError(ValueError):
    """An entry could not be stored in any segment."""


class ConcurrentModificationError(RuntimeError):
    """The chain being written diverged from the one that is stored.

    Two writers that both read a case and then both append are not extending
    one chain — they are two branches from the same point. Writing either one
    over the other silently drops the loser's entries and leaves a head that
    does not match the journal, so verification reports tampering on a record
    nobody tampered with. Refusing the write is the only honest outcome: the
    caller retries against current state.
    """


class DocumentCollection(Protocol):
    """The minimum a backend must offer: read one, write one, list ids."""

    def read(self, doc_id: str) -> Optional[dict]: ...
    def write(self, doc_id: str, data: dict) -> None: ...
    def ids(self) -> list: ...
    def delete(self, doc_id: str) -> None: ...


def sizeof(item) -> int:
    """Bytes this item costs in a document. JSON is a close enough proxy for
    Firestore's own accounting to keep segments far from the real limit."""
    return len(json.dumps(item, ensure_ascii=False, default=str).encode("utf-8"))


def new_index() -> dict:
    """The index a case document carries for one chain.

    ``boundaries[k]`` is the position in the chain of the first entry stored in
    segment k, so a segment's content is a pure slice of the chain the writer
    holds. That makes writing a segment idempotent — it is computed, never
    read-modify-written — and it makes the case document the single commit
    point: ``count`` is how many entries are committed, and anything a
    half-finished write left in a segment beyond that is ignored until an index
    commits it.
    """
    return {"segments": 0, "count": 0, "tail_bytes": 0, "head": None,
            "boundaries": []}


def head_of(item) -> Optional[str]:
    """The chain hash of an entry, when it has one.

    Only the two hash chains (the sealed verdict stream and the mission
    journal) carry ``entry_hash``. The other stored lists have no identity to
    compare, so divergence between two writers cannot be detected for them —
    stated here rather than left implied.
    """
    if isinstance(item, dict):
        value = item.get("entry_hash")
        if isinstance(value, str) and value:
            return value
    return None


def prev_of(item) -> Optional[str]:
    """The hash an entry chains onto, when it declares one.

    The two chains name it differently — the sealed verdict stream uses
    ``prev_entry_hash``, the mission journal uses ``prev_hash`` — so read
    either. Entries without one simply skip the continuity check.
    """
    if isinstance(item, dict):
        for key in ("prev_entry_hash", "prev_hash"):
            value = item.get(key)
            if isinstance(value, str) and value:
                return value
    return None


def segment_id(field: str, number: int) -> str:
    return f"{field}-{number:06d}"


def plan_appends(index: dict, items) -> dict:
    """Where the new entries go, without touching storage.

    Returns the index the chain would have after appending. Pure, so the
    placement rule is testable on its own.
    """
    boundaries = list(index.get("boundaries") or [])
    count = int(index.get("count", 0))
    tail_bytes = int(index.get("tail_bytes", 0))
    head = index.get("head")

    for item in items:
        size = sizeof(item)
        if size > MAX_ENTRY_BYTES:
            raise ChainStoreError(
                f"a single chain entry of {size} bytes exceeds the "
                f"{MAX_ENTRY_BYTES}-byte segment budget and cannot be stored")
        if not boundaries or tail_bytes + size > SEGMENT_MAX_BYTES:
            boundaries.append(count)
            tail_bytes = 0
        tail_bytes += size
        count += 1
        head = head_of(item) or head

    return {"segments": len(boundaries), "count": count,
            "tail_bytes": tail_bytes, "head": head, "boundaries": boundaries}


class SegmentedChain:
    """One append-only chain, stored across bounded documents."""

    def __init__(self, collection: DocumentCollection, field: str):
        self.collection = collection
        self.field = field

    def check(self, index: dict, chain: list) -> None:
        """Refuse a writer whose chain is not an extension of the stored one.

        Under two concurrent writers the caller's chain is a divergent branch
        from the same point, not a longer version of the same chain, and
        slicing by count would write the wrong entries — dropping the other
        writer's work and leaving a head that does not match the journal, so
        verification would report tampering on a record nobody tampered with.

        Separated from the write so a caller can validate every chain before
        committing any of them: a check that fired half way through would leave
        segments written that no index references.
        """
        already = int((index or {}).get("count", 0))
        if not already:
            return
        if len(chain) < already:
            raise ConcurrentModificationError(
                f"chain {self.field!r} has {already} stored entries but the "
                f"writer holds only {len(chain)} — it is working from state "
                f"that has since been replaced")
        stored_head = (index or {}).get("head")
        writer_head = head_of(chain[already - 1])
        if stored_head and writer_head and stored_head != writer_head:
            raise ConcurrentModificationError(
                f"chain {self.field!r} diverged: the stored chain ends at "
                f"{stored_head[:12]}… but the writer's entry at that position "
                f"is {writer_head[:12]}… — another cycle wrote this case in "
                f"between")

        # The prefix matching is not enough on its own. A writer can hold a
        # correct prefix and still be appending entries minted against a stale
        # head: the sealed verdict stream is built by a *session* constructed
        # from the case as it was read, so two concurrent cycles mint entries
        # with the same sequence number and the same prev hash, and the second
        # writer then re-reads the case — making its prefix match perfectly.
        # Storing that produces a chain whose own verifier rejects it.
        # So the first NEW entry must chain onto the stored head.
        if stored_head and len(chain) > already:
            writer_prev = prev_of(chain[already])
            if writer_prev and writer_prev != stored_head:
                raise ConcurrentModificationError(
                    f"chain {self.field!r}: the writer's first new entry chains "
                    f"onto {writer_prev[:12]}… but the stored chain ends at "
                    f"{stored_head[:12]}… — it was minted against state that "
                    f"has since been replaced")

    def append_from(self, index: dict, chain: list) -> dict:
        """Store whatever part of ``chain`` is not yet committed.

        Only the segments the new entries land in are written, and each is
        written as a slice of ``chain`` rather than by reading and extending —
        so a retry after a failed write stores the same bytes rather than
        duplicating entries.
        """
        index = dict(index or new_index())
        chain = list(chain or [])
        already = int(index.get("count", 0))
        if len(chain) <= already:
            return index

        updated = plan_appends(index, chain[already:])
        boundaries = updated["boundaries"]
        first_touched = max(0, len(index.get("boundaries") or []) - 1)
        for number in range(first_touched, len(boundaries)):
            start = boundaries[number]
            end = (boundaries[number + 1] if number + 1 < len(boundaries)
                   else updated["count"])
            self.collection.write(segment_id(self.field, number),
                                  {"field": self.field, "segment": number,
                                   "start": start, "items": chain[start:end]})
        return updated

    def read_all(self, index: dict) -> list:
        """Every committed entry, in order.

        Truncated to the committed ``count``: the case document's index is the
        commit point, so entries a half-finished write left in a segment beyond
        it are not yet part of the record and must not be read as if they were.
        """
        index = index or {}
        out: list = []
        for number in range(int(index.get("segments", 0))):
            doc = self.collection.read(segment_id(self.field, number))
            if doc is None:
                # A missing segment is a hole in a chain that claims to be
                # unbroken. Say so loudly: a verifier handed a silently short
                # list would report a clean chain over incomplete history.
                raise ChainStoreError(
                    f"segment {number} of chain {self.field!r} is missing — the "
                    f"stored history is incomplete and must not be verified as "
                    f"if it were whole")
            out.extend(doc.get("items", []))
        committed = int(index.get("count", len(out)))
        if len(out) < committed:
            raise ChainStoreError(
                f"chain {self.field!r} claims {committed} entries but only "
                f"{len(out)} are stored — the history is incomplete")
        return out[:committed]

    def delete_all(self, index: dict) -> None:
        for number in range(int((index or {}).get("segments", 0))):
            self.collection.delete(segment_id(self.field, number))
