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
    """The index a case document carries for one chain."""
    return {"segments": 0, "count": 0, "tail_bytes": 0}


def segment_id(field: str, number: int) -> str:
    return f"{field}-{number:06d}"


def plan_appends(index: dict, items: Iterable) -> tuple:
    """Decide where each new item goes, without touching storage.

    Returns ``(writes, new_index)`` where ``writes`` is a list of
    ``(segment_number, items, appends_to_existing)`` — the tail segment is
    extended when the items fit, otherwise fresh segments are started. Pure, so
    the placement rule is testable on its own.
    """
    segments = int(index.get("segments", 0))
    count = int(index.get("count", 0))
    tail_bytes = int(index.get("tail_bytes", 0))

    writes: list = []
    for item in items:
        size = sizeof(item)
        if size > MAX_ENTRY_BYTES:
            raise ChainStoreError(
                f"a single chain entry of {size} bytes exceeds the "
                f"{MAX_ENTRY_BYTES}-byte segment budget and cannot be stored")
        if segments == 0 or tail_bytes + size > SEGMENT_MAX_BYTES:
            segments += 1
            tail_bytes = 0
            writes.append([segments - 1, [], False])
        elif not writes or writes[-1][0] != segments - 1:
            writes.append([segments - 1, [], True])
        writes[-1][1].append(item)
        tail_bytes += size
        count += 1

    return ([tuple(w) for w in writes],
            {"segments": segments, "count": count, "tail_bytes": tail_bytes})


class SegmentedChain:
    """One append-only chain, stored across bounded documents."""

    def __init__(self, collection: DocumentCollection, field: str):
        self.collection = collection
        self.field = field

    def append(self, index: dict, items: list) -> dict:
        """Append items, returning the updated index for the case document."""
        if not items:
            return dict(index or new_index())
        writes, updated = plan_appends(index or new_index(), items)
        for number, chunk, extends in writes:
            doc_id = segment_id(self.field, number)
            if extends:
                existing = self.collection.read(doc_id) or {}
                stored = list(existing.get("items", []))
            else:
                stored = []
            stored.extend(chunk)
            self.collection.write(doc_id, {"field": self.field,
                                           "segment": number,
                                           "items": stored})
        return updated

    def read_all(self, index: dict) -> list:
        """Every entry, in order. Concatenating the segments reproduces exactly
        the list the chain verifiers already consume."""
        out: list = []
        for number in range(int((index or {}).get("segments", 0))):
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
        return out

    def delete_all(self, index: dict) -> None:
        for number in range(int((index or {}).get("segments", 0))):
            self.collection.delete(segment_id(self.field, number))
