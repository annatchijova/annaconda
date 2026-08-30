"""The anti-flooding limit cuts by position, so it can cut by evidence class.

CAIE accepts at most _MAX_ARTIFACTS (1000) artifacts and rejects the rest. The
limit itself is a legitimate DoS control. What these tests pin is its METHOD:
the cut is positional, so which artifacts get analysed is a function of the
order they were collected in rather than of what they contain.

This is not hypothetical. A live Velociraptor collection from an idle Windows 11
host produced 1683 artifacts -- netstat alone was 963 -- and the engine received
963 network_flow plus 37 windows_event_log. Every one of the 397 memory_process
artifacts and all 275 filesystem_artifact ones fell past the cut, so the verdict
was reached without the engine seeing a single process.

The consequence that matters: every cross-artifact rule needs two kinds of
artifact at once. TEMPORAL_CAUSALITY_VIOLATION needs a network artifact AND a
memory_process one. On that collection it could not have fired whatever its
inputs said, because one whole side of the pair was never admitted -- which is a
different reason for "no fractures on a healthy host" than the one the rule's
own logic would give, and the two are indistinguishable from the verdict alone.

These are characterisation tests. They assert what the code does today so that
changing it -- raising the cap, sampling across evidence types, or refusing to
adjudicate a truncated window -- is a deliberate edit with a visible diff, not
an accident. They do NOT assert that the current behaviour is correct.
"""

from collections import Counter

from tools.caie import _MAX_ARTIFACTS, Artifact, CrossArtifactIncongruenceEngine


def _artifact(kind: str, n: int) -> Artifact:
    """A minimal, valid artifact of the given evidence type."""
    return Artifact(
        source_tool="velociraptor",
        evidence_type=kind,
        raw_score=0.05,
        description=f"{kind} #{n}",
        metadata={"pid": n},
        timestamp="2026-08-30T12:00:00Z",
    )


def _admitted(artifacts) -> Counter:
    """Evidence types the engine actually accepted, by count."""
    engine = CrossArtifactIncongruenceEngine()
    accepted = [a for a in artifacts if engine.add_artifact(a)]
    return Counter(a.evidence_type for a in accepted)


def test_a_whole_evidence_class_can_be_excluded_by_position_alone():
    """Artifacts past the cut are dropped whatever they are.

    Shaped like the real collection: a large block of network rows, then the
    processes. Nothing here is malformed or of an unknown type -- every one of
    these would be analysed if it arrived earlier in the list.
    """
    network = [_artifact("network_flow", n) for n in range(_MAX_ARTIFACTS)]
    processes = [_artifact("memory_process", n) for n in range(100)]

    admitted = _admitted(network + processes)

    assert admitted["network_flow"] == _MAX_ARTIFACTS
    assert admitted["memory_process"] == 0, (
        "every process artifact was excluded, so any rule needing a process "
        "cannot fire -- and the verdict does not say so"
    )


def test_arriving_evidence_can_displace_evidence_already_analysable():
    """Adding valid evidence can REMOVE other valid evidence from the analysis.

    Reproduces what a real fix did: recovering 48 previously-dropped
    process-creation events pushed the last analysable process artifacts past
    the cut, and the verdict changed as a result -- from evidence gained, but
    by evidence lost.
    """
    network = [_artifact("network_flow", n) for n in range(_MAX_ARTIFACTS - 40)]
    processes = [_artifact("memory_process", n) for n in range(100)]
    newly_recovered = [_artifact("windows_event_log", n) for n in range(48)]

    before = _admitted(network + processes)
    after = _admitted(network + newly_recovered + processes)

    assert before["memory_process"] == 40
    assert after["memory_process"] == 0
    assert after["windows_event_log"] == 40
    assert before.total() == after.total() == _MAX_ARTIFACTS, (
        "the analysed set stayed the same size; only its composition changed"
    )


def test_the_engine_reports_the_rejection_rather_than_hiding_it():
    """add_artifact returns False for the overflow, which callers must honour.

    The disclosure is what keeps this a documented limitation instead of a
    silent one: vigia_scorer records each rejected artifact and names the limit
    as the cause, separately from a by-design whitelist rejection.
    """
    engine = CrossArtifactIncongruenceEngine()
    for n in range(_MAX_ARTIFACTS):
        assert engine.add_artifact(_artifact("network_flow", n)) is True

    over_the_line = _artifact("memory_process", 0)
    assert engine.add_artifact(over_the_line) is False
    assert over_the_line.evidence_type in {"memory_process"}, (
        "the rejected artifact is of a type the engine does analyse -- it was "
        "refused for its position, not its content"
    )
