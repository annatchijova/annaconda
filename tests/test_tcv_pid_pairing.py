"""TEMPORAL_CAUSALITY_VIOLATION must pair artifacts that belong together.

The rule reads "network activity happened before the process that caused it".
Deciding that requires knowing the network event and the process are the same
execution -- otherwise any host whose oldest connection predates its newest
process (that is: every host) fabricates a severity-1.0 fracture whose text
claims "the originating process" about two unrelated PIDs.

This was invisible while the only telemetry carrying the structured event
times was a fixture annotating exactly one hand-picked pair. It surfaces the
moment real Velociraptor rows carry their own event times.

Doctrine followed here, matching the rule's existing M1 comment:
  - two KNOWN and different PIDs are a determinate answer ("not the same
    execution"), so the pair is simply not evaluated and nothing is recorded;
  - a MISSING PID is decision-relevant missing data, so the pair is recorded
    in temporal_pairs_skipped rather than silently treated either way.
"""

from tools.caie import Artifact, CrossArtifactIncongruenceEngine

BOOT_CONN = "2026-08-12T08:00:30Z"      # svchost's connection, from boot
LATE_PROC = "2026-08-12T14:30:00Z"      # chrome, started six hours later


def _net(pid=None, when=BOOT_CONN, tool="velociraptor"):
    md = {"network_log_time": when}
    if pid is not None:
        md["pid"] = pid
    return Artifact(source_tool=tool, evidence_type="network_flow",
                    raw_score=0.05, description="connection", metadata=md,
                    timestamp=when)


def _proc(pid=None, when=LATE_PROC, tool="velociraptor"):
    md = {"process_creation_time": when}
    if pid is not None:
        md["pid"] = pid
    return Artifact(source_tool=tool, evidence_type="memory_process",
                    raw_score=0.05, description="process", metadata=md,
                    timestamp=when)


def _fractures_of(*artifacts):
    engine = CrossArtifactIncongruenceEngine()
    for a in artifacts:
        engine.add_artifact(a)
    found = engine.detect_fractures()
    tcv = [f for f in found if f.fracture_type == "TEMPORAL_CAUSALITY_VIOLATION"]
    return tcv, engine


def test_unrelated_pids_on_a_clean_host_produce_no_violation():
    """The regression: svchost's boot connection vs chrome started later.

    Both event times are genuine and correctly reported. They belong to
    different processes, so no causal claim can be made between them.
    """
    tcv, engine = _fractures_of(_net(pid=612), _proc(pid=3320))
    assert tcv == [], (
        "fabricated a temporal-causality violation between PID 612's "
        "connection and unrelated PID 3320's creation")
    assert engine._temporal_pairs_skipped == [], (
        "two known, different PIDs are a determinate answer, not missing "
        "data -- recording a skip would drive an otherwise clean host to "
        "ABSTAIN on every collection")


def test_same_pid_violation_still_fires():
    """The demo's finding must survive: a beacon before its own process."""
    tcv, _ = _fractures_of(_net(pid=6120), _proc(pid=6120))
    assert len(tcv) == 1, "the real structural impossibility stopped firing"
    assert tcv[0].severity == 1.0
    assert tcv[0].ttp_id == "T1070.006"


def test_missing_pid_is_recorded_as_unevaluated_not_as_a_fracture():
    """No PID on either side: the link cannot be established, so the pair is
    disclosed as unevaluated rather than asserted or silently dropped."""
    tcv, engine = _fractures_of(_net(pid=None), _proc(pid=None))
    assert tcv == [], "asserted causality between artifacts with no PID link"
    skipped = engine._temporal_pairs_skipped
    assert skipped, "the unevaluated pair was dropped silently"
    assert any(s.get("rule") == "TEMPORAL_CAUSALITY_VIOLATION" for s in skipped)


def test_one_side_missing_a_pid_is_also_unevaluated():
    tcv, engine = _fractures_of(_net(pid=612), _proc(pid=None))
    assert tcv == []
    assert engine._temporal_pairs_skipped


def test_pid_comparison_survives_string_versus_int():
    """Velociraptor returns Pid as a number; other analyzers report strings.
    The same process must not read as two just because of the JSON type."""
    tcv, _ = _fractures_of(_net(pid="6120"), _proc(pid=6120))
    assert len(tcv) == 1, "same PID missed across int/str representations"


# --------------------------------------------------------------------------
# PID 0 -- observed in real Windows telemetry: 59% of a netstat collection,
# all TIME_WAIT sockets with no owning process.
# --------------------------------------------------------------------------

def test_sockets_with_no_owning_process_do_not_pair_with_each_other():
    """PID 0 is a sentinel for "no owner", not an id two rows can share.

    Without this, hundreds of unrelated closed sockets all carry pid 0 and
    match each other the moment the structured event times get derived --
    which is precisely the work still outstanding.
    """
    tcv, _ = _fractures_of(_net(pid=0), _proc(pid=0))
    assert tcv == [], "two 'no owning process' rows were treated as one execution"


def test_a_no_owner_socket_does_not_pair_with_a_real_process():
    tcv, _ = _fractures_of(_net(pid=0), _proc(pid=4212))
    assert tcv == []


def test_no_owner_is_a_determinate_answer_not_a_disclosed_gap():
    """It must not reach temporal_pairs_skipped: that gate turns an otherwise
    clean verdict into ABSTAIN, and "this socket has no owner" is knowledge,
    not missing data."""
    _, engine = _fractures_of(_net(pid=0), _proc(pid=4212))
    assert engine._temporal_pairs_skipped == []


def test_a_real_pid_still_fires_alongside_no_owner_noise():
    """The signal must survive the noise: a genuine same-PID violation still
    fires in a window full of ownerless sockets."""
    artifacts = [_net(pid=0) for _ in range(50)]
    artifacts += [_net(pid=6120), _proc(pid=6120)]
    tcv, _ = _fractures_of(*artifacts)
    assert len(tcv) == 1, "the real violation was lost among ownerless sockets"
    assert tcv[0].severity == 1.0
