"""Deterministic tool layer for the annaconda purple-team agent.

These are the functions the ADK agent is allowed to call. They are plain,
type-hinted, docstring'd Python (ADK introspects the signatures and docstrings
to build the tool schema Gemini sees) and they import nothing from ADK or
Gemini — so the whole layer is testable offline and deterministically.

The security stance is encoded in the signatures, not in a prompt:
- The agent can only NAME curated hunts (validated against the VQL registry);
  it cannot author VQL or pass a raw query.
- The agent cannot pass a score, a verdict, or a hash anywhere. Adjudication
  runs the deterministic core and SEALS the result; the tool re-verifies the
  seal before returning, so a model that tried to fabricate is overruled by
  the seal, not trusted.
- Every tool call is appended to an in-session audit trail (chain of custody
  of the investigation itself).

One PurpleTeamSession instance holds the state for one investigation; its
bound methods are handed to the ADK Agent as tools.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from core.verdict_stream import (
    GENESIS_HASH, append_entry, build_stream_entry, verify_stream,
)
from tools.velociraptor.adapter import (
    AdapterError, Transport, collect_window, verify_window, window_to_case,
)
from tools.velociraptor.vql_templates import TEMPLATES

# Safe default parameter slots per template. The agent chooses WHICH hunts to
# run; the session fills the vetted parameter values. (Letting the agent fill
# IOC slots is a deliberate later step — see PLAN.md; v1 keeps params off the
# model entirely.)
_DEFAULT_PARAMS: dict[str, dict] = {
    "process_creation_evtx": {"Channel": "Security"},
}

_TS_FMT = "%Y-%m-%dT%H:%M:%SZ"


def _fmt_ts(value: datetime) -> str:
    return value.strftime(_TS_FMT)


class PurpleTeamSession:
    """State for one live investigation, exposing tools as bound methods.

    Deterministic when constructed with a MockTransport and a ``time_base``
    (mock/replay/demo); live when constructed with a RestTransport and no
    time base (wall clock recorded as evidence, same discipline as the
    live_runner).
    """

    def __init__(self, transport: Transport, *, case_id: str, host: dict,
                 examiner_id: str, out_dir: str | Path,
                 source: str = "velociraptor",
                 time_base: Optional[str] = None, interval_s: int = 60,
                 start_sequence: int = 0, start_prev_hash: str = GENESIS_HASH):
        if not examiner_id or not examiner_id.strip():
            raise ValueError("examiner_id is required (chain of custody)")
        self.transport = transport
        self.case_id = case_id
        self.host = dict(host)
        self.examiner_id = examiner_id.strip()
        self.source = source
        self.interval_s = interval_s
        self._time_base = (
            datetime.strptime(time_base, _TS_FMT).replace(tzinfo=timezone.utc)
            if time_base else None
        )
        self.out_dir = Path(out_dir)
        (self.out_dir / "windows").mkdir(parents=True, exist_ok=True)
        self.stream_path = self.out_dir / "stream.jsonl"
        # Chain continuation: an investigation run INTO an existing case picks
        # up the case's next sequence number and previous seal, so the case's
        # sealed chain stays one unbroken record across many runs — the model
        # a forensic examiner needs (verdicts for a host accumulate over time
        # into a single tamper-evident case).
        self._seq = start_sequence
        self._windows: dict[str, dict] = {}
        self._prev_entry_hash = start_prev_hash
        self._entries: list[dict] = []
        self.audit_trail: list[dict] = []

    # -- audit -------------------------------------------------------------

    def _audit(self, action: str, detail: dict) -> None:
        self.audit_trail.append({
            "seq": len(self.audit_trail),
            "action": action,
            "detail": detail,
        })

    def _window_span(self) -> tuple[str, str]:
        """Time bounds for the next window. Deterministic from time_base in
        mock mode; wall clock in live mode (recorded as evidence)."""
        if self._time_base is not None:
            start = self._time_base + timedelta(seconds=self._seq * self.interval_s)
            end = start + timedelta(seconds=self.interval_s)
        else:
            now = datetime.now(timezone.utc)
            start, end = now - timedelta(seconds=self.interval_s), now
        return _fmt_ts(start), _fmt_ts(end)

    # -- tools (handed to the ADK agent) -----------------------------------

    def list_available_hunts(self) -> dict:
        """List the curated hunt collections the investigator may run.

        Returns the available hunt ids and what each collects. These are the
        ONLY hunts that can run: raw or ad-hoc queries are not permitted.
        """
        hunts = {
            tid: {
                "collects": t["description"],
                "evidence_type": t["evidence_type"],
            }
            for tid, t in sorted(TEMPLATES.items())
        }
        self._audit("list_available_hunts", {"count": len(hunts)})
        return {"hunts": hunts}

    def run_hunt(self, hunt_ids: list[str], reason: str) -> dict:
        """Run one or more curated hunts and freeze a sealed evidence window.

        Use this to collect endpoint telemetry for the current time window.
        ``hunt_ids`` must be ids returned by list_available_hunts. ``reason``
        is your stated investigative purpose (recorded in the audit trail).

        Returns a SUMMARY of the frozen window — window id, sequence, how many
        artifacts and over what time span, and how many rows were dropped. It
        does NOT return a verdict: call adjudicate(window_id) for that.
        """
        if not isinstance(hunt_ids, list) or not hunt_ids:
            return {"error": "hunt_ids must be a non-empty list of hunt ids"}
        unknown = [h for h in hunt_ids if h not in TEMPLATES]
        if unknown:
            return {"error": f"unknown hunt ids {unknown}; "
                             f"call list_available_hunts first"}

        requests = [(h, _DEFAULT_PARAMS.get(h, {})) for h in hunt_ids]
        start, end = self._window_span()
        try:
            window, reports = collect_window(
                self.transport, case_id=self.case_id, sequence=self._seq,
                source=self.source, host=self.host,
                time_start_utc=start, time_end_utc=end,
                examiner_id=self.examiner_id, requests=requests,
            )
        except AdapterError as exc:
            # A hunt that cannot be collected must not crash the investigation
            # — the agent gets a plain error and can try a different hunt.
            self._audit("run_hunt_failed", {"hunt_ids": hunt_ids, "error": str(exc)})
            return {"error": f"hunt {hunt_ids} could not be collected: {exc}"}
        window_path = self.out_dir / "windows" / f"window-{self._seq:06d}.json"
        window_path.write_text(
            json.dumps(window, sort_keys=True, ensure_ascii=True, indent=1),
            encoding="utf-8",
        )
        self._windows[window["window_id"]] = window
        self._seq += 1

        dropped = sum(r.get("dropped_no_timestamp", 0) for r in reports)
        summary = {
            "window_id": window["window_id"],
            "sequence": window["sequence"],
            "time_span": f"{start} to {end}",
            "artifacts": len(window["artifacts"]),
            "rows_dropped": dropped,
            "window_hash": window["window_hash"][:16],
            "note": "window frozen and sealed; call adjudicate() to get the verdict",
        }
        self._audit("run_hunt",
                    {"hunt_ids": hunt_ids, "reason": reason, **summary})
        return summary

    def adjudicate(self, window_id: str) -> dict:
        """Adjudicate a frozen evidence window and return the SEALED verdict.

        Runs the deterministic forensic core over the window and seals the
        result into the tamper-evident verdict chain. The verdict, score,
        confidence, and MITRE techniques are produced by the engine and are
        FINAL — you cannot change them, and you must report them exactly as
        returned. If you state anything that contradicts this sealed result,
        you are wrong; the seal is authoritative.
        """
        window = self._windows.get(window_id)
        if window is None:
            return {"error": f"unknown window_id {window_id!r}; "
                             f"run_hunt first, then adjudicate the id it returns"}

        # Integrity gate: never adjudicate a window whose seal does not hold.
        if not verify_window(window):
            return {"error": f"window {window_id} failed its seal check — "
                             f"refusing to adjudicate tampered evidence"}

        from vigia_scorer import _vigia_score  # heavy import, deferred
        result = _vigia_score(window_to_case(window))
        entry = build_stream_entry(
            window=window, scorer_result=result,
            prev_entry_hash=self._prev_entry_hash,
        )
        append_entry(self.stream_path, entry)
        self._entries.append(entry)
        self._prev_entry_hash = entry["entry_hash"]

        verdict = {
            "window_id": window_id,
            "sequence": entry["sequence"],
            "verdict_state": entry["verdict"]["state"],
            "score": entry["verdict"]["score"],
            "confidence": entry["verdict"]["confidence"],
            "mitre_techniques": entry["verdict"]["mitre_techniques"],
            "determinism_level": entry["verdict"]["determinism_level"],
            "entry_hash": entry["entry_hash"],
            "sealed": True,
        }
        self._audit("adjudicate", verdict)
        return verdict

    def verify_chain(self) -> dict:
        """Verify the integrity of the sealed verdict chain so far.

        Re-checks that every sealed verdict still matches its content and that
        no entry was altered, inserted, reordered, or dropped. Use this to
        assure the examiner the record is intact.
        """
        report = verify_stream(
            self._entries,
            windows={w["window_hash"]: w for w in self._windows.values()},
        )
        out = {
            "chain_ok": report["chain_ok"],
            "sealed_verdicts": report["entries"],
            "errors": report["errors"],
        }
        self._audit("verify_chain", out)
        return out
