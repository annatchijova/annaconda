"""The sandbox's public functions must actually be callable.

security/__init__ exports sandboxed_execute and safe_grep, and safe_grep is the
P0 remediation for "search_pattern ran arbitrary subprocesses with no memory
limits, no depth caps and no path confinement". None of that matters while the
function raises on the first line of its body.

It did, on every platform. The body opened with `from vigia.security import
_sanitize_path, audit_logger` and no `vigia` package exists in this repository,
so any real call ended in ModuleNotFoundError.

That is the SECOND time the same line broke the same function. Its own comment
records the first: "audit_logger: TANDA 2 -- estaba SIN bindear en este modulo;
safe_grep crasheaba con NameError en la primera llamada real. Latente porque el
corpus JSON no ejercita grep." The repair for a function nothing calls was
itself never called, so a NameError became a ModuleNotFoundError on the same
line, hidden by the same absence.

These tests exist to end that cycle: they call the functions. An import-shaped
regression fails here instead of waiting for a real incident.
"""

import asyncio
import sys

import pytest

from security import safe_grep, sandboxed_execute

WINDOWS = sys.platform == "win32"
NEEDLE = "AGUJA-SANDBOX-CALLABLE-7F3A21"


@pytest.fixture
def haystack(tmp_path):
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "hit.txt").write_text(f"{NEEDLE} lives here\n")
    (tmp_path / "miss.txt").write_text("nothing of interest\n")
    return tmp_path


def test_sandboxed_execute_runs_a_command():
    """The sandbox itself: exercised on the platform's own event loop.

    Windows defaults to ProactorEventLoop, where asyncio subprocess handling
    differs from the selector loop used on POSIX, so "it works on Linux" is not
    evidence for this path.
    """
    echo = ["cmd", "/c", "echo", NEEDLE] if WINDOWS else ["echo", NEEDLE]
    result = asyncio.run(sandboxed_execute(echo))

    assert result["returncode"] == 0, result.get("error")
    assert NEEDLE.encode() in result["stdout"]
    assert result["error"] is None


def test_safe_grep_is_callable_at_all(haystack):
    """The regression guard for the import: reaching a RESULT, not an exception.

    Deliberately weak about the search outcome and strict about the call. A
    broken import raised before any search could happen, so what has to be
    pinned is that the function runs and answers in its documented shape. The
    outcome itself depends on tools this repository does not ship.
    """
    result = asyncio.run(safe_grep(NEEDLE, str(haystack)))

    assert isinstance(result, dict)
    assert {"matches", "truncated", "error"} <= set(result)


def test_a_failed_scan_is_never_reported_as_a_clean_one(haystack):
    """Whatever happens, "found nothing" must not be how a broken scan looks.

    The needle is definitely present. So either the scan worked and found it,
    or the scan failed and says so -- an empty match list with error=None would
    mean the caller is told the directory is clean when it was never read.
    """
    result = asyncio.run(safe_grep(NEEDLE, str(haystack)))

    if result["error"] is None:
        assert result["matches"], (
            "the scan reported success and no matches, for a directory that "
            "contains the needle: a failed scan wearing a clean verdict"
        )
    else:
        assert result["matches"] == []


@pytest.mark.skipif(WINDOWS, reason="needs the POSIX find/xargs/grep trio")
def test_safe_grep_finds_the_needle_on_posix(haystack):
    """Where the tools exist, the search must actually work."""
    result = asyncio.run(safe_grep(NEEDLE, str(haystack)))

    assert result["error"] is None, result["error"]
    assert any("hit.txt" in str(m) for m in result["matches"]), result["matches"]


@pytest.mark.skipif(not WINDOWS, reason="documents a Windows-only tool collision")
def test_on_windows_the_scan_fails_loudly_rather_than_silently(haystack):
    """Windows resolves "find" to System32\\find.exe, a different tool entirely.

    CreateProcess searches the system directory before PATH, so the argv-0
    "find" reaches Windows' string-search utility rather than GNU find, even
    when shutil.which() reports the GNU one. It rejects -maxdepth/-print0 with
    "FIND: Parameter format not correct" and exits 2.

    Pinned because the honest failure is the valuable part: the caller learns
    the scan did not happen. If this ever starts passing with error=None the
    search began working and the skip above should go.
    """
    result = asyncio.run(safe_grep(NEEDLE, str(haystack)))

    assert result["error"] is not None
    assert result["matches"] == []
