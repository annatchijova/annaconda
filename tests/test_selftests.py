"""Pytest wrappers around the module-embedded self-tests.

The historical test suites live inline in their modules (``python3 -m <module>``
runs them). These wrappers make them visible to pytest/CI without rewriting
them. Two honest tiers, kept distinct on purpose:

- ASSERT_SUITES: modules whose __main__ block is a real assert-based suite.
  Passing means "verified correct".
- SMOKE_DEMOS: modules whose __main__ block is a demo run. Passing means only
  "ran without crashing" — weaker, and labeled as such (see CLAUDE.md section
  on honest degradation: a green that cannot distinguish the two is forbidden).
"""

import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent

ASSERT_SUITES = [
    "sift.sans_phase",
    "inference.abductive_reasoner_v2",
]

SMOKE_DEMOS = [
    "tools.caie",
    "core.hallucination_guard",
]

SUCCESS_MARKER = "TODOS LOS TESTS PASARON"


def _run_module(module: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", module],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=300,
    )


@pytest.mark.parametrize("module", ASSERT_SUITES)
def test_inline_assert_suite(module):
    proc = _run_module(module)
    assert proc.returncode == 0, (
        f"{module} self-test failed (exit {proc.returncode}):\n"
        f"{proc.stdout[-2000:]}\n{proc.stderr[-2000:]}"
    )
    assert SUCCESS_MARKER in proc.stdout, (
        f"{module} exited 0 but did not print the success marker — "
        f"the suite may not have run at all:\n{proc.stdout[-2000:]}"
    )


@pytest.mark.parametrize("module", SMOKE_DEMOS)
def test_inline_smoke_demo(module):
    """Smoke tier only: asserts the demo runs to completion, not correctness."""
    proc = _run_module(module)
    assert proc.returncode == 0, (
        f"{module} demo crashed (exit {proc.returncode}):\n"
        f"{proc.stdout[-2000:]}\n{proc.stderr[-2000:]}"
    )
