"""PathGuard must refuse a path that is redirected out of its allowlist.

The allowlist is evaluated on the LEXICAL path, deliberately: resolving first
would lose the evidence that the path crossed a redirection. That makes the
redirection check the whole of the confinement, so anything the check does not
recognise is a way out of the allowlist.

``is_symlink()`` does not recognise a Windows junction. A junction is a
directory reparse point, any unprivileged user can create one with ``mklink /J``,
and it redirects exactly like a symlink -- but ``Path.is_symlink()`` and
``os.path.islink()`` both return False for it. Nothing else caught it either:
the S_ISREG check passes because the target really is a regular file, and
``O_NOFOLLOW`` does not exist on Windows, so ``safe_open`` has no second line.

Verified on Windows 11 / Python 3.12 before the fix: the file read directly was
rejected OUTSIDE_ALLOWLIST, and the same file reached through a junction planted
inside the allowed directory validated VALID and ``safe_read()`` returned its
contents.

PathGuard guards evidence paths in sift/memory_forensics.py,
sift/registry_timeline_reconstructor.py and sift/sift_orchestrator.py, whose
comment states "PathGuard sigue rechazando symlinks, TOCTOU" as the reason the
allowlist can be widened safely. These tests exist so that claim is checked on
the platform where it was false, and had no test coverage at all.
"""

import os
import subprocess
import sys

import pytest

from core.path_guard import PathGuard

WINDOWS = sys.platform == "win32"


def _make_redirect(link, target):
    """A directory redirection, in whatever form this platform offers.

    Junction rather than symlink on Windows on purpose: a symlink needs
    Developer Mode or elevation, a junction needs neither, so the junction is
    both the weaker assumption for an attacker and the case that was missed.
    """
    if WINDOWS:
        subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)],
                       capture_output=True, check=True)
    else:
        os.symlink(str(target), str(link))


@pytest.fixture
def tree(tmp_path):
    """An allowed directory, a secret outside it, and a redirection between."""
    allowed = tmp_path / "allowed"
    secret = tmp_path / "secret"
    allowed.mkdir()
    secret.mkdir()
    (secret / "loot.txt").write_text("evidence the guard must not hand over")
    (allowed / "real.txt").write_text("a file that is genuinely inside")
    _make_redirect(allowed / "link", secret)
    return allowed, secret


def test_a_file_outside_the_allowlist_is_refused(tree):
    """Negative control: without a redirection the guard already says no.

    If this ever passes, the tests below prove nothing -- they would be
    measuring a guard that rejects everything.
    """
    allowed, secret = tree
    result = PathGuard(allowed_base_paths=[str(allowed)]).validate(
        str(secret / "loot.txt"))
    assert result.valid is False
    assert result.reason == "OUTSIDE_ALLOWLIST"


def test_a_file_genuinely_inside_the_allowlist_is_admitted(tree):
    """The other control: the guard is not simply refusing everything."""
    allowed, _ = tree
    result = PathGuard(allowed_base_paths=[str(allowed)]).validate(
        str(allowed / "real.txt"))
    assert result.valid is True, result.reason


def test_the_same_file_reached_through_a_redirection_is_refused(tree):
    """The bypass: lexically inside, actually outside.

    On Windows this is a junction, which is_symlink() reports as False. The
    path is inside the allowlist by every textual measure and the target is a
    perfectly regular file, so the reparse tag is the only thing left to catch
    it.
    """
    allowed, _ = tree
    result = PathGuard(allowed_base_paths=[str(allowed)]).validate(
        str(allowed / "link" / "loot.txt"))
    assert result.valid is False, (
        "a redirection out of the allowlist was accepted: the guard confines "
        "nothing an attacker can plant a junction inside"
    )
    assert result.reason in {"SYMLINK_DETECTED_IN_PATH",
                             "REPARSE_POINT_DETECTED_IN_PATH"}


def test_reading_through_the_redirection_is_refused_too(tree):
    """validate() and safe_read() must agree; the read is what leaks the file."""
    allowed, _ = tree
    guard = PathGuard(allowed_base_paths=[str(allowed)])
    with pytest.raises(PermissionError):
        guard.safe_read(str(allowed / "link" / "loot.txt"))


@pytest.mark.skipif(not WINDOWS, reason="junction semantics are Windows-only")
def test_a_junction_is_not_reported_as_a_symlink(tree):
    """Pins WHY the check needed widening, so the fix cannot be undone by tidying.

    Deleting the reparse-tag check because "is_symlink already covers it" is
    the obvious cleanup, and it would silently reopen the hole. This records
    that the two predicates disagree on Windows.
    """
    allowed, _ = tree
    junction = allowed / "link"
    assert junction.is_symlink() is False
    assert os.path.islink(str(junction)) is False
    assert getattr(os.lstat(str(junction)), "st_reparse_tag", 0)
