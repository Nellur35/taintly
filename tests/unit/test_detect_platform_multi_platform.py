"""``detect_platform`` returns None when 2+ platforms are present.

Anchors the multi-platform detection fix.  The prior implementation
returned the first match in ``has_github → has_gitlab → has_jenkins``
order, so any repo with both ``.github/workflows/`` and a
``Jenkinsfile`` (a common shape during CI migrations and in projects
that publish via multiple CI systems) had its Jenkinsfile silently
dropped from scan coverage.

With the new behaviour, ``detect_platform`` returns None whenever
multiple signals are present, and ``scan_repo``'s existing fallback
path probes all three platforms via ``discover_files``.  This is the
same shape as the pre-existing github+gitlab dual-platform handling
— now generalised to all combinations.
"""

from __future__ import annotations

from pathlib import Path

from taintly.engine import detect_platform
from taintly.models import Platform


def _touch(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("# placeholder\n", encoding="utf-8")


def test_detects_github_only(tmp_path):
    _touch(tmp_path / ".github" / "workflows" / "ci.yml")
    assert detect_platform(str(tmp_path)) == Platform.GITHUB


def test_detects_gitlab_only(tmp_path):
    _touch(tmp_path / ".gitlab-ci.yml")
    assert detect_platform(str(tmp_path)) == Platform.GITLAB


def test_detects_jenkins_only(tmp_path):
    _touch(tmp_path / "Jenkinsfile")
    assert detect_platform(str(tmp_path)) == Platform.JENKINS


def test_detects_jenkins_variant_only(tmp_path):
    _touch(tmp_path / "Jenkinsfile.release")
    assert detect_platform(str(tmp_path)) == Platform.JENKINS


def test_returns_none_when_github_and_jenkins(tmp_path):
    """The common cross-platform shape — repos that publish via
    both GitHub Actions and a Jenkinsfile previously had their
    Jenkinsfile silently skipped."""
    _touch(tmp_path / ".github" / "workflows" / "ci.yml")
    _touch(tmp_path / "Jenkinsfile")
    assert detect_platform(str(tmp_path)) is None


def test_returns_none_when_gitlab_and_jenkins(tmp_path):
    _touch(tmp_path / ".gitlab-ci.yml")
    _touch(tmp_path / "Jenkinsfile")
    assert detect_platform(str(tmp_path)) is None


def test_returns_none_when_github_and_gitlab(tmp_path):
    """Existing behaviour — preserved by the new generalised logic."""
    _touch(tmp_path / ".github" / "workflows" / "ci.yml")
    _touch(tmp_path / ".gitlab-ci.yml")
    assert detect_platform(str(tmp_path)) is None


def test_returns_none_when_all_three(tmp_path):
    _touch(tmp_path / ".github" / "workflows" / "ci.yml")
    _touch(tmp_path / ".gitlab-ci.yml")
    _touch(tmp_path / "Jenkinsfile")
    assert detect_platform(str(tmp_path)) is None


def test_returns_none_when_empty_repo(tmp_path):
    assert detect_platform(str(tmp_path)) is None


def test_detects_github_via_dependabot_alone(tmp_path):
    """Regression: a repo with only ``.github/dependabot.yml`` (no
    workflows dir) still detects GitHub."""
    _touch(tmp_path / ".github" / "dependabot.yml")
    assert detect_platform(str(tmp_path)) == Platform.GITHUB
