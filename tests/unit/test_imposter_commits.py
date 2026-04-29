"""Unit tests for SEC3-GH-009 (imposter-commit detection) and the
underlying ``taintly.platform.github_sha_verify`` cache module.

The rule itself depends on a network call to the GitHub Commits API.
Tests inject a stub via ``set_verifier_override`` so no real HTTP
traffic happens; the cache logic is exercised via the same module-
level state the production code uses.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from taintly.engine import scan_file
from taintly.models import Platform
from taintly.platform import github_sha_verify
from taintly.rules.registry import load_all_rules


@pytest.fixture(autouse=True)
def _reset_verifier_state():
    """Each test starts with a fresh, disabled, empty verifier."""
    github_sha_verify.set_enabled(False)
    github_sha_verify.set_verifier_override(None)
    github_sha_verify.reset_cache()
    yield
    github_sha_verify.set_enabled(False)
    github_sha_verify.set_verifier_override(None)
    github_sha_verify.reset_cache()


@pytest.fixture(scope="module")
def gh_rules():
    return [r for r in load_all_rules() if r.platform == Platform.GITHUB]


def _write_workflow(tmp_path: Path, content: str) -> Path:
    p = tmp_path / "workflow.yml"
    p.write_text(content)
    return p


# ---------------------------------------------------------------------------
# Cache and verifier-override semantics
# ---------------------------------------------------------------------------


def test_cache_returns_overridden_verdict():
    github_sha_verify.set_verifier_override(lambda o, r, s: True)
    assert github_sha_verify.is_sha_reachable("acme", "act", "a" * 40) is True


def test_cache_avoids_double_call_for_same_sha():
    calls: list[tuple[str, str, str]] = []

    def stub(owner: str, repo: str, sha: str):
        calls.append((owner, repo, sha))
        return False

    github_sha_verify.set_verifier_override(stub)

    sha = "0" * 40
    assert github_sha_verify.is_sha_reachable("acme", "act", sha) is False
    assert github_sha_verify.is_sha_reachable("acme", "act", sha) is False
    assert len(calls) == 1, (
        f"Cache must collapse repeated checks for the same SHA, got {len(calls)} calls"
    )


def test_indeterminate_verdict_is_not_cached():
    """A ``None`` outcome (rate limit / transport error) must NOT be
    cached so the next invocation can retry rather than re-using an
    'unknown' verdict.
    """
    sequence = iter([None, True])

    def stub(owner: str, repo: str, sha: str):
        return next(sequence)

    github_sha_verify.set_verifier_override(stub)

    sha = "1" * 40
    assert github_sha_verify.is_sha_reachable("acme", "act", sha) is None
    assert github_sha_verify.is_sha_reachable("acme", "act", sha) is True


# ---------------------------------------------------------------------------
# Rule behaviour
# ---------------------------------------------------------------------------


_PINNED_WORKFLOW = (
    "name: CI\n"
    "on: push\n"
    "permissions:\n"
    "  contents: read\n"
    "jobs:\n"
    "  build:\n"
    "    runs-on: ubuntu-latest\n"
    "    steps:\n"
    # Two distinct SHA-pinned actions for the same scan.
    "      - uses: actions/checkout@deadbeefdeadbeefdeadbeefdeadbeefdeadbeef\n"
    "      - uses: some-org/some-action@cafebabecafebabecafebabecafebabecafebabe\n"
)


def test_rule_silent_when_flag_disabled(tmp_path: Path, gh_rules):
    """Default state: the flag is off, so the rule must not fire even
    when we'd otherwise call the verifier.
    """
    fixture = _write_workflow(tmp_path, _PINNED_WORKFLOW)
    findings = scan_file(str(fixture), gh_rules)
    fired = [f for f in findings if f.rule_id == "SEC3-GH-009"]
    assert not fired


def test_rule_fires_on_orphan_sha(tmp_path: Path, gh_rules):
    github_sha_verify.set_enabled(True)
    github_sha_verify.set_verifier_override(lambda o, r, s: False)

    fixture = _write_workflow(tmp_path, _PINNED_WORKFLOW)
    findings = scan_file(str(fixture), gh_rules)
    fired = [f for f in findings if f.rule_id == "SEC3-GH-009"]
    # Two SHA-pinned uses: refs in the fixture, both stubbed orphan.
    assert len(fired) == 2, (
        f"Expected one finding per orphan SHA-pinned uses: ref, got "
        f"{len(fired)}: {[(f.line, f.snippet) for f in fired]}"
    )
    # Snippet cites the owner/repo and a short SHA.
    assert all("@" in f.snippet for f in fired)


def test_rule_silent_on_reachable_sha(tmp_path: Path, gh_rules):
    github_sha_verify.set_enabled(True)
    github_sha_verify.set_verifier_override(lambda o, r, s: True)

    fixture = _write_workflow(tmp_path, _PINNED_WORKFLOW)
    findings = scan_file(str(fixture), gh_rules)
    fired = [f for f in findings if f.rule_id == "SEC3-GH-009"]
    assert not fired


def test_rule_silent_on_indeterminate_verdict(tmp_path: Path, gh_rules):
    """A network blip (verifier returns None) must NOT produce a
    SEC3-GH-009 finding — only definitive 404s do.
    """
    github_sha_verify.set_enabled(True)
    github_sha_verify.set_verifier_override(lambda o, r, s: None)

    fixture = _write_workflow(tmp_path, _PINNED_WORKFLOW)
    findings = scan_file(str(fixture), gh_rules)
    fired = [f for f in findings if f.rule_id == "SEC3-GH-009"]
    assert not fired


def test_rule_skips_non_sha_pinned_refs(tmp_path: Path, gh_rules):
    """Tag- and branch-pinned refs are SEC3-GH-001's scope; SEC3-GH-009
    only fires on full 40-char SHA pins.
    """
    github_sha_verify.set_enabled(True)
    github_sha_verify.set_verifier_override(lambda o, r, s: False)

    fixture = _write_workflow(
        tmp_path,
        "jobs:\n  build:\n    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "      - uses: actions/setup-node@main\n"
        "      - uses: short-sha/short@deadbeef\n",  # 8 hex, not 40
    )
    findings = scan_file(str(fixture), gh_rules)
    fired = [f for f in findings if f.rule_id == "SEC3-GH-009"]
    assert not fired


def test_rule_skips_commented_uses(tmp_path: Path, gh_rules):
    github_sha_verify.set_enabled(True)
    github_sha_verify.set_verifier_override(lambda o, r, s: False)

    fixture = _write_workflow(
        tmp_path,
        "jobs:\n  build:\n    steps:\n"
        "      # - uses: actions/checkout@deadbeefdeadbeefdeadbeefdeadbeefdeadbeef\n"
        "      - run: echo hi\n",
    )
    findings = scan_file(str(fixture), gh_rules)
    fired = [f for f in findings if f.rule_id == "SEC3-GH-009"]
    assert not fired
