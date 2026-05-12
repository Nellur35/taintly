"""SEC4-GH-005 downstream consumer-set extension coverage.

The 11 tests below pin the artipacked-style consumer set: pypa-publish,
peter-evans/create-pull-request, softprops/action-gh-release, and the
cibuildwheel -> pypa-publish two-step are TPs; lint / CodeQL / docker
build-without-push / persist-credentials:false stay suppressed; shell
git push and pre-existing documented push actions still fire.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from taintly.engine import scan_file
from taintly.models import Platform
from taintly.rules.registry import load_rules_for_platform


@pytest.fixture(scope="module")
def github_rules():
    return load_rules_for_platform(Platform.GITHUB)


def _write_workflow(tmp_path: Path, content: str) -> Path:
    target = tmp_path / ".github" / "workflows" / "ci.yml"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    return target


def _sec4_gh_005_findings(tmp_path: Path, content: str, github_rules) -> list:
    wf = _write_workflow(tmp_path, content)
    return [f for f in scan_file(str(wf), github_rules) if f.rule_id == "SEC4-GH-005"]


# ---------------------------------------------------------------------------
# True positives — new consumers
# ---------------------------------------------------------------------------


def test_pypa_publish_fires(tmp_path, github_rules):
    findings = _sec4_gh_005_findings(
        tmp_path,
        "name: release\n"
        "on: [push]\n"
        "jobs:\n"
        "  pypi:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "      - run: python -m build\n"
        "      - uses: pypa/gh-action-pypi-publish@release/v1\n",
        github_rules,
    )

    assert findings, "checkout + pypa-publish in same job must fire SEC4-GH-005"


def test_peter_evans_create_pull_request_fires(tmp_path, github_rules):
    findings = _sec4_gh_005_findings(
        tmp_path,
        "name: bump-deps\n"
        "on:\n  schedule:\n    - cron: '0 6 * * *'\n"
        "jobs:\n"
        "  bump:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "      - run: ./scripts/bump.sh\n"
        "      - uses: peter-evans/create-pull-request@v6\n",
        github_rules,
    )

    assert findings, "checkout + peter-evans/create-pull-request must fire SEC4-GH-005"


def test_softprops_action_gh_release_fires(tmp_path, github_rules):
    findings = _sec4_gh_005_findings(
        tmp_path,
        "name: release\n"
        "on:\n  push:\n    tags: ['v*']\n"
        "jobs:\n"
        "  release:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "      - run: make dist\n"
        "      - uses: softprops/action-gh-release@v1\n"
        "        with:\n          files: dist/*\n",
        github_rules,
    )

    assert findings, "checkout + softprops/action-gh-release must fire SEC4-GH-005"


def test_pages_docs_publish_action_fires(tmp_path, github_rules):
    findings = _sec4_gh_005_findings(
        tmp_path,
        "name: docs\n"
        "on: [push]\n"
        "jobs:\n"
        "  docs:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "      - run: mkdocs build\n"
        "      - uses: peaceiris/actions-gh-pages@v3\n"
        "        with:\n          publish_dir: ./site\n",
        github_rules,
    )

    assert findings, "checkout + peaceiris/actions-gh-pages must fire SEC4-GH-005"


def test_cibuildwheel_then_pypa_publish_two_step_fires(tmp_path, github_rules):
    findings = _sec4_gh_005_findings(
        tmp_path,
        "name: wheels\n"
        "on:\n  push:\n    tags: ['v*']\n"
        "jobs:\n"
        "  wheels:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "      - uses: pypa/cibuildwheel@v2.21.0\n"
        "      - uses: pypa/gh-action-pypi-publish@release/v1\n"
        "        with:\n          packages-dir: wheelhouse/\n",
        github_rules,
    )

    assert findings, (
        "checkout + cibuildwheel + pypa-publish two-step must fire SEC4-GH-005 "
        "on the pypa-publish step"
    )


# ---------------------------------------------------------------------------
# Negatives — must stay suppressed
# ---------------------------------------------------------------------------


def test_lint_typecheck_only_does_not_fire(tmp_path, github_rules):
    findings = _sec4_gh_005_findings(
        tmp_path,
        "name: lint\n"
        "on: [push]\n"
        "jobs:\n"
        "  lint:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "      - run: ruff check .\n"
        "      - run: mypy src/\n",
        github_rules,
    )

    assert findings == []


def test_codeql_only_does_not_fire(tmp_path, github_rules):
    findings = _sec4_gh_005_findings(
        tmp_path,
        "name: codeql\n"
        "on: [push]\n"
        "jobs:\n"
        "  analyze:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "      - uses: github/codeql-action/init@v3\n"
        "      - uses: github/codeql-action/analyze@v3\n",
        github_rules,
    )

    assert findings == []


def test_docker_build_without_push_does_not_fire(tmp_path, github_rules):
    findings = _sec4_gh_005_findings(
        tmp_path,
        "name: docker\n"
        "on: [push]\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "      - uses: docker/build-push-action@v5\n"
        "        with:\n          push: false\n",
        github_rules,
    )

    assert findings == []


def test_persist_credentials_false_before_new_consumer_does_not_fire(
    tmp_path, github_rules
):
    findings = _sec4_gh_005_findings(
        tmp_path,
        "name: release\n"
        "on:\n  push:\n    tags: ['v*']\n"
        "jobs:\n"
        "  pypi:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "        with:\n          persist-credentials: false\n"
        "      - run: python -m build\n"
        "      - uses: pypa/gh-action-pypi-publish@release/v1\n",
        github_rules,
    )

    assert findings == [], (
        "persist-credentials: false on checkout must suppress SEC4-GH-005 even "
        "when a newly-recognised consumer (pypa-publish) is downstream"
    )


# ---------------------------------------------------------------------------
# Regressions — existing trigger shapes must still fire
# ---------------------------------------------------------------------------


def test_shell_git_push_regression_still_fires(tmp_path, github_rules):
    findings = _sec4_gh_005_findings(
        tmp_path,
        "name: deploy\n"
        "on: [push]\n"
        "jobs:\n"
        "  deploy:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "      - run: |\n"
        "          git config user.email bot@example.com\n"
        "          git push origin gh-pages\n",
        github_rules,
    )

    assert findings, "shell git push regression: must still fire SEC4-GH-005"


def test_existing_documented_push_action_still_fires(tmp_path, github_rules):
    # Pick JamesIves/github-pages-deploy-action since the peaceiris case
    # is already covered in test_pages_docs_publish_action_fires above —
    # use a different pre-existing entry to guard against accidental
    # narrowing of the allowlist.
    findings = _sec4_gh_005_findings(
        tmp_path,
        "name: deploy-pages\n"
        "on: [push]\n"
        "jobs:\n"
        "  deploy:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "      - run: npm run build\n"
        "      - uses: JamesIves/github-pages-deploy-action@v4\n"
        "        with:\n          folder: dist\n",
        github_rules,
    )

    assert findings, (
        "JamesIves/github-pages-deploy-action regression: pre-existing consumer "
        "must still fire SEC4-GH-005"
    )
