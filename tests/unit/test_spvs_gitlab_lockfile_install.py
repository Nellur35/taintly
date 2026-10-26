"""Authored GitLab contrasts for the bounded npm release-install decision."""

from pathlib import Path

import pytest

from taintly.engine import scan_file
from taintly.models import IncompletePatternMatches
from taintly.rules.gitlab.lockfile_install import RULES, NonFrozenNpmPublishPattern


def _scan(tmp_path: Path, workflow: str):
    path = tmp_path / ".gitlab-ci.yml"
    path.write_text(workflow, encoding="utf-8")
    return [finding for finding in scan_file(str(path), RULES) if finding.rule_id == "LOTP-GL-006"]


@pytest.mark.parametrize(
    ("workflow", "line"),
    [
        (
            "publish:\n  before_script:\n    - npm install\n  script:\n    - npm publish\n",
            3,
        ),
        (
            "publish:\n  script:\n    - npm install --unsafe-perm\n"
            "    - npm publish --unsafe-perm\n",
            3,
        ),
        (
            "publish:\n  script:\n    - npm install --prefix backend\n"
            "    - npm publish --prefix backend\n",
            3,
        ),
        (
            "publish:\n  only:\n    - tags\n  script:\n"
            "    - npm install --ignore-scripts\n"
            "    - npm ci\n    - npm publish\n",
            5,
        ),
    ],
)
def test_direct_non_frozen_install_precedes_publish(
    tmp_path: Path, workflow: str, line: int
) -> None:
    findings = _scan(tmp_path, workflow)
    assert [finding.line for finding in findings] == [line]
    assert all(finding.review_needed and "npm install" in finding.snippet for finding in findings)


@pytest.mark.parametrize(
    "workflow",
    [
        "publish:\n  script:\n    - npm ci\n    - npm publish\n",
        "publish:\n  script:\n    - npm install -g npm@latest\n    - npm ci\n    - npm publish\n",
        "build:\n  script:\n    - npm install\npublish:\n  script:\n    - npm publish\n",
        "publish:\n  script:\n    - npm publish\n    - npm install\n",
        "publish:\n  script:\n    - npm install --prefix backend\n    - npm publish\n",
        "publish:\n  script:\n    - echo npm install\n    - npm publish\n",
        "publish:\n  script:\n    # - npm install\n    - npm publish\n",
        "publish:\n  script:\n    - npm install --dry-run\n    - npm publish\n",
    ],
)
def test_no_confident_path_for_other_command_or_owner(tmp_path: Path, workflow: str) -> None:
    assert _scan(tmp_path, workflow) == []


@pytest.mark.parametrize(
    "workflow",
    [
        "publish:\n  script:\n    - npm install\n    - cd backend\n    - npm publish\n",
        "publish:\n  script:\n    - npm install && npm publish\n",
        "publish:\n  script:\n    - npm install --prefix $PACKAGE_DIR\n    - npm publish\n",
        "publish:\n  script:\n    - |\n"
        "      if true; then\n        npm install\n"
        "      fi\n      npm publish\n",
        "publish:\n  script:\n    - |\n"
        "      cat > example.sh <<EOF\n      npm install\n"
        "      EOF\n      npm publish\n",
        "publish:\n  script:\n    - |\n"
        "      function maybe_install() {\n      npm install\n"
        "      }\n      npm publish\n",
        "before_script:\n  - npm install\npublish:\n  script:\n    - npm publish\n",
        "before_script:\n  - npm\tinstall\npublish:\n  script:\n    - npm publish\n",
        "default:\n  before_script:\n    - npm install\npublish:\n  script:\n    - npm publish\n",
        ".template:\n  before_script:\n    - npm install\n"
        "publish:\n  extends: .template\n  script:\n    - npm publish\n",
        "publish:\n  before_script:\n    - npm install\n"
        "  script:\n    - echo prepared\n"
        "  after_script:\n    - npm publish\n",
    ],
)
def test_unresolved_context_is_not_a_clean_negative(workflow: str) -> None:
    result = NonFrozenNpmPublishPattern().check(workflow, workflow.splitlines())
    assert isinstance(result, IncompletePatternMatches)
    assert not result
    assert result.reason


@pytest.mark.parametrize(
    "workflow",
    [
        "publish:\n  script:\n    - npm install\n    - cd backend\n    - npm publish\n",
        "before_script:\n  - npm install\npublish:\n  script:\n    - npm publish\n",
    ],
)
def test_unresolved_context_reaches_product_diagnostic(tmp_path: Path, workflow: str) -> None:
    path = tmp_path / ".gitlab-ci.yml"
    path.write_text(workflow, encoding="utf-8")
    findings = scan_file(str(path), RULES)
    assert [finding.rule_id for finding in findings] == ["ENGINE-ERR"]
    assert "LOTP-GL-006" in findings[0].title
    assert "directory context" in findings[0].description
