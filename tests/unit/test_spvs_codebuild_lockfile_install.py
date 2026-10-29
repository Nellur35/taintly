"""Authored CodeBuild contrasts for the direct npm release-install profile."""

from pathlib import Path

import pytest

from taintly.engine import scan_file
from taintly.models import IncompletePatternMatches
from taintly.parsers.structural import EventKind, walk_workflow
from taintly.rules.codebuild.lockfile_install import RULES, NonFrozenNpmPublishPattern


def _scan(tmp_path: Path, source: str):
    path = tmp_path / "buildspec.yml"
    path.write_text(source, encoding="utf-8")
    return [finding for finding in scan_file(str(path), RULES) if finding.rule_id == "LOTP-CB-002"]


@pytest.mark.parametrize(
    ("source", "line"),
    [
        (
            "version: 0.2\nphases:\n  install:\n    commands:\n      - npm install\n"
            "  build:\n    commands:\n      - npm publish\n",
            5,
        ),
        (
            "version: 0.2\nphases:\n  build:\n    commands:\n      - npm install\n"
            "      - npm publish\n",
            5,
        ),
        (
            "version: 0.2\nphases:\n  build:\n    commands:\n      - npm publish\n"
            "  install:\n    commands:\n      - npm install\n",
            8,
        ),
        (
            "version: '0.2'\nphases:\n  install:\n    commands:\n"
            "      - npm install --prefix backend\n  post_build:\n"
            "    commands:\n      - npm publish --prefix backend\n",
            5,
        ),
    ],
)
def test_direct_install_before_publish(tmp_path: Path, source: str, line: int) -> None:
    findings = _scan(tmp_path, source)
    assert [finding.line for finding in findings] == [line]
    assert all(finding.review_needed and "npm install" in finding.snippet for finding in findings)


@pytest.mark.parametrize(
    "source",
    [
        "version: 0.2\nphases:\n  install:\n    commands:\n      - npm ci\n"
        "  build:\n    commands:\n      - npm publish\n",
        "version: 0.2\nphases:\n  install:\n    commands:\n"
        "      - npm install -g npm@latest\n      - npm ci\n"
        "  build:\n    commands:\n      - npm publish\n",
        "version: 0.2\nphases:\n  build:\n    commands:\n"
        "      - npm publish\n      - npm install\n",
        "version: 0.2\nphases:\n  install:\n    commands:\n"
        "      - npm install --prefix backend\n  build:\n"
        "    commands:\n      - npm publish\n",
        "version: 0.2\nphases:\n  install:\n    commands:\n"
        "      - echo npm install\n  build:\n"
        "    commands:\n      - npm publish\n",
        "version: 0.2\nphases:\n  install:\n    commands:\n"
        "      # - npm install\n      - npm ci\n  build:\n"
        "    commands:\n      - npm publish\n",
        "version: 0.2\nphases:\n  install:\n    commands:\n"
        "      - npm install --dry-run\n  build:\n"
        "    commands:\n      - npm publish\n",
    ],
)
def test_no_supported_non_frozen_path(tmp_path: Path, source: str) -> None:
    assert _scan(tmp_path, source) == []


@pytest.mark.parametrize(
    "source",
    [
        "version: 0.1\nphases:\n  install:\n    commands:\n"
        "      - npm install\n  build:\n    commands:\n      - npm publish\n",
        "version: 0.2\nenv:\n  shell: powershell.exe\nphases:\n"
        "  build:\n    commands:\n      - npm install\n      - npm publish\n",
        "version: 0.2\nphases:\n  build:\n    commands:\n"
        "      - npm install\n      - cd backend\n      - npm publish\n",
        "version: 0.2\nphases:\n  build:\n    commands:\n"
        "      - npm install\n      - . ./change-directory.sh\n"
        "      - npm publish\n",
        "version: 0.2\nphases:\n  build:\n    commands:\n      - npm install && npm publish\n",
        "version: 0.2\nphases:\n  build:\n    commands:\n"
        "      - npm install --prefix $PACKAGE_DIR\n"
        "      - npm publish\n",
        "version: 0.2\nphases:\n  build:\n    commands:\n      - npm i\n      - npm publish\n",
        "version: 0.2\nphases:\n  install:\n"
        "    commands:\n      - npm install\n"
        "    finally:\n      - cd backend\n"
        "  build:\n    commands:\n      - npm publish\n",
        "version: 0.2\nphases:\n  build:\n    commands:\n"
        "      - |\n        if true; then\n          npm install\n"
        "        fi\n        npm publish\n",
    ],
)
def test_unresolved_shell_or_version_is_explicit(source: str) -> None:
    result = NonFrozenNpmPublishPattern().check(source, source.splitlines())
    assert isinstance(result, IncompletePatternMatches)
    assert not result
    assert result.reason


def test_unresolved_directory_reaches_product_diagnostic(tmp_path: Path) -> None:
    source = (
        "version: 0.2\nphases:\n  build:\n    commands:\n"
        "      - npm install\n      - source ./change-directory.sh\n"
        "      - npm publish\n"
    )
    path = tmp_path / "buildspec.yml"
    path.write_text(source, encoding="utf-8")
    findings = scan_file(str(path), RULES)
    assert [finding.rule_id for finding in findings] == ["ENGINE-ERR"]
    assert "LOTP-CB-002" in findings[0].title
    assert "shell or command context" in findings[0].description


def test_whitespace_mutant_removes_version_mapping_instead_of_rephrasing_it() -> None:
    source = (
        "version:0.2\nphases:\n  build:\n    commands:\n      - npm install\n      - npm publish\n"
    )
    events = tuple(walk_workflow("buildspec.yml", content=source, recover=True))
    assert not any(
        event.kind is EventKind.LEAF_SCALAR and event.path == ("version",) for event in events
    )
    assert not NonFrozenNpmPublishPattern().check(source, source.splitlines())
