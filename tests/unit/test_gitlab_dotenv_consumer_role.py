"""End-to-end source-owned dotenv consumer distinctions."""
import pytest

from taintly.engine import scan_file
from taintly.models import Severity
from taintly.rules.registry import load_all_rules


_URL = (
    "${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/packages/generic/record/${LABEL}/report.zip"
)
_UPLOAD = f'curl --header "JOB-TOKEN: ${{CI_JOB_TOKEN}}" --upload-file report.zip "{_URL}"'
_SOURCE = """producer:
  script:
    - echo "LABEL=$CI_COMMIT_TITLE" > vars.env
  artifacts:
    reports:
      dotenv: vars.env
consumer:
  needs: [producer]
  script:
"""


def findings(tmp_path, script, context=""):
    path = tmp_path / ".gitlab-ci.yml"
    path.write_text(context + _SOURCE + script, encoding="utf-8")
    rules = [rule for rule in load_all_rules() if rule.id == "TAINT-GL-003"]
    return scan_file(str(path), rules)


def finding(tmp_path, script, context=""):
    selected = [item for item in findings(tmp_path, script, context) if item.rule_id == "TAINT-GL-003"]
    assert len(selected) == 1
    return selected[0]


@pytest.mark.parametrize("presentation", ('    - |\n      {}\n', "    - '{}'\n"))
def test_package_destination_preserves_dotenv_path_and_qualifies_the_finding(tmp_path, presentation):
    result = finding(
        tmp_path,
        presentation.format(_UPLOAD),
        context="include:\n  - local: external.yml\n",
    )
    assert result.severity == Severity.MEDIUM
    assert result.review_needed
    assert "dotenv(producer).LABEL" in result.snippet
    assert "gitlab-dotenv-role-data" in result.context_tags
    assert any("unverified" in note and "publication authority" in note for note in result.context_notes)
    assert any("job 'consumer'" in note for note in result.context_notes)


def test_configured_interpreter_operand_still_keeps_the_critical_candidate(tmp_path):
    result = finding(tmp_path, '    - eval "$LABEL"\n')
    assert result.severity == Severity.CRITICAL
    assert result.review_needed
    assert "gitlab-dotenv-role-code" in result.context_tags
    assert "interpreter program input" in result.title


@pytest.mark.parametrize(
    "script",
    [
        '    - custom "$LABEL"\n',
        '    - "echo pending \\\\\\\\"\n    - |\n      ' + _UPLOAD + '\n',
        '    - |\n      cat <<EOF\n      ' + _UPLOAD + '\n      EOF\n',
        '    - >\n      ' + _UPLOAD + '\n',
        '    - |\n      ' + _UPLOAD.replace(' --upload-file', ' --config settings --upload-file') + '\n',
        '    - |\n      ' + _UPLOAD.replace('/${LABEL}/', '/fixed/').replace('report.zip"', '$' + '{LABEL}.zip"; :') + '\n',
    ],
)
def test_unsupported_or_ambiguous_consumer_preserves_the_candidate(tmp_path, script):
    result = finding(tmp_path, script)
    assert result.severity == Severity.CRITICAL
    assert result.review_needed
    assert "gitlab-dotenv-role-unknown" in result.context_tags
    assert "execute in bash" not in result.description
