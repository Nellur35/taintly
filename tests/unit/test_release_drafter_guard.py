import pytest

from taintly.engine import scan_repo
from taintly.models import IncompletePatternMatches, Platform
from taintly.rules.github.release_drafter_guard import RULES

_STEP = "      - uses: release-drafter/release-drafter@44a942e465867c7465b76aa808ddca6e0acae5da\n"
_INPUT = "        with:\n          disable-releaser: true\n"
_WORKFLOW = (
    "on: [pull_request_target, push]\n"
    "permissions: {contents: write}\n"
    "jobs:\n"
    "  label:\n"
    "    permissions: {contents: read}\n"
    "    runs-on: ubuntu-latest\n"
    "    steps:\n"
)


def _check(source):
    return RULES[0].pattern.check(source, source.splitlines())


def _notes(source, matches):
    (context,) = RULES[0].pattern.context_notes_for_matches(source, "ci.yml", matches)
    assert context is not None
    return " ".join(context.notes)


@pytest.mark.parametrize("value", ["true", "True", "'true'", "${{ github.event_name != 'push' }}"])
def test_pr_draft_write_keeps_step_token_and_job_permission(value):
    workflow = _WORKFLOW + _STEP + _INPUT.replace("true", value)
    matches = _check(workflow)
    ((line, snippet),) = matches
    note = _notes(workflow, matches)
    assert workflow.splitlines()[line - 1].strip().startswith("disable-releaser:")
    assert snippet == "disable-releaser"
    assert "pull_request_target" in note and "For push" not in note
    assert "Configured action token: github.token" in note
    assert "Declared job Contents: read at line 5" in note
    assert "at line 8" in note


@pytest.mark.parametrize(
    "pin",
    [
        "5de93583980a40bd78603b6dfdcda5b4df377b32",
        "693d20e7c1ce1a81d3a41962f85914253b518449",
    ],
)
def test_verified_root_bundles_ignore_event_guard_without_dry_run(pin):
    step = f"      - uses: release-drafter/release-drafter@{pin}\n"
    guard = _INPUT.replace("true", "${{ github.event_name == 'pull_request_target' }}")
    source = _WORKFLOW + step + guard
    assert _check(source) == [(10, "disable-releaser")]
    assert _check(source + "          dry-run: true\n") == []


@pytest.mark.parametrize(
    ("body", "input_body"),
    [
        (_WORKFLOW.replace("[pull_request_target, push]", "push") + _STEP, _INPUT),
        (_WORKFLOW + _STEP.replace("drafter@", "drafter/autolabeler@"), _INPUT),
        (_WORKFLOW + _STEP.replace(_STEP.split("@")[1].strip(), "v7"), _INPUT),
        (_WORKFLOW + _STEP + "        if: ${{ github.event_name == 'push' }}\n", _INPUT),
        (_WORKFLOW.replace("    steps:", "    if: false\n    steps:") + _STEP, _INPUT),
        (_WORKFLOW + _STEP, _INPUT + "          dry-run: true\n"),
        (_WORKFLOW + _STEP, _INPUT.replace("true", "false")),
        (_WORKFLOW + _STEP + "      - uses: example/other@v1\n", _INPUT),
    ],
)
def test_does_not_join_disconnected_or_out_of_scope_inputs(body, input_body):
    matches = _check(body + input_body)
    assert matches == []
    assert not isinstance(matches, IncompletePatternMatches)


@pytest.mark.parametrize(
    "input_body",
    [
        _INPUT + "          disable-releaser: false\n",
        _INPUT + "          dry-run: ${{ inputs.dry_run }}\n",
        _INPUT + "          publish: ${{ inputs.publish }}\n",
        _INPUT.replace("true", "${{ inputs.labels_only }}"),
    ],
)
def test_unresolved_semantics_stay_incomplete(input_body):
    matches = _check(_WORKFLOW + _STEP + input_body)
    assert isinstance(matches, IncompletePatternMatches)
    assert matches == []


def test_configured_token_override_does_not_borrow_job_scope():
    workflow = _WORKFLOW + _STEP + _INPUT + "          token: ${{ secrets.EXPLICIT_TOKEN }}\n"
    note = _notes(workflow, _check(workflow))
    assert "explicit input, effective scope unknown" in note
    assert "EXPLICIT_TOKEN" not in note


def test_unresolved_job_permissions_do_not_inherit_parent_grant():
    workflow = _WORKFLOW.replace("{contents: read}", "invalid") + _STEP + _INPUT
    note = _notes(workflow, _check(workflow))
    assert "Declared job Contents: unknown" in note


def test_engine_preserves_review_and_incomplete_step(tmp_path):
    fixtures = tmp_path / ".github" / "workflows"
    fixtures.mkdir(parents=True)
    workflow = _WORKFLOW + _STEP + _INPUT + _STEP + _INPUT.replace("true", "${{ inputs.flag }}")
    path = fixtures / "ci.yml"
    path.write_text(workflow, encoding="utf-8")
    (report,) = scan_repo(str(tmp_path), RULES, platform=Platform.GITHUB)
    (finding,) = [finding for finding in report.findings if finding.rule_id == "SEC1-GH-004"]
    assert finding.severity.value == "MEDIUM" and finding.review_needed
    assert finding.snippet == "disable-releaser"
    assert any("Declared job Contents: read" in note for note in finding.context_notes)
    assert any(finding.rule_id == "ENGINE-ERR" for finding in report.findings)
