"""Authored comparisons for API response ownership and source scope."""

import hashlib
import json

import pytest

from taintly.ingestion.github_release_request import release_request_observation

SOURCE = """\
on:
  pull_request:
    types: [synchronize]
jobs:
  draft:
    runs-on: ubuntu-latest
    permissions:
      contents: write
    steps:
      - uses: release-drafter/release-drafter@v6
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
"""
REPO = "team/project"
HEAD = "a" * 40
PATH = ".github/workflows/draft.yml"
RUN_URL = f"https://github.com/{REPO}/actions/runs/10"
STARTED = "2026-05-13T00:23:16Z"
COMPLETED = "2026-05-13T00:23:23Z"


@pytest.fixture
def capture(tmp_path):
    def bind(content=SOURCE):
        path = tmp_path / PATH
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content.encode())
        return {
            "path": PATH,
            "revision": HEAD,
            "sha256": hashlib.sha256(content.encode()).hexdigest(),
        }

    job_window = {
        "head_sha": HEAD,
        "started_at": STARTED,
        "completed_at": COMPLETED,
        "conclusion": "success",
    }
    cap = {
        "schema": "github-draft-release-request-v1",
        "repository": REPO,
        "run": {
            "id": 10,
            "html_url": RUN_URL,
            "event": "pull_request",
            "head_sha": HEAD,
            "head_repository": "fork/project",
            "run_attempt": 1,
            "conclusion": "success",
            "referenced_workflows": [],
            "path": PATH,
            "check_suite_id": 30,
            "created_at": "2026-05-13T00:23:05Z",
            "updated_at": COMPLETED,
        },
        "job": {
            **job_window,
            "id": 20,
            "run_id": 10,
            "run_attempt": 1,
            "name": "draft",
            "check_run_url": f"https://api.github.com/repos/{REPO}/check-runs/20",
        },
        "check_run": {
            **job_window,
            "id": 20,
            "app": "github-actions",
            "check_suite_id": 30,
            "details_url": f"{RUN_URL}/job/20",
        },
        "pr": {
            "number": 40,
            "base_repository": REPO,
            "head_repository": "fork/project",
            "head_sha": HEAD,
        },
        "source": bind(),
        "denial": {
            "check_run": 20,
            "run": 10,
            "attempt": 1,
            "status": 403,
            "message": "Resource not accessible by integration",
            "method": "POST",
            "url": f"https://api.github.com/repos/{REPO}/releases",
            "draft": True,
            "target_commitish": "refs/pull/40/merge",
            "action": "release-drafter/release-drafter@v6",
            "response_at": "2026-05-13T00:23:21Z",
            "request_id": "2411:342B08:95AE9B",
            "annotation_sha256": "b" * 64,
            "action_annotation_sha256": "c" * 64,
            "accepted_permissions": "contents=write; contents=write,workflows=write",
        },
    }

    def assess():
        evidence = tmp_path / "capture.json"
        evidence.write_text(json.dumps(cap), encoding="utf-8")
        return release_request_observation(evidence, tmp_path, REPO, 10, 20)

    return cap, bind, assess


def test_job_success_can_coexist_with_owned_request_denial(capture):
    _, _, assess = capture
    result = assess()
    assert result["state"] == "draft-release-create-denied"
    assert result["job_conclusion"] == "success"
    assert result["operation"]["target_commitish"] == "refs/pull/40/merge"
    assert result["configured"]["credential_binding"] == "GITHUB_TOKEN"
    assert result["source_role"] == "fork-head"
    assert "publication" not in result


@pytest.fixture
def denial_grant_capture(capture):
    cap, _, _ = capture
    action = cap["denial"]["action"]
    cap["job"]["steps"] = [
        {
            "number": 1,
            "name": "Set up job",
            "conclusion": "success",
            "started_at": STARTED,
            "completed_at": "2026-05-13T00:23:18Z",
        },
        {
            "number": 2,
            "name": f"Run {action}",
            "conclusion": "success",
            "started_at": "2026-05-13T00:23:18Z",
            "completed_at": COMPLETED,
        },
    ]
    rows = []
    for second, value in (
        ("16.1000000", "##[group]GITHUB_TOKEN Permissions"),
        ("16.1100000", "Contents: read"),
        ("16.1200000", "##[endgroup]"),
        ("17.0500000", f"Download action repository '{action}' (SHA:{'a' * 40})"),
        ("18.0200000", f"##[group]Run {action}"),
        ("21.1000000", "##[error]Resource not accessible by integration"),
    ):
        time = f"2026-05-13T00:23:{second}Z"
        rows.append(
            {
                "time": time,
                "value": value,
                "sha256": hashlib.sha256(f"{time} {value}".encode()).hexdigest(),
            }
        )
    cap["custody"] = {"job_log_sha256": "d" * 64}
    cap["effective_permission_log"] = {
        "run": 10,
        "job": 20,
        "attempt": 1,
        "log_sha256": "d" * 64,
        "response_request_id": cap["denial"]["request_id"],
        "response_block_sha256": "f" * 64,
        "rows": rows,
    }
    return capture


def test_exact_denial_correlates_own_job_reported_grant(denial_grant_capture):
    _, _, assess = denial_grant_capture
    result = assess()
    assert result["state"] == "draft-release-create-denied"
    assert result["operation"]["status"] == 403
    assert result["effective_permission"]["contents"] == "read"
    assert result["configured"]["requested_permission"] == "contents: write"


@pytest.mark.parametrize(
    ("key", "value"),
    [("job", 21), ("attempt", 2), ("response_request_id", "BAD:BAD:BAD"), ("log_sha256", "b" * 64)],
)
def test_denial_grant_rejects_different_owners(denial_grant_capture, key, value):
    cap, _, assess = denial_grant_capture
    cap["effective_permission_log"][key] = value
    assert assess()["state"] == "unresolved"


def test_denial_grant_cannot_borrow_rows_outside_setup(denial_grant_capture):
    cap, _, assess = denial_grant_capture
    row = cap["effective_permission_log"]["rows"][1]
    row["time"] = "2026-05-13T00:23:19Z"
    row["sha256"] = hashlib.sha256(f"{row['time']} {row['value']}".encode()).hexdigest()
    assert assess()["state"] == "unresolved"


@pytest.mark.parametrize(
    ("override", "state", "permission_line"),
    [
        ("", "draft-release-create-denied", 5),
        ("    permissions:\n      contents: write\n", "draft-release-create-denied", 10),
        ("    permissions:\n      contents: read\n", "unresolved", None),
        ("    permissions:\n      pull-requests: write\n", "unresolved", None),
        ("    permissions: {}\n", "unresolved", None),
    ],
)
def test_fork_draft_workflow_permission_respects_job_override(capture, override, state, permission_line):
    cap, bind, assess = capture
    source = SOURCE.replace("jobs:\n", "permissions:\n  contents: write\njobs:\n")
    source = source.replace("    permissions:\n      contents: write\n", override)
    cap["source"] = bind(source)
    result = assess()
    assert result["state"] == state
    if permission_line is not None:
        assert result["configured"]["permission_line"] == permission_line
        assert "effective_permission" not in result


@pytest.mark.parametrize(
    ("record", "key", "wrong"),
    [
        ("check_run", "app", "other-integration"),
        ("check_run", "check_suite_id", 31),
        ("denial", "check_run", 21),
        ("denial", "attempt", True),
        ("denial", "response_at", "2026-05-13T00:23:25Z"),
        ("denial", "target_commitish", "refs/pull/41/merge"),
        ("denial", "status", 403.0),
        ("denial", "message", "API rate limit exceeded"),
        ("denial", "action_annotation_sha256", "b" * 64),
        ("pr", "head_sha", "b" * 40),
    ],
)
def test_mismatched_owner_or_response_remains_unresolved(capture, record, key, wrong):
    cap, _, assess = capture
    cap[record][key] = wrong
    result = assess()
    assert result["state"] == "unresolved" and "operation" not in result


def test_missing_response_cannot_be_inferred_from_source_or_status(capture):
    cap, _, assess = capture
    del cap["denial"]
    assert "No owned draft-create API denial" in assess()["reason"]


def test_source_with_intervening_command_has_no_unique_action_binding(capture):
    cap, bind, assess = capture
    cap["source"] = bind(SOURCE.replace("    steps:\n", "    steps:\n      - run: echo other\n"))
    assert assess()["state"] == "unresolved"


@pytest.mark.parametrize("contrast", [None, "wrong-name", "wrong-version", "other-document"])
def test_named_single_action_and_explicit_document_start(capture, contrast):
    cap, bind, assess = capture
    label = "✏️ Draft release"
    source = "---\n" + SOURCE.replace(
        "  draft:\n", f'  draft:\n    name: "{label}"\n'
    ).replace(
        "      - uses: release-drafter/release-drafter@v6",
        "      - name: Run Release Drafter\n        uses: release-drafter/release-drafter@v6.0.0",
    )
    if contrast == "other-document":
        source += "---\nname: Sibling document\n"
    cap["source"] = bind(source)
    cap["job"]["name"] = "Different job" if contrast == "wrong-name" else label
    cap["denial"]["action"] = "release-drafter/release-drafter@v6.0.0"
    if contrast == "wrong-version":
        cap["denial"]["action"] = "release-drafter/release-drafter@v6.0.1"
    result = assess()
    if contrast is None:
        assert result["state"] == "draft-release-create-denied"
        assert result["configured"]["action_line"] == next(
            line for line, text in enumerate(source.splitlines(), 1) if "uses: release-drafter" in text
        )
    else:
        assert result["state"] == "unresolved" and "operation" not in result


@pytest.fixture
def push_capture(capture):
    cap, bind, assess = capture
    action = "release-drafter/release-drafter@v7"
    source = SOURCE.replace("pull_request:\n    types: [synchronize]", "push:\n    branches: [master]")
    cap["source"] = bind(source.replace("@v6", "@v7"))
    cap["run"].update(event="push", head_repository=REPO, head_branch="master")
    del cap["denial"]
    timings = [
        ("Set up job", 16, 17),
        (f"Run {action}", 18, 22),
        ("Complete job", 22, 23),
    ]
    cap["job"]["steps"] = [
        {
            "name": name,
            "number": number,
            "started_at": f"2026-05-13T00:23:{start}Z",
            "completed_at": f"2026-05-13T00:23:{end}Z",
            "conclusion": "success",
        }
        for number, (name, start, end) in enumerate(timings, 1)
    ]
    action_commit = "978bb0b30c5ee8cdd332ced253758157150d43f0"
    rows = []
    for second, value in (
        ("16.100", f"Download action repository '{action}' (SHA:{action_commit})"),
        ("18.100", f"##[group]Run {action}"),
        ("20.100", "  tag:    2.3.4"),
        ("20.200", "  targetCommitish: master"),
        ("20.300", "  draft:  true"),
        ("20.400", "Creating new release..."),
        ("20.800", "Release created!"),
        ("22.150", "Cleaning up orphan processes"),
    ):
        time = f"2026-05-13T00:23:{second}Z"
        rows.append({"time": time, "value": value, "sha256": hashlib.sha256(f"{time} {value}".encode()).hexdigest()})
    cap["creation"] = {"run": 10, "job": 20, "attempt": 1, "log_sha256": "a" * 64, "rows": rows}
    return cap, source, bind, assess


def test_success_is_scoped_to_owned_draft_create(push_capture):
    _, _, _, assess = push_capture
    result = assess()
    assert result["state"] == "draft-release-create-reported"
    assert result["source_role"] == "repository-push"
    op = result["operation"]
    assert op["url"] == f"https://api.github.com/repos/{REPO}/releases"
    assert (op["method"], op["draft"], op["requested_tag"], op["target_commitish"]) == (
        "POST", True, "2.3.4", "master",
    )
    assert "status" not in op and "publication" not in result
    assert "effective_permission" not in result


@pytest.fixture
def push_grant_capture(push_capture):
    cap, _, _, assess = push_capture
    values = ("##[group]GITHUB_TOKEN Permissions", "Contents: write", "##[endgroup]")
    rows = []
    for index, value in enumerate(values, 1):
        time = f"2026-05-13T00:23:16.00{index}Z"
        digest = hashlib.sha256(f"{time} {value}".encode()).hexdigest()
        rows.append({"time": time, "value": value, "sha256": digest})
    cap["creation"]["effective_permission_rows"] = rows
    return rows, assess


def test_success_can_include_owned_setup_grant(push_grant_capture):
    rows, assess = push_grant_capture
    assert assess()["effective_permission"] == {
        "credential": "GITHUB_TOKEN",
        "contents": "write",
        "time": rows[1]["time"],
        "line_sha256": rows[1]["sha256"],
    }


@pytest.mark.parametrize(
    ("index", "field", "value"),
    [
        (0, "value", "##[group]Permissions"),
        (1, "value", "Contents: read"),
        (1, "time", "2026-05-13T00:23:18Z"),
        (2, "time", "2026-05-13T00:23:16.150Z"),
    ],
)
def test_push_grant_requires_matching_setup_step_and_order(push_grant_capture, index, field, value):
    rows, assess = push_grant_capture
    row = rows[index]
    row[field] = value
    row["sha256"] = hashlib.sha256(f"{row['time']} {row['value']}".encode()).hexdigest()
    result = assess()
    assert result["state"] == "unresolved" and "effective_permission" not in result


def test_push_grant_rejects_incomplete_group(push_grant_capture):
    rows, assess = push_grant_capture
    rows.pop()
    assert assess()["state"] == "unresolved"


def test_push_uses_workflow_permission_when_job_has_no_override(push_capture):
    cap, source, bind, assess = push_capture
    workflow_permission = "permissions:\n  contents: write\n"
    job_permission = "    permissions:\n      contents: write\n"
    source = workflow_permission + source.replace(job_permission, "").replace("@v6", "@v7")
    cap["source"] = bind(source)
    result = assess()
    assert result["state"] == "draft-release-create-reported", result
    assert result["configured"]["permission_line"] == 2
    for new_permission in (
        "    permissions:\n      contents: read\n",
        "    permissions:\n      pull-requests: read\n",
        "    permissions: {}\n",
    ):
        cap["source"] = bind(source.replace("    steps:\n", new_permission + "    steps:\n"))
        assert assess()["state"] == "unresolved"


def test_push_preserves_numeric_version_tag_prefix(push_capture):
    cap, _, _, assess = push_capture
    row = cap["creation"]["rows"][2]
    row["value"] = "  tag:    v2.3.4"
    row["sha256"] = hashlib.sha256(f"{row['time']} {row['value']}".encode()).hexdigest()
    assert assess()["operation"]["requested_tag"] == "v2.3.4"


@pytest.mark.parametrize(
    ("record", "key", "wrong"),
    [
        ("run", "event", "pull_request"),
        ("run", "head_repository", "fork/project"),
        ("run", "head_branch", "main"),
        ("job", "run_attempt", True),
        ("creation", "job", 21),
        ("creation", "attempt", True),
    ],
)
def test_push_creation_does_not_cross_an_invocation(push_capture, record, key, wrong):
    cap, _, _, assess = push_capture
    cap[record][key] = wrong
    assert assess()["state"] == "unresolved"


@pytest.mark.parametrize(
    ("row_index", "field", "wrong"),
    [
        (0, "value", "Download action repository 'other/action@v7' (SHA:" + "a" * 40 + ")"),
        (3, "value", "  targetCommitish: main"),
        (4, "value", "  draft:  false"),
        (5, "value", "[dry-run] Would create release"),
        (6, "value", "Updating existing release..."),
        (6, "time", "2026-05-13T00:23:17.900Z"),
        (6, "time", "2026-05-13T00:23:20.350Z"),
        (6, "time", "2026-05-13T00:23:22.200Z"),
    ],
)
def test_owned_log_must_affirm_the_exact_operation(push_capture, row_index, field, wrong):
    cap, _, _, assess = push_capture
    row = cap["creation"]["rows"][row_index]
    row[field] = wrong
    row["sha256"] = hashlib.sha256(f"{row['time']} {row['value']}".encode()).hexdigest()
    assert assess()["state"] == "unresolved"


def test_draft_creation_does_not_infer_success_or_accept_unverified_rows(push_capture):
    cap, _, _, assess = push_capture
    rows = cap["creation"]["rows"]
    completion = rows.pop(-2)
    assert assess()["state"] == "unresolved"
    rows.insert(-1, {**completion, "sha256": "e" * 64})
    assert assess()["state"] == "unresolved"


def test_nondefault_action_inputs_are_outside_the_push_profile(push_capture):
    cap, source, bind, assess = push_capture
    cap["source"] = bind(source.replace("@v6\n", "@v7\n        with:\n          dry-run: true\n"))
    assert assess()["state"] == "unresolved"


def test_branch_exclusions_are_outside_the_literal_push_profile(push_capture):
    cap, source, bind, assess = push_capture
    source = source.replace("@v6", "@v7").replace("[master]", "[master, '!master']")
    cap["source"] = bind(source)
    assert assess()["state"] == "unresolved"


@pytest.mark.parametrize("extra", ["- []", "- {}", "-", "- [elsewhere]", "- master: foo"])
def test_literal_push_list_checks_invisible_and_nested_items(push_capture, extra):
    cap, source, bind, assess = push_capture
    block = source.replace("@v6", "@v7").replace("[master]", "\n      - main\n      - master")
    cap["source"] = bind(block)
    assert assess()["state"] == "draft-release-create-reported"
    cap["source"] = bind(block.replace("      - master", f"      - master\n      {extra}"))
    assert assess()["state"] == "unresolved"


@pytest.fixture
def logged_fork_capture(capture):
    cap, bind, assess = capture
    action_pin = "34d80673e067bdc0c24568d3af899c216adcfaa9"
    checkout_pin = "11bd71901bbe5b1630ceea73d27597364c9af683"
    action = f"release-drafter/release-drafter@{action_pin}"
    merge, base = "d" * 40, "b" * 40
    workflow = f"""\
on:
  pull_request:
    types:
      - opened
      - reopened
      - synchronize
jobs:
  draft:
    runs-on: ubuntu-latest
    permissions:
      contents: write
    if: github.actor != 'dependabot[bot]' && github.actor != 'github-actions[bot]'
    steps:
      - name: Checkout code
        uses: actions/checkout@{checkout_pin}
      - name: Release Drafter
        uses: {action}
        env:
          GITHUB_TOKEN: ${{{{ secrets.GITHUB_TOKEN }}}}
        with:
          config-name: release-drafter.yml
          commitish: develop
          disable-autolabeler: false
      - name: Summary
        run: echo summary
"""

    def bind_merged(text):
        cap["source"] = {**bind(text), "revision": merge}

    del cap["denial"]
    bind_merged(workflow)
    for record in ("run", "job", "check_run"):
        cap[record]["conclusion"] = "failure"
    cap["run"]["actor"] = "maintainer"
    cap["job"]["steps"] = [
        {"name": name, "number": number, "started_at": f"2026-05-13T00:23:{start}Z",
         "completed_at": f"2026-05-13T00:23:{end}Z", "conclusion": conclusion}
        for number, name, start, end, conclusion in (
            (1, "Set up job", 16, 17, "success"),
            (2, "Checkout code", 18, 19, "success"),
            (3, "Release Drafter", 20, 22, "failure"),
            (4, "Summary", 22, 22, "skipped"),
            (8, "Post Checkout code", 22, 22, "success"),
            (9, "Complete job", 22, 23, "success"),
        )
    ]
    entries = (
        ("16.100", "##[group]GITHUB_TOKEN Permissions"),
        ("16.200", "Contents: read"),
        ("16.300", "##[endgroup]"),
        ("17.100", f"Download action repository '{action}' (SHA:{action_pin})"),
        ("18.150", f"##[group]Run actions/checkout@{checkout_pin}"),
        ("19.500", merge),
        ("20.100", f"##[group]Run {action}"),
        ("20.200", f'Config fetched from "{REPO}/.github/release-drafter.yml@refs/pull/40/merge".'),
        ("20.300", "No draft release found"),
        ("21.100", "  targetCommitish: develop"),
        ("21.200", "  draft: true"),
        ("21.300", "Creating new release..."),
        ("21.400", "##[error]Resource not accessible by integration - "
                   "https://docs.github.com/rest/releases/releases#create-a-release"),
        ("22.000", "Post job cleanup."),
        ("22.200", "Cleaning up orphan processes"),
    )
    rows = []
    for stamp, value in entries:
        time = f"2026-05-13T00:23:{stamp}Z"
        rows.append({"time": time, "value": value, "sha256": hashlib.sha256(f"{time} {value}".encode()).hexdigest()})
    cap["custody"] = {"log_sha256": "c" * 64, "annotation_list_sha256": "e" * 64}
    cap["verified_log"] = {
        "run": 10, "job": 20, "attempt": 1,
        "log_sha256": "c" * 64, "merge_record_sha256": "d" * 64, "annotation_list_sha256": "e" * 64,
        "merge_commit": merge, "base_commit": base, "merge_parents": [base, HEAD],
        "action_commit": action_pin, "rows": rows,
        "failure_annotation": {
            "check_run": 20,
            "level": "failure",
            "message": "Resource not accessible by integration - "
                       "https://docs.github.com/rest/releases/releases#create-a-release",
        },
    }
    return cap, workflow, bind_merged, assess


def test_owned_fork_grant_and_rejection_preserve_unknown_http_status(logged_fork_capture):
    cap, _, _, assess = logged_fork_capture
    result = assess()
    assert result["state"] == "draft-release-create-rejection-reported"
    assert result["effective_permission"]["contents"] == "read"
    assert result["configured"]["requested_permission"] == "contents: write"
    assert result["source"]["revision"] == cap["verified_log"]["merge_commit"]
    assert result["operation"]["status"] is None
    assert result["operation"]["url"] == f"https://api.github.com/repos/{REPO}/releases"
    assert result["operation"]["target_commitish"] == "develop"
    assert "publication" not in result


@pytest.mark.parametrize(
    ("index", "field", "wrong"),
    [
        (1, "value", "Contents: write"),
        (1, "time", "2026-05-13T00:23:19.150Z"),
        (5, "value", HEAD),
        (7, "value", f'Config fetched from "{REPO}/.github/release-drafter.yml@refs/heads/develop".'),
        (9, "value", "  targetCommitish: main"),
        (10, "value", "  draft: false"),
        (11, "value", "Updating existing release..."),
        (12, "value", "##[error]Resource not accessible by integration"),
    ],
)
def test_fork_log_must_describe_the_exact_grant_and_operation(logged_fork_capture, index, field, wrong):
    cap, _, _, assess = logged_fork_capture
    row = cap["verified_log"]["rows"][index]
    row[field] = wrong
    row["sha256"] = hashlib.sha256(f"{row['time']} {row['value']}".encode()).hexdigest()
    assert assess()["state"] == "unresolved"


@pytest.mark.parametrize(
    ("key", "wrong"), [("job", 99), ("attempt", True), ("merge_parents", [HEAD, "b" * 40])]
)
def test_fork_grant_does_not_cross_job_attempt_or_merge(logged_fork_capture, key, wrong):
    cap, _, _, assess = logged_fork_capture
    cap["verified_log"][key] = wrong
    assert assess()["state"] == "unresolved"


def test_fork_checkout_override_disables_the_profile(logged_fork_capture):
    _, workflow, bind, assess = logged_fork_capture
    bind(workflow.replace("      - name: Release Drafter", "        with:\n          ref: develop\n      - name: Release Drafter"))
    assert assess()["state"] == "unresolved"


def test_logged_fork_rejects_contradictory_job_guard(logged_fork_capture):
    _, workflow, bind, assess = logged_fork_capture
    bind(workflow.replace("    if: github.actor != 'dependabot[bot]' && github.actor != 'github-actions[bot]'", "    if: false"))
    assert assess()["state"] == "unresolved"


def test_logged_fork_rejects_conflicting_log_provenance(logged_fork_capture):
    cap, _, _, assess = logged_fork_capture
    cap["custody"]["log_sha256"] = "8" * 64
    assert assess()["state"] == "unresolved"


def test_logged_fork_rejects_response_after_cleanup_within_same_second(logged_fork_capture):
    cap, _, _, assess = logged_fork_capture
    rows = cap["verified_log"]["rows"]
    for row, stamp in zip(rows[-3:], ("22.900", "22.100", "22.300"), strict=True):
        row["time"] = f"2026-05-13T00:23:{stamp}Z"
        row["sha256"] = hashlib.sha256(f"{row['time']} {row['value']}".encode()).hexdigest()
    assert assess()["state"] == "unresolved"

@pytest.mark.parametrize("filter_line", ["    branches: [main]\n", "    paths-ignore: ['**']\n"])
def test_logged_fork_rejects_unmodeled_trigger_filters(logged_fork_capture, filter_line):
    _, workflow, bind, assess = logged_fork_capture
    bind(workflow.replace("    types:\n", filter_line + "    types:\n"))
    assert assess()["state"] == "unresolved"
