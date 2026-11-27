"""Same-repository source selection stays separate from workspace paths."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from taintly.local_call_graph import CallAuthorityResolver, find_local_flows
from taintly.workflow_corpus import build_corpus

CALLER = ".github/workflows/caller.yml"
WORKFLOW = ".github/workflows/reusable.yml"
ACTION = ".github/actions/print/action.yml"


def write(root, rel, text):
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def commit(root):
    git = ["git", "-C", str(root)]
    subprocess.run([*git, "init", "-q"], check=True)
    subprocess.run([*git, "add", ".github"], check=True)
    subprocess.run(
        [
            *git,
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "-c",
            "core.hooksPath=.git/hooks",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-qm",
            "Source fixture",
        ],
        check=True,
    )


def caller(ref):
    return f"on: push\njobs:\n  call:\n    uses: {ref}\n"


REUSABLE = "on: workflow_call\njobs:\n  check:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hello\n"


def capture(root, monkeypatch):
    edges = []
    orig = CallAuthorityResolver.call

    def call(self, authority, file, kind, owner, target, target_kind, line):
        edges.append((Path(file).name, line, Path(target).name, target_kind))
        return orig(self, authority, file, kind, owner, target, target_kind, line)

    monkeypatch.setattr(CallAuthorityResolver, "call", call)
    gaps = set()
    find_local_flows(build_corpus(str(root)), source_gaps=gaps)
    return edges, [gap.reason for gap in sorted(gaps, key=lambda row: row.line)]


@pytest.mark.parametrize(
    ("changed", "reason"),
    [(None, None), (CALLER, "Caller source"), (WORKFLOW, "differs from local Git commit")],
)
def test_requires_matching_caller_and_callee_sources(tmp_path, monkeypatch, changed, reason):
    write(tmp_path, CALLER, caller("$/" + WORKFLOW))
    write(tmp_path, WORKFLOW, REUSABLE)
    commit(tmp_path)
    if changed:
        path = tmp_path / changed
        path.write_text(path.read_text(encoding="utf-8") + "# workspace copy\n", encoding="utf-8")
    edges, gaps = capture(tmp_path, monkeypatch)
    if changed:
        assert not edges
        assert len(gaps) == 1
        assert reason in gaps[0]
    else:
        assert not gaps
        assert edges == [("caller.yml", 4, "reusable.yml", "workflow")]


def test_workspace_copy_cannot_supply_absent_commit_target(tmp_path, monkeypatch):
    write(tmp_path, CALLER, caller("$/" + WORKFLOW))
    commit(tmp_path)
    write(tmp_path, WORKFLOW, REUSABLE)
    edges, gaps = capture(tmp_path, monkeypatch)
    assert edges == []
    assert len(gaps) == 1
    assert "is unavailable at local Git commit" in gaps[0]


def test_source_binding_does_not_follow_adjacent_workspace_checkout(tmp_path, monkeypatch):
    write(
        tmp_path,
        CALLER,
        """on: push
jobs:
  call:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          repository: example/other
      - uses: $/.github/actions/print
      - run: echo '$/.github/actions/data'
      - uses: ./.github/actions/print
""",
    )
    write(
        tmp_path,
        ACTION,
        "runs:\n  using: composite\n  steps:\n    - run: echo hello\n      shell: bash\n",
    )
    commit(tmp_path)
    edges, gaps = capture(tmp_path, monkeypatch)
    assert not gaps
    assert edges == [
        ("caller.yml", 9, "action.yml", "action"),
        ("caller.yml", 11, "action.yml", "action"),
    ]


def test_plain_source_archive_names_the_missing_commit_evidence(tmp_path, monkeypatch):
    write(tmp_path, CALLER, caller("$/" + WORKFLOW))
    write(tmp_path, WORKFLOW, REUSABLE)
    edges, gaps = capture(tmp_path, monkeypatch)
    assert edges == []
    assert len(gaps) == 1
    assert "needs a local Git checkout at the caller commit" in gaps[0]


@pytest.mark.parametrize(
    ("case", "reason"),
    [
        ("committed", None),
        ("workspace", "through a workspace-relative action"),
        ("docker", "action execution type 'docker' is outside the local call analysis"),
    ],
)
def test_cli_preserves_self_repository_source_boundaries(tmp_path, case, reason):
    if case == "committed":
        write(tmp_path, CALLER, caller("$/" + WORKFLOW))
    else:
        ref = "./" if case == "workspace" else "$/"
        write(
            tmp_path,
            CALLER,
            f"on: push\njobs:\n  check:\n    runs-on: ubuntu-latest\n"
            f"    steps:\n      - uses: {ref}.github/actions/print\n",
        )
        manifest = (
            "runs:\n  using: composite\n  steps:\n    - uses: $/.github/actions/helper\n"
            if case == "workspace"
            else "runs:\n  using: docker\n  image: Dockerfile\n"
        )
        write(tmp_path, ACTION, manifest)
        if case == "workspace":
            write(
                tmp_path,
                ".github/actions/helper/action.yml",
                "runs:\n  using: composite\n  steps:\n    - run: echo hello\n      shell: bash\n",
            )
    write(tmp_path, WORKFLOW, REUSABLE)
    commit(tmp_path)

    result = subprocess.run(
        [
            sys.executable, "-m", "taintly", str(tmp_path),
            "--platform", "github", "--no-config", "--no-color", "--format", "sarif",
            "--min-severity", "CRITICAL",
        ],
        capture_output=True, encoding="utf-8", timeout=20,
        env={**os.environ, "PYTHONUTF8": "1"},
    )
    assert result.returncode == (11 if reason else 0), result.stderr
    run, = json.loads(result.stdout)["runs"]
    notices = run["invocations"][0]["toolExecutionNotifications"]
    assert run["properties"]["coverage_status"] == ("incomplete" if reason else "not_established")
    if reason:
        matching = [notice for notice in notices if reason in notice["message"]["text"]]
        assert matching, notices
        expected_file = ACTION if case == "workspace" else CALLER
        assert all(
            notice["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            .replace("\\", "/").endswith(expected_file)
            for notice in matching
        )
    else:
        assert not notices
