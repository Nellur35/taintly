"""Authored controls for observed matrix publisher decisions."""

import hashlib
import json
import sys

import pytest

from taintly import __main__ as cli
from taintly.ingestion import jenkins_matrix_snapshot as matrix
from taintly.ingestion.jenkins_maven_snapshot import maven_snapshot_observation

FORK = matrix._FOLDER + "job/PR-7/3/"
MAIN = matrix._FOLDER + "job/main/2/"
HEAD, BASE, MERGE = "a" * 40, "b" * 40, "c" * 40
START = 1794510000000
RECEIPT = "d" * 64


def _record(job, is_pull):
    branch = "PR-7" if is_pull else "main"
    revision = HEAD if is_pull else BASE
    checkout = f"Checking out Revision {revision} ({branch})"
    definition = f"{HEAD}+{BASE} ({MERGE})" if is_pull else BASE
    kinds = [
        ("Checkout and Initialization", [matrix._CHECKOUT]),
        ("Compile and package", ["Shell Script", "Stash some files to be used later in the build"]),
        *[("Checkout and Restore build", [matrix._CHECKOUT, "Restore files previously stashed"])]
        * 3,
        *[("Deploy", ["Get contextual object from internal APIs"])] * 3,
    ]
    if not is_pull:
        kinds[5] = ("Deploy", ["Shell Script"])

    def flow(identifier, name, start, duration):
        route = job + f"execution/node/{identifier}/wfapi/describe"
        return {
            "id": str(identifier),
            "name": name,
            "startTimeMillis": start,
            "durationMillis": duration,
            "status": "SUCCESS",
            "_links": {"self": {"href": route.removeprefix(matrix._CONTROLLER)}},
        }

    stages, details, logs = [], [], []
    for index, (name, node_names) in enumerate(kinds, start=1):
        stage_start = START + (index if index < 6 else index + 2) * 100
        stage = flow(index, name, stage_start, 90)
        nodes = []
        for offset, node_name in enumerate(node_names, start=1):
            node = flow(10 * index + offset, node_name, stage_start + offset * 10, 4)
            nodes.append(node)
            if node_name == matrix._CHECKOUT:
                logs.append(
                    {
                        "node": node["id"],
                        "url": job + f"execution/node/{node['id']}/wfapi/log",
                        "complete": True,
                        "line": checkout,
                        "sha256": RECEIPT,
                    }
                )
            elif node_name == "Shell Script":
                node["parameterDescription"] = matrix._VERIFY if index == 2 else matrix._DEPLOY
            elif node_name.startswith(("Restore", "Stash")):
                node["parameterDescription"] = matrix._STASH
            else:
                node["durationMillis"] = 0
                stage["status"] = "NOT_EXECUTED"
        stages.append(stage)
        details.append(
            {
                **stage,
                "url": matrix._CONTROLLER + stage["_links"]["self"]["href"],
                "receipt_sha256": RECEIPT,
                "nodes": nodes,
            }
        )
    stages.extend(
        flow(200 + i, name, START + 250, 40) for i, name in enumerate(sorted(matrix._BRANCHES))
    )
    stages.extend(flow(300 + i, "Run tests", START + 600 + 100 * i, 80) for i in range(3))
    kind = (
        "org.jenkinsci.plugins.github_branch_source.PullRequestSCMRevision"
        if is_pull
        else "jenkins.plugins.git.AbstractGitSCMSource$SCMRevisionImpl"
    )
    number = int(job.rstrip("/").rsplit("/", 1)[1])
    return {
        "run": {
            "url": job,
            "number": number,
            "building": False,
            "result": "SUCCESS",
            "timestamp": START - 40,
            "duration": 1200,
            "actions": [
                {},
                {
                    "_class": "jenkins.scm.api.SCMRevisionAction",
                    "revision": {
                        "_class": kind,
                        "pullHash" if is_pull else "hash": revision,
                    },
                },
                {
                    "_class": "hudson.plugins.git.util.BuildData",
                    "lastBuiltRevision": {"SHA1": revision},
                },
            ],
        },
        "run_sha256": RECEIPT,
        "graph_sha256": RECEIPT,
        "graph": {
            "id": str(number),
            "status": "SUCCESS",
            "startTimeMillis": START,
            "durationMillis": 1200,
            "endTimeMillis": START + 1200,
            "queueDurationMillis": 40,
            "stages": stages,
            "_links": {"self": {"href": job.removeprefix(matrix._CONTROLLER) + "wfapi/describe"}},
        },
        "stages": details,
        "checkout_logs": logs,
        "console": {
            "url": job + "consoleText",
            "sha256": RECEIPT,
            "markers": {
                "3": f"Obtained .jenkins.groovy from {definition}",
                **{str(line): checkout for line in range(5, 9)},
                **{
                    str(line): 'Stage "Deploy" skipped due to when conditional'
                    for line in range(20, 23)
                },
            },
        },
    }


@pytest.fixture
def packet(tmp_path, monkeypatch):
    # Exercise actual blob/SHA validation against an authored definition, using a test-only pin.
    source = b"// Inert authored definition\n"
    digest = hashlib.sha256(source).hexdigest()
    monkeypatch.setattr(matrix, "_DEFINITION", digest)
    blob = hashlib.sha1(
        f"blob {len(source)}\0".encode() + source, usedforsecurity=False
    ).hexdigest()
    (tmp_path / "source").mkdir()
    for name in ("pipeline.groovy", "main.groovy"):
        (tmp_path / "source" / name).write_bytes(source)
    main = _record(MAIN, False)
    main["source"] = {"path": ".jenkins.groovy", "commit": BASE, "blob": blob, "sha256": digest}
    main["shell"] = {
        "url": MAIN + "execution/node/61/log/logText/progressiveText?start=0",
        "node": "61",
        "complete": True,
        "sha256": RECEIPT,
        "command": matrix._DEPLOY,
        "maven_goal": "[INFO] --- deploy:3.2.0:deploy (default-deploy) @ shiro-core ---",
        "module_build": "[INFO] Building Apache Shiro :: Core 3.0.3-SNAPSHOT      [15/56]",
    }
    path = "/org/apache/shiro/shiro-core/3.0.3-SNAPSHOT/shiro-core-3.0.3-20261113.022213-2.jar"
    stored = b"Inert object"
    (tmp_path / "registry-object.bin").write_bytes(stored)
    main["nexus"] = {
        "path": path,
        "object_url": matrix._TARGET + path,
        "receipt_sha256": RECEIPT,
        "url": matrix._REGISTRY
        + "/service/local/repositories/snapshots/content"
        + path
        + "?describe",
        "attributes": {
            "storageItem-path": path,
            "storageItem-repositoryId": "snapshots",
            "storageItem-created": str(START + 811),
            "storageItem-modified": str(START + 811),
            "storageItem-generation": "2",
            "request.user": "ci-hudson",
            "digest.sha256": hashlib.sha256(stored).hexdigest(),
        },
    }
    return {
        "schema": matrix.MATRIX_SCHEMA,
        "pull": {
            "number": 7,
            "head": HEAD,
            "base": BASE,
            "source_repository": "fork/shiro",
            "target_repository": "apache/shiro",
            "base_ref": "main",
        },
        "merge": {"commit": MERGE, "parents": [BASE, HEAD]},
        "source": {**main["source"], "commit": MERGE},
        "fork": _record(FORK, True),
        "comparison": main,
    }


def _observe(tmp_path, packet):
    (tmp_path / "snapshot.json").write_text(json.dumps(packet), encoding="utf-8")
    return maven_snapshot_observation(tmp_path, "apache/shiro", 7, FORK, matrix._TARGET)


def test_conditional_skip_and_same_window_record_are_distinct(tmp_path, packet):
    observed = _observe(tmp_path, packet)
    assert observed["state"] == "remote-matrix-publisher-skipped"
    assert observed["remote_publisher"]["stage_ids"] == ["6", "7", "8"]
    assert observed["stash"]["reported_restores"] == 3
    assert observed["authority"] == observed["comparison"]["authority"] == "unresolved"
    comparison = observed["comparison"]
    assert comparison["state"] == "deploy-command-observed"
    assert comparison["registry_record"]["state"] == "same-window-stored-record"
    assert comparison["registry_record"]["run_to_object"] == "unverified"


@pytest.mark.parametrize(
    "contradiction",
    ["source", "merge", "earlier_failure", "wrong_owner", "command", "stash", "missing"],
)
def test_guard_requires_own_stages_exact_source_and_condition(tmp_path, packet, contradiction):
    fork = packet["fork"]
    if contradiction == "source":
        (tmp_path / "source" / "pipeline.groovy").write_bytes(b"different")
    elif contradiction == "merge":
        packet["merge"]["parents"].reverse()
    elif contradiction == "earlier_failure":
        fork["console"]["markers"]["20"] = 'Stage "Deploy" skipped due to earlier failure(s)'
    elif contradiction == "wrong_owner":
        fork["checkout_logs"][0]["url"] = MAIN + "execution/node/11/wfapi/log"
    elif contradiction == "command":
        fork["stages"][5]["nodes"][0]["name"] = "Shell Script"
    elif contradiction == "stash":
        fork["stages"][2]["nodes"][1]["parameterDescription"] = "different"
    else:
        fork["stages"].pop()
    assert _observe(tmp_path, packet)["state"] == "unresolved"


@pytest.mark.parametrize(
    "contradiction",
    ["wrapper_owner", "wrapper_failure", "test_failure", "early_marker", "context_failure"],
)
def test_matrix_predecessors_and_skip_markers_must_agree(tmp_path, packet, contradiction):
    fork = packet["fork"]
    inventory = fork["graph"]["stages"]
    wrapper = next(row for row in inventory if row["name"].startswith("Matrix - "))
    if contradiction == "wrapper_owner":
        wrapper["_links"]["self"]["href"] = wrapper["_links"]["self"]["href"].replace(
            "PR-7", "PR-8"
        )
    elif contradiction == "wrapper_failure":
        wrapper["status"] = "FAILED"
    elif contradiction == "test_failure":
        next(row for row in inventory if row["name"] == "Run tests")["status"] = "FAILED"
    elif contradiction == "early_marker":
        markers = fork["console"]["markers"]
        markers["4"] = markers.pop("20")
    else:
        fork["stages"][5]["nodes"][0]["status"] = "FAILED"
    assert _observe(tmp_path, packet)["state"] == "unresolved"


@pytest.mark.parametrize(
    "contradiction", ["wrong_owner", "partial_log", "wrong_object", "wrong_time", "missing_module"]
)
def test_invalid_comparison_preserves_the_guard(tmp_path, packet, contradiction):
    main = packet["comparison"]
    if contradiction == "wrong_owner":
        main["shell"]["url"] = FORK + "execution/node/61/log/logText/progressiveText?start=0"
    elif contradiction == "partial_log":
        main["shell"]["complete"] = False
    elif contradiction == "wrong_object":
        (tmp_path / "registry-object.bin").write_bytes(b"different bytes")
    elif contradiction == "wrong_time":
        main["nexus"]["attributes"]["storageItem-created"] = str(START - 1)
    else:
        main["shell"]["module_build"] = "unknown version"
    observed = _observe(tmp_path, packet)
    assert observed["state"] == "remote-matrix-publisher-skipped"
    comparison = observed["comparison"]
    if contradiction in {"wrong_owner", "partial_log"}:
        assert comparison["state"] == "unresolved"
    else:
        assert comparison["state"] == "deploy-command-observed"
        assert comparison["registry_record"]["state"] == "unresolved"


@pytest.mark.parametrize("status", ["complete", "guard_only", "partial"])
def test_cli_preserves_scope_and_reports_partial_comparison(
    tmp_path, packet, monkeypatch, capsys, status
):
    if status == "guard_only":
        del packet["comparison"]
    elif status == "partial":
        packet["comparison"]["shell"]["complete"] = False
    (tmp_path / "snapshot.json").write_text(json.dumps(packet), encoding="utf-8")
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "taintly",
            str(tmp_path),
            "--no-config",
            "--jenkins-maven-snapshot-observation",
            "apache/shiro",
            "7",
            FORK,
            matrix._TARGET,
        ],
    )
    with pytest.raises(SystemExit) as exc:
        cli.main()
    output = capsys.readouterr().out
    assert "All 3 Deploy stages were skipped by their conditions." in output
    assert "registry permission on PR executors" in output
    assert exc.value.code == (11 if status == "partial" else 0)
    assert ("Run-to-object attribution is unverified" in output) == (status == "complete")
