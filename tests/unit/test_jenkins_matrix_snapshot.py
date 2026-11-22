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


@pytest.fixture
def target_base_packet(packet):
    packet.pop("merge")
    packet["definition_role"] = "target-base"
    packet["source"]["commit"] = BASE
    fork = packet["fork"]
    markers = fork["console"]["markers"]
    markers["3"] = f"Obtained .jenkins.groovy from {BASE}"
    revisions = [MERGE, "d" * 40, MERGE, "e" * 40]
    for n, (entry, revision) in enumerate(zip(fork["checkout_logs"], revisions, strict=True), 5):
        markers[str(n)] = entry["line"] = f"Checking out Revision {revision} (PR-7)"
        entry["merge_line"] = (
            f"Merging remotes/origin/main commit {BASE} into PR head commit {HEAD}"
        )
        entry["merge_result"] = f"Merge succeeded, producing {revision}"
    actions = fork["run"]["actions"]
    actions.pop()
    actions.extend(
        {
            "_class": "hudson.plugins.git.util.BuildData",
            "lastBuiltRevision": {"SHA1": revision},
            "remoteUrls": ["https://github.com/apache/shiro.git"],
        }
        for revision in sorted(set(revisions))
    )
    return packet


def test_target_base_definition_keeps_distinct_checkout_nodes(tmp_path, target_base_packet):
    observed = _observe(tmp_path, target_base_packet)
    assert observed["state"] == "remote-matrix-publisher-skipped"
    assert observed["source"]["revision"] == BASE
    assert observed["source"]["role"] == "target-base"
    selected = observed["reported_checkouts"]
    assert selected["head"] == HEAD
    assert selected["base"] == BASE
    assert [row["revision"] for row in selected["nodes"]] == [MERGE, "d" * 40, MERGE, "e" * 40]
    assert len({row["node"] for row in selected["nodes"]}) == 4
    assert selected["merge_bytes"] == "unverified"
    assert observed["authority"] == "unresolved"


@pytest.mark.parametrize(
    "contradiction",
    [
        "role",
        "loader",
        "merge",
        "checkout",
        "remote",
        "console",
        "duplicate_line",
        "earlier_failure",
    ],
)
def test_target_base_requires_own_loader_and_checkout_logs(
    tmp_path, target_base_packet, contradiction
):
    fork = target_base_packet["fork"]
    markers = fork["console"]["markers"]
    first = fork["checkout_logs"][0]
    if contradiction == "role":
        target_base_packet["definition_role"] = "fork-head"
    elif contradiction == "loader":
        markers["3"] = f"Obtained .jenkins.groovy from {HEAD}"
    elif contradiction == "merge":
        first["merge_line"] = first["merge_line"].replace(HEAD, "f" * 40)
    elif contradiction == "checkout":
        first["merge_result"] = "Merge succeeded, producing " + "f" * 40
    elif contradiction == "remote":
        fork["run"]["actions"][-1]["remoteUrls"] = ["https://github.com/fork/shiro.git"]
    elif contradiction == "console":
        markers["5"] = markers["6"]
    elif contradiction == "duplicate_line":
        markers["020"] = markers.pop("21")
    else:
        markers["20"] = 'Stage "Deploy" skipped due to earlier failure(s)'
    assert _observe(tmp_path, target_base_packet)["state"] == "unresolved"


@pytest.fixture
def axis_packet(packet, monkeypatch):
    monkeypatch.setattr(matrix, "_AXIS_DEFINITION", matrix._DEFINITION)
    monkeypatch.setattr(matrix, "_DEFINITION", "f" * 64)
    packet["definition_role"] = "target-base"
    packet.pop("comparison")
    packet.pop("merge")
    packet["source"]["commit"] = BASE
    fork = packet["fork"]
    fork["run"]["actions"][-1]["remoteUrls"] = ["https://github.com/apache/shiro.git"]
    fork["graph"]["stages"] = []
    fork["stages"] = []
    fork["checkout_logs"] = []
    checkout = f"Checking out Revision {HEAD} (PR-7)"
    fork["console"]["markers"] = {
        "3": f"Obtained .jenkins.groovy from {BASE}",
        **{str(i): checkout for i in range(5, 11)},
        **{str(i): 'Stage "Deploy" skipped due to when conditional' for i in range(20, 23)},
    }

    def add_stage(identifier, name, start, duration, node_name=None):
        route = FORK + f"execution/node/{identifier}/wfapi/describe"
        stage = {
            "name": name,
            "id": str(identifier),
            "startTimeMillis": START + start,
            "durationMillis": duration,
            "status": "NOT_EXECUTED" if name == "Deploy" else "SUCCESS",
            "_links": {"self": {"href": route.removeprefix(matrix._CONTROLLER)}},
        }
        fork["graph"]["stages"].append(stage)
        if node_name is None:
            return
        node_id = str(identifier + 100)
        node_url = FORK + f"execution/node/{node_id}/wfapi/"
        node = {
            **stage,
            "name": node_name,
            "id": node_id,
            "durationMillis": 3,
            "status": "SUCCESS",
            "_links": {"self": {"href": node_url.removeprefix(matrix._CONTROLLER) + "describe"}},
        }
        fork["stages"].append({**stage, "nodes": [node], "url": route, "receipt_sha256": RECEIPT})
        if node_name == matrix._CHECKOUT:
            fork["checkout_logs"].append({
                "node": node_id, "url": node_url + "log", "complete": True,
                "sha256": RECEIPT, "line": checkout,
                "merge_line": f"Merging remotes/origin/main commit {BASE} into PR head commit {HEAD}",
                "merge_result": f"Merge succeeded, producing {HEAD}",
            })

    add_stage(1, "Build", 10, 10)
    for index, name in enumerate(sorted(matrix._AXIS_BRANCHES)):
        add_stage(10 + index, name, 100, 80, matrix._CHECKOUT)
        add_stage(20 + index, "Checkout", 250, 80, matrix._CHECKOUT)
        add_stage(30 + index, "Build", 400, 80)
        add_stage(40 + index, "Deploy", 600, 80, "Get contextual object from internal APIs")
    return packet


@pytest.mark.parametrize(
    "contrast", [None, "missing-auto-checkout", "different-base", "sibling-log", "mixed-deploy", "changed-source"]
)
def test_per_axis_matrix_requires_owned_checkout_and_all_skips(tmp_path, axis_packet, contrast):
    fork = axis_packet["fork"]
    if contrast == "missing-auto-checkout":
        fork["checkout_logs"].pop(0)
    elif contrast == "different-base":
        first = fork["checkout_logs"][0]
        first["merge_line"] = first["merge_line"].replace(BASE, MERGE)
    elif contrast == "sibling-log":
        fork["checkout_logs"][0]["url"] = fork["checkout_logs"][2]["url"]
    elif contrast == "mixed-deploy":
        next(stage for stage in fork["graph"]["stages"] if stage["id"] == "40")["status"] = "SUCCESS"
        next(stage for stage in fork["stages"] if stage["id"] == "40")["status"] = "SUCCESS"
    elif contrast == "changed-source":
        (tmp_path / "source" / "pipeline.groovy").write_bytes(b"// unrelated")
    observation = _observe(tmp_path, axis_packet)
    if contrast is not None:
        assert observation["state"] == "unresolved"
        return
    assert observation["build_layout"] == "per-axis"
    assert observation["remote_publisher"]["stage_ids"] == ["40", "41", "42"]
    assert "stash" not in observation
    assert observation["source"]["line"] == 152
    assert len(observation["reported_checkouts"]["nodes"]) == 6
    assert observation["authority"] == "unresolved"


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
