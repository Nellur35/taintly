"""Observe the pinned Shiro matrix publisher from saved Jenkins records."""

from __future__ import annotations

import hashlib
import re
from collections import Counter
from pathlib import Path
from typing import Any

from .jenkins_incrementals import IncrementalsEvidenceError, _one, _project_file, _require
from .jenkins_maven_snapshot import _CONTROLLER, _REGISTRY, _REPOSITORY, _interval, _source_bytes

MATRIX_SCHEMA = "jenkins-asf-matrix-maven-guard-v1"
MATRIX_SCOPE = (
    "This profile uses trusted saved GitHub and Jenkins records and covers the pinned "
    "remote stage in the selected run. "
    "Exact stash contents, filesystem identity, registry permission on PR executors, and other "
    "publication paths remain unverified."
)
_FOLDER = f"{_CONTROLLER}/job/Shiro/job/Shiro-all/"
_TARGET = (_REGISTRY + _REPOSITORY).rstrip("/")
_REPO = "apache/shiro"
_PATH = ".jenkins.groovy"
_DEFINITION = "17be97dabe8bb2d54afde62f35ee2ad251d5d016e83daafe0b030a731ad22ab1"
_AXIS_DEFINITION = "ac30858ff34360b8108d789fae651610fe43e58da69280bb0b61b4ebbd461809"
_STASH = "ci-build"
_CHECKOUT = "Check out from version control"
_VERIFY = (
    "./mvnw verify --show-version --errors --batch-mode --no-transfer-progress "
    "-Pdocs -DskipTests -DskipITs"
)
_DEPLOY = (
    "./mvnw deploy --show-version --errors --batch-mode --no-transfer-progress "
    "-Dmaven.main.skip=true -Dmaven.test.compile.skip=true -Daspectj.skip=true "
    "-Pdocs -DskipTests -DskipITs -Dmaven.install.skip=true -Dcheckstyle.skip"
)
_BRANCHES = {f"Matrix - MATRIX_JDK = 'jdk_{jdk}_latest'" for jdk in (21, 25, 27)}
_STAGES = {
    "Checkout and Initialization": 1,
    "Compile and package": 1,
    "Checkout and Restore build": 3,
    "Deploy": 3,
}
_AXIS_BRANCHES = {f"Matrix - MATRIX_JDK = 'jdk_{jdk}_latest'" for jdk in (21, 25, 26)}
_AXIS_STAGES = {"Checkout": 3, "Deploy": 3, **dict.fromkeys(_AXIS_BRANCHES, 1)}
_SHA = r"[0-9a-f]{40}"
_DIGEST = r"[0-9a-f]{64}"
_ID = r"[1-9][0-9]{0,9}"
_Row = dict[str, Any]


def _pinned_source(
    root: Path, source: _Row, revision: str, filename: str, *, allow_per_axis: bool = False
) -> bool:
    body = _source_bytes(root, source, revision, filename, path=_PATH)
    digest = hashlib.sha256(body).hexdigest()
    per_axis = allow_per_axis and digest == _AXIS_DEFINITION
    _require(digest == _DEFINITION or per_axis, "unreviewed matrix definition")
    return per_axis


def _owned_flow(record: _Row, job: str) -> str:
    node = record["id"]
    _require(isinstance(node, str) and re.fullmatch(_ID, node), "malformed matrix flow id")
    route = f"{job}execution/node/{node}/"
    _require(
        record["_links"]["self"]["href"] == route.removeprefix(_CONTROLLER) + "wfapi/describe",
        "matrix stage or node belongs to another run",
    )
    return route


def _matrix_stages(data: _Row, job: str, *, per_axis: bool = False) -> dict[str, list[_Row]]:
    run, graph = data["run"], data["graph"]
    started, ended = _interval(graph)
    queued, delay, duration = run["timestamp"], graph["queueDurationMillis"], run["duration"]
    number = job.rstrip("/").rsplit("/", 1)[1]
    _require(
        run["url"] == job
        and type(run["number"]) is int
        and str(run["number"]) == number
        and run["building"] is False
        and run["result"] == graph["status"] == "SUCCESS"
        and graph["id"] == number
        and type(queued) is int
        and type(delay) is int
        and delay >= 0
        and type(duration) is int
        and queued + delay == started
        and started + duration == ended == graph["endTimeMillis"]
        and re.fullmatch(_DIGEST, data["run_sha256"])
        and re.fullmatch(_DIGEST, data["graph_sha256"])
        and graph["_links"]["self"]["href"] == job.removeprefix(_CONTROLLER) + "wfapi/describe",
        "saved matrix graph and completed run do not match",
    )
    inventory = graph["stages"]
    stage_counts = _AXIS_STAGES if per_axis else _STAGES
    selected = [row for row in inventory if row["name"] in stage_counts]
    branches = [row for row in inventory if row["name"].startswith("Matrix - ")]
    tests = [row for row in inventory if row["name"] == ("Build" if per_axis else "Run tests")]
    if per_axis:
        tests.sort(key=lambda row: _interval(row)[0])
        _require(
            len(tests) == 4
            and len(branches) == 3
            and _interval(tests[0])[1] <= min(_interval(row)[0] for row in branches),
            "saved graph lacks the reviewed outer matrix and three builds",
        )
        tests = tests[1:]
    _require(
        len(inventory) == len({row["id"] for row in inventory})
        and Counter(row["name"] for row in selected) == stage_counts
        and Counter(row["name"] for row in branches)
        == Counter(_AXIS_BRANCHES if per_axis else _BRANCHES)
        and len(tests) == 3
        and len(data["stages"]) == len(selected),
        "saved graph lacks the complete supported matrix inventory",
    )
    result: dict[str, list[_Row]] = {name: [] for name in stage_counts}
    all_ids = {row["id"] for row in inventory}
    for stage in [*branches, *tests]:
        _owned_flow(stage, job)
        stage_start, stage_end = _interval(stage)
        _require(
            stage["status"] == "SUCCESS" and started <= stage_start < stage_end <= ended,
            "saved matrix branch or test stage did not succeed in the selected run",
        )
    for expected in selected:
        stage = _one(
            [row for row in data["stages"] if row["id"] == expected["id"]],
            "saved matrix stage is missing or ambiguous",
        )
        route = _owned_flow(expected, job)
        stage_start, stage_end = _interval(stage)
        _require(
            _owned_flow(stage, job) == route
            and stage["url"] == route + "wfapi/describe"
            and stage["name"] == expected["name"]
            and stage["status"] == expected["status"]
            and (stage_start, stage_end) == _interval(expected)
            and started <= stage_start < stage_end <= ended
            and re.fullmatch(_DIGEST, stage["receipt_sha256"]),
            "matrix detail contradicts the run graph",
        )
        for node in stage["nodes"]:
            _owned_flow(node, job)
            if (
                type(node["durationMillis"]) is int
                and node["durationMillis"] == 0
                and node["name"] in {"Print Message", "Get contextual object from internal APIs"}
            ):
                node_start = node_end = node["startTimeMillis"]
            else:
                node_start, node_end = _interval(node)
            _require(
                type(node_start) is int
                and node["id"] not in all_ids
                and stage_start <= node_start <= node_end <= stage_end,
                "matrix node is repeated or outside the owning stage",
            )
            all_ids.add(node["id"])
        result[stage["name"]].append(stage)
    # The flat inventory supports aggregate order, with no per-JDK predecessor attribution.
    checkouts = result["Checkout" if per_axis else "Checkout and Restore build"]
    for before, after in ((branches, checkouts), (checkouts, tests), (tests, result["Deploy"])):
        ends = sorted(_interval(row)[1] for row in before)
        starts = sorted(_interval(row)[0] for row in after)
        _require(
            all(end <= start for end, start in zip(ends, starts, strict=True)),
            "matrix stage order contradicts the reviewed build, tests and deploy sequence",
        )
    return result


def _stage_node(stage: _Row, name: str) -> _Row:
    node = _one(
        [node for node in stage["nodes"] if node["name"] == name],
        "matrix stage lacks a unique supported node",
    )
    _require(node["status"] == "SUCCESS", "saved matrix node did not succeed")
    return node


def _owned_checkout_log(stage: _Row, job: str, logs: list[_Row]) -> tuple[_Row, _Row]:
    checkout = _stage_node(stage, _CHECKOUT)
    log = _one([row for row in logs if row["node"] == checkout["id"]], "ambiguous checkout log")
    _require(
        log["url"] == _owned_flow(checkout, job) + "wfapi/log"
        and log["complete"] is True
        and re.fullmatch(_DIGEST, log["sha256"]),
        "matrix checkout log has the wrong revision or owner",
    )
    return checkout, log


def _bind_axis_checkouts(
    data: _Row, job: str, head: str, branch: str, base: str
) -> tuple[list[_Row], list[_Row]]:
    groups = _matrix_stages(data, job, per_axis=True)
    logs = data["checkout_logs"]
    wanted = f"Checking out Revision {head} ({branch})"
    actions = data["run"]["actions"]
    revision = _one(
        [
            row["revision"]
            for row in actions
            if row.get("_class") == "jenkins.scm.api.SCMRevisionAction"
        ],
        "ambiguous revision action",
    )
    build = _one(
        [row for row in actions if row.get("_class") == "hudson.plugins.git.util.BuildData"],
        "ambiguous matrix Git BuildData",
    )
    console = data["console"]
    _require(
        all(re.fullmatch(_ID, key) for key in console["markers"]),
        "invalid matrix console positions",
    )
    markers = [
        line for _, line in sorted((int(pos), line) for pos, line in console["markers"].items())
    ]
    _require(
        revision["_class"] == "org.jenkinsci.plugins.github_branch_source.PullRequestSCMRevision"
        and revision["pullHash"] == head
        and build["lastBuiltRevision"]["SHA1"] == head
        and build["remoteUrls"] == [f"https://github.com/{_REPO}.git"]
        and console["url"] == job + "consoleText"
        and re.fullmatch(_DIGEST, console["sha256"])
        and bool(markers)
        and markers[0] == f"Obtained {_PATH} from {base}"
        and sum(value.startswith(f"Obtained {_PATH} from ") for value in markers) == 1
        and [value for value in markers if value.startswith("Checking out Revision ")]
        == [wanted] * 6
        and isinstance(logs, list)
        and len(logs) == 6,
        "saved matrix source or complete fork-head checkouts are unverified",
    )
    checkouts = [groups[name][0] for name in sorted(_AXIS_BRANCHES)] + groups["Checkout"]
    reported: list[_Row] = []
    for stage in checkouts:
        _require(stage["status"] == "SUCCESS", "matrix checkout stage did not succeed")
        node, log = _owned_checkout_log(stage, job, logs)
        _require(
            log["line"] == wanted
            and log["merge_line"]
            == f"Merging remotes/origin/main commit {base} into PR head commit {head}"
            and log["merge_result"] == f"Merge succeeded, producing {head}",
            "matrix checkout does not report the selected fork head and historical base",
        )
        reported.append({"stage": stage["id"], "node": node["id"], "revision": head})
    return groups["Deploy"], reported


def _bind_build(
    data: _Row, job: str, head: str, branch: str, loader: str, *, merge_base: str | None = None
) -> tuple[list[_Row], _Row, list[_Row]]:
    groups = _matrix_stages(data, job)
    initial = groups["Checkout and Initialization"][0]
    compiled = groups["Compile and package"][0]
    restores = groups["Checkout and Restore build"]
    deploys = groups["Deploy"]
    expected_checkout = f"Checking out Revision {head} ({branch})"
    actions = data["run"]["actions"]
    revision = _one(
        [
            row["revision"]
            for row in actions
            if row.get("_class") == "jenkins.scm.api.SCMRevisionAction"
        ],
        "ambiguous revision action",
    )
    checkout_data = [
        row for row in actions if row.get("_class") == "hudson.plugins.git.util.BuildData"
    ]
    if merge_base is None:
        single = _one(checkout_data, "ambiguous matrix Git BuildData")
        _require(
            single["lastBuiltRevision"]["SHA1"] == head,
            "selected matrix source, workspaces or checkpoint order is unverified",
        )
    kind = (
        "org.jenkinsci.plugins.github_branch_source.PullRequestSCMRevision"
        if branch.startswith("PR-")
        else "jenkins.plugins.git.AbstractGitSCMSource$SCMRevisionImpl"
    )
    console = data["console"]
    markers = sorted((int(key), value) for key, value in console["markers"].items())
    checkouts = [value for _, value in markers if value.startswith("Checking out Revision ")]
    _require(
        revision["_class"] == kind
        and revision.get("pullHash" if branch.startswith("PR-") else "hash") == head
        and console["url"] == job + "consoleText"
        and re.fullmatch(_DIGEST, console["sha256"])
        and bool(markers)
        and markers[0][0] > 0
        and markers[0][1] == loader
        and sum(value.startswith(f"Obtained {_PATH} from ") for _, value in markers) == 1
        and (merge_base is not None or checkouts == [expected_checkout] * 4)
        and all(row["status"] == "SUCCESS" for row in [initial, compiled, *restores])
        and _interval(initial)[1] <= _interval(compiled)[0]
        and _interval(compiled)[1] <= min(_interval(row)[0] for row in restores)
        and max(_interval(row)[1] for row in restores) <= min(_interval(row)[0] for row in deploys),
        "selected matrix source, workspaces or checkpoint order is unverified",
    )
    logs = data["checkout_logs"]
    _require(len(logs) == 4, "saved matrix checkout inventory is incomplete")
    reported_checkouts: list[_Row] = []
    for stage in [initial, *restores]:
        expected_nodes = [_CHECKOUT]
        if stage is not initial:
            expected_nodes.append("Restore files previously stashed")
        _require(
            [node["name"] for node in stage["nodes"] if node["name"] != "Print Message"]
            == expected_nodes,
            "unsupported operation in the selected checkout and restore stage",
        )
        checkout, log = _owned_checkout_log(stage, job, logs)
        if merge_base is None:
            _require(
                log["line"] == expected_checkout,
                "matrix checkout log has the wrong revision or owner",
            )
        else:
            merged = re.fullmatch(
                rf"Checking out Revision ({_SHA}) \({re.escape(branch)}\)", log["line"]
            )
            if merged is None:
                raise IncrementalsEvidenceError(
                    "matrix checkout log has no reported merge revision"
                )
            revision_sha = merged[1]
            _require(
                revision_sha not in {head, merge_base}
                and log["merge_line"]
                == f"Merging remotes/origin/main commit {merge_base} into PR head commit {head}"
                and log["merge_result"] == f"Merge succeeded, producing {revision_sha}",
                "matrix checkout does not bind the selected PR head and historical base",
            )
            reported_checkouts.append(
                {"stage": stage["id"], "node": checkout["id"], "revision": revision_sha}
            )
        if stage is not initial:
            restore = _stage_node(stage, "Restore files previously stashed")
            _require(
                restore["parameterDescription"] == _STASH
                and _interval(checkout)[1] <= _interval(restore)[0],
                "unsupported stash restore or checkout order",
            )
    if merge_base is not None:
        revisions = {row["revision"] for row in reported_checkouts}
        _require(
            all(re.fullmatch(_ID, key) for key in console["markers"])
            and Counter(checkouts)
            == Counter(
                f"Checking out Revision {row['revision']} ({branch})" for row in reported_checkouts
            )
            and len(checkout_data) == len(revisions)
            and {row["lastBuiltRevision"]["SHA1"] for row in checkout_data} == revisions
            and all(
                row["remoteUrls"] == [f"https://github.com/{_REPO}.git"] for row in checkout_data
            ),
            "matrix console and controller BuildData do not match the owned checkout logs",
        )
    package = _stage_node(compiled, "Shell Script")
    stash = _stage_node(compiled, "Stash some files to be used later in the build")
    _require(
        [node["id"] for node in compiled["nodes"] if node["name"] != "Print Message"]
        == [package["id"], stash["id"]]
        and " ".join(package["parameterDescription"].split()) == _VERIFY
        and stash["parameterDescription"] == _STASH
        and _interval(package)[1] <= _interval(stash)[0],
        "saved package or stash does not match the reviewed route",
    )
    return deploys, stash, reported_checkouts


def _snapshot_record(root: Path, data: _Row, shell: _Row, target: str) -> _Row:
    nexus, saved_shell = data["nexus"], data["shell"]
    attrs = nexus["attributes"]
    built = re.fullmatch(
        r"\[INFO\] Building Apache Shiro :: Core ([0-9]{1,6}(?:\.[0-9]{1,6}){2})-SNAPSHOT +\[\d+/\d+\]",
        saved_shell["module_build"],
    )
    if built is None:
        raise IncrementalsEvidenceError(
            "owned Maven shell lacks the selected snapshot module and version"
        )
    version = re.escape(built[1])
    start, end = _interval(shell)
    path, created = nexus["path"], attrs["storageItem-created"]
    stored = _project_file(root, "registry-object.bin", 1_000_000)
    digest = hashlib.sha256(stored).hexdigest()
    _require(
        re.fullmatch(
            rf"/org/apache/shiro/shiro-core/{version}-SNAPSHOT/shiro-core-{version}-[0-9]{{8}}\.[0-9]{{6}}-{_ID}\.jar",
            path,
        )
        and nexus["object_url"] == target + path
        and attrs["storageItem-path"] == path
        and nexus["url"]
        == f"{_REGISTRY}/service/local/repositories/snapshots/content{path}?describe"
        and re.fullmatch(_DIGEST, nexus["receipt_sha256"])
        and attrs["storageItem-repositoryId"] == "snapshots"
        and re.fullmatch(r"[0-9]{13}", created)
        and start <= int(created) <= end
        and created == attrs["storageItem-modified"]
        and re.fullmatch(_ID, attrs["storageItem-generation"])
        and attrs["request.user"] == "ci-hudson"
        and stored
        and attrs["digest.sha256"] == digest,
        "stored Nexus item does not match the requested object, actor and Maven interval",
    )
    return {
        "state": "same-window-stored-record",
        "object_url": nexus["object_url"],
        "sha256": digest,
        "recorded_writer": attrs["request.user"],
        "generation": int(attrs["storageItem-generation"]),
        "run_to_object": "unverified",
    }


def _main_comparison(root: Path, data: _Row, target: str) -> _Row:
    try:
        job = data["run"]["url"]
        revision = data["source"]["commit"]
        _require(
            re.fullmatch(re.escape(_FOLDER) + rf"job/main/{_ID}/", job)
            and re.fullmatch(_SHA, revision),
            "main comparison has a foreign run or revision",
        )
        _pinned_source(root, data["source"], revision, "main.groovy")
        deploys, _, _ = _bind_build(
            data, job, revision, "main", f"Obtained {_PATH} from {revision}"
        )
        selected = _one(
            [row for row in deploys if row["status"] == "SUCCESS"], "no unique main deploy stage"
        )
        node = _stage_node(selected, "Shell Script")
        receipt = data["shell"]
        _require(
            all(_skipped(row) for row in deploys if row is not selected)
            and [row["id"] for row in selected["nodes"] if row["name"] != "Print Message"]
            == [node["id"]]
            and receipt["complete"] is True
            and receipt["node"] == node["id"]
            and receipt["url"] == _owned_flow(node, job) + "log/logText/progressiveText?start=0"
            and re.fullmatch(_DIGEST, receipt["sha256"])
            and receipt["command"] == " ".join(node["parameterDescription"].split()) == _DEPLOY
            and receipt["maven_goal"]
            == "[INFO] --- deploy:3.2.0:deploy (default-deploy) @ shiro-core ---",
            "no owned main Maven deployment command and module goal",
        )
    except (
        IncrementalsEvidenceError,
        AttributeError,
        IndexError,
        KeyError,
        OSError,
        TypeError,
        ValueError,
    ):
        return {
            "state": "unresolved",
            "reason": "main run does not corroborate the matched publisher invocation",
        }
    result: _Row = {
        "state": "deploy-command-observed",
        "job": job,
        "revision": revision,
        "node": node["id"],
        "command": _DEPLOY,
        "authority": "unresolved",
    }
    if "nexus" in data:
        try:
            result["registry_record"] = _snapshot_record(root, data, node, target)
        except (
            IncrementalsEvidenceError,
            AttributeError,
            IndexError,
            KeyError,
            OSError,
            TypeError,
            ValueError,
        ):
            result["registry_record"] = {
                "state": "unresolved",
                "reason": "no bound same-window Nexus object",
            }
    return result


def _skipped(stage: _Row) -> bool:
    return stage["status"] == "NOT_EXECUTED" and [
        (node["name"], node["status"]) for node in stage["nodes"]
    ] == [("Get contextual object from internal APIs", "SUCCESS")]


def matrix_snapshot_observation(
    root: Path, data: _Row, repo: str, pr: int, job: str, target: str
) -> _Row:
    pull = data["pull"]
    head, base = pull["head"], pull["base"]
    target_base = data.get("definition_role") == "target-base"
    if target_base:
        _require("merge" not in data, "target-base definition has conflicting merge evidence")
        revision, loader_suffix = base, base
    else:
        _require("definition_role" not in data, "unsupported matrix definition role")
        merge = data["merge"]
        revision = merge["commit"]
        _require(
            revision not in {head, base} and merge["parents"] == [base, head],
            "outside the reviewed Shiro fork matrix and snapshot profile",
        )
        loader_suffix = f"{head}+{base} ({revision})"
    branch = f"PR-{pr}"
    _require(
        repo == pull["target_repository"] == _REPO
        and type(pull["number"]) is int
        and pull["number"] == pr > 0
        and pull["base_ref"] == "main"
        and pull["source_repository"].lower() != repo
        and re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", pull["source_repository"])
        and target == _TARGET
        and re.fullmatch(re.escape(f"{_FOLDER}job/{branch}/") + rf"{_ID}/", job)
        and all(re.fullmatch(_SHA, value) for value in (head, base, revision))
        and head != base,
        "outside the reviewed Shiro fork matrix and snapshot profile",
    )
    per_axis = _pinned_source(
        root, data["source"], revision, "pipeline.groovy", allow_per_axis=target_base
    )
    fork = data["fork"]
    if per_axis:
        _require("comparison" not in data, "comparison requires the reviewed shared-build matrix")
        deploys, checkouts = _bind_axis_checkouts(fork, job, head, branch, base)
        stash = None
    else:
        deploys, stash, checkouts = _bind_build(
            fork,
            job,
            head,
            branch,
            f"Obtained {_PATH} from {loader_suffix}",
            merge_base=base if target_base else None,
        )
    markers = [(int(line), value) for line, value in fork["console"]["markers"].items()]
    skips = [(line, value) for line, value in markers if value.startswith('Stage "Deploy" skipped')]
    last_checkout = max(
        line for line, value in markers if value.startswith("Checking out Revision ")
    )
    _require(
        all(_skipped(row) for row in deploys)
        and len(skips) == 3
        and all(
            line > last_checkout and value == 'Stage "Deploy" skipped due to when conditional'
            for line, value in skips
        ),
        "saved run does not corroborate conditional skips for all remote publisher instances",
    )
    result: _Row = {
        "state": "remote-matrix-publisher-skipped",
        "repository": repo,
        "pr": pr,
        "job": job,
        "head": head,
        "source": {"path": _PATH, "revision": revision, "line": 152 if per_axis else 180},
        **(
            {"stash": {"name": _STASH, "producer_node": stash["id"], "reported_restores": 3}}
            if stash is not None
            else {"build_layout": "per-axis"}
        ),
        "remote_publisher": {
            "stage": "Deploy",
            "stage_ids": [row["id"] for row in deploys],
            "condition": "not { changeRequest() }",
            "candidate_repository": target,
        },
        "authority": "unresolved",
        "scope": (
            "This profile covers the pinned remote stages in one matrix run. Actual workspace bytes, "
            "registry permissions on PR executors, and other publication paths remain unverified."
            if per_axis
            else MATRIX_SCOPE
        ),
    }
    if target_base:
        result["source"]["role"] = "target-base"
        result["reported_checkouts"] = {
            "head": head,
            "base": base,
            "nodes": checkouts,
            "merge_bytes": "unverified",
        }
    if "comparison" in data:
        result["comparison"] = _main_comparison(root, data["comparison"], target)
    return result
