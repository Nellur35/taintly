"""Corroborate the reviewed Sling library's publisher exclusion in a saved fork run."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any

from taintly.parsers.jenkinsfile.groovy_lex import TokKind, tokenize

from .jenkins_incrementals import IncrementalsEvidenceError, _one, _project_file, _require
from .jenkins_maven_snapshot import _CONTROLLER, _REGISTRY, _REPOSITORY, _interval, _source_bytes

SLING_SCHEMA = "jenkins-asf-sling-shared-guard-v1"
SLING_STATE = "remote-shared-library-publisher-excluded"
SLING_SCOPE = (
    "The trusted saved records corroborate a fork checkout, Maven verify and the "
    "branch exclusion for the reviewed remote publisher. Nexus credentials, backend "
    "authorization and other publication paths remain unresolved."
)
_LIBRARY = "apache/sling-tooling-jenkins"
_LIBRARY_PATH = "vars/slingOsgiBundleBuild.groovy"
_REVISION = "faf4eceda538082b3cc2136e12361cefa5f3c7ef"
_LIBRARY_SHA256 = "7eb563fdd9afd1d6c321947754fa467aab224836223208691ec2ee75069d9e4a"
_TARGET = (_REGISTRY + _REPOSITORY).rstrip("/")
_PUBLISH_STAGE = "Deploy to Nexus"
_BUILD_DATA = "hudson.plugins.git.util.BuildData"
_SHA = r"[a-f0-9]{40}"
_ID = r"[1-9][0-9]{0,9}"
_VERIFY = re.compile(
    r"mvn --show-version -U -B -e clean verify javadoc:javadoc"
    r"(?: -Dit\.startTimeoutSeconds=[0-9]{1,5})? -Pjacoco-report -Dci"
)
_Row = dict[str, Any]


def _flow_interval(record: _Row, job: str) -> tuple[int, int]:
    identifier = record["id"]
    path = job.removeprefix(_CONTROLLER) + f"execution/node/{identifier}/wfapi/describe"
    _require(
        re.fullmatch(_ID, identifier) and record["_links"]["self"]["href"] == path,
        "Jenkins stage or node belongs to another run",
    )
    return _interval(record)


def _log_lines(record: _Row, node: _Row, job: str) -> list[str]:
    _require(
        record["node"] == node["id"]
        and record["url"] == job + f"execution/node/{node['id']}/log/logText/progressiveText"
        and re.fullmatch(r"[a-f0-9]{64}", record["sha256"]),
        "Jenkins log does not identify the selected flow node",
    )
    lines = record["lines"]
    if not isinstance(lines, list) or any(not isinstance(line, str) for line in lines):
        raise IncrementalsEvidenceError("Saved Jenkins node lines are malformed")
    return lines


def _verify_stage(data: _Row, job: str, branch: str, base: str, head: str) -> tuple[str, str]:
    run, graph, stage = data["run"], data["graph"], data["stage"]
    started, ended = _interval(graph)
    queued, delayed, duration = run["timestamp"], graph["queueDurationMillis"], run["duration"]
    _require(
        graph["_links"]["self"]["href"] == job.removeprefix(_CONTROLLER) + "wfapi/describe"
        and graph["id"] == str(run["number"])
        and graph["status"] == "SUCCESS"
        and type(queued) is type(delayed) is type(duration) is int
        and delayed >= 0
        and queued + delayed == started
        and started + duration == ended == graph["endTimeMillis"],
        "Jenkins graph and completed run do not match",
    )
    stages = graph["stages"]
    _require(
        1 <= len(stages) <= 64
        and len({item["id"] for item in stages}) == len(stages)
        and all(item["name"] != _PUBLISH_STAGE for item in stages),
        "Selected graph lacks an unambiguous inventory without the remote publisher",
    )
    listed = _one(
        [item for item in stages if item["id"] == stage["id"]], "Maven stage is not listed"
    )
    stage_start, stage_end = _flow_interval(stage, job)
    _require(
        re.fullmatch(r"Maven Build \(Java [0-9]{1,2}, verify\)", stage["name"])
        and stage["status"] == listed["status"] == "SUCCESS"
        and listed["name"] == stage["name"]
        and _flow_interval(listed, job) == (stage_start, stage_end)
        and started <= stage_start < stage_end <= ended,
        "Saved Maven verify stage does not match the owning successful run",
    )
    nodes = stage["stageFlowNodes"]
    checkout = _one(
        [n for n in nodes if n["name"] == "Check out from version control"], "No unique checkout"
    )
    shell = _one([n for n in nodes if n["name"] == "Shell Script"], "No unique Maven shell node")
    checkout_start, checkout_end = _flow_interval(checkout, job)
    shell_start, shell_end = _flow_interval(shell, job)
    _require(
        checkout["id"] != shell["id"]
        and checkout["status"] == shell["status"] == "SUCCESS"
        and stage_start <= checkout_start < checkout_end <= shell_start < shell_end <= stage_end,
        "Checkout and Maven must be ordered successful nodes in the same verify stage",
    )
    parents, merged, selected = _log_lines(data["checkout"], checkout, job)
    revision = re.fullmatch(rf"Merge succeeded, producing ({_SHA})", merged)
    expected_parents = f"Merging remotes/origin/master commit {base} into PR head commit {head}"
    if revision is None or parents != expected_parents:
        raise IncrementalsEvidenceError(
            "Selected checkout does not identify the historical base and this fork head"
        )
    _require(
        selected == f"Checking out Revision {revision[1]} ({branch})",
        "Selected checkout does not report the same merge revision",
    )
    command = re.sub(r" +", " ", shell["parameterDescription"])
    executed, status = _log_lines(data["maven"], shell, job)
    _require(
        _VERIFY.fullmatch(command)
        and executed == "+ " + command
        and status == "[INFO] BUILD SUCCESS",
        "Owning shell does not corroborate the reviewed Maven verify command",
    )
    return revision[1], shell["id"]


def _bind_controller(
    data: _Row, repo: str, job: str, branch: str, base: str, head: str
) -> tuple[str, str]:
    run = data["run"]
    actions = [row for row in run["actions"] if row.get("_class") == _BUILD_DATA]
    library = _one(
        [row for row in actions if row["remoteUrls"] == [f"https://github.com/{_LIBRARY}.git"]],
        "Controller does not identify a unique Sling library checkout",
    )
    _require(
        library["lastBuiltRevision"]
        == {"SHA1": _REVISION, "branch": [{"SHA1": _REVISION, "name": "master"}]},
        "Controller did not load the reviewed Sling library",
    )
    console = data["console"]
    _require(
        console["url"] == job + "consoleText" and re.fullmatch(r"[a-f0-9]{64}", console["sha256"]),
        "Jenkins console does not belong to the selected run",
    )
    previous = 0
    for name, expected in (
        ("loader", f"Obtained Jenkinsfile from {base}"),
        ("library_load", "Loading library sling@master"),
        ("library_resolved", f"Resolved master as branch master at revision {_REVISION}"),
        (
            "guard",
            f"Maven goal set to verify since branch is not master ( {branch} ) or version is not snapshot",
        ),
        ("finished", "Finished: SUCCESS"),
    ):
        line, text = console["markers"][name]
        _require(
            type(line) is int and line > previous and text == expected,
            "Saved console lacks the ordered definition, library and branch-guard observations",
        )
        previous = line
    revision, shell = _verify_stage(data, job, branch, base, head)
    _require(
        any(
            row["remoteUrls"] == [f"https://github.com/{repo}.git"]
            and row["lastBuiltRevision"]
            in (
                {"SHA1": revision, "branch": [{"SHA1": ref, "name": branch}]}
                for ref in {head, revision}
            )
            for row in actions
        ),
        "Selected stage checkout does not match the controller's BuildData",
    )
    return revision, shell


def sling_exclusion(root: Path, data: _Row, repo: str, pr: int, job: str, target: str) -> _Row:
    branch = f"PR-{pr}"
    name = repo.removeprefix("apache/")
    folder = f"{_CONTROLLER}/job/Sling/job/modules/job/{name}/job/{branch}/"
    _require(
        re.fullmatch(r"apache/sling-[a-z0-9-]{1,90}", repo)
        and target == _TARGET
        and re.fullmatch(re.escape(folder) + _ID + "/", job),
        "Outside the supported Sling fork and Nexus snapshots profile",
    )
    run, pull = data["run"], data["pull"]
    head, base, fork = pull["observed_head"], data["source"]["commit"], pull["head_repository"]
    _require(
        type(pull["number"]) is int
        and pull["number"] == pr
        and pull["base_repository"] == repo
        and pull["base_ref"] == "master"
        and re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", fork)
        and fork.lower() != repo
        and head != base
        and re.fullmatch(_SHA, head)
        and re.fullmatch(_SHA, base)
        and run["url"] == job
        and type(run["number"]) is int
        and str(run["number"]) == job.rstrip("/").rsplit("/", 1)[1]
        and run["result"] == "SUCCESS"
        and run["building"] is False,
        "External fork and completed Jenkins run identity is unverified",
    )
    raw = _source_bytes(root, data["source"], base, "Jenkinsfile")
    tokens = [
        token
        for token in tokenize(raw.decode("utf-8"))
        if token.kind not in (TokKind.NEWLINE, TokKind.COMMENT, TokKind.EOF)
    ]
    _require(
        [token.kind for token in tokens] == [TokKind.IDENT, TokKind.LPAREN, TokKind.RPAREN]
        and tokens[0].value == "slingOsgiBundleBuild",
        "Loaded Jenkinsfile is outside the reviewed Sling invocation",
    )
    library = _project_file(root, "source/library.groovy", 50_000)
    _require(
        hashlib.sha256(library).hexdigest() == _LIBRARY_SHA256,
        "Saved Sling library differs from the reviewed publisher guard",
    )
    checkout, shell = _bind_controller(data, repo, job, branch, base, head)
    return {
        "state": SLING_STATE,
        "repository": repo,
        "pr": pr,
        "head_repository": fork,
        "head": head,
        "checkout": checkout,
        "job": job,
        "branch": branch,
        "node": shell,
        "source": {"path": "Jenkinsfile", "revision": base, "line": tokens[0].line},
        "library": {
            "repository": _LIBRARY,
            "revision": _REVISION,
            "path": _LIBRARY_PATH,
            "line": 337,
        },
        "local_build": {"maven_goal": "verify"},
        "remote_publisher": {
            "stage": _PUBLISH_STAGE,
            "target": target,
            "operation": "maven-wagon-repository-merge",
            "state": "not-created",
            "required_branch": "master",
        },
        "authority": "unresolved",
        "scope": SLING_SCOPE,
    }
