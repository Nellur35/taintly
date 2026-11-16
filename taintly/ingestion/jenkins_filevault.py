"""Corroborate the pinned FileVault publisher's branch exclusion in a saved PR run."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any

from taintly.parsers.jenkinsfile.groovy_lex import TokKind, tokenize

from .jenkins_incrementals import _one, _project_file, _require
from .jenkins_maven_snapshot import _CONTROLLER, _REGISTRY, _REPOSITORY, _interval, _source_bytes

FILEVAULT_SCHEMA = "jenkins-asf-filevault-exclusion-v1"
FILEVAULT_SCOPE = (
    "Trusted saved Jenkins and GitHub records corroborate the exclusion of this configured "
    "remote Maven publisher and the reported local staging. Nexus credentials, backend "
    "authorization, filesystem identity and other publication paths remain unverified."
)
_REPO = "apache/jackrabbit-filevault-package-maven-plugin"
_LIBRARY = "apache/jackrabbit-filevault-jenkins-lib"
_LIBRARY_COMMIT = "029d10294811f6428dcbaf76aadcaa33f13c0c4d"
_PUBLISH_STAGE = "Deployment to Maven Repository"
_LOCAL_STAGE = "Main Maven Build (JDK 11, Maven 3, ubuntu)"
_TARGET = (_REGISTRY + _REPOSITORY).rstrip("/")
_LIBRARY_FILES = {
    "vars/vaultPipeline.groovy": "20dca0eb8a43b8798b60eb6b1cf61b992572c04147c0558c625fb3dc21c33419",
    "vars/vaultStageBuild.groovy": "d26f38aeb4847bad61fe7f253b1784089d88ba554c14786ec664e9576b34b930",
    "vars/vaultStageDeploy.groovy": "9155b67235520af981694ff254040329cb566b2428e70509bf27e3afb979c96f",
    "src/org/apache/jackrabbit/vault/PipelineSupport.groovy": "7803c093c52c5ae4700e7b1a3ae3077581f4169e11e7f368c480be653b061e1d",
}
_PREFIX = (
    "@ Library ( 'filevault@master' ) _ vaultPipeline ( 'ubuntu' , 11 , '3' "
    ", { vaultStageSanityCheck ( ) vaultStageBuild ( [ 'Windows' ] , [ 17 ] , "
    "[ '3.6.3' ] , 'apache_jackrabbit-filevault-package-maven-plugin' , "
    "[ hasSeparateItExecution : true ] ) vaultStageIT ("
)
_LIBRARY_CHECKOUT = [
    "Loading library filevault@master",
    f"Checking out Revision {_LIBRARY_COMMIT} (master)",
]
_RECIPE = re.compile(
    re.escape(_PREFIX)
    + r" \[ 'Windows' , 'ubuntu' \] , \[ (?:[0-9]{1,2} , ){0,3}[0-9]{1,2} \] , "
    + r"\[ '3'(?: , '4')? \] \) vaultStageDeploy \( \) } \)"
)
_LOCAL_COMMAND = (
    "mvn -B -e -U clean site deploy -Pjacoco-report "
    "-Dlogback.configurationFile=vault-core/src/test/resources/logback-only-errors.xml "
    "-DaltDeploymentRepository=snapshot-repo::default::file:"
)
_Row = dict[str, Any]


def _recipe(raw: bytes) -> int:
    tokens = [
        token
        for token in tokenize(raw.decode("utf-8"))
        if token.kind not in (TokKind.EOF, TokKind.NEWLINE, TokKind.COMMENT)
    ]
    normalized = " ".join(
        repr(token.value) if token.kind is TokKind.STRING else token.value for token in tokens
    )
    _require(_RECIPE.fullmatch(normalized), "Jenkinsfile is outside the reviewed FileVault recipe")
    return next(token.line for token in tokens if token.value == "vaultStageDeploy")


def _bind_checkouts(run: _Row, head: str, branch: str) -> None:
    actions = [
        row for row in run["actions"] if row.get("_class") == "hudson.plugins.git.util.BuildData"
    ]
    for repo, commit, ref in ((_REPO, head, branch), (_LIBRARY, _LIBRARY_COMMIT, "master")):
        remote = f"https://github.com/{repo}.git"
        action = _one(
            [row for row in actions if row["remoteUrls"] == [remote]],
            "controller does not identify the exact source and library checkouts",
        )
        saved = action["lastBuiltRevision"]
        _require(
            saved["SHA1"] == commit and saved["branch"] == [{"SHA1": commit, "name": ref}],
            "controller-selected revision or branch does not match the supported profile",
        )


def _own_metadata(row: _Row, path: str) -> None:
    _require(
        row["_links"]["self"]["href"] == path and row["status"] == "SUCCESS",
        "Jenkins graph, stage or node is not owned by the selected successful run",
    )


def _local_staging(
    data: _Row, job: str, run: _Row, head: str, base: str, branch: str
) -> tuple[str, str]:
    root_path = job.removeprefix(_CONTROLLER)
    graph, stage = data["graph"], data["stage"]
    _own_metadata(graph, root_path + "wfapi/describe")
    graph_start, graph_end = _interval(graph)
    queued, delay = run["timestamp"], graph["queueDurationMillis"]
    # The run API reports enqueue time, while Stage View reports executor start.
    _require(
        graph["id"] == str(run["number"])
        and type(queued) is int
        and type(delay) is int
        and 10**12 <= queued <= graph_start
        and delay == graph_start - queued
        and type(run["duration"]) is int
        and graph_end == graph["endTimeMillis"] == graph_start + run["duration"],
        "completed graph does not match the selected run interval",
    )
    stages = graph["stages"]
    _require(
        len(stages) == len({row["id"] for row in stages})
        and all(
            isinstance(row["name"], str) and row["name"].isprintable() and row["name"].strip()
            for row in stages
        )
        and all(row["name"] != _PUBLISH_STAGE for row in stages),
        "stage inventory is ambiguous or contains the remote publisher",
    )
    local = _one(
        [row for row in stages if row["name"] == _LOCAL_STAGE],
        "graph lacks the unique local Maven stage",
    )
    stage_id = local["id"]
    _require(
        re.fullmatch(r"[1-9][0-9]{0,9}", stage_id) and stage["id"] == stage_id,
        "saved Maven stage has a different owner",
    )
    stage_path = f"{root_path}execution/node/{stage_id}/wfapi/describe"
    _own_metadata(local, stage_path)
    _own_metadata(stage, stage_path)
    stage_start, stage_end = _interval(stage)
    _require(
        stage["name"] == _LOCAL_STAGE
        and (stage_start, stage_end) == _interval(local)
        and graph_start <= stage_start < stage_end <= graph_end,
        "saved stage does not match the run graph",
    )
    nodes = stage["stageFlowNodes"]
    checkout = _one(
        [node for node in nodes if node["name"] == "Check out from version control"],
        "stage lacks a unique owned source checkout",
    )
    selected = data["maven_log"]
    shell = _one(
        [node for node in nodes if node["id"] == selected["node_id"]],
        "stage lacks the named local Maven command node",
    )
    for node in (checkout, shell):
        _require(re.fullmatch(r"[1-9][0-9]{0,9}", node["id"]), "malformed Jenkins node ID")
        _own_metadata(node, f"{root_path}execution/node/{node['id']}/wfapi/describe")
    executors = {node["execNode"] for node in (checkout, shell) if node.get("execNode")}
    _require(len(executors) <= 1, "checkout and Maven command report different executors")
    checkout_start, checkout_end = _interval(checkout)
    shell_start, shell_end = _interval(shell)
    _require(
        shell["name"] == "Shell Script"
        and stage_start <= checkout_start < checkout_end <= shell_start < shell_end <= stage_end,
        "checkout and Maven nodes are outside their owning stage or order",
    )
    command = selected["command"]
    _require(
        selected["url"] == f"{job}execution/node/{shell['id']}/log/logText/progressiveText?start=0"
        and selected["complete"] is True
        and command == shell["parameterDescription"]
        and command.startswith(_LOCAL_COMMAND),
        "controller did not report the owned local Maven command",
    )
    destination = command.removeprefix(_LOCAL_COMMAND)
    workspace = destination.removesuffix("/local-snapshots-dir")
    _require(
        destination == f"{workspace}/local-snapshots-dir"
        and re.fullmatch(r"/(?:[A-Za-z0-9_@.-]+/)*[A-Za-z0-9_@.-]+", workspace)
        and not {".", ".."}.intersection(workspace.split("/"))
        and selected["maven_target"]
        == f"[INFO] Using alternate deployment repository snapshot-repo::default::file:{destination}",
        "Maven did not report a matching workspace-local deployment target",
    )
    checked = data["checkout_log"]
    _require(
        checked["url"] == f"{job}execution/node/{checkout['id']}/wfapi/log"
        and checked["node_id"] == checkout["id"]
        and checked["complete"] is True
        and checked["revision_line"] == f"Checking out Revision {head} ({branch})"
        and checked["merge_line"]
        == f"Merging remotes/origin/master commit {base} into PR head commit {head}"
        and checked["merge_result"] == f"Merge succeeded, producing {head}"
        and checked["workspace_line"]
        in (f"git init {workspace}", f"git rev-parse --resolve-git-dir {workspace}/.git"),
        "scoped checkout does not identify the selected PR revision and workspace",
    )
    return shell["id"], destination


def filevault_exclusion(root: Path, data: _Row, repo: str, pr: int, job: str, target: str) -> _Row:
    branch = f"PR-{pr}"
    job_shape = f"{_CONTROLLER}/job/Jackrabbit/job/filevault-package-maven-plugin/job/{branch}/"
    _require(
        repo == _REPO
        and target == _TARGET
        and re.fullmatch(re.escape(job_shape) + r"[1-9][0-9]{0,9}/", job),
        "outside the FileVault PR and Nexus snapshot target profile",
    )
    run, pull = data["run"], data["pull"]
    head = pull["observed_head"]
    _require(
        pull["number"] == pr
        and pull["base_repository"] == pull["head_repository"] == repo
        and pull["base_ref"] == "master"
        and re.fullmatch(r"[a-f0-9]{40}", head)
        and run["url"] == job
        and type(run["number"]) is int
        and str(run["number"]) == job.rstrip("/").rsplit("/", 1)[1]
        and run["result"] == "SUCCESS"
        and run["building"] is False
        and data["branch_log"] == f"Building auxiliary branch {branch}",
        "same-repository PR identity or successful branch run is unverified",
    )
    _bind_checkouts(run, head, branch)
    _require(
        data["library_log"] == _LIBRARY_CHECKOUT,
        "controller does not report loading the reviewed FileVault library",
    )
    loader = data["jenkinsfile_checkout"]
    base, parent = loader["parents"]
    revision = loader["revision"]
    _require(
        parent == head
        and base != head
        and re.fullmatch(r"[a-f0-9]{40}", base)
        and re.fullmatch(r"[a-f0-9]{40}", revision)
        and loader["line"] == f"Obtained Jenkinsfile from {head}+{base} ({revision})",
        "controller-selected Jenkinsfile merge does not match the PR and base",
    )
    line = _recipe(_source_bytes(root, data["source"], revision, "Jenkinsfile"))
    for path, digest in _LIBRARY_FILES.items():
        body = _project_file(root, f"source/library/{path}", 50000)
        _require(
            hashlib.sha256(body).hexdigest() == digest,
            "saved shared-library files do not match the reviewed branch guard",
        )
    node, destination = _local_staging(data, job, run, head, base, branch)
    return {
        "state": "remote-publisher-excluded",
        "repository": repo,
        "pr": pr,
        "head": head,
        "job": job,
        "branch": branch,
        "node": node,
        "source": {"path": "Jenkinsfile", "revision": revision, "line": line},
        "library": {"repository": _LIBRARY, "revision": _LIBRARY_COMMIT, "line": 45},
        "local_staging": {"operation": "maven-local-deploy", "destination": f"file:{destination}"},
        "remote_publisher": {
            "stage": _PUBLISH_STAGE,
            "target": target,
            "operation": "maven-wagon-deploy",
            "state": "not-created",
            "required_branch": "master",
        },
        "authority": "unresolved",
        "scope": FILEVAULT_SCOPE,
    }
