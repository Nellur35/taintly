"""Corroborate an ASF Jenkins PR build's observed Maven snapshot upload."""

from __future__ import annotations

import hashlib
import json
import re
from itertools import pairwise
from pathlib import Path
from typing import Any

from taintly.parsers.jenkinsfile.groovy_lex import TokKind, tokenize

from .jenkins_incrementals import (
    IncrementalsEvidenceError as EvidenceError,
)
from .jenkins_incrementals import (
    _int,
    _keys,
    _one,
    _project_file,
    _require,
)

_CONTROLLER = "https://ci-builds.apache.org"
_REGISTRY = "https://repository.apache.org"
_REPOSITORY = "/content/repositories/snapshots/"
_COMMAND = "mvn deploy -Dmaven.test.skip=true"
_PACKAGE = (
    "mvn clean org.jacoco:jacoco-maven-plugin:prepare-agent package "
    "org.jacoco:jacoco-maven-plugin:report -T 1C"
)
_UPSTREAM_SCOPE = (
    "Corroboration of the reported Git checkout feeding the selected Maven stage. "
    "The fetched snapshot matches the Maven node digest. The authority for that write "
    "is unresolved. Other ways that fork data might enter the build, effective repository "
    "policy, and filesystem identity are outside this observation."
)
_SCOPE = (
    "Corroboration of trusted saved GitHub, Jenkins and Apache Nexus records for one Maven "
    "snapshot object. The Nexus stored request identifies the writer. Other credentials, "
    "unobserved permission grants, production promotion and future fork admission are unresolved. "
    "The receipts corroborate the upload and matching reported workspace paths. A shared "
    "network request ID and underlying filesystem identity are unverified."
)
_Row = dict[str, Any]


def _source_bytes(
    root: Path, data: _Row, revision: str, name: str, *, path: str = "Jenkinsfile"
) -> bytes:
    raw = _project_file(root, f"source/{name}", 50000)
    blob = hashlib.sha1(
        b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw, usedforsecurity=False
    ).hexdigest()
    _require(
        data["path"] == path
        and data["commit"] == revision
        and data["blob"] == blob
        and data["sha256"] == hashlib.sha256(raw).hexdigest(),
        "saved Jenkinsfile differs from the controller-selected Git source",
    )
    return raw


def _maven_line(raw: bytes) -> int:
    tokens = [
        token
        for token in tokenize(raw.decode("utf-8"))
        if token.kind not in (TokKind.NEWLINE, TokKind.COMMENT, TokKind.EOF)
    ]
    lines = [
        before.line
        for before, after in pairwise(tokens)
        if before.kind == TokKind.IDENT
        and before.value == "sh"
        and after.kind == TokKind.STRING
        and after.value == _COMMAND
    ]
    _require(len(lines) == 1, "no unique source line for the reported Maven invocation")
    return lines[0]


def _interval(row: _Row) -> tuple[int, int]:
    start, duration = row["startTimeMillis"], row["durationMillis"]
    _require(
        type(start) is int
        and type(duration) is int
        and 10**12 <= start < 10**13
        and 0 < duration <= 7 * 24 * 60 * 60 * 1000,
        "Jenkins execution timestamps are malformed",
    )
    return start, start + duration


def _reject_constant(_value: str) -> None:
    raise EvidenceError("saved capture contains a nonfinite JSON value")


def _upstream_branch(data: _Row, repo: str, head: str) -> str:
    revision = data["pull"]["base"]
    if not isinstance(revision, str):
        raise EvidenceError("upstream checkout revision is unavailable")
    compare = data["comparison"]
    _require(
        re.fullmatch(r"[a-f0-9]{40}", revision)
        and revision != head
        and compare["repository"] == repo
        and compare["base"] == compare["merge_base"] == revision
        and compare["head"] == head
        and compare["status"] == "ahead"
        and type(compare["ahead_by"]) is int
        and compare["ahead_by"] > 0
        and type(compare["behind_by"]) is int
        and compare["behind_by"] == 0,
        "no pinned upstream-to-fork ancestry for the checkout",
    )
    return revision


def _review_maven_preparation(nodes: list[_Row], pr: int) -> None:
    # A checkout can initialize a workspace that a later command replaces.
    # Recognize only the visible preparation in the selected Maven profile.
    expected_names = ("Shell Script", "Print Message", "Shell Script", "Read a maven project file.")
    _require(
        tuple(node.get("name") for node in nodes) == expected_names
        and all(node["status"] == "SUCCESS" for node in nodes),
        "unsupported operation between checkout and Maven deployment",
    )
    package, message, sonar, pom = (node.get("parameterDescription") for node in nodes)
    _require(
        package == _PACKAGE
        and message == "Will use SonarQube instance at https://sonarcloud.io"
        and isinstance(sonar, str)
        and re.fullmatch(
            r"mvn sonar:sonar -Dsonar\.projectKey=[A-Za-z0-9_.-]+ -Dsonar\.organization=apache "
            rf"-Dsonar\.branch\.name=PR-{pr} -Dsonar\.host\.url=https://sonarcloud\.io "
            r"-Dsonar\.login=\$\{SONAR_TOKEN\}",
            sonar,
        )
        and pom == "pom.xml",
        "unsupported command between checkout and Maven deployment",
    )


def _stage(data: _Row, owner: str, head: str, pr: int, repo: str) -> tuple[_Row, str, str]:
    base = owner.removeprefix(_CONTROLLER)
    flow, stage = data["flow"], data["stage"]
    stage_ref = f"{base}execution/node/{stage['id']}/wfapi/describe"
    _require(
        flow["_links"]["self"]["href"] == base + "wfapi/describe"
        and stage["_links"]["self"]["href"] == stage_ref
        and stage["status"] == "SUCCESS",
        "provided stage does not belong to the selected Jenkins run",
    )
    summary = _one(
        [row for row in flow["stages"] if row["id"] == stage["id"]],
        "selected deployment stage is not unique in its parent run",
    )
    fields = ("name", "status", "startTimeMillis", "durationMillis", "_links")
    flow_start, flow_end = _interval(flow)
    stage_start, stage_end = _interval(stage)
    _require(
        flow["id"] == str(data["run"]["number"])
        and flow["status"] == "SUCCESS"
        and flow_start <= stage_start <= stage_end <= flow_end
        and all(summary[field] == stage[field] for field in fields),
        "deployment stage conflicts with its parent run",
    )
    nodes = stage["stageFlowNodes"]
    command = _one(
        [
            node
            for node in nodes
            if node.get("name") == "Shell Script" and node.get("parameterDescription") == _COMMAND
        ],
        "no unique Maven deployment command in the selected stage",
    )
    command_start, _ = _interval(command)
    checkouts = [
        node
        for node in nodes
        if node["name"] in ("Check out from version control", "Git")
        and _interval(node)[0] <= command_start
    ]
    checkout = _one(checkouts, "no unique checkout for the selected Maven deployment stage")
    _require(
        _interval(checkout)[1] <= command_start, "checkout overlaps the selected deployment command"
    )
    first, last = nodes.index(checkout), nodes.index(command)
    _require(first < last, "checkout is out of order in the deployment stage")
    between = nodes[first + 1 : last]
    upstream = checkout["name"] == "Git"
    revision = _upstream_branch(data, repo, head) if upstream else head
    if upstream or between:
        _review_maven_preparation(between, pr)
    owned_nodes = nodes if upstream else nodes[first : last + 1]
    _require(
        len({node["id"] for node in nodes}) == len(nodes)
        and all(_interval(a)[1] <= _interval(b)[0] for a, b in pairwise(nodes)),
        "checkout, preparation or deployment nodes have ambiguous order or identity",
    )
    if upstream:
        _require(
            nodes[0]["name"] == "Delete workspace when build is done"
            and nodes[1] is checkout
            and nodes[-1] is command,
            "upstream deployment stage has unsupported steps or ordering",
        )
    for node in owned_nodes:
        start, end = _interval(node)
        _require(
            node["status"] == "SUCCESS"
            and re.fullmatch(r"[1-9][0-9]{0,9}", node["id"])
            and stage_start <= start <= end <= stage_end
            and node["_links"]["self"]["href"]
            == f"{base}execution/node/{node['id']}/wfapi/describe",
            "checkout or command does not belong to the selected successful Jenkins stage",
        )
    executors = {node["execNode"] for node in owned_nodes if node.get("execNode")}
    _require(
        len(executors) <= 1,
        "checkout and Maven command report different executors",
    )
    checkout_log = data["checkout_log"]
    lines = checkout_log["text"].splitlines()
    url = f"https://github.com/{repo}" + ("" if upstream else ".git")
    branch = "refs/remotes/origin/master" if upstream else f"PR-{pr}"
    revisions = [line for line in lines if line.lstrip().startswith("Checking out Revision")]
    _require(
        revisions == [f"Checking out Revision {revision} ({branch})"],
        "selected Git node has ambiguous upstream repository or revision evidence"
        if upstream
        else "selected checkout node has ambiguous repository or revision evidence",
    )
    if upstream:
        clones = [line for line in lines if line.lstrip().startswith("Cloning repository")]
        _require(
            clones == [f"Cloning repository <a href='{url}'>{url}</a>"],
            "selected Git node has ambiguous upstream repository or revision evidence",
        )
    else:
        # A checkout plugin may fetch from the same origin more than once.
        fetches = {
            line for line in lines if line.lstrip().startswith("Fetching upstream changes from")
        }
        _require(
            fetches == {f"Fetching upstream changes from <a href='{url}'>{url}</a>"},
            "selected checkout node has ambiguous fork repository evidence",
        )
    selected_action = _one(
        [row for row in data["run"]["actions"] if url in row.get("remoteUrls", ())],
        "missing or ambiguous checkout record for the selected repository",
    )
    saved_checkout = selected_action["lastBuiltRevision"]
    _require(
        checkout_log["nodeId"] == checkout["id"]
        and checkout_log["nodeStatus"] == "SUCCESS"
        and checkout_log["hasMore"] is False
        and checkout_log["consoleUrl"] == f"{base}execution/node/{checkout['id']}/log"
        and selected_action["remoteUrls"] == [url]
        and saved_checkout["SHA1"] == revision
        and saved_checkout["branch"] == [{"name": branch}],
        "selected upstream checkout node cannot establish the exact base revision and repository"
        if upstream
        else "selected checkout node cannot establish the exact fork revision and repository",
    )
    workspaces = [
        match[1]
        for line in lines
        if (match := re.fullmatch(r" &gt; git init (/[-A-Za-z0-9_/]+) # timeout=[0-9]+", line))
    ]
    _require(len(workspaces) == 1, "checkout workspace path could not be established")
    return command, workspaces[0], revision


def _registry(
    root: Path,
    data: _Row,
    archive_path: str,
    target_url: str,
    command: _Row,
    *,
    attribute_writer: bool,
) -> _Row:
    target = target_url.removeprefix(_REGISTRY + _REPOSITORY)
    coordinate = re.fullmatch(
        r"((?:[A-Za-z0-9_-]+/)+)([A-Za-z0-9_.-]+)/([0-9]+(?:\.[0-9]+)*-SNAPSHOT)/"
        r"\2-([0-9]+(?:\.[0-9]+)*)-([0-9]{8}\.[0-9]{6}-[1-9][0-9]*)\.jar",
        target,
    )
    if coordinate is None:
        raise EvidenceError("only an exact ASF Maven SNAPSHOT JAR is supported")
    prefix, name, snapshot, version, _ = coordinate.groups()
    _require(
        snapshot == version + "-SNAPSHOT"
        and archive_path == f"{prefix}{name}/{snapshot}/{name}-{snapshot}.jar",
        "selected registry object differs from the Jenkins artifact coordinate",
    )
    stored = data["stored_attributes"]
    response = data["response"]
    milliseconds = data["stored_properties"]["created"]
    _require(
        re.fullmatch(r"[0-9]{13}", milliseconds)
        and stored["storageItem-created"] == stored["storageItem-modified"] == milliseconds
        and command["startTimeMillis"]
        <= int(milliseconds)
        <= command["startTimeMillis"] + command["durationMillis"],
        "Nexus object creation does not belong to the selected Maven command interval",
    )
    _require(
        data["provider_url"]
        == f"{_REGISTRY}/service/local/repositories/snapshots/content/{target}?describe"
        and response["responseType"] == "FILE"
        and response["originatingRepositoryMainFacet"]
        == "org.sonatype.nexus.proxy.maven.MavenHostedRepository"
        and response["originatingRepositoryId"] == stored["storageItem-repositoryId"] == "snapshots"
        and response["responsePath"] == stored["storageItem-path"] == f"/{target}"
        and response["responseUid"] == f"snapshots:/{target}",
        "Nexus hosted-object receipt does not identify the exact requested target",
    )
    job_bytes = _project_file(root, "artifact.jar", 8 * 1024 * 1024)
    registry_bytes = _project_file(root, "registry-artifact.jar", 8 * 1024 * 1024)
    digest = hashlib.sha256(job_bytes).hexdigest()
    _require(
        job_bytes == registry_bytes
        and stored["digest.sha256"] == digest
        and stored["digest.sha512"] == hashlib.sha512(job_bytes).hexdigest(),
        "Jenkins archive and Nexus object bytes or stored digests differ",
    )
    result = {"object_url": target_url, "sha256": digest, "created_ms": int(milliseconds)}
    if attribute_writer:
        actor = stored.get("request.user", "")
        _require(
            stored["storageItem-generation"] == "1"
            and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", actor)
            and actor.lower() != "anonymous",
            "Nexus stored write identity is unavailable",
        )
        return {
            "operation": "maven-snapshot-write",
            "object_url": target_url,
            "sha256": digest,
            "registry_actor": actor,
            "created_ms": int(milliseconds),
        }
    return result


def maven_snapshot_observation(root: Path, repo: str, pr: int, job: str, target: str) -> _Row:
    from .jenkins_filevault import FILEVAULT_SCHEMA, FILEVAULT_SCOPE, filevault_exclusion
    from .jenkins_matrix_snapshot import MATRIX_SCHEMA, MATRIX_SCOPE, matrix_snapshot_observation

    scope = _SCOPE
    try:
        root = root.resolve()
        capture = json.loads(
            _project_file(root, "snapshot.json", 256 * 1024).decode("utf-8"),
            object_pairs_hook=_keys,
            parse_int=_int,
            parse_constant=_reject_constant,
        )
        if capture["schema"] == FILEVAULT_SCHEMA:
            scope = FILEVAULT_SCOPE
            return filevault_exclusion(root, capture, repo, pr, job, target)
        if capture["schema"] == MATRIX_SCHEMA:
            scope = MATRIX_SCOPE
            return matrix_snapshot_observation(root, capture, repo, pr, job, target)
        _require(
            capture["schema"] == "jenkins-asf-maven-snapshot-v1"
            and re.fullmatch(r"apache/[a-z0-9][a-z0-9-]{0,110}", repo)
            and re.fullmatch(
                rf"{re.escape(_CONTROLLER)}(?:/job/[A-Za-z0-9_-]+){{1,6}}/job/PR-{pr}/[1-9][0-9]{{0,9}}/",
                job,
            )
            and target.startswith(_REGISTRY + _REPOSITORY),
            "outside the ASF Jenkins and hosted snapshots observation profile",
        )
        run, pull = capture["run"], capture["pull"]
        head = pull["observed_head"]
        _require(
            pull["number"] == pr
            and pull["base_repository"] == repo
            and pull["head_is_fork"] is True
            and re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", pull["head_repository"])
            and pull["head_repository"].lower() != repo
            and re.fullmatch(r"[a-f0-9]{40}", head)
            and run["url"] == job
            and run["number"] == int(job.rstrip("/").rsplit("/", 1)[1])
            and run["result"] == "SUCCESS"
            and run["building"] is False,
            "fork PR identity or successful Jenkins run is unverified",
        )
        _require(
            capture["jenkinsfile_loader"] == f"Obtained Jenkinsfile from {head}",
            "controller did not identify the supported exact PR-head Jenkinsfile",
        )
        original = _source_bytes(root, capture["source"], head, "Jenkinsfile")
        line = _maven_line(original)
        command, workspace, revision = _stage(capture, job, head, pr, repo)
        upstream = revision != head
        if upstream:
            pinned = _source_bytes(
                root, capture["upstream_definition"], revision, "base.Jenkinsfile"
            )
            _require(original == pinned, "fork and upstream Jenkinsfile differ for this checkout")
        artifact_path = capture["archive_path"]
        _require(
            capture["archive_url"] == job + "artifact/" + artifact_path
            and sum(item.get("relativePath") == artifact_path for item in run["artifacts"]) == 1,
            "no unique matching Jenkins job artifact",
        )
        publication = _registry(
            root, capture["registry"], artifact_path, target, command, attribute_writer=not upstream
        )
        artifact_name = artifact_path.rsplit("/", 1)[1]
        sha512 = capture["registry"]["stored_attributes"]["digest.sha512"]
        deploy_log = capture["deploy_log"]
        _require(
            deploy_log["url"]
            == f"{job}execution/node/{command['id']}/log/logText/progressiveText?start=0"
            and deploy_log["node_id"] == command["id"]
            and deploy_log["complete"] is True
            and deploy_log["command_line"] == f"+ {_COMMAND}"
            and deploy_log["digest_line"] == f"[INFO] {artifact_name} - SHA-512 : {sha512}",
            "exact Maven deployment node did not corroborate the published artifact digest",
        )
        _require(
            re.fullmatch(
                rf"\[INFO\] Installing {re.escape(workspace)}"
                rf"/(?:[A-Za-z0-9_-]+/)*target/{re.escape(artifact_name)} to /[-A-Za-z0-9_/\.]+",
                deploy_log["artifact_install_line"],
            ),
            "Maven artifact path differs from the checkout workspace",
        )
        state = "upstream-checkout-observed" if upstream else "snapshot-write-observed"
        result = {
            "state": state,
            "repository": repo,
            "pr": pr,
            "head_repository": pull["head_repository"],
            "head": head,
            "job": job,
            "node": command["id"],
            "source": {"path": "Jenkinsfile", "line": line},
            "command": _COMMAND,
            "reported_workspace": workspace,
            "jenkins_artifact": job + "artifact/" + artifact_path,
        }
        if upstream:
            result.update(
                checkout={
                    "repository": repo,
                    "ref": "refs/remotes/origin/master",
                    "revision": revision,
                },
                snapshot_evidence=publication,
                authority="unresolved",
                scope=_UPSTREAM_SCOPE,
            )
        else:
            result.update(
                publication=publication,
                review_action="If fork PRs must not publish snapshots, remove the snapshot "
                "publisher from fork builds and use a separate job bound to an approved revision.",
                scope=_SCOPE,
            )
        return result
    except EvidenceError as exc:
        reason = str(exc)
    except (AttributeError, KeyError, OSError, RecursionError, RuntimeError, TypeError, ValueError):
        reason = "saved Jenkins, source or Nexus evidence is unavailable or malformed"
    return {"state": "unresolved", "reason": reason, "scope": scope}
