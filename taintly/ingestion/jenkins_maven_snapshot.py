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
_SCOPE = (
    "Corroboration of trusted saved GitHub, Jenkins and Apache Nexus records for one Maven "
    "snapshot object. The Nexus stored request identifies the writer. Other credentials, "
    "unobserved permission grants, production promotion and future fork admission are unresolved. "
    "The receipts corroborate the upload and matching reported workspace paths. A shared "
    "network request ID and underlying filesystem identity are unverified."
)
_Row = dict[str, Any]


def _source(root: Path, data: _Row, head: str) -> int:
    raw = _project_file(root, "source/Jenkinsfile", 50000)
    blob = hashlib.sha1(
        b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw, usedforsecurity=False
    ).hexdigest()
    _require(
        data["path"] == "Jenkinsfile"
        and data["commit"] == head
        and data["blob"] == blob
        and data["sha256"] == hashlib.sha256(raw).hexdigest(),
        "saved Jenkinsfile differs from the controller-selected Git source",
    )
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


def _stage(data: _Row, owner: str, head: str, pr: int, repo: str) -> tuple[_Row, str]:
    base = owner.removeprefix(_CONTROLLER)
    stage = data["stage"]
    stage_ref = f"{base}execution/node/{stage['id']}/wfapi/describe"
    _require(
        data["flow"]["_links"]["self"]["href"] == base + "wfapi/describe"
        and stage["_links"]["self"]["href"] == stage_ref
        and stage["status"] == "SUCCESS"
        and any(
            row["id"] == stage["id"] and row["_links"]["self"]["href"] == stage_ref
            for row in data["flow"]["stages"]
        ),
        "provided stage does not belong to the selected Jenkins run",
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
    stage_start, stage_end = _interval(stage)
    command_start, _ = _interval(command)
    checkouts = [
        node
        for node in nodes
        if node["name"] == "Check out from version control" and _interval(node)[0] <= command_start
    ]
    checkout = _one(checkouts, "no unique checkout for the selected Maven deployment stage")
    _require(
        _interval(checkout)[1] <= command_start, "checkout overlaps the selected deployment command"
    )
    for node in (checkout, command):
        start, end = _interval(node)
        _require(
            node["status"] == "SUCCESS"
            and re.fullmatch(r"[1-9][0-9]{0,9}", node["id"])
            and stage_start <= start <= end <= stage_end
            and node["_links"]["self"]["href"]
            == f"{base}execution/node/{node['id']}/wfapi/describe",
            "checkout or command does not belong to the selected successful Jenkins stage",
        )
    checkout_executor = checkout.get("execNode")
    command_executor = command.get("execNode")
    _require(
        not (checkout_executor and command_executor and checkout_executor != command_executor),
        "checkout and Maven command report different executors",
    )
    checkout_log = data["checkout_log"]
    lines = checkout_log["text"].splitlines()
    _require(
        checkout_log["nodeId"] == checkout["id"]
        and checkout_log["nodeStatus"] == "SUCCESS"
        and checkout_log["hasMore"] is False
        and checkout_log["consoleUrl"] == f"{base}execution/node/{checkout['id']}/log"
        and f"Checking out Revision {head} (PR-{pr})" in lines
        and f"https://github.com/{repo}.git" in checkout_log["text"]
        and any(
            row.get("remoteUrls") == [f"https://github.com/{repo}.git"]
            and row.get("lastBuiltRevision", {}).get("SHA1") == head
            for row in data["run"]["actions"]
        ),
        "selected checkout node cannot establish the exact fork revision and repository",
    )
    workspaces = [
        match[1]
        for line in lines
        if (match := re.fullmatch(r" &gt; git init (/[-A-Za-z0-9_/]+) # timeout=[0-9]+", line))
    ]
    _require(len(workspaces) == 1, "checkout workspace path could not be established")
    return command, workspaces[0]


def _registry(root: Path, data: _Row, archive_path: str, target_url: str, command: _Row) -> _Row:
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
        and stored["storageItem-generation"] == "1"
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
    actor = stored.get("request.user", "")
    _require(
        re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", actor) and actor.lower() != "anonymous",
        "Nexus stored write identity is unavailable",
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
    return {
        "operation": "maven-snapshot-write",
        "object_url": target_url,
        "sha256": digest,
        "registry_actor": actor,
        "created_ms": int(milliseconds),
    }


def maven_snapshot_observation(root: Path, repo: str, pr: int, job: str, target: str) -> _Row:
    try:
        root = root.resolve()
        capture = json.loads(
            _project_file(root, "snapshot.json", 256 * 1024).decode("utf-8"),
            object_pairs_hook=_keys,
            parse_int=_int,
            parse_constant=_reject_constant,
        )
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
            and pull["head_repository"] != repo
            and re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", pull["head_repository"])
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
        line = _source(root, capture["source"], head)
        command, workspace = _stage(capture, job, head, pr, repo)
        artifact_path = capture["archive_path"]
        _require(
            capture["archive_url"] == job + "artifact/" + artifact_path
            and sum(item.get("relativePath") == artifact_path for item in run["artifacts"]) == 1,
            "no unique matching Jenkins job artifact",
        )
        publication = _registry(root, capture["registry"], artifact_path, target, command)
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
        return {
            "state": "snapshot-write-observed",
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
            "publication": publication,
            "review_action": "If fork PRs must not publish snapshots, remove the snapshot "
            "publisher from fork builds and use a separate job bound to an approved revision.",
            "scope": _SCOPE,
        }
    except EvidenceError as exc:
        reason = str(exc)
    except (AttributeError, KeyError, OSError, RecursionError, RuntimeError, TypeError, ValueError):
        reason = "saved Jenkins, source or Nexus evidence is unavailable or malformed"
    return {"state": "unresolved", "reason": reason, "scope": _SCOPE}
