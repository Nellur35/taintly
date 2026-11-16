"""Authored controls for the bounded ASF Jenkins Maven snapshot profile."""

import hashlib
import json

import pytest

from taintly.ingestion.jenkins_maven_snapshot import maven_snapshot_observation

REPO = "apache/example"
HEAD = "a" * 40
JOB_PATH = "/job/Example/job/build/job/PR-7/3/"
JOB = "https://ci-builds.apache.org" + JOB_PATH
ARTIFACT = "org/apache/example/1.0-SNAPSHOT/example-1.0-SNAPSHOT.jar"
TARGET_PATH = "/org/apache/example/1.0-SNAPSHOT/example-1.0-20261116.095044-1.jar"
REGISTRY = "https://repository.apache.org"
TARGET = REGISTRY + "/content/repositories/snapshots" + TARGET_PATH
COMMAND = "mvn deploy -Dmaven.test.skip=true"
START = 1794822644000


@pytest.fixture
def capture(tmp_path):
    workflow = f"node {{\n  checkout scm\n  sh '{COMMAND}'\n}}\n".encode()
    (tmp_path / "source").mkdir()
    (tmp_path / "source" / "Jenkinsfile").write_bytes(workflow)
    artifact = b"Inert authored bytes."
    sha256 = hashlib.sha256(artifact).hexdigest()
    sha512 = hashlib.sha512(artifact).hexdigest()
    for name in ("artifact.jar", "registry-artifact.jar"):
        (tmp_path / name).write_bytes(artifact)

    def node(identifier, name, start, duration):
        return {
            "id": identifier,
            "name": name,
            "status": "SUCCESS",
            "_links": {"self": {"href": JOB_PATH + f"execution/node/{identifier}/wfapi/describe"}},
            "startTimeMillis": start,
            "durationMillis": duration,
        }

    stage = node("5", "Publish", START - 5000, 6000)
    checkout = node("6", "Check out from version control", START - 4000, 500)
    command = node("7", "Shell Script", START, 1000)
    command["parameterDescription"] = COMMAND
    return {
        "schema": "jenkins-asf-maven-snapshot-v1",
        "pull": {
            "number": 7,
            "base_repository": REPO,
            "head_repository": "fork/example",
            "head_is_fork": True,
            "observed_head": HEAD,
        },
        "run": {
            "url": JOB,
            "number": 3,
            "building": False,
            "result": "SUCCESS",
            "artifacts": [{"relativePath": ARTIFACT}],
            "actions": [
                {
                    "remoteUrls": [f"https://github.com/{REPO}.git"],
                    "lastBuiltRevision": {"SHA1": HEAD},
                }
            ],
        },
        "flow": {"_links": {"self": {"href": JOB_PATH + "wfapi/describe"}}, "stages": [stage]},
        "stage": {**stage, "stageFlowNodes": [checkout, command]},
        "archive_path": ARTIFACT,
        "archive_url": JOB + "artifact/" + ARTIFACT,
        "jenkinsfile_loader": f"Obtained Jenkinsfile from {HEAD}",
        "source": {
            "path": "Jenkinsfile",
            "commit": HEAD,
            "blob": hashlib.sha1(
                f"blob {len(workflow)}\0".encode() + workflow, usedforsecurity=False
            ).hexdigest(),
            "sha256": hashlib.sha256(workflow).hexdigest(),
        },
        "checkout_log": {
            "nodeId": "6",
            "nodeStatus": "SUCCESS",
            "hasMore": False,
            "consoleUrl": JOB_PATH + "execution/node/6/log",
            "text": f" &gt; git init /ci/workspace/example # timeout=10\nFetching https://github.com/{REPO}.git\n"
            f"Checking out Revision {HEAD} (PR-7)",
        },
        "deploy_log": {
            "node_id": "7",
            "complete": True,
            "url": JOB + "execution/node/7/log/logText/progressiveText?start=0",
            "command_line": f"+ {COMMAND}",
            "artifact_install_line": "[INFO] Installing /ci/workspace/example/target/example-1.0-SNAPSHOT.jar to /repo/example.jar",
            "digest_line": f"[INFO] example-1.0-SNAPSHOT.jar - SHA-512 : {sha512}",
        },
        "registry": {
            "provider_url": REGISTRY
            + "/service/local/repositories/snapshots/content"
            + TARGET_PATH
            + "?describe",
            "stored_properties": {"created": str(START)},
            "response": {
                "responseType": "FILE",
                "originatingRepositoryId": "snapshots",
                "responseUid": "snapshots:" + TARGET_PATH,
                "responsePath": TARGET_PATH,
                "originatingRepositoryMainFacet": "org.sonatype.nexus.proxy.maven.MavenHostedRepository",
            },
            "read_request_user": "unrelated-reader",
            "stored_attributes": {
                "request.user": "writer",
                "storageItem-generation": "1",
                "storageItem-repositoryId": "snapshots",
                "storageItem-path": TARGET_PATH,
                "storageItem-created": str(START),
                "storageItem-modified": str(START),
                "digest.sha256": sha256,
                "digest.sha512": sha512,
            },
        },
    }


def evaluate(tmp_path, capture):
    (tmp_path / "snapshot.json").write_text(json.dumps(capture), encoding="utf-8")
    return maven_snapshot_observation(tmp_path, REPO, 7, JOB, TARGET)


def test_correlates_owned_fork_command_with_stored_writer(tmp_path, capture):
    result = evaluate(tmp_path, capture)
    assert result["state"] == "snapshot-write-observed"
    assert result["publication"]["registry_actor"] == "writer"
    assert result["source"]["line"] == 3


def test_refuses_digest_from_sibling_node(tmp_path, capture):
    capture["deploy_log"]["node_id"] = "9"
    result = evaluate(tmp_path, capture)
    assert result["state"] == "unresolved"
    assert "exact Maven deployment node" in result["reason"]


def test_refuses_reader_only_identity(tmp_path, capture):
    del capture["registry"]["stored_attributes"]["request.user"]
    result = evaluate(tmp_path, capture)
    assert result["state"] == "unresolved"
    assert "write identity" in result["reason"]


def test_refuses_overlapping_checkout(tmp_path, capture):
    capture["stage"]["stageFlowNodes"][0]["startTimeMillis"] = START - 1
    assert "overlaps" in evaluate(tmp_path, capture)["reason"]


def test_refuses_nonfinite_timestamp(tmp_path, capture):
    capture["stage"]["durationMillis"] = float("inf")
    assert "nonfinite" in evaluate(tmp_path, capture)["reason"]


def test_refuses_different_executor(tmp_path, capture):
    checkout, publisher = capture["stage"]["stageFlowNodes"]
    checkout["execNode"] = "alpha"
    publisher["execNode"] = "beta"
    assert "different executors" in evaluate(tmp_path, capture)["reason"]


def test_refuses_different_workspace(tmp_path, capture):
    log = capture["deploy_log"]
    log["artifact_install_line"] = log["artifact_install_line"].replace(
        "/ci/workspace/", "/different/workspace/"
    )
    assert "differs from the checkout workspace" in evaluate(tmp_path, capture)["reason"]
