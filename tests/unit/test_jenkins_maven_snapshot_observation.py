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
                    "lastBuiltRevision": {"SHA1": HEAD, "branch": [{"name": "PR-7"}]},
                }
            ],
        },
        "flow": {
            "id": "3",
            "status": "SUCCESS",
            "startTimeMillis": START - 6000,
            "durationMillis": 8000,
            "_links": {"self": {"href": JOB_PATH + "wfapi/describe"}},
            "stages": [stage],
        },
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
            "text": f" &gt; git init /ci/workspace/example # timeout=10\n"
            f"Fetching upstream changes from <a href='https://github.com/{REPO}.git'>"
            f"https://github.com/{REPO}.git</a>\n"
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


@pytest.mark.parametrize("head_repository", ["apache/example", "Apache/Example"])
def test_same_github_repository_cannot_supply_fork_identity(tmp_path, capture, head_repository):
    capture["pull"]["head_repository"] = head_repository
    result = evaluate(tmp_path, capture)
    assert result["state"] == "unresolved"
    assert "fork PR identity" in result["reason"]


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


def test_fork_checkout_requires_the_reviewed_interval_before_the_writer(tmp_path, capture):
    checkout, publisher = capture["stage"]["stageFlowNodes"]
    intermediate = {
        **checkout,
        "id": "9",
        "name": "Shell Script",
        "parameterDescription": "git reset --hard " + "b" * 40,
        "startTimeMillis": START - 3000,
        "_links": {"self": {"href": JOB_PATH + "execution/node/9/wfapi/describe"}},
    }
    capture["stage"]["stageFlowNodes"] = [checkout, intermediate, publisher]
    result = evaluate(tmp_path, capture)
    assert result["state"] == "unresolved" and "publication" not in result
    assert "unsupported operation between checkout and Maven deployment" in result["reason"]


def test_fork_checkout_requires_one_owned_revision(tmp_path, capture):
    capture["checkout_log"]["text"] += "\nChecking out Revision " + "b" * 40 + " (master)"
    result = evaluate(tmp_path, capture)
    assert result["state"] == "unresolved" and "publication" not in result
    assert "ambiguous repository or revision" in result["reason"]


@pytest.fixture
def upstream_capture(tmp_path, capture):
    base = "b" * 40
    raw = (tmp_path / "source" / "Jenkinsfile").read_bytes()
    (tmp_path / "source" / "base.Jenkinsfile").write_bytes(raw)
    capture["pull"]["base"] = base
    capture["upstream_definition"] = {**capture["source"], "commit": base}
    capture["comparison"] = {
        "repository": REPO,
        "base": base,
        "merge_base": base,
        "head": HEAD,
        "status": "ahead",
        "ahead_by": 1,
        "behind_by": 0,
    }
    branch = "refs/remotes/origin/master"
    capture["run"]["actions"] = [
        {
            "remoteUrls": [f"https://github.com/{REPO}"],
            "lastBuiltRevision": {"SHA1": base, "branch": [{"name": branch}]},
        }
    ]
    stage = capture["stage"]
    checkout, publisher = stage["stageFlowNodes"]
    checkout["name"] = "Git"
    capture["checkout_log"]["text"] = (
        f"Cloning repository <a href='https://github.com/{REPO}'>https://github.com/{REPO}</a>\n"
        f" &gt; git init /ci/workspace/example # timeout=10\nChecking out Revision {base} ({branch})"
    )
    capture["flow"].update(
        id="3", status="SUCCESS", startTimeMillis=START - 6000, durationMillis=8000
    )

    def step(identifier, name, parameter, start):
        return {
            "id": identifier,
            "name": name,
            "parameterDescription": parameter,
            "status": "SUCCESS",
            "startTimeMillis": start,
            "durationMillis": 1,
            "_links": {"self": {"href": JOB_PATH + f"execution/node/{identifier}/wfapi/describe"}},
        }

    cleanup = step("8", "Delete workspace when build is done", None, START - 4900)
    intermediate = [
        step(
            "9",
            "Shell Script",
            (
                "mvn clean org.jacoco:jacoco-maven-plugin:prepare-agent package "
                "org.jacoco:jacoco-maven-plugin:report -T 1C"
            ),
            START - 3000,
        ),
        step(
            "10",
            "Print Message",
            "Will use SonarQube instance at https://sonarcloud.io",
            START - 2000,
        ),
        step(
            "11",
            "Shell Script",
            (
                "mvn sonar:sonar -Dsonar.projectKey=example -Dsonar.organization=apache "
                "-Dsonar.branch.name=PR-7 -Dsonar.host.url=https://sonarcloud.io "
                "-Dsonar.login=$"
                "{SONAR_TOKEN}"
            ),
            START - 1500,
        ),
        step("12", "Read a maven project file.", "pom.xml", START - 1000),
    ]
    stage["stageFlowNodes"] = [cleanup, checkout, *intermediate, publisher]
    capture["registry"]["stored_attributes"]["storageItem-generation"] = "2"
    return capture


def test_reports_upstream_checkout_and_keeps_writer_unknown(tmp_path, upstream_capture):
    result = evaluate(tmp_path, upstream_capture)
    assert result["state"] == "upstream-checkout-observed"
    assert result["checkout"]["revision"] == "b" * 40
    assert result["head"] == HEAD
    assert result["authority"] == "unresolved"
    assert "registry_actor" not in result["snapshot_evidence"]


def test_checkout_initialization_does_not_hide_a_later_pr_fetch(tmp_path, upstream_capture):
    intermediate = upstream_capture["stage"]["stageFlowNodes"][2]
    intermediate["parameterDescription"] = "git fetch origin pull/7/head && git checkout FETCH_HEAD"
    assert "unsupported command" in evaluate(tmp_path, upstream_capture)["reason"]


def test_missing_upstream_ancestry_remains_unresolved(tmp_path, upstream_capture):
    upstream_capture["comparison"]["head"] = "c" * 40
    assert "pinned upstream-to-fork ancestry" in evaluate(tmp_path, upstream_capture)["reason"]


def test_identity_proof_still_required_on_fork_checkout(tmp_path, capture):
    capture["registry"]["stored_attributes"]["storageItem-generation"] = "2"
    assert "write identity is unavailable" in evaluate(tmp_path, capture)["reason"]


def test_refuses_multiple_reported_revisions_in_one_git_node(tmp_path, upstream_capture):
    checkout = upstream_capture["checkout_log"]
    checkout["text"] += f"\nChecking out Revision {HEAD} (PR-7)"
    result = evaluate(tmp_path, upstream_capture)
    assert result["state"] == "unresolved"
    assert "ambiguous upstream repository or revision" in result["reason"]
