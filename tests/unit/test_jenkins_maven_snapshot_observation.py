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


def evaluate(tmp_path, capture, target=TARGET):
    (tmp_path / "snapshot.json").write_text(json.dumps(capture), encoding="utf-8")
    return maven_snapshot_observation(tmp_path, REPO, 7, JOB, target)


def test_correlates_owned_fork_command_with_stored_writer(tmp_path, capture):
    result = evaluate(tmp_path, capture)
    assert result["state"] == "snapshot-write-observed"
    assert result["publication"]["registry_actor"] == "writer"
    assert result["source"]["line"] == 3


@pytest.mark.parametrize("defect", [None, "flow", "publisher", "older-object", "zero-checkout"])
def test_snapshot_write_is_decided_by_the_owned_node_and_registry(tmp_path, capture, defect):
    capture["run"]["result"] = "FAILURE"
    capture["flow"]["status"] = "FAILED"
    if defect == "flow":
        capture["flow"]["status"] = "SUCCESS"
    elif defect == "publisher":
        capture["stage"]["stageFlowNodes"][-1]["status"] = "FAILED"
    elif defect == "older-object":
        stored = capture["registry"]["stored_attributes"]
        rec = str(START - 1)
        stored.update({"storageItem-created": rec, "storageItem-modified": rec})
        capture["registry"]["stored_properties"]["created"] = rec
    elif defect == "zero-checkout":
        capture["stage"]["stageFlowNodes"][0]["durationMillis"] = 0

    result = evaluate(tmp_path, capture)
    if defect is None:
        assert result["state"] == "snapshot-write-observed"
        assert result["jenkins_run_result"] == "FAILURE"
        assert result["publication"]["registry_actor"] == "writer"
    else:
        assert result["state"] == "unresolved"
        assert "publication" not in result


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
    result = evaluate(tmp_path, capture)
    assert result["state"] == "unresolved"
    assert "write identity is unavailable" in result["reason"]
    assert result["authority"] == "unresolved"
    assert result["checkout"]["revision"] == HEAD
    assert result["snapshot_evidence"]["object_url"] == TARGET
    assert "publication" not in result
    assert "registry_actor" not in result["snapshot_evidence"]


def test_missing_writer_cannot_expose_unbound_snapshot(tmp_path, capture):
    capture["registry"]["stored_attributes"]["storageItem-generation"] = "2"
    capture["deploy_log"]["node_id"] = "9"
    result = evaluate(tmp_path, capture)
    assert result["state"] == "unresolved"
    assert "exact Maven deployment node" in result["reason"]
    assert "snapshot_evidence" not in result


def test_refuses_multiple_reported_revisions_in_one_git_node(tmp_path, upstream_capture):
    checkout = upstream_capture["checkout_log"]
    checkout["text"] += f"\nChecking out Revision {HEAD} (PR-7)"
    result = evaluate(tmp_path, upstream_capture)
    assert result["state"] == "unresolved"
    assert "ambiguous upstream repository or revision" in result["reason"]


@pytest.fixture
def failed_upstream_capture(upstream_capture):
    upstream_capture["run"]["result"] = "FAILURE"
    upstream_capture["flow"]["status"] = "FAILED"
    upstream_capture["registry"] = None
    message = upstream_capture["stage"]["stageFlowNodes"][3]
    assert message["name"] == "Print Message"
    message["durationMillis"] = 0
    return upstream_capture


def test_keeps_proven_upstream_path_when_parent_fails_and_nexus_is_unavailable(
    tmp_path,
    failed_upstream_capture,
):
    alias = REGISTRY + "/content/repositories/snapshots/" + ARTIFACT
    result = evaluate(tmp_path, failed_upstream_capture, alias)
    assert result["state"] == result["authority"] == "unresolved"
    assert result["checkout"]["revision"] == "b" * 40
    assert result["jenkins_run_result"] == "FAILURE"
    assert result["node"] == "7"
    assert result["jenkins_archive_sha256"] == hashlib.sha256(b"Inert authored bytes.").hexdigest()
    assert result["requested_snapshot"] == alias
    assert "publication" not in result
    assert "snapshot_evidence" not in result


@pytest.mark.parametrize(
    ("fixture", "revision"), [("capture", HEAD), ("upstream_capture", "b" * 40)]
)
def test_success_keeps_only_local_archive_when_nexus_is_unavailable(tmp_path, request, fixture, revision):
    selected = request.getfixturevalue(fixture)
    selected["registry"] = None
    alias = REGISTRY + "/content/repositories/snapshots/" + ARTIFACT

    result = evaluate(tmp_path, selected, alias)

    assert result["state"] == result["authority"] == "unresolved"
    assert result["jenkins_run_result"] == "SUCCESS"
    assert result["checkout"]["revision"] == revision
    assert result["jenkins_archive_sha256"] == hashlib.sha256(b"Inert authored bytes.").hexdigest()
    assert result["requested_snapshot"] == alias
    assert "publication" not in result
    assert "snapshot_evidence" not in result


@pytest.mark.parametrize(
    ("corruption", "reason"),
    [
        ("registry-file", "Jenkins archive and Nexus object bytes or stored digests differ"),
        ("registry-time", "Nexus object creation does not belong to the selected Maven command interval"),
        ("registry-record", "saved Jenkins, source or Nexus evidence is unavailable or malformed"),
        ("local-file", "exact Maven deployment node did not corroborate the published artifact digest"),
    ],
)
def test_local_archive_and_registry_evidence_are_verified_separately(tmp_path, capture, corruption, reason):
    if corruption == "registry-file":
        (tmp_path / "registry-artifact.jar").write_bytes(b"Different receiver bytes.")
    elif corruption == "registry-time":
        created = str(START - 1)
        capture["registry"]["stored_properties"]["created"] = created
        capture["registry"]["stored_attributes"].update(
            {"storageItem-created": created, "storageItem-modified": created}
        )
    elif corruption == "registry-record":
        del capture["registry"]["response"]
    else:
        (tmp_path / "artifact.jar").write_bytes(b"Different local archive.")

    result = evaluate(tmp_path, capture)

    assert result["state"] == "unresolved"
    assert result["reason"] == reason
    assert "publication" not in result
    assert "snapshot_evidence" not in result
    if corruption != "local-file":
        assert result["authority"] == "unresolved"
        assert result["checkout"]["revision"] == HEAD
        assert result["requested_snapshot"] == TARGET
        assert result["jenkins_archive_sha256"] == hashlib.sha256(b"Inert authored bytes.").hexdigest()
    else:
        assert "checkout" not in result
        assert "jenkins_archive_sha256" not in result


@pytest.mark.parametrize(
    "corruption", ["target", "log", "archive", "zero-checkout", "stage", "flow"]
)
def test_failed_run_needs_an_owned_successful_command_and_exact_archive(
    tmp_path, failed_upstream_capture, corruption
):
    capture = failed_upstream_capture
    alias = REGISTRY + "/content/repositories/snapshots/" + ARTIFACT
    if corruption == "target":
        alias = TARGET
    elif corruption == "log":
        capture["deploy_log"]["node_id"] = "9"
    elif corruption == "archive":
        (tmp_path / "artifact.jar").write_bytes(b"Different authored bytes.")
    elif corruption == "zero-checkout":
        capture["stage"]["stageFlowNodes"][1]["durationMillis"] = 0
    elif corruption == "stage":
        capture["stage"]["status"] = "FAILED"
    else:
        capture["flow"]["status"] = "SUCCESS"
    result = evaluate(tmp_path, capture, alias)
    assert result["state"] == "unresolved"
    assert "checkout" not in result
    assert "publication" not in result


@pytest.mark.parametrize("base", [None, "b" * 40])
def test_failed_run_retains_the_maven_nodes_fork_checkout(tmp_path, capture, base):
    if base is not None:
        capture["pull"]["base"] = base
    capture["run"]["result"] = "FAILURE"
    capture["flow"]["status"] = "FAILED"
    capture["registry"] = None
    alias = REGISTRY + "/content/repositories/snapshots/" + ARTIFACT
    result = evaluate(tmp_path, capture, alias)
    assert result["state"] == result["authority"] == "unresolved"
    assert result["checkout"] == {"repository": REPO, "ref": "PR-7", "revision": HEAD}
    assert result["jenkins_run_result"] == "FAILURE"
    assert "reported fork checkout" in result["scope"]
    assert "publication" not in result
    assert "snapshot_evidence" not in result


@pytest.mark.parametrize("registry_available", [True, False])
def test_exact_maven_credential_selection(tmp_path, capture, registry_available):
    deploy = capture["deploy_log"]
    warning = (
        "[WARNING] Using credentials of server 'example.snapshots' for repository "
        "https://repository.apache.org/content/repositories/snapshots, although no repository or "
        "mirror with this id is declared in settings or on the command line and the server declares "
        "no <repositoryOrigins>. Set maven.repository.credentialScope=strict."
    )
    raw = "\n".join(
        [deploy["command_line"], warning, deploy["artifact_install_line"], deploy["digest_line"]]
    ).encode()
    (tmp_path / "maven-node.log").write_bytes(raw)
    deploy["credential_log_sha256"] = hashlib.sha256(raw).hexdigest()
    target = TARGET
    if not registry_available:
        capture["run"]["result"] = "FAILURE"
        capture["flow"]["status"] = "FAILED"
        capture["registry"] = None
        target = REGISTRY + "/content/repositories/snapshots/" + ARTIFACT
    (tmp_path / "snapshot.json").write_text(json.dumps(capture), encoding="utf-8")

    result = maven_snapshot_observation(tmp_path, REPO, 7, JOB, target)

    if registry_available:
        assert result["state"] == "snapshot-write-observed"
    else:
        assert result["state"] == result["authority"] == "unresolved"
        assert "publication" not in result
    assert result["maven_credential_selection"] == {
        "state": "authentication-selection-reported",
        "server_id": "example.snapshots",
        "repository_url": "https://repository.apache.org/content/repositories/snapshots",
        "repository_origin": "not-explicitly-bound-in-reported-settings",
        "log_url": deploy["url"],
        "log_sha256": deploy["credential_log_sha256"],
        "line": 2,
    }


@pytest.mark.parametrize(
    "variation", ["wrong-digest", "wrong-target", "conflict", "wrong-node-log", "missing-log", "control-char"]
)
def test_maven_credential_selection_needs_unique_bound_evidence(tmp_path, capture, variation):
    deploy = capture["deploy_log"]
    target = "https://repository.apache.org/content/repositories/snapshots"
    warning = (
        "[WARNING] Using credentials of server 'example.snapshots' for repository "
        + target
        + ", although no repository or mirror with this id is declared in settings or on "
        "the command line and the server declares no <repositoryOrigins>. "
        "Set maven.repository.credentialScope=strict."
    )
    if variation == "wrong-target":
        warning = warning.replace(target, target + "-other")
    if variation == "conflict":
        warning += "\n" + warning.replace("Using credentials", "Not using credentials")
    if variation == "control-char":
        warning = "\x1b[31m" + warning
    command = "+ mvn test" if variation == "wrong-node-log" else deploy["command_line"]
    raw = "\n".join(
        [command, warning, deploy["artifact_install_line"], deploy["digest_line"]]
    ).encode()
    if variation != "missing-log":
        (tmp_path / "maven-node.log").write_bytes(raw)
    deploy["credential_log_sha256"] = (
        "f" * 64 if variation == "wrong-digest" else hashlib.sha256(raw).hexdigest()
    )
    (tmp_path / "snapshot.json").write_text(json.dumps(capture), encoding="utf-8")

    result = maven_snapshot_observation(tmp_path, REPO, 7, JOB, TARGET)

    assert result["state"] == "snapshot-write-observed"
    assert result["maven_credential_selection"]["state"] == "unresolved"
    assert "server_id" not in result["maven_credential_selection"]


@pytest.mark.parametrize(
    "variant",
    [
        "supported", "wrong-run", "digest", "missing", "escaped", "other-allocation",
        "missing-start", "other-allocation-without-registry",
    ],
)
def test_controller_allocation_is_bound_to_both_operations(tmp_path, capture, variant):
    other_allocation = variant.startswith("other-allocation")
    command_parent = "3" if other_allocation or variant == "missing-start" else "5"
    html = f"""Obtained Jenkinsfile from {HEAD}
<span class="pipeline-new-node" nodeId="2" startId="2">[Pipeline] node
</span><span class="pipeline-node-2">Running on <a href="/computer/first/">first</a> in /ci/workspace/example
</span><span class="pipeline-new-node" nodeId="5" startId="5" enclosingId="2">[Pipeline] stage
</span><span class="pipeline-new-node" nodeId="3" startId="3" enclosingId="5">[Pipeline] node
</span><span class="pipeline-node-3">Running on <a href="/computer/second/">second</a> in /ci/workspace/example
</span><span class="pipeline-new-node" nodeId="6" enclosingId="5">[Pipeline] checkout
</span><span class="pipeline-new-node" nodeId="7" enclosingId="{command_parent}">[Pipeline] sh
</span>"""
    if variant == "wrong-run":
        html = html.replace(HEAD, "b" * 40)
    elif variant == "escaped":
        html = html.replace("<", "&lt;").replace(">", "&gt;")
    if variant == "missing-start":
        html = html.replace(' startId="3"', "")
    body = html.encode()
    if variant != "missing":
        (tmp_path / "maven-workspace-console.html").write_bytes(body)
    capture["workspace_console"] = {
        "url": JOB + "logText/progressiveHtml?start=0",
        "complete": True,
        "sha256": "0" * 64 if variant == "digest" else hashlib.sha256(body).hexdigest(),
    }
    target = TARGET
    if variant == "other-allocation-without-registry":
        capture["registry"] = None
        target = REGISTRY + "/content/repositories/snapshots/" + ARTIFACT
    result = evaluate(tmp_path, capture, target)
    if other_allocation:
        assert result["state"] == "unresolved"
        assert "different Jenkins allocations" in result["reason"]
        assert "jenkins_archive_sha256" not in result
        assert "publication" not in result
    else:
        assert result["state"] == "snapshot-write-observed"
        allocation = result["workspace_allocation"]
        if variant == "supported":
            assert allocation["state"] == "controller-allocation-correlated"
            assert allocation["allocation_node"] == "2"
            assert allocation["agent"] == "first"
        else:
            assert allocation["state"] == "unresolved"
            assert "agent" not in allocation
