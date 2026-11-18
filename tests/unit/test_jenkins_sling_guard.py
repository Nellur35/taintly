"""Authored controls for source-bound Sling Maven guard observations."""

import hashlib
import json

import pytest

from taintly.ingestion import jenkins_sling_guard as sling
from taintly.ingestion.jenkins_maven_snapshot import maven_snapshot_observation

REPO = "apache/sling-unit-example"
JOB = sling._CONTROLLER + "/job/Sling/job/modules/job/sling-unit-example/job/PR-7/3/"
HEAD, BASE, MERGE = "a" * 40, "b" * 40, "c" * 40
START = 1794510000000
HASH = "d" * 64
VERIFY = "mvn --show-version -U -B -e clean verify javadoc:javadoc -Pjacoco-report -Dci"


def _flow(identifier, name, start, duration):
    route = JOB.removeprefix(sling._CONTROLLER)
    return {
        "id": str(identifier),
        "name": name,
        "status": "SUCCESS",
        "startTimeMillis": START + start,
        "durationMillis": duration,
        "_links": {"self": {"href": route + f"execution/node/{identifier}/wfapi/describe"}},
    }


def _log(node, lines):
    return {
        "node": str(node),
        "url": JOB + f"execution/node/{node}/log/logText/progressiveText",
        "lines": lines,
        "sha256": HASH,
    }


def _build_data(repo, revision, ref, ref_head):
    return {
        "_class": sling._BUILD_DATA,
        "remoteUrls": [f"https://github.com/{repo}.git"],
        "lastBuiltRevision": {"SHA1": revision, "branch": [{"SHA1": ref_head, "name": ref}]},
    }


def _fixture(tmp_path, monkeypatch):
    # The byte identity and revision are kept separate in the authored fixture.
    # The actual library hash and source semantics are checked on frozen real receipts.
    lib = b"synthetic pinned library bytes"
    monkeypatch.setattr(sling, "_LIBRARY_SHA256", hashlib.sha256(lib).hexdigest())
    path = tmp_path / "source"
    path.mkdir()
    (path / "library.groovy").write_bytes(lib)
    caller = b"slingOsgiBundleBuild()\n"
    (path / "Jenkinsfile").write_bytes(caller)
    stage = _flow(10, "Maven Build (Java 17, verify)", 10, 80)
    return {
        "schema": sling.SLING_SCHEMA,
        "pull": {
            "number": 7,
            "base_repository": REPO,
            "base_ref": "master",
            "head_repository": "fork-owner/sling-unit-example",
            "observed_head": HEAD,
        },
        "run": {
            "url": JOB,
            "number": 3,
            "building": False,
            "result": "SUCCESS",
            "timestamp": START - 5,
            "duration": 100,
            "actions": [
                _build_data(sling._LIBRARY, sling._REVISION, "master", sling._REVISION),
                _build_data(REPO, MERGE, "PR-7", HEAD),
            ],
        },
        "source": {
            "path": "Jenkinsfile",
            "commit": BASE,
            "blob": hashlib.sha1(
                f"blob {len(caller)}\0".encode("ascii") + caller, usedforsecurity=False
            ).hexdigest(),
            "sha256": hashlib.sha256(caller).hexdigest(),
        },
        "graph": {
            "id": "3",
            "status": "SUCCESS",
            "startTimeMillis": START,
            "durationMillis": 100,
            "endTimeMillis": START + 100,
            "queueDurationMillis": 5,
            "stages": [dict(stage)],
            "_links": {"self": {"href": JOB.removeprefix(sling._CONTROLLER) + "wfapi/describe"}},
        },
        "stage": {
            **stage,
            "stageFlowNodes": [
                _flow(11, "Check out from version control", 20, 10),
                {**_flow(12, "Shell Script", 40, 30), "parameterDescription": VERIFY},
            ],
        },
        "checkout": _log(
            11,
            [
                f"Merging remotes/origin/master commit {BASE} into PR head commit {HEAD}",
                f"Merge succeeded, producing {MERGE}",
                f"Checking out Revision {MERGE} (PR-7)",
            ],
        ),
        "maven": _log(12, ["+ " + VERIFY, "[INFO] BUILD SUCCESS"]),
        "console": {
            "url": JOB + "consoleText",
            "sha256": HASH,
            "markers": {
                "loader": [1, f"Obtained Jenkinsfile from {BASE}"],
                "library_load": [2, "Loading library sling@master"],
                "library_resolved": [
                    3,
                    f"Resolved master as branch master at revision {sling._REVISION}",
                ],
                "guard": [
                    4,
                    "Maven goal set to verify since branch is not master ( PR-7 ) or version is not snapshot",
                ],
                "finished": [5, "Finished: SUCCESS"],
            },
        },
    }


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        ("none", None),
        ("foreign-log", "log does not identify"),
        ("sibling-checkout", "controller's BuildData"),
        ("guard", "branch-guard observations"),
        ("deploy-stage", "inventory without the remote publisher"),
        ("maven", "reviewed Maven verify command"),
        ("library", "differs from the reviewed publisher guard"),
        ("source", "controller-selected Git source"),
    ],
)
def test_sling_observation_retains_guard_authority_boundary(tmp_path, monkeypatch, change, reason):
    receipt = _fixture(tmp_path, monkeypatch)
    if change == "foreign-log":
        receipt["checkout"]["url"] = receipt["checkout"]["url"].replace("PR-7/3/", "PR-7/2/")
    elif change == "sibling-checkout":
        receipt["run"]["actions"][1]["lastBuiltRevision"]["SHA1"] = "e" * 40
    elif change == "guard":
        receipt["console"]["markers"]["guard"][0] = 2
    elif change == "deploy-stage":
        receipt["graph"]["stages"].append(_flow(20, "Deploy to Nexus", 91, 5))
    elif change == "maven":
        receipt["maven"]["lines"][0] = "+ mvn deploy"
    elif change == "library":
        (tmp_path / "source/library.groovy").write_bytes(b"other library")
    elif change == "source":
        (tmp_path / "source/Jenkinsfile").write_bytes(b"'slingOsgiBundleBuild'()\n")
    (tmp_path / "snapshot.json").write_text(json.dumps(receipt), encoding="utf8")

    result = maven_snapshot_observation(tmp_path, REPO, 7, JOB, sling._TARGET)
    if reason:
        assert result["state"] == "unresolved"
        assert reason in result["reason"]
        assert "remote_publisher" not in result
    else:
        assert result["state"] == sling.SLING_STATE
        assert result["checkout"] == MERGE
        assert result["node"] == "12"
        assert result["remote_publisher"]["state"] == "not-created"
        assert result["authority"] == "unresolved"
