"""A single-command PutObject profile rejects conflicting runner records."""

from base64 import b64encode
from datetime import datetime, timezone
from hashlib import sha256
from io import BytesIO
from zipfile import ZipFile

import pytest

from taintly.ingestion.codebuild_put import (
    _audit,
    _bound_launch,
    _bound_s3_input,
    _denial_reason,
    _pinned_github_source,
    _request_transport,
    _trace,
    _workspace_identity,
)
from taintly.ingestion.codebuild_snapshot import SnapshotError


@pytest.mark.parametrize(
    ("conflict", "error"),
    [
        (None, None),
        ("missing-pr", "GitHub pull request evidence"),
        ("wrong-number", "pinned external fork head"),
        ("wrong-base-repo", "pinned external fork head"),
        ("same-owner-fork", "pinned external fork head"),
        ("wrong-head", "pinned external fork head"),
        ("same-base-and-head", "pinned external fork head"),
        ("wrong-pin", "pinned GitHub branch or PR head"),
        ("merge-ref", "pinned GitHub branch or PR head"),
    ],
)
def test_pinned_external_pr_requires_independent_matching_identity(conflict, error):
    head, base = "a" * 40, "b" * 40
    selector = f"refs/pull/11/head^{{{head}}}"
    source = {"type": "GITHUB", "location": "https://github.com/owner/repo", "insecureSsl": False}
    build = {"resolvedSourceVersion": head}
    pr = {"number": 11, "repository": "owner/repo", "fork": "contributor/repo", "head": head, "base": base}
    if conflict == "missing-pr":
        pr = None
    elif conflict == "wrong-number":
        pr["number"] = 12
    elif conflict == "wrong-base-repo":
        pr["repository"] = "owner/another-repo"
    elif conflict == "same-owner-fork":
        pr["fork"] = "owner/another-repo"
    elif conflict == "wrong-head":
        pr["head"] = "c" * 40
    elif conflict == "same-base-and-head":
        pr["base"] = head
    elif conflict == "wrong-pin":
        selector = f"refs/pull/11/head^{{{base}}}"
    elif conflict == "merge-ref":
        selector = selector.replace("/head^", "/merge^")
    if error:
        with pytest.raises(SnapshotError, match=error):
            _pinned_github_source(build, source, selector, "owner/repo", pr)
        return
    assert _pinned_github_source(build, source, selector, "owner/repo", pr) == (
        head, {"number": 11, "head_repository": "contributor/repo", "base": base},
    )


@pytest.mark.parametrize("conflict", [None, "other-issuer", "early-event", "other-session"])
def test_workspace_identity_is_scoped_to_the_sts_call(conflict):
    account = "012345678901"
    role = f"arn:aws:iam::{account}:role/test-role"
    session = f"arn:aws:sts::{account}:assumed-role/test-role/test-session"
    moment = datetime(2026, 11, 18, 12, 0, tzinfo=timezone.utc)
    event = {
        "eventID": "3f7948f9-c22a-4c21-af8d-5743b349a40a",
        "eventSource": "sts.amazonaws.com",
        "eventName": "GetCallerIdentity",
        "eventCategory": "Management",
        "readOnly": True,
        "awsRegion": "us-east-1",
        "recipientAccountId": account,
        "eventTime": moment.isoformat(),
        "userIdentity": {
            "type": "AssumedRole",
            "accountId": account,
            "arn": session,
            "sessionContext": {
                "sessionIssuer": {"type": "Role", "accountId": account, "arn": role}
            },
        },
    }
    start = moment.timestamp() - 1
    if conflict == "early-event":
        start += 5
    elif conflict == "other-issuer":
        event["userIdentity"]["sessionContext"]["sessionIssuer"]["arn"] += "-other"
    elif conflict == "other-session":
        event["userIdentity"]["arn"] += "-sibling"
    args = (event, "us-east-1", account, role, session, (start, start + 10))
    if conflict:
        with pytest.raises(SnapshotError, match="Saved STS"):
            _workspace_identity(*args)
    else:
        result = _workspace_identity(*args)
        assert result["event_id"] == event["eventID"]
        assert result["service_role"] == role
        assert result["s3_request_identity"] == "unverified"


@pytest.mark.parametrize(
    ("replace", "conflicts", "expected"),
    [
        (("", ""), False, "explicit-resource-policy-deny"),
        (("PutObject", "GetObject"), True, None),
        (("session", "other"), True, None),
        (("bucket/marker", "bucket/sibling"), True, None),
        (("resource-based policy", "identity-based policy"), False, None),
    ],
)
def test_enhanced_denial_checks_the_request_subject(replace, conflicts, expected):
    session = "arn:aws:sts::012345678901:assumed-role/role/session"
    target = "arn:aws:s3:::bucket/marker"
    runner = (
        f'User: {session} is not authorized to perform: s3:PutObject on resource: "{target}"'
        " with an explicit deny in a resource-based policy"
    )
    audit = runner.replace(*replace) if replace[0] else runner
    if conflicts:
        with pytest.raises(SnapshotError, match="conflicts with the bound request"):
            _denial_reason(audit, runner, session, target)
    else:
        assert _denial_reason(audit, runner, session, target) == expected
    assert _denial_reason("Access Denied", runner, session, target) is None


@pytest.mark.parametrize("extra_second", [None, 2, 4, 7])
def test_only_one_runner_command_inside_owning_build(extra_second):
    start = datetime(2026, 1, 1, tzinfo=timezone.utc).timestamp()
    build = {
        "logs": {
            "groupName": "group",
            "streamName": "stream",
            "cloudWatchLogsArn": "arn:aws:logs:us-east-1:012345678901:log-group:group:log-stream:stream",
        }
    }

    def event(second, message):
        return {
            "timestamp": int((start + second) * 1000),
            "message": f"[Container] 2026/01/01 00:00:{second:02}.000000 {message}\n",
        }

    events = [
        event(3, "Running command set -euo pipefail\naws s3api put-object"),
        event(6, "Phase complete: BUILD State: SUCCEEDED"),
    ]
    if extra_second is not None:
        events.append(event(extra_second, "Running command printf control"))
    events.sort(key=lambda entry: entry["timestamp"])
    capture = {"logs": {"group": "group", "stream": "stream", "events": events}}
    inline = "\n" * 7 + "        set -euo pipefail\n        aws s3api put-object"

    if extra_second in {2, 4}:
        with pytest.raises(SnapshotError, match="reports more than one command"):
            _trace(
                capture, build, inline, start, start + 6, "SUCCEEDED", "us-east-1", "012345678901"
            )
    else:
        assert _trace(
            capture, build, inline, start, start + 6, "SUCCEEDED", "us-east-1", "012345678901"
        ) == ("", start + 3, start + 6)


@pytest.mark.parametrize(("second", "matches"), [(1, False), (2, True), (4, True), (5, False)])
def test_cloudtrail_second_must_overlap_owning_command(second, matches):
    account = "012345678901"
    role = f"arn:aws:iam::{account}:role/build"
    session = f"arn:aws:sts::{account}:assumed-role/build/run"
    event = {
        "eventTime": f"2026-01-01T00:00:{second:02}Z",
        "requestID": "test-request",
        "eventSource": "s3.amazonaws.com",
        "eventName": "PutObject",
        "eventCategory": "Data",
        "readOnly": False,
        "awsRegion": "us-east-1",
        "recipientAccountId": account,
        "userIdentity": {
            "type": "AssumedRole",
            "accountId": account,
            "arn": session,
            "sessionContext": {"sessionIssuer": {"arn": role}},
        },
        "requestParameters": {"bucketName": "test-bucket", "key": "marker.txt"},
        "errorCode": "AccessDenied",
    }
    start = datetime(2026, 1, 1, tzinfo=timezone.utc).timestamp()
    args = ("us-east-1", account, role, session, "test-bucket", "marker.txt")
    if matches:
        assert _audit(event, *args, start + 2.5, start + 4.5, "AccessDenied") == (
            "test-request",
            {},
        )
    else:
        with pytest.raises(SnapshotError, match="outside the owning command"):
            _audit(event, *args, start + 2.5, start + 4.5, "AccessDenied")


@pytest.mark.parametrize(
    ("members", "version", "reason"),
    [
        ([("marker.txt", b"proof")], "same-version", None),
        ([("marker.txt", b"proof")], "other-version", "bounded versioned S3 input receipt"),
        ([("marker.txt", b"other")], "same-version", "does not match the pinned Git file"),
        (
            [("marker.txt", b"proof"), ("other.txt", b"unused")],
            "same-version",
            "contain exactly one data file",
        ),
    ],
)
def test_versioned_zip_input_binds_exact_member_and_version(members, version, reason):
    data = BytesIO()
    with ZipFile(data, "w") as archive:
        for path, content in members:
            archive.writestr(path, content)
    payload = data.getvalue()
    checksum = sha256(payload)
    record = {
        "bucket": "test-bucket",
        "key": "input.zip",
        "receipt": {
            "VersionId": "same-version",
            "ChecksumType": "FULL_OBJECT",
            "ChecksumSHA256": b64encode(checksum.digest()).decode("ascii"),
        },
        "archive_base64": b64encode(payload).decode("ascii"),
    }
    source = {"location": "test-bucket/input.zip", "insecureSsl": False}
    args = (record, source, version, "marker.txt", b"proof")
    if reason:
        with pytest.raises(SnapshotError, match=reason):
            _bound_s3_input(*args)
    else:
        assert _bound_s3_input(*args) == {
            "object_arn": "arn:aws:s3:::test-bucket/input.zip",
            "version": "same-version",
            "sha256": checksum.hexdigest(),
        }


@pytest.mark.parametrize("override", [True, False])
def test_launch_receipt_binds_the_selected_version_with_or_without_an_override(override):
    account = "012345678901"
    region = "us-east-1"
    event_id = "01234567-0123-0123-0123-0123456789ab"
    actor = f"arn:aws:iam::{account}:user/launcher"
    build = {
        "id": f"project:{event_id}",
        "arn": f"arn:aws:codebuild:{region}:{account}:build/project:{event_id}",
        "projectName": "project",
        "sourceVersion": "input-version",
        "initiator": "launcher",
        "startTime": "2026-01-01T00:00:00.500Z",
        "serviceRole": f"arn:aws:iam::{account}:role/worker",
    }
    receipt = {
        "eventID": event_id,
        "requestID": "11234567-0123-0123-0123-0123456789ab",
        "eventTime": "2026-01-01T00:00:00Z",
        "eventSource": "codebuild.amazonaws.com",
        "eventName": "StartBuild",
        "eventCategory": "Management",
        "awsRegion": region,
        "recipientAccountId": account,
        "readOnly": False,
        "userIdentity": {"type": "IAMUser", "arn": actor, "accountId": account},
        "requestParameters": {"projectName": "project"},
        "responseElements": {"build": {key: build[key] for key in ("id", "arn", "sourceVersion")}},
    }
    if override:
        receipt["requestParameters"]["sourceVersion"] = "input-version"
    assert _bound_launch(receipt, build, region, account) == {
        "operation": "codebuild:StartBuild",
        "actor": actor,
        "event_id": event_id,
    }
    if override:
        receipt["requestParameters"]["sourceVersion"] = "another-version"
        with pytest.raises(SnapshotError, match="does not match the build"):
            _bound_launch(receipt, build, region, account)
        receipt["requestParameters"]["sourceVersion"] = None
        with pytest.raises(SnapshotError, match="does not match the build"):
            _bound_launch(receipt, build, region, account)
        receipt["requestParameters"]["sourceVersion"] = "input-version"
    receipt["responseElements"]["build"]["sourceVersion"] = "another-version"
    with pytest.raises(SnapshotError, match="does not match the build"):
        _bound_launch(receipt, build, region, account)


@pytest.mark.parametrize(
    ("updates", "message"),
    [
        ({}, None),
        ({"startTime": 1767225602000}, "outside the owning command"),
        ({"endTime": 1767225604000}, "completion conflicts"),
        ({"endTime": None}, "complete millisecond record"),
        ({"httpStatusCode": 200}, "HTTP status conflicts"),
    ],
)
def test_precise_s3_transport_can_disprove_a_coarse_time_match(updates, message):
    base = datetime(2026, 1, 1, tzinfo=timezone.utc).timestamp()
    actual = {
        "startTime": int((base + 2.7) * 1000),
        "endTime": int((base + 3.05) * 1000),
        "httpStatusCode": 403,
    } | updates
    args = ({"additionalEventData": actual}, base + 3, base + 2.5, base + 4.5, True)
    if message:
        with pytest.raises(SnapshotError, match=message):
            _request_transport(*args)
    else:
        assert _request_transport(*args) == {
            "start_ms": actual["startTime"],
            "end_ms": actual["endTime"],
            "http_status": 403,
        }


@pytest.mark.parametrize(
    ("audit_version", "audit_state"),
    [
        (None, "unavailable"),
        ("", "unresolved-version-binding"),
        ("test-version", "bound-s3-data-event"),
        ("different-version", None),
    ],
)
def test_only_version_bound_audit_identifies_s3_writer(
    tmp_path, monkeypatch, audit_version, audit_state
):
    from taintly.ingestion import codebuild_put

    account = "012345678901"
    region = "us-east-1"
    role = f"arn:aws:iam::{account}:role/build-role"
    session = f"arn:aws:sts::{account}:assumed-role/build-role/runner"
    build_id = "test-project:01234567-0123-0123-0123-0123456789ab"
    arn = f"arn:aws:codebuild:{region}:{account}:build/{build_id}"
    repo = "https://github.com/owner/repo"
    head = "a" * 40
    digest = sha256(b"marker")
    checksum = b64encode(digest.digest()).decode()
    inline = codebuild_put._PLAN.replace("@FILE@", "marker.txt").replace("@KEY@", "marker.txt")
    start = datetime(2026, 1, 1, tzinfo=timezone.utc).timestamp()
    trace = (
        f"source={head}\nbuild={arn}\n"
        f'{{\n  "Account": "{account}",\n  "Arn": "{session}"\n}}\n'
        f"operation=PutObject\nkey=marker.txt\nsha256_base64={checksum}\n"
        f'{{\n  "VersionId": "test-version",\n  "ChecksumSHA256": "{checksum}"\n}}\n'
    )
    monkeypatch.setattr(codebuild_put, "_require_git_revision", lambda *_args: None)
    monkeypatch.setattr(
        codebuild_put, "_blob", lambda *_args: ("marker", {"sha256": digest.hexdigest()})
    )
    monkeypatch.setattr(
        codebuild_put,
        "_phase",
        lambda _build, phase, *_args: (start, start + (2 if phase == "BUILD" else 0)),
    )
    monkeypatch.setattr(codebuild_put, "_trace", lambda *_args: (trace, start, start + 2))
    values = {
        "EXPERIMENT_BUCKET": "test-bucket",
        "EXPERIMENT_SOURCE_SHA": head,
        "EXPERIMENT_MARKER_SHA256": digest.hexdigest(),
    }
    capture = {
        "build": {
            "arn": arn,
            "id": build_id,
            "projectName": "test-project",
            "buildStatus": "SUCCEEDED",
            "buildComplete": True,
            "secondarySources": [],
            "cache": {"type": "NO_CACHE"},
            "sourceVersion": f"refs/heads/main^{{{head}}}",
            "resolvedSourceVersion": head,
            "serviceRole": role,
            "source": {
                "type": "GITHUB",
                "location": repo,
                "insecureSsl": False,
                "buildspec": inline,
            },
            "environment": {
                "type": "LINUX_CONTAINER",
                "privilegedMode": False,
                "image": "aws/codebuild/standard:7.0",
                "imagePullCredentialsType": "CODEBUILD",
                "environmentVariables": [
                    {"name": name, "value": value, "type": "PLAINTEXT"}
                    for name, value in values.items()
                ],
            },
        },
        "retrieval": {
            "bucket": "test-bucket",
            "key": "marker.txt",
            "bytes_base64": b64encode(b"marker").decode(),
            "response": {
                "VersionId": "test-version",
                "ChecksumSHA256": checksum,
                "ChecksumType": "FULL_OBJECT",
                "ContentLength": 6,
                "LastModified": "2026-01-01T00:00:01Z",
            },
        },
    }
    if audit_version is not None:
        capture["s3_event"] = {
            "eventTime": "2026-01-01T00:00:01Z",
            "requestID": "request-id",
            "eventSource": "s3.amazonaws.com",
            "eventName": "PutObject",
            "eventCategory": "Data",
            "readOnly": False,
            "awsRegion": region,
            "recipientAccountId": account,
            "userIdentity": {
                "type": "AssumedRole",
                "accountId": account,
                "arn": session,
                "sessionContext": {"sessionIssuer": {"arn": role}},
            },
            "requestParameters": {"bucketName": "test-bucket", "key": "marker.txt"},
            "responseElements": {"x-amz-version-id": audit_version} if audit_version else None,
        }
    if audit_state is None:
        with pytest.raises(SnapshotError, match="different object version"):
            codebuild_put.direct_s3_put(capture, tmp_path, arn, repo)
        return
    result = codebuild_put.direct_s3_put(capture, tmp_path, arn, repo)
    assert result["state"] == "direct-s3-write-observed"
    assert result["publication"]["audit"] == audit_state
    if audit_state == "bound-s3-data-event":
        assert result["publication"]["acting_session"] == session
        assert "reported_sts_session" not in result
    else:
        assert result["publication"]["acting_session"] == "unverified"
        assert result["reported_sts_session"] == session
