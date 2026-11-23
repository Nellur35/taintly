"""A single-command PutObject profile rejects conflicting runner records."""

import json
import sys
from base64 import b64encode
from datetime import datetime, timezone
from hashlib import sha256
from io import BytesIO
from zipfile import ZipFile

import pytest

from taintly import __main__ as cli
from taintly.ingestion import codebuild_s3
from taintly.ingestion.codebuild_put import (
    _audit,
    _bound_launch,
    _bound_s3_input,
    _denial_reason,
    _owned_log_rows,
    _pinned_github_source,
    _request_transport,
    _source_launch_context,
    _trace,
    _workspace_identity,
)
from taintly.ingestion.codebuild_snapshot import SnapshotError


@pytest.mark.parametrize("actor_bound", [True, False])
def test_report_distinguishes_s3_request_actor_from_launcher_and_workspace(
    actor_bound, tmp_path, monkeypatch, capsys
):
    role = "arn:aws:iam::012345678901:role/build-role"
    session = "arn:aws:sts::012345678901:assumed-role/build-role/build-session"
    launcher = "arn:aws:iam::012345678901:user/launcher"
    observation = {
        "state": "direct-s3-write-observed",
        "build": "build-id",
        "repository": "example/project",
        "head": "a" * 40,
        "influence": {"path": "marker.txt"},
        "publication": {
            "operation": "s3:PutObject",
            "object_arn": "arn:aws:s3:::bucket/marker.txt",
            "service_role": role,
            "acting_session": session if actor_bound else "unverified",
            "audit": "bound-s3-data-event" if actor_bound else "unavailable",
        },
        "launch": {"actor": launcher, "event_id": "launch-id"},
        "workspace_identity": {"s3_request_identity": "unverified"},
        "scope": "One observed request.",
    }
    if not actor_bound:
        observation["reported_sts_session"] = session
    monkeypatch.setattr(codebuild_s3, "codebuild_s3_observation", lambda *_: observation)
    monkeypatch.setattr(
        sys,
        "argv",
        ["taintly", str(tmp_path), "--no-config", "--codebuild-public-s3-observation",
         str(tmp_path / "receipt.json"), "build-arn", "https://github.com/example/project"],
    )
    with pytest.raises(SystemExit) as exit_:
        cli.main()
    assert exit_.value.code == 0
    output = capsys.readouterr().out
    assert "S3 operation: s3:PutObject." in output
    assert f"Build role: {role}." in output
    assert f"CloudTrail StartBuild caller: {launcher}" in output
    assert "The workspace STS event identifies the workspace session only." in output
    if actor_bound:
        assert f"S3 request actor: {session} (bound to the S3 data event)." in output
        assert "Runner-reported STS session:" not in output
    else:
        assert "S3 request actor: unverified." in output
        assert f"Runner-reported STS session: {session}." in output


@pytest.mark.parametrize("fmt", ["json", "text"])
def test_incompatible_optional_credential_preserves_s3_denial_and_fails_incomplete(
    tmp_path, monkeypatch, capsys, fmt
):
    observation = {
        "state": "direct-s3-write-denied",
        "build": "build-id",
        "repository": "example/project",
        "head": "a" * 40,
        "influence": {"path": "marker.txt"},
        "publication": {
            "operation": "s3:PutObject",
            "object_arn": "arn:aws:s3:::bucket/marker.txt",
            "service_role": "build-role",
            "acting_session": "owning-session",
            "audit": "bound-s3-data-event",
            "runtime_credential": {
                "state": "unresolved",
                "reason": "temporary credential belongs to another call",
            },
        },
        "scope": "One observed request.",
    }
    monkeypatch.setattr(codebuild_s3, "codebuild_s3_observation", lambda *_: observation)
    monkeypatch.setattr(
        sys,
        "argv",
        ["taintly", str(tmp_path), "--no-config", "--format", fmt,
         "--codebuild-public-s3-observation", str(tmp_path / "receipt.json"),
         "build-arn", "https://github.com/example/project"],
    )
    with pytest.raises(SystemExit) as exit_:
        cli.main()
    assert exit_.value.code == 11
    output = capsys.readouterr().out
    if fmt == "json":
        assert json.loads(output)["codebuild_s3_observation"] == observation
    else:
        assert "was denied access to write" in output
        assert "Runtime credential unresolved: temporary credential belongs to another call." in output
        assert "CloudTrail ties the build's STS" not in output


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
    rows = _owned_log_rows(capture, build, "us-east-1", "012345678901")

    if extra_second in {2, 4}:
        with pytest.raises(SnapshotError, match="reports more than one command"):
            _trace(rows, inline, start, start + 6, "SUCCEEDED")
    else:
        assert _trace(rows, inline, start, start + 6, "SUCCEEDED") == ("", start + 3, start + 6)


@pytest.mark.parametrize(
    ("variant", "reason"),
    [
        ("github", ""),
        ("zip", ""),
        ("compact", ""),
        ("missing-entry", "unambiguous source workspace"),
        ("wrong-root", "recorded workspace"),
        ("sibling", "Workspace entry does not match"),
        ("intervening-command", "unambiguous source workspace"),
        ("outside-download", "Workspace entry does not match"),
    ],
)
def test_source_workspace_uses_the_runner_order_in_its_owned_stream(variant, reason):
    start = datetime(2026, 1, 1, tzinfo=timezone.utc).timestamp()
    identity = None if variant == "zip" else "owner/project"
    workspace = "/codebuild/output/src123/src"
    if identity is not None:
        workspace += "/github.com/Owner/Project"
    declaration = workspace.replace("Project", "Sibling") if variant == "wrong-root" else workspace
    movement = workspace.replace("123", "456") if variant == "sibling" else workspace
    completion = 6 if variant == "outside-download" else 3
    messages = [(completion, "Phase complete: DOWNLOAD_SOURCE State: SUCCEEDED")]
    if variant != "compact":
        messages.append((1, f"CODEBUILD_SRC_DIR={declaration}"))
        if variant != "missing-entry":
            messages.append((2, f"Moving to directory {movement}"))
    if variant == "intervening-command":
        messages.append((4, "Running command printf inert"))
    # Simulate CloudWatch delivery in one later batch.
    rows = [
        (int((start + 10) * 1000), f"[Container] 2026/01/01 00:00:{sec:02}.000000 {line}\n")
        for sec, line in sorted(messages)
    ]
    if reason:
        with pytest.raises(SnapshotError, match=reason):
            _source_launch_context(rows, (start, start + 5), start + 7, identity)
    else:
        assert _source_launch_context(rows, (start, start + 5), start + 7, identity) == (
            None if variant == "compact" else workspace,
            None,
        )


@pytest.mark.parametrize(
    ("before_command", "after_command", "conflict"),
    [
        ([(2, "inline")], [], False),
        ([], [], False),
        ([(2, "checkout")], [], True),
        ([(2, "inline"), (3, "inline")], [], True),
        ([(5, "inline")], [], True),
        ([(2, "inline")], [(2, "checkout")], False),
        ([], [(2, "checkout")], False),
    ],
)
def test_source_workspace_checks_only_the_owning_inline_selection(
    before_command, after_command, conflict,
):
    start = datetime(2026, 1, 1, tzinfo=timezone.utc).timestamp()
    workspace = "/codebuild/output/src123/src"
    paths = {"inline": "/codebuild/readonly/buildspec.yml", "checkout": f"{workspace}/buildspec.yml"}
    rows = [
        (1, f"CODEBUILD_SRC_DIR={workspace}"),
        (3, f"Moving to directory {workspace}"),
        (4, "Phase complete: DOWNLOAD_SOURCE State: SUCCEEDED"),
    ]
    rows.extend((when, f"YAML location is {paths[label]}") for when, label in before_command)
    rows.sort()
    rows.append((7, "Running command set -euo pipefail"))
    rows.extend((when, f"YAML location is {paths[label]}") for when, label in after_command)
    formatted = [
        (int((start + 10) * 1000), f"[Container] 2026/01/01 00:00:{sec:02}.000000 {line}\n")
        for sec, line in rows
    ]
    if conflict:
        with pytest.raises(SnapshotError, match="buildspec selection"):
            _source_launch_context(formatted, (start, start + 5), start + 7, None)
    else:
        assert _source_launch_context(formatted, (start, start + 5), start + 7, None) == (
            workspace, None,
        )


@pytest.mark.parametrize(
    ("records", "expected_shell"),
    [
        ([(3, "bash")], "bash"),
        ([(3, "/bin/sh")], None),
        ([(3, "bash"), (3, "bash")], None),
        ([(5, "bash")], None),
        ([(7, "bash")], None),
        ([(8, "bash")], None),
    ],
)
def test_shell_selection_requires_the_owned_inline_launch(records, expected_shell):
    start = datetime(2026, 1, 1, tzinfo=timezone.utc).timestamp()
    workspace = "/codebuild/output/src123/src"
    messages = [
        (1, f"CODEBUILD_SRC_DIR={workspace}"),
        (2, "YAML location is /codebuild/readonly/buildspec.yml"),
        (4, f"Moving to directory {workspace}"),
        (6, "Phase complete: DOWNLOAD_SOURCE State: SUCCEEDED"),
        (8, "Running command set -euo pipefail"),
    ]
    messages.extend(
        (when, f"Selecting shell {shell} as specified in buildspec.") for when, shell in records
    )
    rows = [
        (int((start + 10) * 1000), f"[Container] 2026/01/01 00:00:{sec:02}.000000 {line}\n")
        for sec, line in sorted(messages, key=lambda item: item[0])
    ]
    if records == [(8, "bash")] or expected_shell:
        assert _source_launch_context(rows, (start, start + 6), start + 8, None) == (
            workspace, expected_shell,
        )
    else:
        with pytest.raises(SnapshotError, match="saved shell selection"):
            _source_launch_context(rows, (start, start + 6), start + 8, None)


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
        ({"AuthenticationMethod": "AuthHeader"}, None),
        ({"AuthenticationMethod": "QueryString"}, "authentication method conflicts"),
        ({"AuthenticationMethod": None}, "authentication method conflicts"),
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
@pytest.mark.parametrize("runtime", [None, "bound", "wrong-key", "bad-timestamp"])
def test_only_version_bound_audit_identifies_s3_writer(
    tmp_path, monkeypatch, audit_version, audit_state, runtime
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
        "logs": {
            "group": "group",
            "stream": "stream",
            "events": [{"timestamp": int(start * 1000), "message": "Owning log stream\n"}],
        },
        "build": {
            "arn": arn,
            "id": build_id,
            "projectName": "test-project",
            "buildStatus": "SUCCEEDED",
            "buildComplete": True,
            "secondarySources": [],
            "cache": {"type": "NO_CACHE"},
            "logs": {
                "groupName": "group",
                "streamName": "stream",
                "cloudWatchLogsArn": f"arn:aws:logs:{region}:{account}:log-group:group:log-stream:stream",
            },
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
    credential_identifier = "ASIA" + "A" * 16
    if runtime is not None:
        capture["runtime_sts_event"] = {
            "eventID": "3f7948f9-c22a-4c21-af8d-5743b349a40a",
            "eventSource": "sts.amazonaws.com",
            "eventName": "GetCallerIdentity",
            "eventCategory": "Management",
            "readOnly": True,
            "awsRegion": region,
            "recipientAccountId": account,
            "eventTime": "invalid" if runtime == "bad-timestamp" else "2026-01-01T00:00:00Z",
            "userIdentity": {
                "type": "AssumedRole",
                "accountId": account,
                "arn": session,
                "credential_id_sha256": (
                    "0" * 64 if runtime == "wrong-key"
                    else sha256(credential_identifier.encode("ascii")).hexdigest()
                ),
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
                "accessKeyId": credential_identifier,
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
    credential = result["publication"].get("runtime_credential")
    if runtime is None:
        assert credential is None
    elif audit_state != "bound-s3-data-event":
        assert credential == {
            "state": "unresolved",
            "reason": "An STS credential join requires an independently matched S3 event",
        }
    elif runtime == "bound":
        assert credential == {
            "source": "cloudtrail-sts-get-caller-identity",
            "event_id": "3f7948f9-c22a-4c21-af8d-5743b349a40a",
        }
    else:
        reason = (
            "Malformed saved STS credential evidence" if runtime == "bad-timestamp"
            else "Saved STS event does not identify the S3 request's temporary credential"
        )
        assert credential == {"state": "unresolved", "reason": reason}
    if audit_state == "bound-s3-data-event":
        assert result["publication"]["acting_session"] == session
        assert "reported_sts_session" not in result
    else:
        assert result["publication"]["acting_session"] == "unverified"
        assert result["reported_sts_session"] == session
