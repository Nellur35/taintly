"""Corroborate one saved direct S3 PutObject from a pinned CodeBuild run."""

from __future__ import annotations

import base64
import hashlib
import json
import re
import stat
from datetime import datetime
from io import BytesIO
from pathlib import Path, PurePosixPath
from typing import Any
from zipfile import ZIP_STORED, BadZipFile, ZipFile

from taintly.ingestion.codebuild_deploy import _RECORD, _phase_window, _record
from taintly.ingestion.codebuild_snapshot import (
    BUILD_ID,
    SnapshotError,
    _github_identity,
    _regular_blob,
    _require_git_revision,
    _unique_keys,
)
from taintly.ingestion.codebuild_start import _blob, _need, _sha

SCOPE = (
    "Trusted saved CodeBuild, CloudWatch and S3 evidence for one direct object request. "
    "Future IAM decisions, fork admission and artifact audience require separate evidence."
)
_POLICY_SCOPE = (
    "The saved policy change matches the observed denial. Other policy changes "
    "and whether this was the only contributing change remain unverified."
)
_COMPARED_BUILD_FIELDS = (
    "projectName",
    "source",
    "sourceVersion",
    "resolvedSourceVersion",
    "environment",
    "serviceRole",
    "artifacts",
    "secondarySources",
    "secondarySourceVersions",
    "secondaryArtifacts",
    "cache",
    "encryptionKey",
    "initiator",
    "timeoutInMinutes",
    "queuedTimeoutInMinutes",
    "vpcConfig",
    "fileSystemLocations",
)
_ARN = re.compile(
    rf"arn:aws:codebuild:([a-z]{{2}}-[a-z0-9-]+-[0-9]):([0-9]{{12}}):build/({BUILD_ID.pattern})"
)
_PATH = r"[A-Za-z0-9_][A-Za-z0-9_.-]*(?:/[A-Za-z0-9_][A-Za-z0-9_.-]*)*"
_REF = rf"refs/heads/{_PATH}"
_PR_HEAD_REF = r"refs/pull/([1-9][0-9]{0,9})/head"
_BUCKET = r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]"
_ROLE = r"[A-Za-z0-9_+=,.@-]{1,64}"
_VERSION = r"[A-Za-z0-9._~+=/-]{1,1024}"
_EVENT_ID = r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}"
_S3_DENIAL_SUBJECT = re.compile(
    rf"^User: (arn:aws:sts::[0-9]{{12}}:assumed-role/{_ROLE}/{_ROLE}) "
    r'is not authorized to perform: (s3:[A-Za-z0-9]+) on resource: "(arn:aws:s3:::[^"\r\n]+)"'
)
_RESOURCE_DENY = " with an explicit deny in a resource-based policy"
# One trusted inline script. Restrict the entire plan so another step, hook,
# executable input, or logging statement cannot impersonate this request.
_PLAN = r"""version: 0.2
env:
  shell: bash
phases:
  build:
    commands:
      - |
        set -euo pipefail
        test -n "${CODEBUILD_BUILD_ARN:-}"
        test -n "${CODEBUILD_RESOLVED_SOURCE_VERSION:-}"
        test -n "${EXPERIMENT_BUCKET:-}"
        test -f @FILE@
        test ! -L @FILE@
        test "$CODEBUILD_RESOLVED_SOURCE_VERSION" = "$EXPERIMENT_SOURCE_SHA"
        test "$(sha256sum @FILE@ | cut -d' ' -f1)" = "$EXPERIMENT_MARKER_SHA256"
        test "$(wc -c < @FILE@)" -le 128
        printf 'source=%s\nbuild=%s\n' "$CODEBUILD_RESOLVED_SOURCE_VERSION" "$CODEBUILD_BUILD_ARN"
        aws sts get-caller-identity --query '{Account:Account,Arn:Arn}' --output json
        checksum=$(openssl dgst -sha256 -binary @FILE@ | base64 -w0)
        printf 'operation=PutObject\nkey=@KEY@\nsha256_base64=%s\n' "$checksum"
        aws s3api put-object --bucket "$EXPERIMENT_BUCKET" --key @KEY@ --body @FILE@ --checksum-sha256 "$checksum" --query '{VersionId:VersionId,ChecksumSHA256:ChecksumSHA256}' --output json"""


def _plan_pattern(plan: str) -> re.Pattern[str]:
    return re.compile(
        re.escape(plan)
        .replace("@FILE@", rf"(?P<file>{_PATH})", 1)
        .replace("@FILE@", r"(?P=file)")
        .replace("@KEY@", rf"(?P<key>{_PATH})", 1)
        .replace("@KEY@", r"(?P=key)")
    )


_PLAN_RE = _plan_pattern(_PLAN)
_S3_PLAN_RE = _plan_pattern(
    _PLAN.replace("CODEBUILD_RESOLVED_SOURCE_VERSION", "CODEBUILD_SOURCE_VERSION").replace(
        "EXPERIMENT_SOURCE_SHA", "EXPERIMENT_SOURCE_VERSION"
    )
)
# Lab-only collector profile. The digest pins the whole operator-owned buildspec,
# including the collector and cleanup. No receipt-supplied digest grants admission.
_OPERATOR_PLAN_SHA256 = "7ff740ec800aec936828853fb418723846a10cf6fc12d00e0c0d162717921800"
_CLOUDTRAIL_REDACTION = "HIDDEN_DUE_TO_SECURITY_REASONS"
_OPERATOR_EXE = r"/usr/local/aws-cli/v2/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/dist/aws"
_OPERATOR_SCRATCH_NAME = re.compile(r"taintly-collector\.[a-zA-Z0-9]{8}")
_OPERATOR_HEADER = (
    rf"operator_cli_path=(?P<executable>{_OPERATOR_EXE})\n"
    r"operator_cli_sha256=(?P<digest>[0-9a-f]{64})\n"
    r"operator_directory=(?P<directory>/[A-Za-z0-9./-]{1,64})\n"
)
_PROCESS_LINE = re.compile(r"^taintly_process_receipt=([^\n]*)$", re.M)
_PROCESS_FIELDS = {
    "operation",
    "request_id",
    "http_status",
    "pid",
    "executable_path",
    "executable_sha256",
    "executable_identity",
    "cwd",
    "cwd_identity",
}
_PHASE_END = r"Phase complete: BUILD State: "
_Row = dict[str, Any]


def _time(value: object) -> float:
    if not isinstance(value, str):
        raise SnapshotError("The AWS timestamp must declare its timezone")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    _need(parsed.utcoffset() is not None, "The AWS timestamp must declare its timezone")
    return parsed.timestamp()


def _map(value: object, label: str) -> _Row:
    if not isinstance(value, dict):
        raise SnapshotError(f"Missing or malformed {label}")
    return value


def _text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise SnapshotError(f"Missing or malformed {label}")
    return value


def _rows(value: object, label: str, limit: int) -> list[_Row]:
    if not isinstance(value, list) or not 0 < len(value) <= limit:
        raise SnapshotError(f"Missing or oversized {label}")
    return [_map(row, label) for row in value]


def _phase(build: _Row, name: str, status: str = "SUCCEEDED") -> tuple[float, float]:
    phases = [
        dict(phase, startTime=_time(phase["startTime"]), endTime=_time(phase["endTime"]))
        for phase in _rows(build.get("phases"), "CodeBuild phases", 64)
        if phase["phaseType"] == name
    ]
    return _phase_window(
        dict(
            build,
            phases=phases,
            startTime=_time(build["startTime"]),
            endTime=_time(build["endTime"]),
        ),
        name,
        status=status,
    )


def _owned_log_rows(capture: _Row, build: _Row, region: str, account: str) -> list[tuple[int, str]]:
    logs = _map(capture.get("logs"), "CloudWatch export")
    owner = _map(build.get("logs"), "CodeBuild log owner")
    _need(
        isinstance(logs.get("group"), str)
        and logs["group"] == owner.get("groupName")
        and isinstance(logs.get("stream"), str)
        and logs["stream"] == owner.get("streamName")
        and owner.get("cloudWatchLogsArn")
        == (
            f"arn:aws:logs:{region}:{account}:log-group:{logs['group']}:log-stream:{logs['stream']}"
        ),
        "CloudWatch export does not identify the selected build stream",
    )
    rows = _rows(logs.get("events"), "CloudWatch events", 4096)
    messages: list[tuple[int, str]] = []
    last = 0
    for row in rows:
        stamp, message = row["timestamp"], row["message"]
        _need(
            type(stamp) is int and stamp >= last and isinstance(message, str),
            "Malformed CloudWatch event order",
        )
        last = stamp
        messages.append((stamp, message))
    return messages


def _trace(
    rows: list[tuple[int, str]],
    inline: str,
    lower: float,
    upper: float,
    status: str,
) -> tuple[str, float, float]:
    # CloudWatch can stamp the runner completion line after the phase timestamp.
    trace = "".join(message for stamp, message in rows if lower <= stamp / 1000 <= upper + 1)
    command = "\n".join(line[8:] for line in inline.splitlines()[7:])
    matches = list(
        re.finditer(
            r"^\[Container\] [^\n]+ Running command " + re.escape(command) + r"\n", trace, re.M
        )
    )
    _need(len(matches) == 1, "Owning BUILD phase lacks the exact configured command")
    start, _ = _record(matches[0][0].splitlines()[0], r"Running command set -euo pipefail")
    tail = trace[matches[0].end() :]
    outcomes = list(re.finditer(r"^\[Container\] [^\n]+ " + _PHASE_END + status + r"$", tail, re.M))
    _need(len(outcomes) == 1, "Owning log lacks the matching BUILD phase result")
    when, _ = _record(outcomes[0][0], _PHASE_END + status)
    _need(
        lower <= start < when <= upper,
        "The recorded command or completion lies outside its BUILD phase",
    )
    active_commands = 0
    for header in re.findall(r"^\[Container\] [^\n]+ Running command [^\n]*", trace, re.M):
        launched, _ = _record(header, r"Running command [^\n]*")
        # Use the runner timestamp. CloudWatch may deliver lines from the
        # following phase within the extra second allowed for log delivery.
        if lower <= launched <= when:
            active_commands += 1
    _need(active_commands == 1, "Owning BUILD log reports more than one command")
    return tail[: outcomes[0].start()], start, when


def _source_launch_context(
    rows: list[tuple[int, str]],
    download: tuple[float, float],
    command_start: float,
    identity: str | None,
) -> tuple[str | None, str | None]:
    lower, upper = download
    expected = r"/codebuild/output/src[0-9]+/src"
    if identity is not None:
        expected += r"/github\.com/(?i:" + re.escape(identity) + ")"
    events: list[tuple[float, str]] = []
    # CloudWatch can deliver DOWNLOAD_SOURCE and BUILD records in the same
    # delayed batch. Compare runner timestamps in the bounded owning stream.
    messages = "".join(message for _, message in rows)
    kinds = (
        r"CODEBUILD_SRC_DIR=[^\n]*|Moving to directory [^\n]*"
        r"|YAML location is [^\n]*|Selecting shell [^\n]*"
        r"|Phase complete: DOWNLOAD_SOURCE State: [^\n]*|Running command [^\n]*"
    )
    pattern = "(" + kinds + ")"
    for header in re.finditer("^" + _RECORD + pattern + "$", messages, re.M):
        when, (record,) = _record(header[0], pattern)
        if when == command_start and record == "Running command set -euo pipefail":
            break
        if record.startswith("Selecting shell ") or lower <= when < command_start:
            events.append((when, record))
    shells = [
        index for index, (_, record) in enumerate(events) if record.startswith("Selecting shell ")
    ]
    shell_time = None
    shell_conflict = (
        "The saved shell selection conflicts with the inline Bash plan in DOWNLOAD_SOURCE"
    )
    if shells:
        index = shells[0]
        shell_time, selection = events.pop(index)
        _need(
            len(shells) == 1
            and lower <= shell_time <= upper
            and selection == "Selecting shell bash as specified in buildspec."
            and not any(
                record.startswith(("Moving to directory ", "Phase complete: DOWNLOAD_SOURCE"))
                for _, record in events[:index]
            )
            and not any(record.startswith("YAML location is ") for _, record in events[index:]),
            shell_conflict,
        )
    selections = [
        index for index, (_, record) in enumerate(events) if record.startswith("YAML location is ")
    ]
    plan_time = None
    if selections:
        index = selections[0]
        plan_time, location = events.pop(index)
        _need(
            len(selections) == 1
            and plan_time <= upper
            and location == "YAML location is /codebuild/readonly/buildspec.yml"
            and not any(
                record.startswith("Phase complete: DOWNLOAD_SOURCE State: ")
                and (position < index or completed < plan_time)
                for position, (completed, record) in enumerate(events)
            ),
            "The saved buildspec selection conflicts with the inline plan in DOWNLOAD_SOURCE",
        )
    if not any(
        record.startswith(("CODEBUILD_SRC_DIR=", "Moving to directory ")) for _, record in events
    ):
        return None, None  # A compact receipt can still establish the request independently.
    _need(len(events) == 3, "The build lacks an unambiguous source workspace before its command")
    (declared, declaration), (entered, movement), (finished, completion) = events
    match = re.fullmatch("CODEBUILD_SRC_DIR=(" + expected + ")", declaration)
    if match is None:
        raise SnapshotError("The recorded workspace does not match the selected source profile")
    workspace = match[1]
    _need(
        lower <= declared < entered < finished <= upper
        and movement == "Moving to directory " + workspace
        and completion == "Phase complete: DOWNLOAD_SOURCE State: SUCCEEDED",
        "Workspace entry does not match the selected source in the owning DOWNLOAD_SOURCE phase",
    )
    if shell_time is None or plan_time is None:
        return workspace, None
    _need(declared < plan_time < shell_time < entered, shell_conflict)
    return workspace, "bash"


def _request_transport(event: _Row, when: float, lower: float, upper: float, denied: bool) -> _Row:
    # S3 captured these optional service fields on the examined direct requests.
    # Older receipts can still support the second-precision audit contract.
    extra = event.get("additionalEventData")
    if extra is None:
        return {}
    fields = _map(extra, "S3 request transport")
    if "AuthenticationMethod" in fields:
        _need(
            fields["AuthenticationMethod"] == "AuthHeader",
            "S3 authentication method conflicts with the direct AWS CLI request",
        )
    result: _Row = {}
    if "httpStatusCode" in fields:
        status = fields["httpStatusCode"]
        _need(
            type(status) is int and status == (403 if denied else 200),
            "Reported HTTP status conflicts with the saved S3 request result",
        )
        result["http_status"] = status
    if "startTime" in fields or "endTime" in fields:
        started, ended = fields.get("startTime"), fields.get("endTime")
        if type(started) is not int or type(ended) is not int:
            raise SnapshotError("S3 request interval is not a complete millisecond record")
        _need(10**12 <= started <= ended < 10**13, "S3 request interval has invalid times")
        _need(
            lower * 1000 <= started <= ended <= upper * 1000,
            "S3 request interval is outside the owning command",
        )
        _need(
            when * 1000 <= ended < (when + 1) * 1000,
            "S3 request completion conflicts with the CloudTrail event time",
        )
        result.update(start_ms=started, end_ms=ended)
    return result


def _audit(
    event: _Row,
    region: str,
    account: str,
    role: str,
    session: str,
    bucket: str,
    key: str,
    lower: float,
    upper: float,
    error: str | None,
) -> tuple[str, _Row]:
    identity = _map(event.get("userIdentity"), "S3 request identity")
    issuer = _map(
        _map(identity.get("sessionContext"), "session context").get("sessionIssuer"),
        "session issuer",
    )
    target = _map(event.get("requestParameters"), "S3 request target")
    when = _time(event.get("eventTime"))
    request_id = _text(event.get("requestID"), "S3 request ID")
    _need(
        event.get("eventSource") == "s3.amazonaws.com"
        and event.get("eventName") == "PutObject"
        and event.get("eventCategory") == "Data"
        and event.get("readOnly") is False
        and event.get("awsRegion") == region
        and event.get("recipientAccountId") == account
        and identity.get("type") == "AssumedRole"
        and identity.get("accountId") == account
        and identity.get("arn") == session
        and issuer.get("arn") == role
        and target.get("bucketName") == bucket
        and target.get("key") == key
        and event.get("errorCode") == error
        and (error is not None or "errorMessage" not in event)
        and re.fullmatch(r"[A-Za-z0-9-]{1,128}", request_id),
        "S3 data event fails to match the exact request, result or acting session",
    )
    # CloudTrail records second precision. Require overlap with the owning command.
    _need(when <= upper and when + 1 > lower, "S3 data event falls outside the owning command")
    return request_id, _request_transport(event, when, lower, upper, error is not None)


def _runtime_process(
    trace: str,
    after_response: int,
    header: re.Match[str],
    request_id: str | None,
    status: int,
) -> _Row:
    try:
        _need(request_id is not None, "A process join requires an independently matched S3 event")
        lines = list(_PROCESS_LINE.finditer(trace))
        _need(
            len(lines) == 1
            and lines[0].start() >= after_response
            and len(lines[0][1]) <= 2048
            and lines[0][1] != "unresolved",
            "No unique process receipt follows the owning PutObject response",
        )
        receipt = _map(json.loads(lines[0][1], object_pairs_hook=_unique_keys), "process receipt")
        _need(set(receipt) == _PROCESS_FIELDS, "Process receipt has unexpected or missing fields")
        _need(
            receipt["operation"] == "PutObject"
            and receipt["request_id"] == request_id
            and type(receipt["http_status"]) is int
            and receipt["http_status"] == status,
            "Process receipt identifies a different S3 request or result",
        )
        _need(
            receipt["executable_path"] == header["executable"]
            and receipt["executable_sha256"] == header["digest"]
            and receipt["cwd"] == header["directory"],
            "Process executable or working directory differs from the operator preparation",
        )
        pid = receipt["pid"]
        identities = (receipt["executable_identity"], receipt["cwd_identity"])
        _need(
            type(pid) is int
            and 0 < pid < 2**31
            and all(
                isinstance(value, list)
                and len(value) == 2
                and all(type(part) is int and 0 <= part < 2**64 for part in value)
                and value[1] > 0
                for value in identities
            ),
            "Malformed process or file identity",
        )
    except SnapshotError as exc:
        return {"state": "unresolved", "reason": str(exc)}
    except (ValueError, RecursionError):
        return {"state": "unresolved", "reason": "Malformed saved process receipt"}
    return {"state": "request-bound-operator-receipt", **receipt}


def _matches_sts_caller(
    receipt: _Row, identity: _Row, event_id: str, region: str, account: str, session: str
) -> bool:
    return (
        receipt.get("eventSource") == "sts.amazonaws.com"
        and receipt.get("eventName") == "GetCallerIdentity"
        and receipt.get("eventCategory") == "Management"
        and receipt.get("readOnly") is True
        and receipt.get("awsRegion") == region
        and receipt.get("recipientAccountId") == account
        and "errorCode" not in receipt
        and "errorMessage" not in receipt
        and re.fullmatch(_EVENT_ID, event_id) is not None
        and identity.get("type") == "AssumedRole"
        and identity.get("arn") == session
        and identity.get("accountId") == account
    )


def _runtime_credential(
    receipt: _Row,
    s3_event: _Row,
    region: str,
    account: str,
    session: str,
    command_start: float,
) -> _Row:
    identity = _map(receipt.get("userIdentity"), "STS identity")
    s3_identity = _map(s3_event.get("userIdentity"), "S3 request identity")
    key_id = _text(s3_identity.get("accessKeyId"), "S3 temporary credential identifier")
    event_id = _text(receipt.get("eventID"), "STS event ID")
    _need(
        _matches_sts_caller(receipt, identity, event_id, region, account, session)
        and re.fullmatch(r"ASIA[A-Z0-9]{16}", key_id)
        and identity.get("credential_id_sha256")
        == hashlib.sha256(key_id.encode("ascii")).hexdigest(),
        "Saved STS event does not identify the S3 request's temporary credential",
    )
    observed = _time(receipt.get("eventTime"))
    _need(
        observed + 1 > command_start and observed <= _time(s3_event.get("eventTime")),
        "Saved STS call falls outside the command-to-S3 interval",
    )
    return {"source": "cloudtrail-sts-get-caller-identity", "event_id": event_id}


def _workspace_identity(
    receipt: _Row,
    region: str,
    account: str,
    role: str,
    session: str,
    command_window: tuple[float, float],
) -> _Row:
    identity = _map(receipt.get("userIdentity"), "STS identity")
    issuer = _map(
        _map(identity.get("sessionContext"), "STS session context").get("sessionIssuer"),
        "STS session issuer",
    )
    event_id = _text(receipt.get("eventID"), "STS event ID")
    _need(
        _matches_sts_caller(receipt, identity, event_id, region, account, session)
        and issuer.get("type") == "Role"
        and issuer.get("arn") == role
        and issuer.get("accountId") == account,
        "Saved STS status does not identify the owning command's session and role",
    )
    stamp = _text(receipt.get("eventTime"), "STS event time")
    observed = _time(stamp)
    start, end = command_window
    _need(
        observed + 1 > start and observed <= end,
        "Saved STS workspace identity falls outside the owning command",
    )
    return {
        "source": "cloudtrail-sts-get-caller-identity",
        "event_id": event_id,
        "observed_at": stamp,
        "session": session,
        "service_role": role,
        "s3_request_identity": "unverified",
    }


def _denial_reason(
    audit_message: object, runner_message: str, session: str, object_arn: str
) -> str | None:
    subject = _S3_DENIAL_SUBJECT.match(audit_message) if isinstance(audit_message, str) else None
    if subject is None:
        return None
    _need(
        subject.groups() == (session, "s3:PutObject", object_arn),
        "S3 enhanced denial message conflicts with the bound request",
    )
    if audit_message == runner_message == subject[0] + _RESOURCE_DENY:
        return "explicit-resource-policy-deny"
    return None


def _bound_launch(receipt: _Row, build: _Row, region: str, account: str) -> _Row:
    identity = _map(receipt.get("userIdentity"), "CodeBuild launch identity")
    request = _map(receipt.get("requestParameters"), "CodeBuild launch request")
    response = _map(
        _map(receipt.get("responseElements"), "CodeBuild launch response").get("build"),
        "started CodeBuild build",
    )
    user = _text(build.get("initiator"), "CodeBuild initiator")
    actor = _text(identity.get("arn"), "CodeBuild launch principal")
    event = _text(receipt.get("eventID"), "CodeBuild launch event ID")
    request_id = _text(receipt.get("requestID"), "CodeBuild launch request ID")
    _need(
        receipt.get("eventSource") == "codebuild.amazonaws.com"
        and receipt.get("eventName") == "StartBuild"
        and receipt.get("eventCategory") == "Management"
        and receipt.get("readOnly") is False
        and receipt.get("awsRegion") == region
        and receipt.get("recipientAccountId") == identity.get("accountId") == account
        and "errorCode" not in receipt
        and "errorMessage" not in receipt
        and identity.get("type") == "IAMUser"
        and re.fullmatch(_ROLE, user)
        and actor == f"arn:aws:iam::{account}:user/{user}"
        and re.fullmatch(_EVENT_ID, event)
        and re.fullmatch(_EVENT_ID, request_id)
        and request.get("projectName") == build["projectName"]
        and response.get("id") == build["id"]
        and response.get("arn") == build["arn"]
        # StartBuild omits sourceVersion when it uses the configured project selector.
        and response.get("sourceVersion") == build["sourceVersion"]
        and ("sourceVersion" not in request or request["sourceVersion"] == build["sourceVersion"]),
        "Saved StartBuild event does not match the build, selected source or initiating principal",
    )
    launched = _time(receipt.get("eventTime"))
    _need(
        0 <= _time(build["startTime"]) - launched < 1,
        "Saved StartBuild time does not overlap the build start",
    )
    return {"operation": "codebuild:StartBuild", "actor": actor, "event_id": event}


def _operator_launch(receipt: _Row, build: _Row, region: str, account: str) -> _Row:
    launch = _bound_launch(receipt, build, region, account)
    source = build["source"]
    supplied = receipt["requestParameters"].get("buildspecOverride")
    if supplied == source["buildspec"]:
        return launch

    # In the observed native event, CloudTrail hides the inline bytes in both
    # request and response. BatchGetBuilds and the owning command trace still
    # have to match the digest-pinned plan. Do not accept a missing override,
    # a conflicting visible override, or a different effective source or role.
    started = receipt["responseElements"]["build"]
    _need(
        supplied == _CLOUDTRAIL_REDACTION
        and started.get("source") == {**source, "buildspec": _CLOUDTRAIL_REDACTION}
        and started.get("serviceRole") == build["serviceRole"]
        and started.get("initiator") == build["initiator"],
        "Operator launch does not bind the reviewed plan or its native CloudTrail redaction",
    )
    return {**launch, "buildspec_override_state": "cloudtrail-redacted"}


def _bound_s3_input(
    evidence: _Row, source: _Row, version: str, member: str, git_bytes: bytes
) -> _Row:
    bucket = _text(evidence.get("bucket"), "input bucket")
    key = _text(evidence.get("key"), "input ZIP key")
    receipt = _map(evidence.get("receipt"), "input ZIP receipt")
    encoded = _text(evidence.get("archive_base64"), "input ZIP bytes")
    _need(
        re.fullmatch(_BUCKET, bucket)
        and len(key) <= 512
        and re.fullmatch(rf"{_PATH}\.zip", key)
        and source.get("location") == f"{bucket}/{key}"
        and source.get("insecureSsl") is False
        and re.fullmatch(_VERSION, version)
        and version != "null"
        and receipt.get("VersionId") == version
        and receipt.get("ChecksumType") == "FULL_OBJECT"
        and len(encoded) <= 4096,
        "CodeBuild source does not match the bounded versioned S3 input receipt",
    )
    payload = base64.b64decode(encoded, validate=True)
    digest = hashlib.sha256(payload)
    _need(
        receipt.get("ChecksumSHA256") == base64.b64encode(digest.digest()).decode("ascii"),
        "The input ZIP differs from its saved S3 checksum",
    )
    try:
        with ZipFile(BytesIO(payload)) as archive:
            members = archive.infolist()
            _need(len(members) == 1, "The input ZIP must contain exactly one data file")
            entry = members[0]
            _need(
                entry.filename == entry.orig_filename == member
                and entry.compress_type == ZIP_STORED
                and entry.flag_bits == 0
                and stat.S_IFMT(entry.external_attr >> 16) in (0, stat.S_IFREG)
                and entry.file_size == entry.compress_size == len(git_bytes)
                and archive.read(entry) == git_bytes,
                "The input ZIP member does not match the pinned Git file",
            )
    except BadZipFile as exc:
        raise SnapshotError("Malformed input ZIP") from exc
    return {
        "object_arn": f"arn:aws:s3:::{bucket}/{key}",
        "version": version,
        "sha256": digest.hexdigest(),
    }


def _pinned_github_source(
    build: _Row, source: _Row, selector: str, identity: str, pr_record: object
) -> tuple[str, _Row | None]:
    head = _text(build.get("resolvedSourceVersion"), "resolved GitHub revision")
    _need(
        _sha(head)
        and len(selector) <= 500
        and source.get("type") == "GITHUB"
        and source.get("gitSubmodulesConfig") in (None, {"fetchSubmodules": False})
        and source.get("insecureSsl") is False
        and _github_identity(source.get("location")) == identity,
        "Saved source lacks the exact selected GitHub repository and commit",
    )
    if re.fullmatch(rf"{_REF}\^{{{head}}}", selector):
        return head, None

    ref = re.fullmatch(rf"{_PR_HEAD_REF}\^{{{head}}}", selector)
    if ref is None:
        raise SnapshotError("Saved source lacks a pinned GitHub branch or PR head")
    pr = _map(pr_record, "GitHub pull request evidence")
    number = pr.get("number")
    repository = _github_identity(
        f"https://github.com/{_text(pr.get('repository'), 'PR base repository')}"
    )
    fork = _github_identity(f"https://github.com/{_text(pr.get('fork'), 'PR head repository')}")
    _need(
        type(number) is int
        and number == int(ref[1])
        and repository == identity
        and fork.split("/", 1)[0] != identity.split("/", 1)[0]
        and pr.get("head") == head
        and _sha(pr.get("base"))
        and pr["base"] != head,
        "GitHub PR evidence does not match the pinned external fork head",
    )
    return head, {"number": number, "head_repository": fork, "base": pr["base"]}


def direct_s3_put(capture: _Row, root: Path, build_arn: str, origin: str) -> _Row:
    build = _map(capture.get("build"), "CodeBuild response")
    match = _ARN.fullmatch(build_arn)
    if match is None or build.get("arn") != build_arn:
        raise SnapshotError("CodeBuild ARN differs from the selected run")
    region, account, build_id = match.groups()
    status = _text(build.get("buildStatus"), "CodeBuild status")
    _need(
        build.get("id") == build_id
        and build.get("projectName") == build_id.split(":")[0]
        and account != "000000000000"
        and build.get("buildComplete") is True
        and status in ("SUCCEEDED", "FAILED")
        and build.get("secondarySources") == []
        and build.get("secondaryArtifacts") in (None, [])
        and build.get("artifacts") in (None, {}, {"location": ""})
        and build.get("cache") == {"type": "NO_CACHE"},
        "Unsupported completed direct-request CodeBuild profile",
    )
    allowed = status == "SUCCEEDED"
    lower, upper = _phase(build, "BUILD", status)
    download = _phase(build, "DOWNLOAD_SOURCE")
    _need(
        download[1] <= lower,
        "CodeBuild source phase must precede the request",
    )
    identity = _github_identity(origin)
    source = _map(build.get("source"), "CodeBuild source")
    selector = _text(build.get("sourceVersion"), "CodeBuild source selector")
    s3_input = None
    fork_pr = None
    if source.get("type") == "S3":
        s3_input = _map(capture.get("s3_input"), "versioned input ZIP evidence")
        head = _text(s3_input.get("operator_selected_head"), "operator-selected Git revision")
        _need(
            _sha(head)
            and build.get("resolvedSourceVersion") is None
            and not build.get("secondarySourceVersions"),
            "Git materialization does not match the supported primary S3 input profile",
        )
    else:
        _need(
            "s3_input" not in capture, "The native GitHub source conflicts with supplied S3 input"
        )
        head, fork_pr = _pinned_github_source(build, source, selector, identity, capture.get("pr"))
    _require_git_revision(root, identity, head, "Pinned GitHub source")
    inline = _text(source.get("buildspec"), "inline buildspec")
    operator_plan = (
        fork_pr is not None
        and len(inline) <= 8192
        and hashlib.sha256(inline.encode("utf-8")).hexdigest() == _OPERATOR_PLAN_SHA256
    )
    launch = None
    if operator_plan:
        launch_event = _map(capture.get("launch_event"), "CodeBuild operator launch event")
        launch = _operator_launch(launch_event, build, region, account)
        file, key = "hello.txt", "controlled/hello.txt"
    else:
        _need(len(inline) <= 4096, "A bounded trusted inline buildspec is required")
        plan = (_S3_PLAN_RE if s3_input is not None else _PLAN_RE).fullmatch(inline.rstrip("\n"))
        if plan is None:
            raise SnapshotError(
                "The inline buildspec is outside the supported direct PutObject command profile"
            )
        file, key = plan.group("file", "key")
    _need(
        len(file) <= 200 and len(key) <= 512,
        "The file or key exceeds the supported direct request profile",
    )
    data, witness = _blob(root, head, file)
    content = data.encode("utf-8")
    _need(len(content) <= 128, "The pinned file exceeds the supported marker size")
    if fork_pr is not None:
        _require_git_revision(root, identity, fork_pr["base"], "PR base")
        _need(
            _regular_blob(root, fork_pr["base"], file) != witness["git_blob"],
            "The selected file has the same Git blob at the PR base and at the fork head",
        )
    digest = base64.b64encode(bytes.fromhex(witness["sha256"])).decode("ascii")
    input_object = (
        _bound_s3_input(s3_input, source, selector, file, content) if s3_input is not None else None
    )
    runtime_source = selector if input_object is not None else head
    version_variable = (
        "EXPERIMENT_SOURCE_VERSION" if input_object is not None else "EXPERIMENT_SOURCE_SHA"
    )

    env = _map(build.get("environment"), "CodeBuild execution environment")
    variables = _rows(env.get("environmentVariables"), "CodeBuild environment variables", 3)
    _need(
        env.get("type") == "LINUX_CONTAINER"
        and env.get("privilegedMode") is False
        and env.get("image") == "aws/codebuild/standard:7.0"
        and env.get("imagePullCredentialsType") == "CODEBUILD"
        and len(variables) == 3,
        "The build environment differs from the supported command profile",
    )
    values = {row["name"]: row["value"] for row in variables if row["type"] == "PLAINTEXT"}
    bucket = _text(values.get("EXPERIMENT_BUCKET"), "S3 bucket binding")
    _need(
        re.fullmatch(_BUCKET, bucket)
        and values.get(version_variable) == runtime_source
        and values.get("EXPERIMENT_MARKER_SHA256") == witness["sha256"],
        "The environment does not bind the exact source, digest and S3 bucket",
    )
    role = _text(build.get("serviceRole"), "CodeBuild service role")
    role_match = re.fullmatch(rf"arn:aws:iam::{account}:role/({_ROLE})", role)
    if role_match is None:
        raise SnapshotError("The CodeBuild role does not belong to the selected account")
    role_name = re.escape(role_match[1])
    rows = _owned_log_rows(capture, build, region, account)
    trace, command_start, completion = _trace(rows, inline, lower, upper, status)
    workspace, reported_shell = _source_launch_context(
        rows, download, command_start, identity if input_object is None else None
    )
    if operator_plan:
        _need(
            workspace is not None and reported_shell == "bash",
            "Operator plan requires the owning source workspace and Bash selection records",
        )
    process_header = _OPERATOR_HEADER if operator_plan else ""
    identity_and_request = re.compile(
        rf"^source={re.escape(runtime_source)}\nbuild={re.escape(build_arn)}\n{process_header}[ \t]*"
        rf'{{\n[ \t]*"Account": "{account}",\n[ \t]*"Arn": "(?P<session>arn:aws:sts::{account}:assumed-role/{role_name}/'
        rf'{_ROLE})"\n}}\noperation=PutObject\nkey={re.escape(key)}\nsha256_base64={re.escape(digest)}\n',
        re.M,
    )
    matches = list(identity_and_request.finditer(trace))
    _need(
        len(matches) == 1,
        "Owning log does not link the selected source, role, checksum and operation",
    )
    request_trace = matches[0]
    if operator_plan:
        # This is the path reported by the remote Linux process. Parse it
        # lexically and require the canonical single private scratch directory.
        scratch = PurePosixPath(request_trace["directory"])
        _need(
            scratch.parts == ("/", "tmp", scratch.name)
            and scratch.as_posix() == request_trace["directory"]
            and _OPERATOR_SCRATCH_NAME.fullmatch(scratch.name),
            "Operator preparation reports an unsupported scratch directory",
        )
    session = request_trace["session"]
    outcome = trace[request_trace.end() :]
    object_arn = f"arn:aws:s3:::{bucket}/{key}"
    publication: _Row = {
        "authorization": "allowed-observed" if allowed else "denied-observed",
        "audit": "unavailable",
    }
    request_id = None
    transport: _Row = {}
    event = capture.get("s3_event")
    if event is not None:
        event = _map(event, "S3 data event")
        request_id, transport = _audit(
            event,
            region,
            account,
            role,
            session,
            bucket,
            key,
            command_start,
            completion,
            None if allowed else "AccessDenied",
        )
    if allowed:
        response = re.match(
            rf'\s*{{\n[ \t]*"VersionId": "({_VERSION})",\n[ \t]*"ChecksumSHA256": "{re.escape(digest)}"\n}}\n',
            outcome,
        )
        if response is None or response[1] == "null":
            raise SnapshotError("Owning PutObject response lacks the version or expected checksum")
        response_end = response.end()
        version = response[1]
        if event is not None:
            response_elements = event.get("responseElements")
            fields = (
                {} if response_elements is None else _map(response_elements, "S3 response fields")
            )
            audited_version = fields.get("x-amz-version-id")
            if audited_version is None:
                publication["audit"] = "unresolved-version-binding"
                request_id = None
            else:
                _need(audited_version == version, "S3 audit identifies a different object version")
        retrieval = _map(capture.get("retrieval"), "version-pinned S3 download")
        fields = _map(retrieval.get("response"), "GetObject response")
        _need(
            retrieval.get("bucket") == bucket
            and retrieval.get("key") == key
            and fields.get("VersionId") == version
            and fields.get("ChecksumSHA256") == digest
            and fields.get("ChecksumType") == "FULL_OBJECT"
            and fields.get("ContentLength") == len(content)
            and retrieval.get("bytes_base64") == base64.b64encode(content).decode("ascii"),
            "Version-pinned S3 result does not match the observed response and Git source bytes",
        )
        modified = _time(fields.get("LastModified"))
        # The native S3 receipt can report the next whole second after runner completion.
        _need(
            lower <= modified <= completion + 1 and modified + 1 > command_start,
            "Version-pinned S3 result falls outside the owning command",
        )
        publication["version"] = version
    else:
        if event is None:
            raise SnapshotError("A matching S3 data event is required to establish denial")
        prefix = (
            "aws: [ERROR]: An error occurred (AccessDenied) when calling the PutObject operation"
        )
        subject = f'User: {session} is not authorized to perform: s3:PutObject on resource: "{object_arn}"'
        runner_line = outcome.lstrip().partition("\n")[0]
        # The reviewed collector sets AWS_MAX_ATTEMPTS=1. On a native denial
        # the AWS CLI can include this exact detail in its rendered error.
        no_retries = " (reached max retries: 0)"
        if operator_plan and runner_line.startswith(prefix + no_retries):
            prefix += no_retries
        prefix += ": "
        response_end = len(outcome) - len(outcome.lstrip()) + len(runner_line) + 1
        _need(
            runner_line.startswith(prefix + subject),
            "Owning PutObject response lacks the exact AccessDenied identity and target",
        )
        denial_reason = _denial_reason(
            event.get("errorMessage"), runner_line.removeprefix(prefix), session, object_arn
        )
        if denial_reason is not None:
            publication["denial_reason"] = denial_reason

    if request_id is not None:
        publication["request_id"] = request_id
        publication["audit"] = "bound-s3-data-event"
        if transport:
            publication["transport"] = transport
    if operator_plan:
        publication["runtime_process"] = _runtime_process(
            trace,
            request_trace.end() + response_end,
            request_trace,
            request_id,
            200 if allowed else 403,
        )

    runtime_event = capture.get("runtime_sts_event")
    if runtime_event is not None:
        if event is None or request_id is None:
            publication["runtime_credential"] = {
                "state": "unresolved",
                "reason": "An STS credential join requires an independently matched S3 event",
            }
        else:
            try:
                publication["runtime_credential"] = _runtime_credential(
                    _map(runtime_event, "STS management event"),
                    event,
                    region,
                    account,
                    session,
                    command_start,
                )
            except SnapshotError as exc:
                publication["runtime_credential"] = {"state": "unresolved", "reason": str(exc)}
            except (TypeError, ValueError, OverflowError):
                publication["runtime_credential"] = {
                    "state": "unresolved",
                    "reason": "Malformed saved STS credential evidence",
                }

    source_plan: _Row = {
        "kind": "operator-inline-process-receipt" if operator_plan else "provider-inline",
        "line": inline[: inline.index(" s3api put-object")].count("\n") + 1,
    }
    if workspace is not None:
        source_plan["workspace"] = workspace
    if reported_shell is not None:
        source_plan["reported_shell"] = reported_shell
    result = {
        "state": "direct-s3-write-observed" if allowed else "direct-s3-write-denied",
        "build": build_id,
        "build_arn": build_arn,
        "repository": identity,
        "head": head,
        "source_ref": selector,
        "source_scope": "pinned-branch",
        "source_plan": source_plan,
        "influence": witness,
        "publication": {
            "operation": "s3:PutObject",
            "object_arn": object_arn,
            "service_role": role,
            "acting_session": session if request_id is not None else "unverified",
            **publication,
        },
        "scope": SCOPE,
    }
    if request_id is None:
        result["reported_sts_session"] = session
    if fork_pr is not None:
        result.update(
            source_scope="matches-supplied-fork-pr-head",
            pull_request=fork_pr["number"],
            head_repository=fork_pr["head_repository"],
            pr_base=fork_pr["base"],
        )
    if input_object is not None:
        del result["head"]
        del result["source_ref"]
        result.update(
            source_scope="operator-materialized-s3-version",
            input_object=input_object,
            scope=SCOPE
            + " The S3 input file matches the supplied Git revision. AWS selected the ZIP version.",
        )
    if launch is not None:
        result["launch"] = launch
    elif "launch_event" in capture:
        result["launch"] = _bound_launch(
            _map(capture["launch_event"], "CodeBuild launch event"), build, region, account
        )
    if "workspace_identity_event" in capture:
        result["workspace_identity"] = _workspace_identity(
            _map(capture["workspace_identity_event"], "STS workspace event"),
            region,
            account,
            role,
            session,
            (command_start, completion),
        )
    return result


def compare_policy_change(capture: _Row, denied: _Row, root: Path, origin: str) -> _Row:
    """Check one opt-in comparison without replacing the direct observation."""
    try:
        return _compare_policy_change(capture, denied, root, origin)
    except SnapshotError as exc:
        return {"state": "unresolved", "reason": str(exc)}
    except (AttributeError, IndexError, KeyError, TypeError, ValueError, OverflowError):
        return {"state": "unresolved", "reason": "Malformed saved S3 policy comparison evidence"}


def _compare_policy_change(capture: _Row, denied: _Row, root: Path, origin: str) -> _Row:
    comparison = _map(capture.get("policy_comparison"), "S3 policy comparison")
    earlier = _map(comparison.get("earlier"), "earlier direct S3 receipt")
    original = _map(earlier.get("build"), "earlier CodeBuild response")
    current = capture["build"]
    previous_arn = _text(original.get("arn"), "earlier CodeBuild ARN")
    _need(
        earlier.get("schema") == capture["schema"]
        and "policy_comparison" not in earlier
        and previous_arn != denied["build_arn"]
        and previous_arn.rsplit(":", 1)[0] == denied["build_arn"].rsplit(":", 1)[0],
        "Comparison requires a distinct earlier direct S3 receipt from the same CodeBuild project",
    )
    destination = denied["publication"]
    _need(
        denied["state"] == "direct-s3-write-denied"
        and destination.get("denial_reason") == "explicit-resource-policy-deny",
        "The selected request lacks a corroborated explicit resource-policy denial",
    )
    allowed = direct_s3_put(earlier, root, previous_arn, origin)
    prior = allowed["publication"]
    for observation in (destination, prior):
        credential = observation.get("runtime_credential", {})
        if credential.get("state") == "unresolved":
            raise SnapshotError(credential["reason"])
    _need(
        allowed["state"] == "direct-s3-write-observed"
        and prior.get("request_id") != destination["request_id"]
        and prior["object_arn"] == destination["object_arn"]
        and allowed["influence"] == denied["influence"]
        and allowed.get("input_object") == denied.get("input_object")
        and all(
            allowed.get(field) == denied.get(field)
            for field in ("source_scope", "pull_request", "head_repository", "pr_base")
        )
        and all(original.get(field) == current.get(field) for field in _COMPARED_BUILD_FIELDS),
        "The earlier write does not match the denied request's build configuration, source or target",
    )
    event = _map(comparison.get("policy_event"), "CloudTrail PutBucketPolicy event")
    parameters = _map(event.get("requestParameters"), "PutBucketPolicy request parameters")
    event_id = _text(event.get("eventID"), "policy event ID")
    request_id = _text(event.get("requestID"), "policy request ID")
    event_time = _text(event.get("eventTime"), "policy event time")
    _, _, _, region, account, _ = denied["build_arn"].split(":", 5)
    object_arn = destination["object_arn"]
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Deny",
                "Principal": "*",
                "Action": destination["operation"],
                "Resource": object_arn,
                "Condition": {"ArnEquals": {"aws:PrincipalArn": destination["service_role"]}},
            }
        ],
    }
    _need(
        event.get("eventSource") == "s3.amazonaws.com"
        and event.get("eventName") == "PutBucketPolicy"
        and event.get("eventCategory") == "Management"
        and event.get("managementEvent") is True
        and event.get("readOnly") is False
        and event.get("awsRegion") == region
        and event.get("recipientAccountId") == account
        and "errorCode" not in event
        and "errorMessage" not in event
        and re.fullmatch(_EVENT_ID, event_id)
        and re.fullmatch(r"[A-Za-z0-9-]{1,128}", request_id)
        and parameters.get("bucketName")
        == object_arn.removeprefix("arn:aws:s3:::").partition("/")[0]
        and parameters.get("bucketPolicy") == policy,
        "Saved PutBucketPolicy must record the exact bucket, S3 action, object and role denial",
    )
    _need(
        re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", event_time),
        "The saved policy event requires a whole-second UTC timestamp",
    )
    installed = _time(event_time)
    _need(
        _time(original["endTime"]) < installed and installed + 1 <= _time(current["startTime"]),
        "The recorded policy change does not fall entirely between the saved builds",
    )
    actor_verified = prior["audit"] == "bound-s3-data-event"
    return {
        "state": "matched-policy-change" if actor_verified else "earlier-writer-unverified",
        "policy_event": {"event_id": event_id, "request_id": request_id, "time": event_time},
        "earlier_build_arn": allowed["build_arn"],
        "earlier_object_version": prior["version"],
        "earlier_request_id": prior.get("request_id"),
        "earlier_acting_session": prior["acting_session"],
        "scope": _POLICY_SCOPE,
    }
