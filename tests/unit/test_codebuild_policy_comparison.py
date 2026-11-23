"""Verify that saved policy evidence binds the two independently assessed requests."""

import json
import sys

import pytest

from taintly import __main__ as cli
from taintly.ingestion import codebuild_put, codebuild_s3


@pytest.fixture
def pair(tmp_path, monkeypatch):
    account = "012345678901"
    role = f"arn:aws:iam::{account}:role/build-role"
    project = f"arn:aws:codebuild:us-east-1:{account}:build/example"
    prior_arn = f"{project}:01234567-0123-0123-0123-0123456789ab"
    later_arn = f"{project}:01234567-0123-0123-0123-0123456789ac"
    target = "arn:aws:s3:::example-bucket/marker.txt"
    role_session = f"arn:aws:sts::{account}:assumed-role/build-role/earlier-session"
    source = {"path": "marker.txt"}
    earlier = {
        "state": "direct-s3-write-observed",
        "build_arn": prior_arn,
        "influence": source,
        "source_scope": "pinned-branch",
        "publication": {
            "object_arn": target,
            "audit": "bound-s3-data-event",
            "request_id": "earlier-request",
            "version": "earlier-version",
            "acting_session": role_session,
        },
    }
    denied = {
        "state": "direct-s3-write-denied",
        "build_arn": later_arn,
        "influence": source,
        "source_scope": "pinned-branch",
        "publication": {
            "object_arn": target,
            "operation": "s3:PutObject",
            "request_id": "denied-request",
            "service_role": role,
            "denial_reason": "explicit-resource-policy-deny",
        },
    }
    settings = {"serviceRole": role, "sourceVersion": "same-source"}
    schema = "codebuild-direct-s3-put-v1"
    event = {
        "eventID": "01234567-0123-0123-0123-0123456789ab",
        "requestID": "policy-request",
        "eventTime": "2026-01-01T00:00:02Z",
        "eventName": "PutBucketPolicy",
        "eventSource": "s3.amazonaws.com",
        "eventCategory": "Management",
        "managementEvent": True,
        "readOnly": False,
        "awsRegion": "us-east-1",
        "recipientAccountId": account,
        "requestParameters": {
            "bucketName": "example-bucket",
            "bucketPolicy": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Deny",
                        "Principal": "*",
                        "Action": "s3:PutObject",
                        "Resource": target,
                        "Condition": {"ArnEquals": {"aws:PrincipalArn": role}},
                    }
                ],
            },
        },
    }
    nested = {
        "schema": schema,
        "build": dict(settings, arn=prior_arn, endTime="2026-01-01T00:00:01.999Z"),
    }
    capture = {
        "schema": schema,
        "build": dict(settings, arn=later_arn, startTime="2026-01-01T00:00:03Z"),
        "policy_comparison": {"earlier": nested, "policy_event": event},
    }

    def direct(receipt, root, build_arn, origin):
        assert root == tmp_path.resolve()
        assert receipt["build"]["arn"] == build_arn
        assert origin == "https://github.com/example/project"
        if build_arn == later_arn:
            return denied.copy()
        assert build_arn == prior_arn
        return earlier

    monkeypatch.setattr(codebuild_put, "direct_s3_put", direct)
    return capture, earlier, denied


@pytest.mark.parametrize(
    ("defect", "state", "reason"),
    [
        (None, "matched-policy-change", None),
        ("no-earlier-audit", "earlier-writer-unverified", None),
        ("wrong-target", "unresolved", "exact bucket, S3 action, object and role denial"),
        ("wrong-bucket", "unresolved", "exact bucket, S3 action, object and role denial"),
        ("wrong-role", "unresolved", "exact bucket, S3 action, object and role denial"),
        ("wrong-account", "unresolved", "exact bucket, S3 action, object and role denial"),
        ("failed-policy", "unresolved", "exact bucket, S3 action, object and role denial"),
        ("same-build", "unresolved", "distinct earlier"),
        ("wrong-region", "unresolved", "same CodeBuild project"),
        ("earlier-sts", "unresolved", "temporary credential belongs to another call"),
        ("denied-sts", "unresolved", "temporary credential belongs to another call"),
        ("different-source", "unresolved", "build configuration, source or target"),
        ("other-revision", "unresolved", "build configuration, source or target"),
        ("same-request", "unresolved", "build configuration, source or target"),
        ("not-explicit", "unresolved", "explicit resource-policy denial"),
        ("at-earlier-end", "unresolved", "entirely between the saved builds"),
        ("unproven-order", "unresolved", "entirely between the saved builds"),
        ("missing-event", "unresolved", "CloudTrail PutBucketPolicy"),
    ],
)
def test_comparison_preserves_request_and_checks_exact_link(pair, tmp_path, defect, state, reason):
    capture, earlier, denied = pair
    comparison = capture["policy_comparison"]
    event = comparison["policy_event"]
    parameters = event["requestParameters"]
    statement = parameters["bucketPolicy"]["Statement"][0]
    earlier_build = comparison["earlier"]["build"]
    if defect == "no-earlier-audit":
        earlier["publication"].update(audit="unavailable", acting_session="unverified")
        earlier["publication"].pop("request_id")
    elif defect == "wrong-target":
        statement["Resource"] += "-other"
    elif defect == "wrong-bucket":
        parameters["bucketName"] = "other-bucket"
    elif defect == "wrong-role":
        statement["Condition"]["ArnEquals"]["aws:PrincipalArn"] += "-other"
    elif defect == "wrong-account":
        event["recipientAccountId"] = "123456789012"
    elif defect == "failed-policy":
        event["errorCode"] = "AccessDenied"
    elif defect == "same-build":
        earlier_build["arn"] = capture["build"]["arn"]
    elif defect == "wrong-region":
        earlier_build["arn"] = earlier_build["arn"].replace("us-east-1", "us-west-2")
    elif defect in ("earlier-sts", "denied-sts"):
        observation = earlier if defect == "earlier-sts" else denied
        observation["publication"]["runtime_credential"] = {
            "state": "unresolved",
            "reason": "temporary credential belongs to another call",
        }
    elif defect == "different-source":
        earlier_build["sourceVersion"] = "different-source"
    elif defect == "other-revision":
        earlier["influence"] = {"path": "marker.txt", "revision": "a" * 40}
    elif defect == "same-request":
        earlier["publication"]["request_id"] = denied["publication"]["request_id"]
    elif defect == "not-explicit":
        denied["publication"].pop("denial_reason")
    elif defect == "at-earlier-end":
        earlier_build["endTime"] = event["eventTime"]
    elif defect == "unproven-order":
        capture["build"]["startTime"] = "2026-01-01T00:00:02.900Z"
    elif defect == "missing-event":
        comparison.pop("policy_event")

    source = tmp_path / "capture.json"
    source.write_text(json.dumps(capture), encoding="utf-8")
    output = codebuild_s3.codebuild_s3_observation(
        source, tmp_path, capture["build"]["arn"], "https://github.com/example/project"
    )
    result = output.pop("policy_comparison")
    assert output == denied
    assert result["state"] == state
    if reason:
        assert reason in result["reason"]
        assert "policy_event" not in result
    else:
        assert result["policy_event"] == {
            "event_id": event["eventID"],
            "request_id": event["requestID"],
            "time": event["eventTime"],
        }
        assert result["earlier_acting_session"] == earlier["publication"]["acting_session"]
        assert result["earlier_request_id"] == earlier["publication"].get("request_id")


def test_unresolved_comparison_exits_incomplete_without_losing_denial(
    pair, tmp_path, monkeypatch, capsys
):
    capture, _, denied = pair
    capture["policy_comparison"].pop("policy_event")
    source = tmp_path / "capture.json"
    source.write_text(json.dumps(capture), encoding="utf-8")
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "taintly",
            str(tmp_path),
            "--no-config",
            "--format",
            "json",
            "--codebuild-public-s3-observation",
            str(source),
            capture["build"]["arn"],
            "https://github.com/example/project",
        ],
    )
    with pytest.raises(SystemExit) as exit_:
        cli.main()
    assert exit_.value.code == 11
    report = json.loads(capsys.readouterr().out)["codebuild_s3_observation"]
    assert report["policy_comparison"]["state"] == "unresolved"
    assert report["publication"] == denied["publication"]
