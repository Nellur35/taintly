"""Check the ownership and meaning of an optional artifact upload record."""

from copy import deepcopy

import pytest

from taintly.ingestion.github_preview import _artifact_upload_authority

_REFS = (
    (
        "actions/upload-artifact@v7",
        "cf430e030ddbb5b0abf93d22962f4752f3646cd9",
    ),
    (
        "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
        "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
    ),
)


@pytest.fixture
def upload():
    step = {
        "number": 7,
        "started_at": "2026-01-01T00:00:02Z",
        "completed_at": "2026-01-01T00:00:03Z",
    }
    job = {"run_id": 91, "run_attempt": 2, "id": 92}
    artifact = {"id": 93, "digest": "sha256:" + "a" * 64, "created_at": "2026-01-01T00:00:03Z"}
    saved = {
        "run": 91,
        "attempt": 2,
        "job": 92,
        "step": 7,
        "artifact_id": 93,
        "sha256": artifact["digest"],
        "action": _REFS[0][0],
        "action_revision": _REFS[0][1],
        "runner_version": "2.338.2",
        "repository_token_permissions": {"Contents": "read", "Actions": "read"},
        "permissions_line": 2,
        "action_line": 5,
        "digest_line": 20,
        "finalize_line": 22,
        "digest_at": "2026-01-01T00:00:02.800Z",
        "finalized_at": "2026-01-01T00:00:03.100Z",
        "log_sha256": "b" * 64,
    }
    return saved, job, step, artifact


@pytest.mark.parametrize(("ref", "pin"), _REFS)
def test_upload_credential_is_independent_from_repository_token(upload, ref, pin):
    saved, job, step, artifact = upload
    saved.update(action=ref, action_revision=pin)
    result = _artifact_upload_authority(saved, job, step, artifact, ref)
    assert result["state"] == "run-artifact-write-observed"
    assert result["credential"] == "ACTIONS_RUNTIME_TOKEN"
    assert result["repository_token"] == "read-only-reported"
    assert (result["job"], result["artifact_id"]) == (job["id"], artifact["id"])


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    [
        ("attempt", 3, "another job"),
        ("job", 101, "another job"),
        ("step", 8, "another job"),
        ("artifact_id", 120, "completion or checksum"),
        ("sha256", "sha256:" + "e" * 64, "completion or checksum"),
        ("log_sha256", "invalid", "completion or checksum"),
        ("runner_version", "2.0.0", "outside the reviewed profile"),
        ("action_revision", "1" * 40, "outside the reviewed profile"),
        ("repository_token_permissions", {"Contents": "read", "Actions": "write"}, "read-only"),
        ("repository_token_permissions", {}, "read-only"),
        ("finalize_line", 6, "completion or checksum"),
        ("finalized_at", "2026-01-01T00:00:04Z", "completion or checksum"),
        ("digest_at", "2026-01-01T00:00:00Z", "completion or checksum"),
    ],
)
def test_wrong_or_incomplete_authority_cannot_claim_an_upload_credential(
    upload, field, value, reason
):
    saved, job, step, artifact = upload
    bad = deepcopy(saved)
    bad[field] = value
    result = _artifact_upload_authority(bad, job, step, artifact, saved["action"])
    assert result["state"] == "unresolved"
    assert reason in result["reason"]
    assert "credential" not in result
