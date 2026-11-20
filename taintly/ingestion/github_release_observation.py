"""Corroborate a saved workflow_run artifact publication to GitHub Releases."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any

from taintly.ingestion.github_preview import (
    _DIGEST,
    _REPOSITORY,
    _SHA,
    PreviewEvidenceError,
    _artifact_upload_authority,
    _field,
    _id,
    _job_steps,
    _matches,
    _observation_capture,
    _observed_step,
    _require,
    _run,
    _run_identity,
    _source,
    _time,
)
from taintly.rules.github._workflow_run_artifact import (
    _Index,
    _is_exact_identifier_expression,
)

_SCHEMA = "github-workflow-run-release-v1"
_SIGNED_SCHEMA = "github-signed-release-v1"
_TAG_SCHEMA = "github-workflow-run-tag-push-v1"
_DISCOVER = "Retrieve information about the original workflow"
_DOWNLOAD = "Download artifact from the previous workflow."
_RELEASE = "Release (SHA-suffixed format)"
_PUSH_TAG = "Push tag"
_AFTER_TAG = "Delete existing releases if present"
_PUSH_GROUP = "##[group]Run git init --bare lean4.git"
_AFTER_TAG_GROUP = "##[group]Run # Delete any existing releases for this PR."
_PR_AVAILABLE = "${{ steps.workflow-info.outputs.pullRequestNumber != '' }}"
_TAG_PROGRAM = "1ca7b8dfa7e155a4c96c7a693f7062cd3b9db32cb86a3e3119f064faf01f9b40"
_TAG_SCOPE = (
    "This profile uses trusted saved workflow, job log and GitHub ref records. "
    "The credential account, broader grants, release or asset "
    "publication, downstream use and later tag changes are unverified."
)
_SCOPE = (
    "Trusted saved GitHub source and provider records. The recorded asset uploader is the "
    "observed release account. The credential value, wider grants, exact release bytes and "
    "effects on later installations remain unverified."
)
_Row = dict[str, Any]


def _publisher_index(root: Path, run: _Row, saved: _Row) -> tuple[_Index, _Row]:
    return _source(root, run, saved, run["head_sha"])


def _job_window(run: _Row, job: _Row) -> None:
    _require(
        _time(run["created_at"])
        <= _time(job["started_at"])
        <= _time(job["completed_at"])
        <= _time(run["updated_at"]),
        "Selected job timestamps are outside its owning run",
    )


def _handoff_source(
    index: _Index, origin: tuple[object, ...], download: tuple[object, ...]
) -> None:
    _require(
        len(index.keys.get(("on", "workflow_run"), ())) == 1
        and _field(index, (*origin, "id")).value == "workflow-info",
        "The source does not declare one owning workflow_run and origin reader",
    )
    _require(
        _matches(_field(index, (*origin, "uses")).value, r"potiuk/get-workflow-origin@[a-f0-9]{40}")
        and _is_exact_identifier_expression(
            str(_field(index, (*origin, "with", "sourceRunId")).value),
            "github.event.workflow_run.id",
        )
        and _matches(
            _field(index, (*download, "uses")).value,
            r"dawidd6/action-download-artifact@[a-f0-9]{40}",
        )
        and _is_exact_identifier_expression(
            str(_field(index, (*download, "with", "run_id")).value), "github.event.workflow_run.id"
        )
        and _field(index, (*download, "with", "path")).value == "artifacts"
        and _field(index, (*download, "with", "name")).value == "build-.*"
        and _field(index, (*download, "with", "name_is_regexp")).value == "true",
        "The source does not bind origin and artifact selection to the same producing run",
    )
    for step, fields in (
        (origin, {"name", "uses", "id", "with"}),
        (download, {"name", "if", "id", "uses", "with"}),
    ):
        _require(
            {key[-1] for key in index.keys if key[:-1] == step} == fields,
            "The selected step has unsupported execution fields or overrides",
        )
    for step, expected in (
        (origin, {"token", "sourceRunId"}),
        (download, {"run_id", "path", "name", "name_is_regexp"}),
    ):
        _require(
            {k[-1] for k in index.keys if k[:-1] == (*step, "with")} == expected
            and len(index.keys.get((*step, "with"), ())) == 1,
            "The owned action carries an unsupported input or duplicate input mapping",
        )


def _release_plan(index: _Index, consumer: _Row, destination: str) -> dict[str, object]:
    (origin, _), (download, _), (publish, published) = _job_steps(
        index, consumer["job"], [_DISCOVER, _DOWNLOAD, _RELEASE]
    )
    _handoff_source(index, origin, download)
    _require(
        {key[-1] for key in index.keys if key[:-1] == publish} == {"name", "if", "run", "env"},
        "The selected step has unsupported execution fields or overrides",
    )
    _require(
        len(index.keys.get((*publish, "env"), ())) == 1
        and {key[-1] for key in index.keys if key[:-1] == (*publish, "env")} == {"GH_TOKEN"},
        "The publishing step does not have a single explicit GH_TOKEN binding",
    )
    credential = _field(index, (*publish, "env", "GH_TOKEN"))
    token = str(credential.value)
    binding = re.fullmatch(r"\$\{\{[ \t]*secrets\.([A-Za-z_][A-Za-z0-9_]{0,127})[ \t]*\}\}", token)
    if binding is None:
        raise PreviewEvidenceError(
            "The publication credential is outside the literal secret profile"
        )
    program = _field(index, (*publish, "run"), literal_block=True)
    clean = [row.lstrip(" \t") for row in str(program.value).strip("\n").split("\n")]
    target_name = destination.split("/")[1]
    _require(
        program.value_kind == "block_literal"
        and clean
        == [
            "gh release create \\",
            "--repo ${{ github.repository_owner }}/" + target_name + " \\",
            '--title "Release for PR ${{ steps.workflow-info.outputs.pullRequestNumber }} (${{ steps.workflow-info.outputs.sourceHeadSha }})" \\',
            '--notes "" \\',
            "pr-release-${{ steps.workflow-info.outputs.pullRequestNumber }}-${{ env.SHORT_SHA }} \\",
            "artifacts/*/*",
        ],
        "The source release command is outside the supported PR tag and staged artifact shape",
    )
    return {
        "line": program.line,
        "credential_binding": "secrets." + binding[1],
        "credential_line": credential.line,
        "step": published["number"],
    }


def _producer(cap: _Row, repository: str, run_id: int) -> tuple[_Row, _Row, _Row]:
    row, pr = cap["producer"], cap["pr"]
    job, trace, artifact = row["job"], row["trace"], row["artifact"]
    _require(
        _id(run_id)
        and row["id"] == run_id
        and row["html_url"] == f"https://github.com/{repository}/actions/runs/{run_id}"
        and row["event"] == "pull_request"
        and _id(pr["number"])
        and _matches(pr["source_head"], _SHA)
        and _matches(pr["source_repository"], _REPOSITORY)
        and row["head_repository"] == pr["source_repository"]
        and row["head_sha"] == job["head_sha"] == pr["source_head"] == trace["checkout"]
        and row["conclusion"] == job["conclusion"] == "success"
        and _id(row["run_attempt"])
        and _id(job["id"])
        and job["run_id"] == run_id
        and job["run_attempt"] == row["run_attempt"]
        and trace["job"] == job["id"],
        "PR, producer run, checkout or producing job identity conflicts",
    )
    _job_window(row, job)
    checked = _observed_step(job, "Checkout")
    packed = _observed_step(job, "Pack")
    uploaded = _observed_step(job, "Run actions/upload-artifact@v7")
    _require(
        checked["number"] < packed["number"] < uploaded["number"]
        and _time(checked["completed_at"])
        <= _time(packed["started_at"])
        <= _time(packed["completed_at"])
        <= _time(uploaded["started_at"]),
        "The producer steps are outside the expected checkout-to-upload order",
    )
    _require(
        _id(artifact["id"])
        and _id(artifact["size_in_bytes"])
        and _time(uploaded["started_at"])
        <= _time(artifact["created_at"])
        <= _time(uploaded["completed_at"])
        and artifact["id"] == trace["artifact_id"]
        and artifact["name"] == "build-Linux release"
        and artifact["workflow_run"]["id"] == run_id
        and artifact["workflow_run"]["head_sha"] == row["head_sha"]
        and _matches(artifact["digest"], r"sha256:" + _DIGEST)
        and artifact["digest"] == trace["digest"],
        "The downloaded artifact name or API record conflicts with the owned producer",
    )
    return row, pr, artifact


def _recorded_release(cap: _Row, consumer: _Row, pr: _Row, repo: str) -> _Row:
    external = cap["published"]
    target, tag = external["target"], external["tag"]
    release, asset, trace = external["release"], external["asset"], consumer["trace"]
    url = f"https://github.com/{target}/releases/tag/{tag}"
    _require(
        _matches(target, _REPOSITORY)
        and target.split("/")[0] == repo.split("/")[0]
        and tag == f"pr-release-{pr['number']}-{pr['source_head'][:7]}"
        and external["tag_commit"] == pr["source_head"]
        and tag == release["tag_name"]
        and _id(release["id"])
        and release["draft"] is False
        and release["html_url"] == trace["release_url"] == url
        and _matches(asset["name"], r"[A-Za-z0-9_.-]+\.tar\.zst")
        and asset["name"] == trace["downloaded_asset"]
        and asset["browser_download_url"]
        == f"https://github.com/{target}/releases/download/{tag}/{asset['name']}"
        and _id(asset["id"])
        and _id(asset["size"])
        and asset["state"] == "uploaded"
        and _matches(asset["digest"], r"sha256:" + _DIGEST),
        "The release or asset belongs to another target, tag, commit or downloaded file",
    )
    writer, author = asset["uploader"], release["author"]
    _require(
        _id(writer["id"])
        and writer["id"] == author["id"]
        and _matches(writer["login"], r"[A-Za-z0-9-]+(?:\[bot\])?")
        and writer["login"] == author["login"],
        "The release author and asset uploader records do not agree",
    )
    publish = _observed_step(consumer["job"], _RELEASE)
    _require(
        _time(publish["started_at"])
        <= _time(asset["created_at"])
        <= _time(release["published_at"])
        <= _time(publish["completed_at"]),
        "The release or asset timestamp falls outside its owned publish step",
    )
    return {
        "operation": "github-release-asset-upload",
        "target_repository": target,
        "tag": tag,
        "release_id": release["id"],
        "asset_id": asset["id"],
        "digest": asset["digest"],
        "asset": asset["name"],
        "url": asset["browser_download_url"],
        "recorded_uploader": {"login": writer["login"], "id": writer["id"]},
    }


def _tag_plan(index: _Index, push: tuple[object, ...], destination: str) -> _Row:
    _require(
        {key[-1] for key in index.keys if key[:-1] == push} == {"name", "if", "run"}
        and _field(index, (*push[:2], "runs-on")).value == "ubuntu-latest"
        and _field(index, (*push, "if")).value == _PR_AVAILABLE
        and ("env",) not in index.keys
        and (*push[:2], "env") not in index.keys,
        "The tag step or runner is outside the supported execution profile",
    )
    program = _field(index, (*push, "run"), literal_block=True)
    _require(program.value_kind == "block_literal", "Tag program is not a literal shell body")
    rows = [
        (line, text.strip())
        for line, text in enumerate(str(program.value).splitlines(), program.line + 1)
        if text.strip() and not text.lstrip().startswith("#")
    ]
    remotes = [(line, text) for line, text in rows if " remote add pr-releases " in text]
    _require(len(remotes) == 1, "Expected one Git release remote declaration")
    credential_line, remote = remotes[0]
    target = destination.split("/")[1]
    binding = re.fullmatch(
        r"git -C lean4\.git remote add pr-releases https://foo:"
        r"'\$\{\{[ \t]*secrets\.([A-Za-z_][A-Za-z0-9_]{0,127})[ \t]*\}\}'"
        r"@github\.com/\$\{\{ github\.repository_owner \}\}/" + re.escape(target) + r"\.git",
        remote,
    )
    if binding is None:
        raise PreviewEvidenceError("Git remote does not use the supported secret and destination")
    # The profile is the reviewed git-init/fetch/tag/push recipe. Check the whole
    # program after binding its sole destination and credential declaration.
    normalized = "\n".join("<reviewed-git-remote>" if line == remote else line for _, line in rows)
    _require(
        hashlib.sha256(normalized.encode()).hexdigest() == _TAG_PROGRAM,
        "The Git tag program is outside the reviewed fetch, tag and push recipe",
    )
    return {
        "line": rows[-1][0],
        "credential_binding": "secrets." + binding[1],
        "credential_line": credential_line,
    }


def _tag_receipt(
    evidence: _Row, job: _Row, step: _Row, following_step: _Row, pr: _Row, repo: str
) -> _Row:
    remote, created, reference = evidence["remote"], evidence["new_tag"], evidence["ref"]
    start, following = evidence["push_start"], evidence["next_start"]
    url = remote["value"]
    match = (
        re.fullmatch(r"https://github\.com/([^/]+/[^/]+)\.git", url)
        if isinstance(url, str)
        else None
    )
    if match is None:
        raise PreviewEvidenceError("Tag log does not identify a supported GitHub remote")
    target = match[1]
    tag = f"pr-release-{pr['number']}-{pr['source_head'][:7]}"
    ref = f"refs/tags/{tag}"
    start_time, remote_time, created_time, following_time = (
        _time(record["time"]) for record in (start, remote, created, following)
    )
    _require(
        _matches(target, _REPOSITORY)
        and target.split("/")[0] == repo.split("/")[0]
        and all(_id(evidence[key]) for key in ("run", "job", "attempt"))
        and _id(job["run_attempt"])
        and evidence["run"] == job["run_id"]
        and evidence["job"] == job["id"]
        and evidence["attempt"] == job["run_attempt"]
        and all(_id(record["row"]) for record in (start, remote, created, following))
        and start["value"] == _PUSH_GROUP
        and following["value"] == _AFTER_TAG_GROUP
        and start["row"] < remote["row"] < created["row"] < following["row"]
        and remote["row"] + 1 == created["row"]
        and _time(step["started_at"]) <= start_time.replace(microsecond=0)
        and start_time < remote_time <= created_time < following_time
        and created_time.replace(microsecond=0) <= _time(step["completed_at"])
        and _time(following_step["started_at"])
        <= following_time.replace(microsecond=0)
        <= _time(following_step["completed_at"])
        and _time(job["completed_at"]) <= _time(evidence["retrieved_at"])
        and created["value"] == tag
        and reference["url"] == f"https://api.github.com/repos/{target}/git/refs/tags/{tag}"
        and reference["ref"] == ref
        and reference["object"]["type"] == "commit"
        and reference["object"]["sha"] == pr["source_head"]
        and reference["object"]["url"]
        == f"https://api.github.com/repos/{target}/git/commits/{pr['source_head']}",
        "Tag push and ref evidence do not match the exact job, target, time and PR commit",
    )
    return {
        "operation": "github-git-tag-push",
        "target_repository": target,
        "ref": ref,
        "commit": pr["source_head"],
        "recorded_at": created["time"],
        "ref_record": reference["url"],
        "log_rows": {"remote": remote["row"], "new_tag": created["row"]},
    }


def _recorded_tag(
    cap: _Row, index: _Index, consumer: _Row, pr: _Row, repo: str
) -> tuple[_Row, _Row]:
    job = consumer["job"]
    (origin, _), (download, _), (push, step), (following, next_step) = _job_steps(
        index, job, [_DISCOVER, _DOWNLOAD, _PUSH_TAG, _AFTER_TAG]
    )
    _handoff_source(index, origin, download)
    trigger = ("on", "workflow_run")
    trigger_values = {
        key: [event.value for event in occurrences]
        for key, occurrences in index.values.items()
        if key[:2] == trigger
    }
    _require(
        all(
            len(index.keys.get(path, ())) == 1
            for path in (("on",), (*trigger, "types"), (*trigger, "workflows"))
        )
        and trigger_values
        == {(*trigger, "workflows", 0): ["CI"], (*trigger, "types", 0): ["completed"]}
        and following[-1] == push[-1] + 1
        and next_step["number"] == step["number"] + 1
        and {key[-1] for key in index.keys if key[:-1] == push[:2]} == {"runs-on", "if", "steps"}
        and _field(index, (*push[:2], "if")).value
        == f"github.event.workflow_run.event == 'pull_request' && github.repository == '{repo}'"
        and _field(index, (*download, "if")).value == _PR_AVAILABLE
        and str(_field(index, (*following, "run"), literal_block=True).value).partition("\n")[0]
        == "# Delete any existing releases for this PR.",
        "The tag profile requires the reviewed trigger, job and download guards, and next step",
    )
    publication = _tag_receipt(cap["tag_push"], job, step, next_step, pr, repo)
    plan = _tag_plan(index, push, publication["target_repository"])
    return publication, {**plan, "step": step["number"]}


def release_observation(
    snapshot: Path, root: Path, repository: str, source_run: int, release_run: int
) -> _Row:
    """Bind an observed release asset or source tag to an exact workflow handoff."""
    scope = _SCOPE
    try:
        _require(_matches(repository, _REPOSITORY), "Expected a literal GitHub repository")
        cap = _observation_capture(snapshot, _SCHEMA, _SIGNED_SCHEMA, _TAG_SCHEMA)
        _require(cap["repository"] == repository, "Receipt belongs to another repository")
        if cap["schema"] == _SIGNED_SCHEMA:
            from taintly.ingestion.github_signed_release import signed_release

            return signed_release(cap, root.resolve(), repository, source_run, release_run)
        tag_push = cap["schema"] == _TAG_SCHEMA
        scope = _TAG_SCOPE if tag_push else _SCOPE
        producer, pr, artifact = _producer(cap, repository, source_run)
        consumer = cap["consumer"]
        if tag_push:
            _run_identity(consumer, consumer["job"], repository, release_run, "workflow_run")
            _require(
                consumer["conclusion"] == consumer["job"]["conclusion"] == "failure",
                "Tag-only profile requires a failed publishing job and run",
            )
        else:
            _run(consumer, consumer["job"], repository, release_run, "workflow_run")
        _job_window(consumer, consumer["job"])
        trace = consumer["trace"]
        download = _observed_step(consumer["job"], _DOWNLOAD)
        origin = _observed_step(consumer["job"], _DISCOVER)
        _require(
            release_run != source_run
            and trace["job"] == consumer["job"]["id"]
            and trace["downloaded_artifact_id"] == artifact["id"]
            and _time(download["started_at"])
            <= _time(trace["downloaded_artifact_at"]).replace(microsecond=0)
            <= _time(download["completed_at"])
            and trace["producer_run"] == source_run
            and trace["source"] == pr["source_head"]
            and trace["pr"] == pr["number"]
            and (tag_push or trace["existing_tag_conflict"] is False)
            and _time(producer["updated_at"]) <= _time(origin["started_at"]),
            "The publication does not bind the exact completed source run and PR",
        )
        index, source = _publisher_index(root.resolve(), consumer, cap["publisher_source"])
        context = {
            "repository": repository,
            "pr": pr,
            "producer_run": source_run,
            "producer_job": producer["job"]["id"],
            "producer_artifact": {key: artifact[key] for key in ("id", "name", "digest")},
            "consumer_run": release_run,
            "consumer_job": consumer["job"]["id"],
            "source": source,
        }
        if "producer_artifact_authority" in cap:
            producer_job = producer["job"]
            context["producer_artifact_authority"] = _artifact_upload_authority(
                cap["producer_artifact_authority"],
                producer_job,
                _observed_step(producer_job, "Run actions/upload-artifact@v7"),
                artifact,
                "actions/upload-artifact@v7",
            )
        if tag_push:
            publication, plan = _recorded_tag(cap, index, consumer, pr, repository)
            return {
                "state": "release-tag-push-observed",
                **context,
                "consumer_conclusion": "failure",
                "consumer_attempt": consumer["run_attempt"],
                "configured_publish": plan,
                "publication": publication,
                "scope": scope,
                "review_action": (
                    "Check changes to public tags separately from the release job conclusion. "
                    "Bind downstream consumers to an approved commit or verified release asset."
                ),
            }
        publication = _recorded_release(cap, consumer, pr, repository)
        plan = _release_plan(index, consumer, publication["target_repository"])
        return {
            "state": "release-asset-observed",
            **context,
            "configured_publish": plan,
            "publication": publication,
            "scope": _SCOPE,
            "review_action": (
                "Before publishing PR previews, verify the approved producer run and revision, "
                "allowlist the archive members to release, and bind the approval to the exact "
                "release asset digest. Limit the publishing credential to the preview repository."
            ),
        }
    except PreviewEvidenceError as exc:
        reason = str(exc)
    except (AttributeError, IndexError, KeyError, OSError, RecursionError, TypeError, ValueError):
        reason = "Required handoff, release record or workflow bytes are unavailable or malformed"
    return {"state": "unresolved", "reason": reason, "scope": scope}
