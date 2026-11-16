"""Corroborate a saved workflow_run artifact publication to GitHub Releases."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from taintly.ingestion.github_preview import (
    _DIGEST,
    _REPOSITORY,
    _SHA,
    PreviewEvidenceError,
    _field,
    _id,
    _job_steps,
    _matches,
    _observation_capture,
    _observed_step,
    _require,
    _run,
    _source_bytes,
    _time,
)
from taintly.parsers.structural.tokenizer import TokenizerError, TokenKind, tokenize
from taintly.rules.github._workflow_run_artifact import (
    _Index,
    _is_exact_identifier_expression,
)

_SCHEMA = "github-workflow-run-release-v1"
_DISCOVER = "Retrieve information about the original workflow"
_DOWNLOAD = "Download artifact from the previous workflow."
_RELEASE = "Release (SHA-suffixed format)"
_SCOPE = (
    "Trusted saved GitHub source and provider records. The recorded asset uploader is the "
    "observed release account. The credential value, wider grants, exact release bytes and "
    "effects on later installations remain unverified."
)
_Row = dict[str, Any]


def _publisher_index(root: Path, run: _Row, saved: _Row) -> tuple[_Index, _Row]:
    path = run["path"]
    _require(
        _matches(path, r"\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml"), "Unsupported publisher path"
    )
    raw, identity = _source_bytes(root, saved, path, run["head_sha"])
    text = raw.decode("utf-8").replace("\r\n", "\n")
    _require(
        "\r" not in text
        and "\ufeff" not in text
        and not re.search(r"^(?:---|\.\.\.)(?:[ \t]|$)", text, re.MULTILINE),
        "Publisher source contains unsupported document boundaries",
    )
    try:
        _require(
            not any(
                tok.kind in {TokenKind.ALIAS, TokenKind.MERGE_KEY}
                or (tok.kind is TokenKind.KEY and "\\" in tok.value)
                for tok in tokenize(text)
            ),
            "Publisher source contains ambiguous keys or aliases",
        )
    except TokenizerError as exc:
        raise PreviewEvidenceError("Publisher source tokenization is incomplete") from exc
    index = _Index.from_source(path, text)
    _require(
        index.error is None and len(index.keys.get(("on",), ())) == 1,
        "Publisher workflow event source is incomplete or ambiguous",
    )
    return index, identity


def _job_window(run: _Row, job: _Row) -> None:
    _require(
        _time(run["created_at"])
        <= _time(job["started_at"])
        <= _time(job["completed_at"])
        <= _time(run["updated_at"]),
        "Selected job timestamps are outside its owning run",
    )


def _release_plan(index: _Index, consumer: _Row, destination: str) -> dict[str, object]:
    job = consumer["job"]
    (origin, _), (download, _), (publish, published) = _job_steps(
        index, job, [_DISCOVER, _DOWNLOAD, _RELEASE]
    )
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
        (publish, {"name", "if", "run", "env"}),
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
    _require(
        len(index.keys.get((*publish, "env"), ())) == 1
        and {key[-1] for key in index.keys if key[:-1] == (*publish, "env")} == {"GH_TOKEN"},
        "The publishing step does not have a single explicit GH_TOKEN binding",
    )
    token = str(_field(index, (*publish, "env", "GH_TOKEN")).value)
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


def release_observation(
    snapshot: Path, root: Path, repository: str, source_run: int, release_run: int
) -> _Row:
    """Bind an observed public release to an exact GitHub workflow handoff."""
    try:
        _require(_matches(repository, _REPOSITORY), "Expected a literal GitHub repository")
        cap = _observation_capture(snapshot, _SCHEMA)
        _require(cap["repository"] == repository, "Receipt belongs to another repository")
        producer, pr, artifact = _producer(cap, repository, source_run)
        consumer = cap["consumer"]
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
            and trace["existing_tag_conflict"] is False
            and _time(producer["updated_at"]) <= _time(origin["started_at"]),
            "The publication does not bind the exact completed source run and PR",
        )
        index, source = _publisher_index(root.resolve(), consumer, cap["publisher_source"])
        publication = _recorded_release(cap, consumer, pr, repository)
        plan = _release_plan(index, consumer, publication["target_repository"])
        return {
            "state": "release-asset-observed",
            "repository": repository,
            "pr": pr,
            "producer_run": source_run,
            "producer_job": producer["job"]["id"],
            "producer_artifact": {key: artifact[key] for key in ("id", "name", "digest")},
            "consumer_run": release_run,
            "consumer_job": consumer["job"]["id"],
            "source": source,
            "configured_publish": plan,
            "publication": publication,
            "scope": _SCOPE,
        }
    except PreviewEvidenceError as exc:
        reason = str(exc)
    except (AttributeError, IndexError, KeyError, OSError, RecursionError, TypeError, ValueError):
        reason = "Required handoff, release record or workflow bytes are unavailable or malformed"
    return {"state": "unresolved", "reason": reason, "scope": _SCOPE}
