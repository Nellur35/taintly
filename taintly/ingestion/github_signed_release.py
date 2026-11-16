"""Compare signed-artifact release evidence from three owned GitHub jobs."""

from __future__ import annotations

import hashlib
import re
from itertools import pairwise
from pathlib import Path

from taintly.ingestion.github_preview import (
    _DIGEST,
    _NAME,
    _REPOSITORY,
    _SHA,
    _WORKFLOW,
    PreviewEvidenceError,
    _bounded_read,
    _field,
    _id,
    _inputs,
    _matches,
    _observed_step,
    _one,
    _parent_binding,
    _receipt,
    _require,
    _Row,
    _StepPath,
    _time,
)
from taintly.ingestion.github_release_observation import _job_window, _publisher_index
from taintly.rules.github._workflow_run_artifact import _Index, _is_exact_identifier_expression

_UPLOAD = "actions/upload-artifact@v4"
_DOWNLOAD = "actions/download-artifact@v4"
_APP_ACTION = "actions/create-github-app-token@v2"
# Only these shell bodies have been reviewed end to end. The publisher
# fingerprint replaces only its single literal repository assignment. Any other
# body (including code hidden in a heredoc or changed control flow) is unresolved.
_BUILD_PROGRAM = "c7009f6a8fba9a4b965076ef1b6ee8b5e4f7b69a0d93bb08c2dc25968236cf42"
_SIGN_PROGRAM = "0b7f99247094bac9b6650e1c894003eedaa91f5caf0dac6b912049befa4e3065"
_PUBLISH_PROGRAM = "207276ba95c2065644a769e92b310af3969950c885e1f01e0901446e9f39c9c5"
_BUILD_CONDITION = "${{ github.event_name != 'pull_request' || !github.event.pull_request.draft }}"
_SIGN_CALL_CONDITION = "${{ needs.authorize.outputs.skip != 'true' }}"
_SIGN_DOWNLOAD_CONDITION = "inputs.run_id != ''"
_SCOPE = (
    "Trusted saved workflow source, job receipts and GitHub release records. "
    "The APK digest reported by the signing step matches the uploaded asset metadata "
    "and the published checksum manifest. Downloaded APK bytes, signature, signing "
    "approval and environment, broader App grants and installation effects remain "
    "unverified. This is a same-repository PR profile."
)


def _job(run: _Row, job: _Row, repository: str, run_id: int, event: str) -> None:
    _require(
        _id(run_id)
        and _id(run["id"])
        and _id(run["run_attempt"])
        and _id(job["id"])
        and _id(job["run_id"])
        and _id(job["run_attempt"])
        and run["id"] == job["run_id"] == run_id
        and run["run_attempt"] == job["run_attempt"]
        and run["html_url"] == f"https://github.com/{repository}/actions/runs/{run_id}"
        and run["repository"]["full_name"] == repository
        and run["head_repository"]["full_name"] == repository
        and run["event"] == event
        and _matches(run["head_sha"], _SHA)
        and run["head_sha"] == job["head_sha"]
        and run["conclusion"] == job["conclusion"] == "success",
        "Run and selected successful job do not share one same-repository invocation",
    )
    _job_window(run, job)


def _value(index: _Index, path: tuple[object, ...]) -> str:
    return str(_field(index, path).value)


def _condition(index: _Index, owner: tuple[object, ...], expected: str | None) -> None:
    path = (*owner, "if")
    _require(
        path not in index.keys if expected is None else _value(index, path) == expected,
        "The selected job or step has an unsupported execution condition",
    )


def _native_runner(index: _Index, owner: str, job: _Row) -> None:
    _require(
        _value(index, ("jobs", owner, "runs-on")) == "ubuntu-24.04"
        and job["labels"] == ["ubuntu-24.04"],
        "Source and job do not establish the supported native Linux runner",
    )


def _step(
    index: _Index, owner: str, criteria: dict[tuple[str, ...], str], *, condition: str | None = None
) -> _StepPath:
    prefix = ("jobs", owner, "steps")
    _require(
        all(len(index.keys.get(path, ())) == 1 for path in (prefix[:1], prefix[:2], prefix))
        and not any(
            (*path, field) in index.keys
            for path in ((), prefix[:2])
            for field in ("defaults", "env")
        )
        and not any((*prefix[:2], key) in index.keys for key in ("container", "uses")),
        "Selected source job or workspace is ambiguous",
    )
    first = next(iter(criteria))
    paths: list[_StepPath] = [
        (*prefix, key[3])
        for key in index.values
        if len(key) == 4 + len(first)
        and key[:3] == prefix
        and isinstance(key[3], int)
        and key[4:] == first
        and all(
            len(index.keys.get((*key[:4], *tail), ())) == 1
            and len(found := index.values.get((*key[:4], *tail), [])) == 1
            and found[0].value == expected
            for tail, expected in criteria.items()
        )
    ]
    _require(
        len(paths) == 1,
        "Selected command or action is absent or ambiguous in its source job",
    )
    step = paths[0]
    _require(
        not any((*step, key) in index.keys for key in ("shell", "working-directory"))
        and sum((*step, key) in index.keys for key in ("uses", "run")) == 1
        and all(
            len(rows) == 1
            for key, rows in index.keys.items()
            if key[:4] == step and all(isinstance(segment, str) for segment in key[4:])
        ),
        "Selected step has duplicate fields or an unsupported shell or workspace",
    )
    _condition(index, step, condition)
    return step


def _same_order(*pairs: tuple[_StepPath, _Row]) -> None:
    _require(
        all(
            a[-1] < b[-1]
            and x["number"] < y["number"]
            and _time(x["completed_at"]) <= _time(y["started_at"])
            for (a, x), (b, y) in pairwise(pairs)
        ),
        "Source and observed step order do not agree",
    )


def _program(
    index: _Index, step: _StepPath, fingerprint: str, command: str, *, target: str = ""
) -> int:
    event = _field(index, (*step, "run"), literal_block=True)
    body = str(event.value).rstrip("\n")
    if target:
        line = f"\nrepo={target}\n"
        _require(body.count(line) == 1, "The release command does not bind its configured target")
        body = body.replace(line, "\nrepo=<destination>\n")
    _require(
        event.value_kind == "block_literal"
        and hashlib.sha256(body.encode()).hexdigest() == fingerprint,
        "The selected source command is outside the supported release profile",
    )
    return event.line + next(
        offset for offset, line in enumerate(body.split("\n"), 1) if line.startswith(command)
    )


def _env(index: _Index, step: _StepPath, names: set[str]) -> None:
    prefix = (*step, "env")
    _require(
        len(index.keys.get(prefix, ())) == 1
        and {key[-1] for key in index.keys if key[:-1] == prefix} == names,
        "Selected command environment includes an unsupported binding",
    )


def _archive(artifact: _Row, selection: _Row, run: _Row, job: _Row, step: _Row) -> None:
    _require(
        _id(artifact["id"])
        and _id(artifact["size_in_bytes"])
        and _matches(artifact["name"], _NAME)
        and _matches(artifact["digest"], "sha256:" + _DIGEST)
        and _id(artifact["workflow_run"]["id"])
        and _id(selection["total_count"])
        and selection["total_count"] == 1
        and selection["artifacts"] == [artifact]
        and artifact["workflow_run"]["id"] == run["id"] == job["run_id"]
        and artifact["workflow_run"]["head_sha"] == run["head_sha"]
        and _time(step["started_at"])
        <= _time(artifact["created_at"])
        <= _time(step["completed_at"]),
        "Archive inventory or creation time does not identify the selected producing run and step",
    )


def _published_asset(
    cap: _Row, root: Path, target: str, tag: str, asset_name: str, digest: str, step: _Row
) -> _Row:
    release = cap["release"]
    url = f"https://github.com/{target}/releases/tag/{tag}"
    _require(
        _id(release["id"])
        and release["draft"] is False
        and release["tag_name"] == tag
        and release["html_url"] == url,
        "The published release belongs to another destination or tag",
    )
    asset, manifest = [
        _one(
            [row for row in release["assets"] if row["name"] == name],
            "Missing unique release asset",
        )
        for name in (asset_name, "SHA256SUMS.txt")
    ]
    writer = asset["uploader"]
    _require(
        _id(writer["id"])
        and _matches(writer["login"], r"[A-Za-z0-9-]+\[bot\]")
        and asset["id"] != manifest["id"]
        and all(
            _id(row["id"])
            and _id(row["size"])
            and row["state"] == "uploaded"
            and _matches(row["digest"], "sha256:" + _DIGEST)
            and row["browser_download_url"]
            == f"https://github.com/{target}/releases/download/{tag}/{row['name']}"
            and row["uploader"]["id"] == writer["id"]
            and row["uploader"]["login"] == writer["login"]
            and _time(step["started_at"]) <= _time(row["created_at"]) <= _time(step["completed_at"])
            for row in (asset, manifest)
        )
        and asset["digest"] == f"sha256:{digest}",
        "Published asset, digest, uploader or upload window does not match the saved operation",
    )
    manifest_path = (root / "published-SHA256SUMS.txt").resolve()
    _require(manifest_path.is_relative_to(root), "Checksum manifest leaves the evidence projection")
    manifest_bytes = _bounded_read(manifest_path)
    _require(
        len(manifest_bytes) == manifest["size"]
        and f"sha256:{hashlib.sha256(manifest_bytes).hexdigest()}" == manifest["digest"],
        "Saved checksum manifest does not match its release asset",
    )
    checksums: dict[str, str] = {}
    for line in manifest_bytes.decode("ascii").removesuffix("\n").split("\n"):
        match = re.fullmatch(r"([a-f0-9]{64}) [ *]([A-Za-z0-9_.-]+)", line)
        if match is None or match[2] in checksums:
            raise PreviewEvidenceError("Published checksum manifest is malformed or ambiguous")
        checksums[match[2]] = match[1]
    _require(
        checksums.get(asset_name) == digest,
        "Published manifest does not uniquely identify the signed APK",
    )
    return {
        "operation": "github-release-asset-upload",
        "target_repository": target,
        "tag": tag,
        "release_id": release["id"],
        "asset_id": asset["id"],
        "asset": asset_name,
        "digest": asset["digest"],
        "url": asset["browser_download_url"],
        "recorded_uploader": {"login": writer["login"], "id": writer["id"]},
        "manifest_asset_id": manifest["id"],
    }


def signed_release(
    cap: _Row, root: Path, repository: str, source_run: int, release_run: int
) -> _Row:
    producer, publisher = cap["producer"], cap["publisher"]
    build, signer, publish = (cap["jobs"][key] for key in ("build", "sign", "publish"))
    _job(producer, build, repository, source_run, "pull_request")
    for job in (signer, publish):
        _job(publisher, job, repository, release_run, "workflow_run")
    _require(
        source_run != release_run
        and len({build["id"], signer["id"], publish["id"]}) == 3
        and _time(producer["updated_at"])
        <= _time(publisher["created_at"])
        <= _time(signer["started_at"])
        <= _time(signer["completed_at"])
        <= _time(publish["started_at"]),
        "Producer, signer and publisher do not appear in distinct jobs in causal order",
    )
    pr, commit, trace = cap["pr"], cap["producer_merge"], cap["trace"]
    number, head = pr["number"], producer["head_sha"]
    merge_sha = commit["sha"]
    _require(
        _id(number)
        and pr["html_url"] == f"https://github.com/{repository}/pull/{number}"
        and pr["head"]["repo"]["full_name"] == pr["base"]["repo"]["full_name"] == repository
        and pr["head"]["sha"] == head
        and _matches(merge_sha, _SHA)
        and commit["parents"] == [pr["base"]["sha"], head]
        and all(
            ref["sha"] == merge_sha and ref["ref"] == f"refs/pull/{number}/merge"
            for ref in producer["referenced_workflows"]
        )
        and producer["referenced_workflows"],
        "PR identity or producer workflow merge revision does not agree",
    )
    src = cap["source"]
    build_index, build_source = _publisher_index(
        root / "producer", {**producer, "head_sha": merge_sha}, src["producer"]
    )
    publish_index, publish_source = _publisher_index(
        root / "publisher", publisher, src["publisher"]
    )
    _parent_binding(build_index, publish_index)
    _condition(build_index, ("jobs", "build"), _BUILD_CONDITION)
    source_archive = cap["producer_archive"]
    build_step = _observed_step(build, "Build")
    checkout = _observed_step(build, "Run actions/checkout@v4")
    _require(
        _value(build_index, ("jobs", "build", "name")) == build["name"]
        and _receipt(trace, checkout, build, "checkout") == head,
        "Build job or checkout does not identify the saved PR head",
    )
    checkout_source = _step(build_index, "build", {("uses",): "actions/checkout@v4"})
    build_source_step = _step(build_index, "build", {("name",): "Build"})
    build_upload = _step(
        build_index, "build", {("uses",): _UPLOAD, ("with", "name"): source_archive["name"]}
    )
    archive_step = _observed_step(build, f"Run {_UPLOAD}", number=cap["build_upload_step"])
    _same_order(
        (checkout_source, checkout), (build_source_step, build_step), (build_upload, archive_step)
    )
    _archive(source_archive, cap["producer_inventory"], producer, build, archive_step)
    _require(
        _value(build_index, (*checkout_source, "with", "ref"))
        == "${{ github.event_name == 'pull_request' && github.event.pull_request.head.sha || github.sha }}"
        and (*checkout_source, "with", "repository") not in build_index.keys
        and (*checkout_source, "with", "path") not in build_index.keys,
        "Build checkout does not select the bound PR head in its working tree",
    )
    _env(build_index, build_source_step, {"DROIDDECK_BUILD_LABEL", "SGDB_API_KEY"})
    build_line = _program(build_index, build_source_step, _BUILD_PROGRAM, "./gradlew ")
    _require(
        _receipt(trace, build_step, build, "assemble-release") == ":app:assembleRelease",
        "Saved build step lacks its owned assembleRelease record",
    )
    _require(
        _receipt(trace, archive_step, build, "producer-upload-name") == source_archive["name"]
        and _receipt(trace, archive_step, build, "producer-upload") == str(source_archive["id"]),
        "Producer upload records do not bind both the archive name and its ID to this step",
    )

    sign_call = ("jobs", "sign")
    _condition(publish_index, sign_call, _SIGN_CALL_CONDITION)
    callee = _value(publish_index, (*sign_call, "uses"))
    _require(
        all(
            len(publish_index.keys.get(path, ())) == 1
            for path in (sign_call[:1], sign_call, (*sign_call, "with"))
        )
        and callee.startswith("./")
        and _matches(callee[2:], _WORKFLOW)
        and _value(publish_index, (*sign_call, "needs")) == "authorize"
        and _is_exact_identifier_expression(
            _value(publish_index, (*sign_call, "with", "run_id")), "needs.authorize.outputs.run_id"
        )
        and _is_exact_identifier_expression(
            _value(publish_index, (*sign_call, "with", "variants")),
            "needs.authorize.outputs.variants",
        ),
        "Signing invocation does not transfer the authorized build-run input",
    )
    sign_ref = _one(
        [
            ref
            for ref in publisher["referenced_workflows"]
            if ref["path"] == f"{repository}/{callee[2:]}@{publisher['head_sha']}"
        ],
        "Provider records do not identify one owning reusable signer",
    )
    _require(sign_ref["sha"] == publisher["head_sha"], "Reusable signer revision differs")
    sign_index, sign_source = _publisher_index(
        root / "signer", {"path": callee[2:], "head_sha": sign_ref["sha"]}, src["signer"]
    )
    _native_runner(sign_index, "sign", signer)
    _condition(sign_index, ("jobs", "sign"), None)
    matrix = ("jobs", "sign", "strategy", "matrix")
    _require(
        len(sign_index.keys.get(matrix[:-1], ())) == 1
        and len(sign_index.keys.get(matrix, ())) == 1
        and {path[-1] for path in sign_index.keys if path[:-1] == matrix} == {"variant"}
        and _value(sign_index, (*matrix, "variant")) == "${{ fromJSON(inputs.variants) }}",
        "Signer matrix is outside the supported invocation profile",
    )
    variant = re.fullmatch(r"sign / sign ([A-Za-z0-9_-]+)", signer["name"])
    if variant is None:
        raise PreviewEvidenceError("Saved signer is outside the supported reusable matrix profile")
    archive_base = _value(publish_index, (*sign_call, "with", "artifact"))
    _require(
        _matches(archive_base, _NAME)
        and len(sign_index.keys.get(("on", "workflow_call", "inputs", "run_id"), ())) == 1
        and _value(sign_index, ("jobs", "sign", "name")) == "sign ${{ matrix.variant }}"
        and _value(sign_index, ("jobs", "sign", "environment")) == "${{ inputs.environment }}",
        "Saved signer is outside the supported reusable matrix profile",
    )
    sign_download = _step(
        sign_index,
        "sign",
        {("name",): "The apk (a main build)"},
        condition=_SIGN_DOWNLOAD_CONDITION,
    )
    sign_execute = _step(sign_index, "sign", {("name",): "Sign"})
    sign_upload = _step(sign_index, "sign", {("uses",): _UPLOAD})
    _inputs(sign_index, sign_upload, {"name", "path", "if-no-files-found"})
    _env(sign_index, sign_download, {"GH_TOKEN", "RUN"})
    _env(
        sign_index,
        sign_execute,
        {
            "RELEASE_KEYSTORE_B64",
            "RELEASE_STORE_PASSWORD",
            "RELEASE_KEY_ALIAS",
            "ENVIRONMENT",
            "VARIANT",
            "LABEL",
        },
    )
    s_download = _observed_step(signer, "The apk (a main build)")
    s_execute = _observed_step(signer, "Sign")
    s_upload = _observed_step(signer, f"Run {_UPLOAD}")
    _same_order((sign_download, s_download), (sign_execute, s_execute), (sign_upload, s_upload))
    signing_archive = cap["signed_archive"]
    _require(
        _is_exact_identifier_expression(
            _value(sign_index, (*sign_download, "env", "RUN")), "inputs.run_id"
        )
        and _value(sign_index, (*sign_download, "run"))
        == f'gh run download "$RUN" -R "$GITHUB_REPOSITORY" -n {source_archive["name"]} -D in'
        and _receipt(trace, s_download, signer, "sign-download-run") == str(source_run)
        and _value(sign_index, (*sign_upload, "with", "name"))
        == "${{ inputs.artifact }}-${{ matrix.variant }}"
        and _value(sign_index, (*sign_upload, "with", "path")) == "out/*"
        and signing_archive["name"] == f"{archive_base}-{variant[1]}"
        and _receipt(trace, s_upload, signer, "sign-upload") == str(signing_archive["id"]),
        "The signing step or upload does not bind the selected producer and signed archive",
    )
    _archive(signing_archive, cap["signed_inventory"], publisher, signer, s_upload)
    sign_line = _program(sign_index, sign_execute, _SIGN_PROGRAM, "tools/release/sign-apk.sh ")
    member = re.fullmatch(
        rf"({_DIGEST})  ([A-Za-z0-9_.-]*PR\.{number}-{head[:7]}[A-Za-z0-9_.-]*\.apk)",
        _receipt(trace, s_execute, signer, "signed-member"),
    )
    if member is None:
        raise PreviewEvidenceError("Signer did not report the checksum of one PR-labelled APK")

    _require(
        publish["name"] == "publish", "The publication job does not own the publishing command"
    )
    _native_runner(publish_index, "publish", publish)
    _condition(publish_index, ("jobs", "publish"), None)
    needs = ("jobs", "publish", "needs")
    _require(
        len(publish_index.keys.get(needs, ())) == 1
        and {
            key[len(needs) :]: [event.value for event in events]
            for key, events in publish_index.values.items()
            if key[: len(needs)] == needs
        }
        == {(0,): ["authorize"], (1,): ["sign"]},
        "Publisher workflow does not retain its authorization and signing dependencies",
    )
    download = _step(publish_index, "publish", {("uses",): _DOWNLOAD})
    token = _step(publish_index, "publish", {("uses",): _APP_ACTION})
    upload = _step(publish_index, "publish", {("id",): "publish"})
    _inputs(publish_index, download, {"path", "pattern", "merge-multiple"})
    _inputs(publish_index, token, {"owner", "repositories", "app-id", "private-key"})
    _env(publish_index, upload, {"GH_TOKEN", "PR_NUMBER", "HEAD_SHA", "BASE_SHA", "VERSION_CODE"})
    observed_download = _observed_step(publish, f"Run {_DOWNLOAD}")
    observed_token = _observed_step(publish, f"Run {_APP_ACTION}")
    observed_upload = _observed_step(publish, _value(publish_index, (*upload, "name")))
    _same_order((download, observed_download), (token, observed_token), (upload, observed_upload))
    name, archive_id, archive_digest = (signing_archive[key] for key in ("name", "id", "digest"))
    _require(
        _value(publish_index, (*download, "with", "pattern")) == f"{archive_base}-*"
        and _value(publish_index, (*download, "with", "path")) == "signed"
        and _value(publish_index, (*download, "with", "merge-multiple")) == "true"
        and _receipt(trace, observed_download, publish, "publish-download-run") == str(release_run)
        and _receipt(trace, observed_download, publish, "publish-download")
        == f"{name}|{archive_id}|{archive_digest}",
        "The publisher download does not identify the same signed archive and digest",
    )
    target_owner = _value(publish_index, (*token, "with", "owner"))
    target_repo = _value(publish_index, (*token, "with", "repositories"))
    target = f"{target_owner}/{target_repo}"
    token_id = _value(publish_index, (*token, "id"))
    _require(
        _matches(target, _REPOSITORY)
        and target_owner == repository.split("/")[0]
        and _matches(token_id, r"[A-Za-z_][A-Za-z0-9_-]*")
        and _matches(
            _value(publish_index, (*token, "with", "app-id")),
            r"\$\{\{[ \t]*vars\.[A-Z_][A-Z0-9_]*[ \t]*\}\}",
        )
        and _matches(
            _value(publish_index, (*token, "with", "private-key")),
            r"\$\{\{[ \t]*secrets\.[A-Z_][A-Z0-9_]*[ \t]*\}\}",
        )
        and _is_exact_identifier_expression(
            _value(publish_index, (*upload, "env", "GH_TOKEN")), f"steps.{token_id}.outputs.token"
        )
        and _is_exact_identifier_expression(
            _value(publish_index, (*upload, "env", "PR_NUMBER")),
            "needs.authorize.outputs.pr_number",
        )
        and _is_exact_identifier_expression(
            _value(publish_index, (*upload, "env", "HEAD_SHA")), "needs.authorize.outputs.head_sha"
        )
        and _receipt(trace, observed_upload, publish, "published-head") == head
        and _receipt(trace, observed_upload, publish, "published-pr") == str(number),
        "Publishing credential or observed PR context does not match the targeted invocation",
    )
    publish_line = _program(
        publish_index, upload, _PUBLISH_PROGRAM, "gh release upload ", target=target
    )
    tag = f"pr-{number}"
    _require(
        _receipt(trace, observed_upload, publish, "published-url")
        == f"https://github.com/{target}/releases/tag/{tag}",
        "The command records a different published release",
    )
    publication = _published_asset(cap, root, target, tag, member[2], member[1], observed_upload)
    return {
        "state": "release-asset-observed",
        "profile": "signed-artifact",
        "repository": repository,
        "pr": {"number": number, "source_head": head, "source_repository": repository},
        "producer_run": source_run,
        "producer_job": build["id"],
        "producer_source": {**build_source, "line": build_line},
        "producer_artifact": {key: source_archive[key] for key in ("id", "name", "digest")},
        "consumer_run": release_run,
        "consumer_job": publish["id"],
        "source": publish_source,
        "signing": {
            "job": signer["id"],
            "source": sign_source,
            "line": sign_line,
            "artifact": {key: signing_archive[key] for key in ("id", "name", "digest")},
            "source_selection": "unique archive name in recorded source run",
            "reported_member_digest": f"sha256:{member[1]}",
        },
        "configured_publish": {
            "credential_binding": f"steps.{token_id}.outputs.token",
            "requested_github_app_token_target": target,
            "line": publish_line,
            "step": observed_upload["number"],
        },
        "publication": publication,
        "scope": _SCOPE,
    }
