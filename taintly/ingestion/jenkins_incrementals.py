"""Corroborate a saved Jenkins Incrementals publication with registry bytes."""

from __future__ import annotations

import hashlib
import io
import json
import re
import zipfile
import zlib
from datetime import datetime
from pathlib import Path
from typing import Any
from xml.parsers import expat

from taintly.parsers.jenkinsfile.groovy_lex import TokKind, tokenize

_REGISTRY = "https://repo.jenkins-ci.org/incrementals/"
_CONTROLLER = "https://ci.jenkins.io/"
_SHA = r"[0-9a-f]{40}"
_NAME = r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}"
_MAVEN_PART = r"[A-Za-z0-9][A-Za-z0-9_-]{0,62}"
_MAVEN_GROUP = rf"{_MAVEN_PART}(?:\.{_MAVEN_PART}){{0,7}}"
_MAVEN_XML = "http://maven.apache.org/POM/4.0.0}"
_MAX_ARCHIVE = 2 * 1024 * 1024
_SCOPE = (
    "Trusted saved GitHub and registry records. The publication is bound to the PR revision "
    "and named registry artifact. The publisher check does not establish the exact Jenkins "
    "invocation that supplied the artifact. Controller checkout, loaded library revision, "
    "credential access within the build and broader registry permissions remain unverified."
)
_Row = dict[str, Any]


class IncrementalsEvidenceError(ValueError):
    """The requested publication could not be corroborated."""


def _require(condition: object, reason: str) -> None:
    if not condition:
        raise IncrementalsEvidenceError(reason)


def _one(rows: list[_Row], reason: str) -> _Row:
    if len(rows) != 1:
        raise IncrementalsEvidenceError(reason)
    return rows[0]


def _read(path: Path, limit: int) -> bytes:
    _require(path.is_file(), "selected evidence file is unavailable")
    with path.open("rb") as handle:
        data = handle.read(limit + 1)
    _require(len(data) <= limit, "selected evidence file exceeds its size limit")
    return data


def _project_file(root: Path, name: str, limit: int) -> bytes:
    path = (root / name).resolve()
    _require(path.is_relative_to(root), "source or package file leaves its evidence directory")
    return _read(path, limit)


def _keys(items: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in items:
        _require(key not in result, "saved capture contains duplicate JSON fields")
        result[key] = value
    return result


def _int(value: str) -> int:
    _require(len(value) <= 20, "saved capture contains an oversized integer")
    return int(value)


def _time(value: str) -> datetime:
    timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    _require(timestamp.utcoffset() is not None, "saved timestamps require an offset")
    return timestamp


def _id(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 < value < 10**19


def _git_blob(raw: bytes) -> str:
    prefix = b"blob " + str(len(raw)).encode("ascii") + b"\0"
    return hashlib.sha1(prefix + raw, usedforsecurity=False).hexdigest()


def _source(root: Path, source: _Row, head: str, base: str, core: bool) -> _Row:
    raw = _project_file(root, "Jenkinsfile", 50_000)
    base_raw = _project_file(root, "base.Jenkinsfile", 50_000)
    digest = hashlib.sha256(raw).hexdigest()
    blob = _git_blob(raw)
    _require(
        raw == base_raw
        and source["head"]["commit"] == head
        and source["base"]["commit"] == base
        and source["head"]["sha256"] == source["base"]["sha256"] == digest,
        "PR head and recorded base Jenkinsfiles are missing, different or mismatched",
    )
    _require(
        source["head"]["blob"] == source["base"]["blob"] == blob,
        "saved Jenkinsfile bytes differ from Git blob identities",
    )
    marker = ("infra", ".", "maybePublishIncrementals", "(", ")") if core else ("buildPlugin", "(")
    tokens = [
        tok
        for tok in tokenize(raw.decode("utf-8"))
        if tok.kind not in {TokKind.NEWLINE, TokKind.COMMENT, TokKind.EOF}
    ]
    positions = [
        token.line
        for start, token in enumerate(tokens)
        if token.col == 1
        and token.kind is TokKind.IDENT
        and tuple(t.value for t in tokens[start : start + len(marker)]) == marker
    ]
    _require(len(positions) == 1, "Jenkinsfile lacks one supported configured call")
    return {
        "path": "Jenkinsfile",
        "head": head,
        "base": base,
        "sha256": digest,
        "configured_call": "infra.maybePublishIncrementals" if core else "buildPlugin",
        "line": positions[0],
    }


def _pom_fields(raw: bytes) -> dict[str, str]:
    paths = {
        ("project", "groupId"): "group",
        ("project", "parent", "groupId"): "parent_group",
        ("project", "artifactId"): "artifact",
        ("project", "packaging"): "packaging",
    }
    stack: list[str] = []
    fields: dict[str, list[str]] = {}
    active: str | None = None
    parent_seen = False

    def start(name: str, _attributes: dict[str, str]) -> None:
        nonlocal active, parent_seen
        _require(active is None, "The saved POM has a nonliteral Maven field")
        _require(len(stack) < 64, "The saved POM exceeds the XML nesting limit")
        _require(
            stack or name == _MAVEN_XML + "project",
            "The saved POM is outside the Maven XML profile",
        )
        maven_name = name.startswith(_MAVEN_XML)
        if not maven_name and tuple(stack) in (("project",), ("project", "parent")):
            raise IncrementalsEvidenceError("The saved POM has a foreign project or parent field")
        stack.append(name.removeprefix(_MAVEN_XML) if maven_name else "")
        if stack == ["project", "parent"]:
            _require(not parent_seen, "The saved POM has ambiguous Maven parents")
            parent_seen = True
        active = paths.get(tuple(stack))
        if active is not None:
            _require(active not in fields, "The saved POM has ambiguous Maven coordinates")
            fields[active] = []

    def end(_name: str) -> None:
        nonlocal active
        stack.pop()
        active = None

    def characters(value: str) -> None:
        if active is not None:
            fields[active].append(value)

    def reject_dtd(*_declaration: object) -> None:
        raise IncrementalsEvidenceError("The saved POM declares a DTD")

    parser = expat.ParserCreate(namespace_separator="}")
    parser.StartDoctypeDeclHandler = reject_dtd
    parser.StartElementHandler = start
    parser.EndElementHandler = end
    parser.CharacterDataHandler = characters
    try:
        parser.Parse(raw.decode("utf-8"), True)
    except expat.ExpatError as exc:
        raise IncrementalsEvidenceError("The saved POM is malformed XML") from exc
    return {name: "".join(chunks).strip() for name, chunks in fields.items()}


def _pom_coordinate(root: Path, evidence: _Row, repository: str, pr: _Row) -> _Row:
    raw = _project_file(root, "pom.xml", 50_000)
    base_raw = _project_file(root, "base.pom.xml", 50_000)
    digest = hashlib.sha256(raw).hexdigest()
    blob = _git_blob(raw)
    _require(raw == base_raw, "The PR and base POM bytes differ")
    for side, owner in (("head", pr["head_repo"]), ("base", repository)):
        record = evidence[side]
        _require(
            record["commit"] == pr[side]
            and record["url"] == f"https://github.com/{owner}/blob/{pr[side]}/pom.xml"
            and record["sha256"] == digest
            and record["blob"] == blob,
            "Saved POM bytes, Git revision and repository identity do not agree",
        )
    fields = _pom_fields(raw)
    group = fields.get("group", fields.get("parent_group"))
    artifact_id = fields.get("artifact")
    _require(
        group is not None
        and re.fullmatch(_MAVEN_GROUP, group)
        and artifact_id is not None
        and re.fullmatch(_NAME, artifact_id)
        and fields.get("packaging") == "hpi",
        "The saved POM lacks literal Maven group, artifact and HPI packaging",
    )
    return {
        "path": "pom.xml",
        "group": group,
        "artifact": artifact_id,
        "sha256": digest,
        "blob": blob,
    }


def _manifest(raw: bytes) -> dict[str, str]:
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        infos = [
            info
            for info in archive.infolist()
            if info.filename.isascii() and info.filename.upper() == "META-INF/MANIFEST.MF"
        ]
        _require(
            len(infos) == 1
            and infos[0].orig_filename == infos[0].filename
            and infos[0].file_size <= 16384,
            "package manifest is missing, oversized or ambiguous",
        )
        _require(
            infos[0].compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED),
            "package manifest uses unsupported ZIP compression",
        )
        with archive.open(infos[0]) as stream:
            data = stream.read(16385)
    _require(len(data) <= 16384, "package manifest exceeds its limit")
    _require(data.endswith((b"\r", b"\n")), "package manifest has an unterminated physical line")
    text = data.decode("utf-8").replace("\r\n", "\n").replace("\r", "\n")
    main = text.partition("\n\n")[0]
    fields: dict[str, str] = {}
    current: str | None = None
    for line in main.removesuffix("\n").split("\n"):
        _require("\0" not in line, "package manifest is malformed or ambiguous")
        if line.startswith(" "):
            if current is None:
                raise IncrementalsEvidenceError("package manifest has an orphan continuation")
            fields[current] += line[1:]
            continue
        key, separator, value = line.partition(": ")
        current = key.lower()
        _require(
            separator
            and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,69}", key)
            and current not in fields,
            "package manifest is malformed or ambiguous",
        )
        fields[current] = value
    return fields


def _assess(data: _Row, root: Path, repository: str, number: int, check_id: int) -> _Row:
    repo = re.fullmatch(r"jenkinsci/(jenkins|([a-z0-9][a-z0-9-]*)-plugin)", repository)
    if repo is None or data["repository"] != repository:
        raise IncrementalsEvidenceError("unsupported or mismatched Jenkins publication repository")
    pr = data["pr"]
    head, base = pr["head"], pr["base"]
    _require(
        _id(check_id)
        and _id(pr["number"])
        and number == pr["number"]
        and re.fullmatch(_SHA, head)
        and re.fullmatch(_SHA, base)
        and re.fullmatch(rf"{_NAME}/{_NAME}", pr["head_repo"]),
        "requested PR or exact head is unresolved",
    )
    core = repo[1] == "jenkins"
    family = "Core" if core else "Plugins"
    escaped = re.escape(repo[1])
    check = _one(
        [row for row in data["checks"] if row["id"] == check_id],
        "no unique Jenkins check for the selected job",
    )
    job = re.fullmatch(rf"{family}/{escaped}/PR-{number}#([1-9][0-9]*)", check["external_id"])
    if job is None:
        raise IncrementalsEvidenceError("Jenkins check does not identify the requested PR job")
    job_url = f"{_CONTROLLER}job/{family}/job/{repo[1]}/job/PR-{number}/{job[1]}/"
    _require(
        check["name"] == "Jenkins"
        and check["conclusion"] == "success"
        and check["head_sha"] == head
        and check["app"] == {"id": 74951, "slug": "ci-jenkins-io"}
        and check["details_url"] == job_url + "display/redirect",
        "Jenkins check lacks matching owner, success or exact revision",
    )
    publisher = _one(
        [
            row
            for row in data["checks"]
            if row["name"] == "Incrementals"
            and row["head_sha"] == head
            and row["conclusion"] == "success"
            and row["app"] == {"id": 164119, "slug": "jenkins-incrementals-publisher"}
        ],
        "no unique successful publisher check for the PR revision",
    )
    _require(_id(publisher["id"]), "publisher check ID is unavailable")
    registry = data["registry"]
    registry_path = registry["path"]
    namespace = (
        "org/jenkins-ci/main"
        if core
        else "(?:org/jenkins-ci/plugins(?:/workflow)?|io/jenkins/plugins)"
    )
    pom = None
    if not core and "coordinate_source" in data:
        pom = _pom_coordinate(root, data["coordinate_source"], repository, pr)
        namespace = re.escape(pom["group"].replace(".", "/"))
    coordinate = re.fullmatch(rf"/{namespace}/({_NAME})/({_NAME})/\1-\2\.(jar|hpi)", registry_path)
    if coordinate is None:
        raise IncrementalsEvidenceError("registry object is outside the expected Maven coordinate")
    artifact, version, extension = coordinate.groups()
    _require(
        (core and extension == "jar")
        or (artifact == (pom["artifact"] if pom else repo[2]) and extension == "hpi"),
        "registry artifact belongs to a different project profile",
    )
    created = _time(registry["created"])
    publisher_end = _time(publisher["completed_at"])
    _require(
        _time(check["started_at"]) <= created <= _time(check["completed_at"])
        and _time(check["started_at"]) <= publisher_end <= _time(check["completed_at"])
        and created.replace(microsecond=0) <= publisher_end,
        "registry creation and publication check fall outside the selected Jenkins job",
    )
    if "lastUpdated" in registry:
        # Artifactory reports milliseconds. GitHub checks report whole seconds.
        updated = _time(registry["lastUpdated"])
        _require(
            created <= updated and updated.replace(microsecond=0) <= publisher_end,
            "registry latest upload conflicts with the selected publication window",
        )
    directory = _REGISTRY + registry_path[1 : registry_path.rindex("/") + 1]
    links = re.findall(
        r"\]\((https://repo\.jenkins-ci\.org/incrementals/[^()\s]+)\)", publisher["summary"]
    )
    # Core uploads several modules per check. Its details URL can name another
    # module listed alongside the selected package.
    details_url = publisher["details_url"]
    check_target_matches = details_url in links if core else details_url == directory
    _require(
        registry["repo"] == "incrementals"
        and directory in links
        and check_target_matches
        and re.fullmatch(_NAME, registry["createdBy"])
        and registry["modifiedBy"] == registry["createdBy"],
        "publisher check, registry target and recorded write identity do not agree",
    )
    source = _source(root, data["source"], head, base, core)
    package = _project_file(root, "package.zip", _MAX_ARCHIVE)
    digest = hashlib.sha256(package).hexdigest()
    _require(
        digest == registry["checksums"]["sha256"] and str(len(package)) == registry["size"],
        "registry object size or checksum does not match saved package bytes",
    )
    fields = _manifest(package)
    _require(
        fields.get("implementation-build") == head
        and fields.get("implementation-version") == version,
        "published package manifest differs from the exact PR revision or version",
    )
    if pom is not None:
        _require(
            fields.get("group-id") == pom["group"]
            and fields.get("artifact-id") == fields.get("short-name") == pom["artifact"],
            "Published HPI manifest does not match the selected Maven group and artifact",
        )
        source["maven_coordinate"] = pom
    return {
        "state": "publication-observed",
        "repository": repository,
        "pr": number,
        "head_repository": pr["head_repo"],
        "head": head,
        "source": source,
        "jenkins": {
            "job_url": job_url,
            "check_id": check_id,
            "result": "success",
            "publisher_handoff": "unverified",
        },
        "publication": {
            "operation": "incrementals-registry-publication",
            "registry_actor": registry["createdBy"],
            "publisher_check_id": publisher["id"],
            "created": registry["created"],
            "object_url": _REGISTRY + registry_path[1:],
            "sha256": digest,
            "version": version,
            "manifest_revision": head,
        },
        "scope": _SCOPE,
    }


def incrementals_observation(
    snapshot: Path, root: Path, repository: str, pr: int, check_id: int
) -> _Row:
    try:
        data = json.loads(
            _read(snapshot, 256 * 1024).decode("utf-8"), object_pairs_hook=_keys, parse_int=_int
        )
        _require(data.get("schema") == "jenkins-incrementals-v1", "unsupported observation schema")
        return _assess(data, root.resolve(), repository, pr, check_id)
    except IncrementalsEvidenceError as exc:
        reason = str(exc)
    except (
        AttributeError,
        IndexError,
        KeyError,
        OSError,
        RecursionError,
        RuntimeError,
        TypeError,
        ValueError,
        zipfile.BadZipFile,
        zlib.error,
    ):
        reason = "saved job, source or package evidence is unavailable or malformed"
    return {"state": "unresolved", "reason": reason, "scope": _SCOPE}
