"""Corroborate a saved Go coverage source panel without rendering the archive."""

from __future__ import annotations

import re
import stat
from hashlib import sha1, sha256
from io import BytesIO
from pathlib import Path
from typing import Any
from urllib.parse import quote
from zipfile import ZIP_DEFLATED, ZIP_STORED, BadZipFile, ZipFile
from zlib import error as CompressionError

from taintly.ingestion.gitlab_registry_job import (
    _SHA,
    RegistryJobError,
    _source_bytes,
    _value,
)

_COMPONENT = r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}"
_PATH = re.compile(rf"{_COMPONENT}(?:/{_COMPONENT}){{0,15}}")
_Row = dict[str, Any]
_MAX_HTML = 10_000_000
_MAX_SOURCE = 131_072
_SCOPE = (
    "The retrieved ZIP contains one coverage panel matching the fork file's displayed source. "
    "The parent file displays differently. This does not establish execution, the generator's "
    "identity, other file origins, current access, or authority in the MR target project."
)
_OPAQUE = re.compile(rb"<(?:script|template|iframe|xmp|textarea|plaintext)\b", re.I)
_MARKUP = re.compile(rb'<span class="cov[0-9]{1,2}" title="[0-9]{1,12}">|</span>')


def _require(condition: object, reason: str) -> None:
    if not condition:
        raise RegistryJobError(reason)


def _source(
    root: Path, claim: _Row, project: int, path: str, rev: str, name: str
) -> tuple[bytes, str]:
    url = f"https://gitlab.com/api/v4/projects/{project}/repository/files/{quote(path, safe='')}?ref={rev}"
    raw = _source_bytes(root, root / name, "pinned coverage source", max_bytes=_MAX_SOURCE)
    blob = sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw, usedforsecurity=False).hexdigest()
    _require(
        claim["url"] == url
        and claim["commit"] == rev
        and claim["file_path"] == path
        and type(claim["size"]) is int
        and claim["size"] == len(raw)
        and claim["blob_id"] == blob
        and claim["sha256"] == sha256(raw).hexdigest()
        and raw,
        "saved coverage source does not match its project, Git revision, file or blob",
    )
    # The Go coverage renderer emits eight spaces for each tab. Keep all
    # other bytes unchanged, including newline style.
    raw.decode("utf-8")
    return raw.replace(b"\t", b" " * 8), blob


def _panel(html: bytes, label: bytes) -> bytes:
    # The renderer places its selector before a dedicated panel container,
    # and its JavaScript after it. Opaque HTML in either region is unsupported.
    container = b'<div id="content">'
    _require(html.count(container) == 1, "coverage panel container is missing or ambiguous")
    prefix, _, content = html.partition(container)
    body, close, _ = content.partition(b"</div>")
    _require(
        close
        and b"<!--" not in prefix
        and b"<!--" not in body
        and not any(_OPAQUE.search(part) for part in (prefix, body)),
        "coverage HTML is outside the supported static renderer layout",
    )
    start = b'<select id="files">'
    _require(prefix.count(start) == 1, "coverage file selector is missing or ambiguous")
    options, end, _ = prefix.split(start, 1)[1].partition(b"</select>")
    _require(end and len(options) <= 1_000_000, "coverage selector is unsupported")
    choices = re.findall(
        rb'<option value="(file[0-9]{1,6})">'
        + re.escape(label)
        + rb" \([0-9]{1,3}(?:\.[0-9]+)?%\)</option>",
        options,
    )
    _require(len(choices) == 1, "coverage file selection is missing or ambiguous")
    _require(
        options.count(b'<option value="' + choices[0] + b'">') == 1,
        "selected coverage file identifier is reused",
    )
    marker = b'<pre class="file" id="' + choices[0] + b'" style="display: none">'
    _require(body.count(marker) == 1, "selected coverage panel is missing or ambiguous")
    text, end, _ = body.split(marker, 1)[1].partition(b"</pre>")
    _require(end and len(text) <= 1_000_000, "selected coverage panel is unsupported")
    depth = 0
    parts = []
    offset = 0
    for markup in _MARKUP.finditer(text):
        part = text[offset : markup.start()]
        _require(b"<" not in part and b">" not in part, "unsupported markup in coverage source")
        parts.append(part)
        depth += -1 if markup[0] == b"</span>" else 1
        _require(0 <= depth <= 1, "coverage source markup is unbalanced")
        offset = markup.end()
    tail = text[offset:]
    _require(
        not depth and b"<" not in tail and b">" not in tail, "unsupported markup in coverage source"
    )
    parts.append(tail)
    escaped = b"".join(parts)
    _require(
        re.search(rb"&(?!amp;|lt;|gt;)", escaped) is None,
        "coverage source uses unsupported HTML escapes",
    )
    return escaped.replace(b"&gt;", b">").replace(b"&lt;", b"<").replace(b"&amp;", b"&")


def coverage_source_observation(
    data: _Row, root: Path, verified_zip: bytes | None, result: _Row
) -> _Row:
    """Compare one Go coverage panel to its saved source and parent blobs."""
    if verified_zip is None:
        return {
            "state": "unresolved",
            "reason": "same-job archive retrieval has not been established",
            "scope": _SCOPE,
        }
    try:
        evidence = data["archive_member_origin"]
        _require(evidence["format"] == "go-cover-html-v1", "unsupported archived source format")
        project, revision = result["project"], result["revision"]
        parents = data["commit"]["parent_ids"]
        _require(
            isinstance(parents, list) and len(parents) == 1, "source commit lacks a unique parent"
        )
        parent = _value(parents[0], _SHA, "pinned parent commit")
        _require(parent != revision, "source and parent revisions are identical")
        path = _value(evidence["path"], _PATH, "coverage source path")
        package = _value(evidence["package"], _PATH, "coverage package")
        directory, _, filename = path.rpartition("/")
        member = _value(evidence["member"], _PATH, "coverage archive member")
        _require(
            path.endswith(".go")
            and member.endswith(".html")
            and (not directory or package.endswith("/" + directory) or package == directory),
            "coverage label does not identify the saved Go file",
        )
        fork, blob = _source(
            root, evidence["source"], project, path, revision, "coverage-source.go"
        )
        previous, _ = _source(root, evidence["parent"], project, path, parent, "coverage-parent.go")
        _require(fork != previous, "fork and parent source are identical in the coverage display")
        with ZipFile(BytesIO(verified_zip)) as archive:
            entries = archive.infolist()
            matches = [entry for entry in entries if entry.filename == member]
            _require(
                len(entries) <= 2048 and len(matches) == 1,
                "coverage ZIP member is missing or ambiguous",
            )
            item = matches[0]
            _require(
                item.orig_filename == member
                and 0 < item.file_size <= _MAX_HTML
                and not item.flag_bits & 1
                and item.compress_type in {ZIP_STORED, ZIP_DEFLATED}
                and stat.S_IFMT(item.external_attr >> 16) in {0, stat.S_IFREG},
                "coverage ZIP member exceeds bounds or uses an unsupported file type",
            )
            with archive.open(item) as reader:
                html = reader.read(_MAX_HTML + 1)
        _require(
            len(html) == item.file_size, "coverage member length disagrees with the ZIP header"
        )
        rendered = _panel(html, f"{package}/{filename}".encode("ascii"))
        _require(rendered == fork, "coverage display source does not match the pinned fork file")
        return {
            "state": "fork-source-display-matched",
            "member": member,
            "member_sha256": sha256(html).hexdigest(),
            "archive_sha256": result["archive_download"]["sha256"],
            "path": path,
            "package": package,
            "source_blob": blob,
            "revision": revision,
            "parent": parent,
            "display_sha256": sha256(rendered).hexdigest(),
            "scope": _SCOPE,
        }
    except RegistryJobError as error:
        reason = str(error)
    except (
        AttributeError,
        BadZipFile,
        CompressionError,
        KeyError,
        OSError,
        RuntimeError,
        TypeError,
        ValueError,
    ):
        reason = "saved ZIP or coverage-source evidence is malformed or unsupported"
    return {"state": "unresolved", "reason": reason, "scope": _SCOPE}
