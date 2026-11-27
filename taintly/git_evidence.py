"""Bound, offline reads of local Git evidence."""

from __future__ import annotations

import os
import re
import subprocess  # nosec B404
from dataclasses import dataclass, field
from pathlib import Path


class GitEvidenceError(ValueError):
    """Required local Git evidence is unavailable."""


def read_local_git(root: Path, *args: str) -> bytes:
    env = {key: value for key, value in os.environ.items() if not key.upper().startswith("GIT_")}
    env.update(GIT_ALLOW_PROTOCOL="", GIT_NO_LAZY_FETCH="1", GIT_TERMINAL_PROMPT="0")
    try:
        # Callers supply read-only Git operations and bounded object reads.
        return subprocess.run(  # nosec B603 B607
            ["git", "--no-replace-objects", "-C", str(root), *args],
            env=env,
            capture_output=True,
            check=True,
            timeout=5,
        ).stdout
    except (OSError, subprocess.SubprocessError) as exc:
        raise GitEvidenceError("Required local Git evidence is unavailable") from exc


@dataclass
class GitSourceSnapshot:
    """An exact local commit, with a small cache of source paths read from it."""

    root: Path
    revision: str
    max_paths: int
    max_bytes: int
    _sources: dict[str, str | GitEvidenceError | None] = field(default_factory=dict, init=False)

    @classmethod
    def capture(cls, root: str, *, max_paths: int, max_bytes: int) -> GitSourceSnapshot:
        path = Path(root).resolve()
        top = read_local_git(path, "rev-parse", "--show-toplevel").rstrip(b"\r\n")
        if Path(os.fsdecode(top)).resolve() != path:
            raise GitEvidenceError("The scan root is not the Git repository root")
        head = read_local_git(path, "rev-parse", "--verify", "HEAD^{commit}").strip()
        if re.fullmatch(rb"[0-9a-f]{40}", head) is None:
            raise GitEvidenceError("An exact Git commit was not established")
        return cls(path, head.decode("ascii"), max_paths, max_bytes)

    def source(self, rel: str) -> str | None:
        """Read one regular file from this commit without fetching missing objects."""
        if rel in self._sources:
            cached = self._sources[rel]
            if isinstance(cached, GitEvidenceError):
                raise GitEvidenceError(str(cached))
            return cached
        if len(self._sources) >= self.max_paths:
            raise GitEvidenceError("The commit source path budget was exhausted")
        # Count even failed reads, so repeated unavailable objects remain bounded.
        try:
            text = self._read_source(rel)
        except GitEvidenceError as exc:
            self._sources[rel] = GitEvidenceError(str(exc))
            raise
        self._sources[rel] = text
        return text

    def _read_source(self, rel: str) -> str | None:
        record = read_local_git(
            self.root,
            "--literal-pathspecs",
            "ls-tree",
            "--full-tree",
            "-z",
            self.revision,
            "--",
            rel,
        )
        if not record:
            return None
        reg = rb"(?:100644|100755) blob ([0-9a-f]{40})\t" + re.escape(rel.encode("utf-8")) + rb"\0"
        match = re.fullmatch(reg, record)
        if match is None:
            raise GitEvidenceError("The commit entry is not an exact regular source file")
        blob = match[1].decode("ascii")
        size = read_local_git(self.root, "cat-file", "-s", blob).strip()
        if not size.isdigit() or int(size) > self.max_bytes:
            raise GitEvidenceError("The Git source file exceeds the byte bound")
        raw = read_local_git(self.root, "cat-file", "blob", blob)
        try:
            return raw.decode("utf-8").replace("\r\n", "\n").replace("\r", "\n")
        except UnicodeDecodeError as exc:
            raise GitEvidenceError("The Git source file is not UTF-8") from exc
