"""Local, checked file replacement; no multi-file transaction is implied.

Staging prevents a failed write from truncating the selected destination. A
snapshot check rejects edits observed during preparation. This is not an atomic
compare-and-swap against non-cooperating concurrent writers: the final check and
os.replace remain separate OS operations. Parent-directory replacement, hard
termination durability and external effects are outside this local contract.
"""

from __future__ import annotations

import io
import os
import stat
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import TextIO


def _identity(info: os.stat_result) -> tuple[int, int, int, int, int]:
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_mode)


@dataclass(frozen=True)
class FileSnapshot:
    path: str
    data: bytes
    identity: tuple[int, int, int, int, int]

    def lines(self) -> list[str]:
        # Match the existing UTF-8 text-mode fixers' universal newline behavior.
        return io.StringIO(self.data.decode("utf-8"), newline=None).readlines()


def read_snapshot(path: str | Path) -> FileSnapshot:
    target = os.path.abspath(path)
    before = os.lstat(target)
    if not stat.S_ISREG(before.st_mode):
        raise OSError("Refusing to replace a non-regular or symbolic-link destination")
    with open(target, "rb") as source:
        opened = os.fstat(source.fileno())
        data = source.read()
        finished = os.fstat(source.fileno())
    after = os.lstat(target)
    if not (_identity(before) == _identity(opened) == _identity(finished) == _identity(after)):
        raise OSError("Source changed while it was read; no replacement committed")
    return FileSnapshot(target, data, _identity(after))


@contextmanager
def staged_text(
    path: str | Path, *, expected: FileSnapshot | None = None
) -> Iterator[tuple[TextIO, Path]]:
    """Commit only after a successful body and unchanged selected destination.

    A missing destination must remain missing. Existing permissions are retained.
    Exceptions, including cancellation, clean the staging file and propagate.
    """
    target = Path(os.path.abspath(path))
    if expected is not None and os.path.normcase(expected.path) != os.path.normcase(str(target)):
        raise OSError("Source snapshot belongs to a different destination")
    if expected is None:
        try:
            expected = read_snapshot(target)
        except FileNotFoundError:
            pass
    descriptor, name = tempfile.mkstemp(prefix=".taintly-", suffix=".tmp", dir=target.parent)
    staged = Path(name)
    try:
        # Ownership transfers only after fdopen succeeds. A failed wrapper must
        # not leak the raw descriptor or hold its temporary path open on Windows.
        try:
            stream = os.fdopen(descriptor, "w", encoding="utf-8")
        except BaseException:
            os.close(descriptor)
            raise
        with stream as output:
            if expected is not None:
                os.chmod(staged, stat.S_IMODE(expected.identity[4]))
            yield output, staged
            output.flush()
            os.fsync(output.fileno())
        if expected is None:
            if os.path.lexists(target):
                raise OSError("Destination appeared during preparation; no replacement committed")
        else:
            current = read_snapshot(target)
            if current.identity != expected.identity or current.data != expected.data:
                raise OSError("Source changed during preparation; no replacement committed")
        os.replace(staged, target)
    finally:
        # This function owns only its exact mkstemp path, never the destination.
        try:
            staged.unlink(missing_ok=True)
        except PermissionError:
            # A staged copy of a read-only Windows destination is also read-only.
            # Adjust only this exact owned temporary file, never the destination.
            os.chmod(staged, stat.S_IRUSR | stat.S_IWUSR)
            staged.unlink(missing_ok=True)


def write_text_atomic(path: str | Path, text: str, *, expected: FileSnapshot | None = None) -> None:
    with staged_text(path, expected=expected) as (output, _):
        output.write(text)
