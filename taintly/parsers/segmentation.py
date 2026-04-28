"""Public segmentation primitives.

  * :func:`for_each_job` walks job segments at 1-based line ranges.
  * :func:`for_each_step` walks the per-step entries inside a job.
  * Both yield typed records (``JobSegment`` / ``StepSegment``) with
    ``name``, ``start_line``, ``end_line``, and ``body_lines``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Imported from models to keep the segmentation truth in one place.
# This is a thin wrapper that produces typed records — the heavy
# lifting still lives next to the dataclass that originally needed it.
from taintly.models import _split_into_job_segments

# Step blocks under a GitHub Actions job's ``steps:`` are sequence
# items: each begins with ``-`` at the steps-indent + 2 spaces, has
# its own keys at +4 indent, and ends when the next ``-`` appears at
# the same indent or the indent decreases below the steps block.
_STEPS_KEY_RE = re.compile(r"^(\s*)steps:\s*(#.*)?$")
_STEP_ITEM_RE = re.compile(r"^(\s*)-\s*(\S.*)?$")
# Recognise step-name keys for the optional ``name`` field.
_STEP_NAME_RE = re.compile(r"^\s*name:\s*(.+?)\s*(#.*)?$")
# Recognise step ``id:`` for the StepSegment.id field.
_STEP_ID_RE = re.compile(r"^\s*id:\s*(\S+)\s*(#.*)?$")
# GitHub job key: 2-space-indented under jobs:.  Used to extract the
# segment's job name.
_GH_JOB_NAME_RE = re.compile(r"^(\s+)([A-Za-z_][A-Za-z0-9_-]*)\s*:\s*(#.*)?$")
# GitLab job key: 0-indent.
_GL_JOB_NAME_RE = re.compile(r"^([A-Za-z_.][A-Za-z0-9_.-]*)\s*:\s*(#.*)?$")


@dataclass(frozen=True)
class JobSegment:
    """A single CI/CD job segment.

    Attributes:
        name: Job identifier (``build``, ``test``, …).  Empty string
            when the segment couldn't be associated with a job key
            (for example, the implicit pre-jobs preamble segment).
        start_line: 1-based line number of the segment's first line in
            the original file.
        end_line: 1-based line number of the segment's last line in
            the original file.  Inclusive.
        body_lines: Raw source lines for this segment, preserving the
            line endings the caller supplied (i.e. ``str.splitlines``
            equivalents — no trailing newlines).
    """

    name: str
    start_line: int
    end_line: int
    body_lines: tuple[str, ...]

    @property
    def text(self) -> str:
        """Convenience: the segment body re-joined with ``\\n``."""
        return "\n".join(self.body_lines)


@dataclass(frozen=True)
class StepSegment:
    """A single GitHub Actions step within a job.

    Attributes:
        job_name: Owning job's ``name`` (see :class:`JobSegment`).
        index: 0-based step index inside the job's ``steps:`` list.
        id: Step ``id:`` value when present, else empty string.
        display_name: Step ``name:`` value when present, else empty
            string.  Distinct from ``id`` because GitHub treats them
            as separate fields and only ``id`` is referenceable from
            ``${{ steps.<id>.outputs.<x> }}`` expressions.
        start_line: 1-based line number of the ``-`` that opened the
            step item.
        end_line: 1-based line number of the step's last line.
            Inclusive.
        body_lines: Raw source lines for this step.
    """

    job_name: str
    index: int
    id: str
    display_name: str
    start_line: int
    end_line: int
    body_lines: tuple[str, ...]

    @property
    def text(self) -> str:
        return "\n".join(self.body_lines)


def for_each_job(content: str) -> list[JobSegment]:
    """Walk job segments in ``content``.

    Returns a list because most callers want to iterate twice (once
    to count, once to process).  The list is ordered by ``start_line``.

    GitHub Actions: jobs live under the ``jobs:`` key at one indent
    level deep.  GitLab CI: jobs are 0-indent non-keyword keys.  The
    underlying segmentation handles both.

    The "preamble" segment (file content before the first job) is
    returned with ``name=""`` so callers can iterate uniformly.
    """
    lines = content.splitlines()
    raw_segments = _split_into_job_segments(lines)
    out: list[JobSegment] = []
    for seg_start, seg_lines in raw_segments:
        name = _extract_job_name(seg_lines)
        end_line = seg_start + len(seg_lines)  # 1-based inclusive
        out.append(
            JobSegment(
                name=name,
                start_line=seg_start + 1,
                end_line=end_line,
                body_lines=tuple(seg_lines),
            )
        )
    return out


def for_each_step(content: str) -> list[StepSegment]:
    """Walk every GitHub Actions step in every job in ``content``.

    Steps are GitHub-specific; GitLab and Jenkins CI don't have an
    equivalent block-list shape.  On a GitLab/Jenkins file the
    function returns ``[]`` rather than raising.

    Step boundaries follow YAML-block-sequence rules: a step begins
    at a ``-`` token indented one level past ``steps:`` and ends just
    before the next ``-`` at the same indent (or the indent dropping
    below the steps block).
    """
    out: list[StepSegment] = []
    for job in for_each_job(content):
        if not job.name:
            # Preamble segment has no job to anchor steps under.
            continue
        out.extend(_steps_in_job(job))
    return out


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


def _extract_job_name(seg_lines: list[str]) -> str:
    """Extract a job name from a segment's first meaningful line.

    The segment-splitter guarantees that for a real job segment the
    first non-blank, non-comment line is the job key.  Preamble
    segments don't have a job key — we return ``""`` for them.
    """
    for line in seg_lines:
        stripped = line.lstrip()
        if not stripped or stripped.startswith("#"):
            continue
        # GitHub Actions: indented job key under jobs:.
        m = _GH_JOB_NAME_RE.match(line)
        if m:
            return m.group(2)
        # GitLab: 0-indent job key.
        if not line.startswith(" ") and not line.startswith("\t"):
            m2 = _GL_JOB_NAME_RE.match(line)
            if m2 and m2.group(1) not in _GITLAB_NON_JOB_KEYS:
                return m2.group(1)
        # Anything else (a ``jobs:`` token from the preamble, a
        # global ``on:``, etc.) — segment doesn't represent a single job.
        return ""
    return ""


# Mirrors the keyword set in ``_split_into_job_segments`` so
# ``_extract_job_name`` doesn't claim a GitLab keyword as a job.
_GITLAB_NON_JOB_KEYS = frozenset(
    [
        "stages",
        "variables",
        "include",
        "cache",
        "default",
        "workflow",
        "image",
        "services",
        "before_script",
        "after_script",
        "spec",
        "jobs",  # GitHub's top-level jobs: header — not a job itself.
        "on",
        "name",
        "permissions",
        "env",
        "concurrency",
        "defaults",
    ]
)


def _steps_in_job(job: JobSegment) -> list[StepSegment]:
    """Walk the steps of a single GitHub Actions job segment."""
    steps: list[StepSegment] = []
    lines = list(job.body_lines)
    steps_anchor: int | None = None
    steps_indent: int | None = None
    for idx, line in enumerate(lines):
        m = _STEPS_KEY_RE.match(line)
        if m:
            steps_anchor = idx
            steps_indent = len(m.group(1))
            break
    if steps_anchor is None or steps_indent is None:
        return steps

    # Walk forward from the line after ``steps:``.  A step starts with
    # a ``-`` at indent > steps_indent; the step body extends until the
    # next such ``-`` or the indent drops to ``<= steps_indent`` on a
    # non-blank line.
    item_indent: int | None = None
    current_start: int | None = None
    current_lines: list[str] = []
    step_index_counter = 0

    def _flush():
        nonlocal current_start, current_lines, step_index_counter
        if current_start is None or not current_lines:
            return
        seg_id, seg_name = _extract_step_meta(current_lines)
        # Convert segment-local indices to file-absolute 1-based line numbers.
        abs_start = job.start_line + current_start
        abs_end = job.start_line + current_start + len(current_lines) - 1
        steps.append(
            StepSegment(
                job_name=job.name,
                index=step_index_counter,
                id=seg_id,
                display_name=seg_name,
                start_line=abs_start,
                end_line=abs_end,
                body_lines=tuple(current_lines),
            )
        )
        step_index_counter += 1
        current_start = None
        current_lines = []

    for idx in range(steps_anchor + 1, len(lines)):
        line = lines[idx]
        stripped = line.lstrip()
        if not stripped:
            # Blank line belongs to the current step (if any).
            if current_start is not None:
                current_lines.append(line)
            continue
        indent = len(line) - len(stripped)
        if indent <= steps_indent:
            # Left the steps block.
            _flush()
            break
        m = _STEP_ITEM_RE.match(line)
        if m and (item_indent is None or indent == item_indent):
            # New step.
            _flush()
            item_indent = indent
            current_start = idx
            current_lines = [line]
            continue
        if current_start is not None:
            current_lines.append(line)

    _flush()
    return steps


def _extract_step_meta(step_lines: list[str]) -> tuple[str, str]:
    """Return ``(id, display_name)`` for a step.

    Only inspects keys at the same indent level as the step's first
    body line — this avoids picking up an ``id:`` or ``name:`` from a
    nested ``with:`` block.
    """
    if not step_lines:
        return ("", "")
    # Determine the step's body indent from the first non-``-`` line,
    # or from the same line as ``-`` when keys share that line.
    body_indent: int | None = None
    for line in step_lines:
        stripped = line.lstrip()
        if not stripped or stripped.startswith("#"):
            continue
        # The first line is the ``- ...`` opener; its body indent for
        # a multi-line step is len("- "); for a single-line step
        # (``- run: foo``) body_indent is the same line and there are
        # no separate sibling keys to scan.
        indent = len(line) - len(stripped)
        body_indent = indent + 2 if stripped.startswith("- ") else indent
        break
    if body_indent is None:
        return ("", "")

    seg_id = ""
    seg_name = ""
    for line in step_lines[1:]:
        stripped = line.lstrip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(line) - len(stripped)
        if indent != body_indent:
            continue
        m_id = _STEP_ID_RE.match(line)
        if m_id and not seg_id:
            seg_id = m_id.group(1)
            continue
        m_name = _STEP_NAME_RE.match(line)
        if m_name and not seg_name:
            # Strip surrounding quotes from name values when present.
            val = m_name.group(1).strip()
            if (val.startswith("'") and val.endswith("'")) or (
                val.startswith('"') and val.endswith('"')
            ):
                val = val[1:-1]
            seg_name = val
    # Also handle the ``- name: ...`` / ``- id: ...`` opener case.
    first = step_lines[0].lstrip()
    if first.startswith("- "):
        rest = first[2:]
        m_id = _STEP_ID_RE.match("  " + rest)  # synth indent for re
        if m_id and not seg_id:
            seg_id = m_id.group(1)
        m_name = _STEP_NAME_RE.match("  " + rest)
        if m_name and not seg_name:
            val = m_name.group(1).strip()
            if (val.startswith("'") and val.endswith("'")) or (
                val.startswith('"') and val.endswith('"')
            ):
                val = val[1:-1]
            seg_name = val
    return (seg_id, seg_name)
