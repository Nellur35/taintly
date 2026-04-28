"""Core data models for taintly."""

from __future__ import annotations

import os
import re
import signal
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Protocol, runtime_checkable


class _PatternTimeout(Exception):
    """Raised when a pattern match exceeds the safety timeout."""


_MAX_SAFE_TEXT_LEN = 50_000  # chars; skip regex beyond this to prevent ReDoS in threads

# YAML boolean representations per the YAML 1.1 spec (used by PyYAML / most CI parsers).
# GitHub Actions convention is true/false, but rules should tolerate all valid forms.
# Uses (?i:...) inline-group syntax so these can be safely embedded in larger patterns.
_YAML_BOOL_TRUE = r"(?i:true|yes|on|y|1|'true'|\"true\"|'yes'|\"yes\"|'on'|\"on\"|'1'|\"1\")"
_YAML_BOOL_FALSE = r"(?i:false|no|off|n|0|'false'|\"false\"|'no'|\"no\"|'off'|\"off\"|'0'|\"0\")"


def _pattern_timeout_handler(signum, frame):
    raise _PatternTimeout()


class scan_session:
    """Install the SIGALRM timeout handler for the duration of a scan.

    Use as a context manager around a loop that calls _safe_search many
    times (engine.scan_file does this). Inside the session, _safe_search
    detects our handler is already installed and skips the per-call
    swap — a measurable win on scans of many rules × many files.

    Outside the session, _safe_search falls back to its own
    swap-and-restore path so ad-hoc callers still get correctness.

    No-op off POSIX main-thread.
    """

    def __enter__(self):
        self._installed = False
        if os.name != "posix":
            return self
        try:
            self._old_handler = signal.signal(signal.SIGALRM, _pattern_timeout_handler)
        except (ValueError, OSError):
            return self
        self._installed = True
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if not self._installed:
            return
        signal.alarm(0)
        signal.signal(signal.SIGALRM, self._old_handler)


def _safe_search(compiled_pattern, text: str):
    """Run a compiled regex search with ReDoS / CPU-exhaustion protection.

    Two defenses stacked so no single path is load-bearing:

      (1) Unconditional text-length cap. Adversarial content longer than
          _MAX_SAFE_TEXT_LEN is skipped before the regex engine sees it.
          A legitimate CI/CD workflow file does not exceed 50KB, so the
          precision cost is effectively zero. This fires on every call path
          — POSIX main-thread, POSIX non-main-thread, Windows — so it
          cannot be bypassed by picking the wrong thread context.

      (2) SIGALRM-backed 5-second timeout on POSIX main-thread. The handler
          is a module-level function (not a per-call closure), so the hot
          path avoids repeatedly allocating a new callable. We still
          save/restore the previous handler so we coexist with outer
          SIGALRM users (pytest-timeout's signal method, uvicorn workers,
          supervisors) rather than stomping their handler.

    Returns None on timeout or cap hit (treat as "pattern did not match").
    """
    # (1) Length cap applies unconditionally.
    if len(text) > _MAX_SAFE_TEXT_LEN:
        return None

    if os.name != "posix":
        return compiled_pattern.search(text)

    # (2) SIGALRM timeout on POSIX main-thread. signal.signal() raises
    # ValueError outside main-thread; fall through to unprotected search
    # (length cap in (1) already bounded the input).
    #
    # Optimisation: only swap the handler if the currently-installed one
    # is not already ours. Inside a tight scan loop this elides two
    # syscalls per regex call after the first, without breaking outer
    # SIGALRM users (pytest-timeout's signal mode, uvicorn, supervisors)
    # because we still observe and restore their handler on the first
    # call into each entry.
    try:
        current = signal.getsignal(signal.SIGALRM)
    except (ValueError, OSError):
        return compiled_pattern.search(text)

    need_swap = current is not _pattern_timeout_handler
    old_handler = current
    if need_swap:
        try:
            signal.signal(signal.SIGALRM, _pattern_timeout_handler)
        except (ValueError, OSError):
            return compiled_pattern.search(text)
    signal.alarm(5)
    try:
        return compiled_pattern.search(text)
    except _PatternTimeout:
        return None
    finally:
        signal.alarm(0)
        if need_swap:
            signal.signal(signal.SIGALRM, old_handler)


# =============================================================================
# Enums
# =============================================================================


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        return {
            Severity.CRITICAL: 4,
            Severity.HIGH: 3,
            Severity.MEDIUM: 2,
            Severity.LOW: 1,
            Severity.INFO: 0,
        }[self]

    def __ge__(self, other):
        return self.rank >= other.rank

    def __gt__(self, other):
        return self.rank > other.rank

    def __le__(self, other):
        return self.rank <= other.rank

    def __lt__(self, other):
        return self.rank < other.rank


class Platform(str, Enum):
    GITHUB = "github"
    GITLAB = "gitlab"
    JENKINS = "jenkins"


class Confidence(str, Enum):
    """Rule precision hint.

    Used by the reporter and scorer to weigh findings whose underlying rule
    is known to be noise-prone (secret detection, shallow taint analysis,
    context-free triggers) against rules with exact syntactic matches.
    """

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def weight(self) -> float:
        return {
            Confidence.HIGH: 1.0,
            Confidence.MEDIUM: 0.6,
            Confidence.LOW: 0.3,
        }[self]


# =============================================================================
# Pattern Types — declarative matching logic
# =============================================================================


@dataclass
class RegexPattern:
    """Match a regex against individual lines.

    Line-level excludes (`exclude=[...]`) handle most same-line
    suppressions (YAML comment lines, single/double-quoted contexts).

    Multi-line heredoc context is handled via `heredoc_aware=True`.
    When set, the check method pre-scans `lines` for quoted heredoc
    openers (`<<'EOF'` / `<<"EOF"` / `<<\\EOF`) and masks the body
    lines before applying the regex — per Bash manual §3.6.6, quoted-
    marker heredocs suppress parameter/command/arithmetic expansion
    on the body, so any rule targeting expansion shapes (unquoted
    `$VAR` etc.) must ignore those lines. Unquoted heredocs (`<<EOF`)
    DO expand; their bodies are not masked.
    """

    match: str
    exclude: list[str] = field(default_factory=list)
    heredoc_aware: bool = False

    def __post_init__(self):
        self._compiled = re.compile(self.match)
        self._excludes = [re.compile(e) for e in self.exclude]

    # CONTRACT: returns (line_num, snippet) where snippet is
    # ``lines[line_num-1].strip()`` — the line whose contents matched
    # ``self.match``.  See taintly._pattern_contract for the executable
    # form of this contract.
    def check(self, content: str, lines: list[str]) -> list[tuple[int, str]]:
        skip = _quoted_heredoc_body_lines(lines) if self.heredoc_aware else set()
        results = []
        for i, line in enumerate(lines):
            if i in skip:
                continue
            if any(ex.search(line) for ex in self._excludes):
                continue
            if _safe_search(self._compiled, line):
                results.append((i + 1, line.strip()))
        return results


_QUOTED_HEREDOC_OPENER = re.compile(
    # <<'EOF' or <<"EOF" or <<\EOF — all three forms suppress
    # expansion per Bash §3.6.6. Optional leading `-` allowed
    # (tab-stripping variant <<-).
    r"<<-?\s*(?:'(\w+)'|\"(\w+)\"|\\(\w+))"
)


def _quoted_heredoc_body_lines(lines: list[str]) -> set[int]:
    """Return 0-based indices of lines inside a quoted-marker heredoc body.

    Walks `lines` once, tracks whether we're inside a heredoc, and
    collects body line indices (not the opener, not the closer). Only
    quoted markers suppress expansion, so only their bodies are
    returned; an unquoted `<<EOF` opener is ignored.
    """
    skip: set[int] = set()
    marker: str | None = None
    for i, line in enumerate(lines):
        if marker is None:
            m = _QUOTED_HEREDOC_OPENER.search(line)
            if m:
                marker = m.group(1) or m.group(2) or m.group(3)
            continue
        if line.strip() == marker:
            marker = None
            continue
        skip.add(i)
    return skip


@dataclass
class AbsencePattern:
    """Trigger when file does NOT contain a pattern."""

    absent: str
    scope: str = "file"  # "file" or "top_level"

    def __post_init__(self):
        self._compiled = re.compile(self.absent, re.MULTILINE)

    # CONTRACT: returns line_num=1 with a sentinel snippet because
    # absence has no per-line evidence — the rule fired because the
    # whole file lacks ``self.absent``.  The contract test treats this
    # as a documented exception.
    def check(self, content: str, lines: list[str]) -> list[tuple[int, str]]:
        if not _safe_search(self._compiled, content):
            return [(1, f"(pattern not found: {self.absent})")]
        return []


def _split_into_job_segments(lines: list[str]) -> list[tuple[int, list[str]]]:
    """Split a CI/CD config into per-job segments for scoped ContextPattern checks.

    Returns a list of (start_line_index, segment_lines) pairs where start_line_index
    is the 0-based index of the first line of the segment in the original file.

    Strategy:
    - GitHub Actions: job names live at 2-space indent directly under the ``jobs:``
      top-level key. Each 2-space-indented key inside that block starts a new segment.
    - GitLab CI: jobs are 0-indent keys that are not reserved keywords. Each such key
      starts a new segment.
    - Falls back to a single segment covering the whole file if neither pattern is found.

    The pre-job content (``on:``, ``name:``, global ``permissions:``, etc.) is included
    in the first segment so that file-level context is preserved.
    """
    _GITLAB_KEYWORDS = frozenset(
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
            # Pipeline-inputs block (GitLab 15.7+): declares typed inputs at
            # the top level of the file. Not a job — must not produce its own
            # segment or ContextPattern(scope=job) rules fire twice.
            "spec",
        ]
    )
    _JOB_KEY = re.compile(r"^(\s*)[a-zA-Z_][a-zA-Z0-9_-]*\s*:")

    # Detect GitHub Actions by presence of a top-level ``jobs:`` key.
    has_jobs_key = any(re.match(r"^jobs:\s*(#.*)?$", line) for line in lines)

    segments: list[tuple[int, list[str]]] = []
    current_start = 0
    current: list[str] = []

    if has_jobs_key:
        in_jobs_block = False
        job_indent: int | None = None  # auto-detected from first job line
        for idx, line in enumerate(lines):
            stripped = line.lstrip()
            indent = len(line) - len(stripped)

            if re.match(r"^jobs:\s*(#.*)?$", line):
                in_jobs_block = True
                current.append(line)
                continue

            if in_jobs_block:
                if indent == 0 and stripped and not stripped.startswith("#"):
                    # Left the jobs block entirely (e.g. a trailing top-level key)
                    in_jobs_block = False
                    current.append(line)
                elif indent > 0 and stripped and not stripped.startswith("#"):
                    # Auto-detect job indent from the first non-comment key under jobs:
                    if job_indent is None:
                        job_indent = indent
                    if indent == job_indent:
                        # New job definition at the detected indent level
                        if current:
                            segments.append((current_start, current))
                        current_start = idx
                        current = [line]
                    else:
                        current.append(line)
                else:
                    current.append(line)
            else:
                current.append(line)

        if current:
            segments.append((current_start, current))

    else:
        # GitLab CI: split at 0-indent non-keyword job keys.
        # Hidden-job templates (`.build:`) are YAML anchors / extendable
        # fragments, not runnable jobs, and `spec:` is the pipeline-inputs
        # block. Neither must produce its own segment, or every
        # ContextPattern(scope=job) rule fires twice on every templated
        # pipeline. We track these so we can drop any segment whose own
        # first meaningful line is one of these non-job keys.
        def _is_non_job_key(k: str) -> bool:
            return k in _GITLAB_KEYWORDS or k.startswith(".")

        for idx, line in enumerate(lines):
            stripped = line.lstrip()
            indent = len(line) - len(stripped)
            if indent == 0 and stripped and not stripped.startswith("#") and ":" in stripped:
                key = stripped.split(":")[0].strip()
                if not _is_non_job_key(key):
                    if current:
                        segments.append((current_start, current))
                    current_start = idx
                    current = [line]
                    continue
            current.append(line)

        if current:
            segments.append((current_start, current))

        # Drop any segment whose first meaningful line is itself a
        # non-job key (e.g. a hidden template `.build:` or `spec:`
        # block that sat above the first real job).
        def _segment_is_job(seg: list[str]) -> bool:
            for line in seg:
                s = line.lstrip()
                if not s or s.startswith("#"):
                    continue
                indent = len(line) - len(s)
                if indent != 0 or ":" not in s:
                    return True
                key = s.split(":")[0].strip()
                return not _is_non_job_key(key)
            # Blank / comment-only segment — keep as-is (harmless).
            return True

        filtered = [(start, seg) for start, seg in segments if _segment_is_job(seg)]
        # If filtering dropped segments, trust the filtered list even at
        # length 1: the file really did contain only template / spec
        # content in the preamble plus exactly one real job.
        if filtered and len(filtered) != len(segments):
            return filtered
        segments = filtered

    return segments if len(segments) > 1 else [(0, lines)]


@dataclass
class ContextPattern:
    """Trigger when BOTH anchor AND requires patterns exist in the same file.

    Optionally, requires_absent can specify a pattern that must NOT be present
    in the file for the rule to fire (useful for "A without B" checks).

    When ``scope="job"`` the co-occurrence check is narrowed to individual job
    segments (identified by ``_split_into_job_segments``).  Use this for rules
    where both ``anchor`` and ``requires`` are job-level content — it prevents
    false positives from two unrelated jobs satisfying the pattern across a
    multi-job workflow.  Do NOT use ``scope="job"`` for rules where either
    pattern lives in the top-level ``on:`` / trigger section, as those patterns
    will not appear in any job segment and the rule will never fire.
    """

    anchor: str
    requires: str
    requires_absent: str = ""  # If set, file must NOT contain this for rule to fire
    exclude: list[str] = field(default_factory=list)
    scope: str = "file"  # "file" (default) or "job"
    anchor_job_exclude: str = (
        ""  # If set, suppress anchor matches found in a job segment that contains this pattern
    )

    def __post_init__(self):
        self._anchor_re = re.compile(self.anchor)
        self._requires_re = re.compile(self.requires)
        self._requires_absent_re = (
            re.compile(self.requires_absent) if self.requires_absent else None
        )
        self._excludes = [re.compile(e) for e in self.exclude]
        self._anchor_job_exclude_re = (
            re.compile(self.anchor_job_exclude) if self.anchor_job_exclude else None
        )

    # CONTRACT: returns (line_num, snippet) where snippet is the
    # ``.strip()``'d anchor line — the line whose contents matched
    # ``self.anchor`` (NOT the requires line, NOT the requires_absent
    # line).  When ``scope='job'``, the line cited is the anchor line
    # within the job segment that satisfies both anchor and requires.
    def check(self, content: str, lines: list[str]) -> list[tuple[int, str]]:
        if self.scope == "job":
            return self._check_job_scoped(lines)
        return self._check_file_scoped(content, lines)

    def _check_file_scoped(self, content: str, lines: list[str]) -> list[tuple[int, str]]:
        if not _safe_search(self._requires_re, content):
            return []
        if self._requires_absent_re and _safe_search(self._requires_absent_re, content):
            return []

        # Build per-line job-segment content map if we need per-job anchor suppression.
        job_content_by_line: dict[int, str] = {}
        if self._anchor_job_exclude_re:
            for seg_start, seg_lines in _split_into_job_segments(lines):
                seg_content = "\n".join(seg_lines)
                for j in range(len(seg_lines)):
                    job_content_by_line[seg_start + j] = seg_content

        results = []
        for i, line in enumerate(lines):
            if any(ex.search(line) for ex in self._excludes):
                continue
            if _safe_search(self._anchor_re, line):
                if self._anchor_job_exclude_re:
                    seg_content = job_content_by_line.get(i, "")
                    if seg_content and _safe_search(self._anchor_job_exclude_re, seg_content):
                        continue
                results.append((i + 1, line.strip()))
        return results

    def _check_job_scoped(self, lines: list[str]) -> list[tuple[int, str]]:
        """Check co-occurrence within each job segment independently."""
        results = []
        for seg_start, seg_lines in _split_into_job_segments(lines):
            seg_content = "\n".join(seg_lines)
            if not _safe_search(self._requires_re, seg_content):
                continue
            if self._requires_absent_re and _safe_search(self._requires_absent_re, seg_content):
                continue
            for j, line in enumerate(seg_lines):
                if any(ex.search(line) for ex in self._excludes):
                    continue
                if _safe_search(self._anchor_re, line):
                    results.append((seg_start + j + 1, line.strip()))
        return results


@dataclass
class SequencePattern:
    """Trigger when pattern_a appears WITHOUT pattern_b within N following lines."""

    pattern_a: str
    absent_within: str
    lookahead_lines: int = 10
    exclude: list[str] = field(default_factory=list)

    def __post_init__(self):
        self._a_re = re.compile(self.pattern_a)
        self._b_re = re.compile(self.absent_within)
        self._excludes = [re.compile(e) for e in self.exclude]

    # CONTRACT: returns (line_num, snippet) where snippet is the
    # ``.strip()``'d FIRST line of the matched sequence — the line
    # that matched ``self.pattern_a``.  The absent_within window
    # extends beyond it but is not cited.
    def check(self, content: str, lines: list[str]) -> list[tuple[int, str]]:
        results = []
        for i, line in enumerate(lines):
            if any(ex.search(line) for ex in self._excludes):
                continue
            if _safe_search(self._a_re, line):
                window = "\n".join(lines[i : i + self.lookahead_lines])
                if not _safe_search(self._b_re, window):
                    results.append((i + 1, line.strip()))
        return results


@dataclass
class BlockPattern:
    """Trigger when pattern exists within the scope of a YAML block."""

    block_anchor: str
    match: str
    exclude: list[str] = field(default_factory=list)

    def __post_init__(self):
        self._anchor_re = re.compile(self.block_anchor)
        self._match_re = re.compile(self.match)
        self._excludes = [re.compile(e) for e in self.exclude]

    # CONTRACT: returns (line_num, snippet) where snippet is the
    # ``.strip()``'d line WITHIN the block that matched ``self.match``
    # (not the block_anchor line that opened the block).
    def check(self, content: str, lines: list[str]) -> list[tuple[int, str]]:
        results = []
        in_block = False
        block_indent = 0
        for i, line in enumerate(lines):
            if any(ex.search(line) for ex in self._excludes):
                continue
            stripped = line.lstrip()
            current_indent = len(line) - len(stripped)
            if _safe_search(self._anchor_re, line):
                in_block = True
                block_indent = current_indent
                continue
            if in_block:
                if stripped and current_indent <= block_indent:
                    in_block = False
                elif _safe_search(self._match_re, line):
                    results.append((i + 1, line.strip()))
        return results


@dataclass
class PathPattern:
    """Match against extracted YAML paths rather than raw text lines.

    Fires when a YAML key at a path matching ``path`` has a value matching
    ``value``.  Optionally fires only when no sibling key matching
    ``sibling_absent`` exists at the *same parent path* — enabling precise
    "key present but expected companion absent" checks without line-window
    heuristics.

    Example — unconstrained workflow_dispatch string input::

        PathPattern(
            path=r"on\\.workflow_dispatch\\.inputs\\.[^.]+\\.type",
            value=r"^string$",
            sibling_absent=r"options",   # fire only if .options is absent
        )

    The ``sibling_absent`` check is path-aware: it looks for
    ``<parent_path>.<sibling_absent>`` in the full extracted path list, not
    just in nearby lines.  This avoids false positives when another sibling
    block happens to contain the absent key.
    """

    path: str  # Regex matched against the dot-path string
    value: str  # Regex matched against the scalar value
    sibling_absent: str = ""  # Key name (regex) that must be absent from same parent path
    exclude: list[str] = field(default_factory=list)

    def __post_init__(self):
        self._path_re = re.compile(self.path)
        self._value_re = re.compile(self.value)
        self._sibling_re = re.compile(self.sibling_absent) if self.sibling_absent else None
        self._excludes = [re.compile(e) for e in self.exclude]

    # CONTRACT: returns (line_num, snippet) where line_num is the
    # ``yaml_path.extract_paths`` lineno for the matching key, and
    # snippet is ``lines[line_num-1].strip()`` (or the value itself
    # when the source line is blank).
    def check(self, content: str, lines: list[str]) -> list[tuple[int, str]]:
        from .yaml_path import extract_paths

        all_paths = extract_paths(content)
        # Build a set of all emitted paths for fast sibling lookup
        path_set = {p for p, _, _ in all_paths}

        results = []
        for path, value, lineno in all_paths:
            # Empty-value entries are block headers — skip for value matching
            # but they ARE in path_set for sibling-absence checks above.
            if not value:
                continue
            if not _safe_search(self._path_re, path):
                continue
            if not _safe_search(self._value_re, value):
                continue

            source_line = lines[lineno - 1] if 0 < lineno <= len(lines) else ""
            if any(ex.search(source_line) for ex in self._excludes):
                continue

            # sibling_absent: fire only when the sibling key does NOT exist
            # at the same parent path level.
            if self._sibling_re:
                # Parent path = everything before the last dot-component
                parent = path.rsplit(".", 1)[0] if "." in path else ""
                sibling_exists = any(
                    p.startswith(parent + ".")
                    and _safe_search(self._sibling_re, p[len(parent) + 1 :].split(".")[0])
                    for p in path_set
                    if p != path and p.startswith(parent + ".")
                )
                if sibling_exists:
                    continue

            results.append((lineno, source_line.strip() or value))

        return results


# Pattern contract — any object exposing ``check(content, lines)``
# returning ``list[tuple[int, str]]``. Structural typing (Protocol) so
# TaintPattern instances from the per-platform taint modules qualify
# without circular imports.
@runtime_checkable
class PatternProtocol(Protocol):
    def check(self, content: str, lines: list[str]) -> list[tuple[int, str]]: ...


# Union kept for explicit concrete references; Rule.pattern accepts
# any PatternProtocol implementor (including TaintPattern).
PatternType = (
    RegexPattern | AbsencePattern | ContextPattern | SequencePattern | BlockPattern | PathPattern
)


# =============================================================================
# CompromisedActionPattern — match `uses: <pkg>@<ref>` against the
# bundled compromised-actions advisory list.
# =============================================================================


_USES_REF_RE = re.compile(r"uses:\s*([^@\s]+)@(\S+)")
_USES_COMMENT_RE = re.compile(r"^\s*#")


@dataclass
class CompromisedActionPattern:
    """Fire when a workflow uses a specific known-compromised action@ref.

    Walks each line for ``uses: <pkg>@<ref>`` and checks the (pkg, ref)
    pair against ``advisories.load_bundled_advisories()``.  When the ref
    falls in an advisory's affected version range, the line is reported
    with the GHSA ID and CVE in the match text so the finding's ``Code:``
    field surfaces the advisory link directly.

    Refs that are not parseable as semver (branch names, full / short
    SHAs) do not fire — see ``advisories._parse_ref`` for the rejection
    rules.  ``SEC3-GH-001`` already warns about branch / tag pinning;
    this rule is specifically about exact known-bad refs.
    """

    exclude: list[str] = field(default_factory=list)

    def __post_init__(self):
        self._excludes = [re.compile(e) for e in self.exclude]

    # CONTRACT: returns (line_num, snippet) where snippet is the
    # ``.strip()``'d ``uses: <pkg>@<ref>`` line annotated with the
    # matching GHSA / CVE list — the line whose pinned reference fell
    # in an advisory's affected range.
    def check(self, content: str, lines: list[str]) -> list[tuple[int, str]]:
        from .advisories import find_advisories_for

        results: list[tuple[int, str]] = []
        for i, line in enumerate(lines):
            if _USES_COMMENT_RE.match(line):
                continue
            if any(ex.search(line) for ex in self._excludes):
                continue
            m = _USES_REF_RE.search(line)
            if not m:
                continue
            pkg, ref = m.group(1), m.group(2).split("#", 1)[0].strip()
            advisories = find_advisories_for(pkg, ref)
            if not advisories:
                continue
            ghsa_list = ", ".join(f"{a.ghsa} ({a.cve})" if a.cve else a.ghsa for a in advisories)
            results.append((i + 1, f"{line.strip()}  [{ghsa_list}]"))
        return results


# =============================================================================
# Rule Definition
# =============================================================================


@dataclass
class Rule:
    """A single security audit rule."""

    id: str
    title: str
    severity: Severity
    platform: Platform
    owasp_cicd: str
    description: str
    pattern: PatternProtocol
    remediation: str
    reference: str
    test_positive: list[str] = field(default_factory=list)
    test_negative: list[str] = field(default_factory=list)
    # STRIDE threat-modelling metadata
    stride: list[str] = field(default_factory=list)
    """Primary STRIDE categories, primary first.
    S=Spoofing, T=Tampering, R=Repudiation, I=Information Disclosure,
    D=Denial of Service, E=Elevation of Privilege."""
    threat_narrative: str = ""
    """1-2 sentence attack story: what the attacker does and what the impact is."""
    incidents: list[str] = field(default_factory=list)
    """Real-world incidents or CVEs where this pattern was exploited."""
    # ------------------------------------------------------------------
    # Reporting v2 metadata
    # ------------------------------------------------------------------
    finding_family: str = ""
    """Optional root-cause cluster ID. When left blank, taintly.families
    falls back to an OWASP-derived default so the reporter can still group
    related findings. Set this explicitly on rules whose default grouping
    would be misleading (e.g., a logging rule whose real root cause is
    credential hygiene)."""
    confidence: str = "high"
    """Rule precision hint: "high" (default), "medium", or "low". Rules with
    a known false-positive profile — shallow taint analysis, secret-string
    heuristics, trigger-level rules that require design review — should set
    a lower confidence so the reporter can surface them as review-needed
    rather than as confirmed risk."""
    review_needed: bool = False
    """When True, the reporter treats this rule as an analyst-review item
    rather than a confirmed risk. Useful for patterns that can be safe or
    dangerous depending on design intent (pull_request_target without
    obvious dangerous operations, workflow_dispatch with constrained
    inputs, etc.)."""
    anchor_aware: bool = False
    """When True, the engine cross-checks per-line matches against an
    anchor-merge expanded copy of the source.  If an anchor expansion
    suppresses the match (because the anchor body satisfies the rule's
    requires-absent constraint), the original match is dropped as an
    anchor-mediated false positive.  Opt-in per rule because the
    expanded scan adds cost and only matters for rules whose evidence
    can legitimately live behind a YAML anchor (e.g. SEC4-GH-005's
    ``persist-credentials: false`` lookahead)."""


# =============================================================================
# Finding & Report
# =============================================================================


@dataclass
class Finding:
    """A single finding from scanning a file or platform setting."""

    rule_id: str
    severity: Severity
    title: str
    description: str
    file: str
    line: int = 0
    snippet: str = ""
    remediation: str = ""
    reference: str = ""
    owasp_cicd: str = ""
    stride: list[str] = field(default_factory=list)
    threat_narrative: str = ""
    incidents: list[str] = field(default_factory=list)
    # Provenance of this finding.  "file" is the default for YAML-pattern
    # scans; platform posture checks set "platform"; taint / cross-workflow
    # analysis will set "taint" / "cross-workflow" in later v2 phases.
    origin: str = "file"
    # ------------------------------------------------------------------
    # Reporting v2 metadata (see taintly/families.py for the model)
    # ------------------------------------------------------------------
    finding_family: str = ""
    """Root-cause cluster ID (e.g. "supply_chain_immutability"). Populated
    by the engine from the originating rule or via families.classify() so
    the reporter can present one cluster in place of N correlated findings.
    """
    confidence: str = "high"
    """Rule precision hint: "high", "medium", or "low". Drives display
    ordering and scoring weight."""
    exploitability: str = "medium"
    """Context-derived exploitability tier: "high", "medium", or "low".
    Set by the engine using taintly.workflow_context.analyze() + the
    rule's finding family.  Distinct from ``severity``: severity is the
    baseline policy violation level (doesn't change across workflows);
    exploitability reflects whether the workflow this rule fires in
    actually offers attackers meaningful leverage."""
    review_needed: bool = False
    """True if this pattern deserves human review before strong conclusion
    (separates review-needed items from confirmed risks in the reporter)."""

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "file": self.file,
            "line": self.line,
            "snippet": self.snippet,
            "remediation": self.remediation,
            "reference": self.reference,
            "owasp_cicd": self.owasp_cicd,
            "stride": self.stride,
            "threat_narrative": self.threat_narrative,
            "incidents": self.incidents,
            "origin": self.origin,
            "finding_family": self.finding_family,
            "confidence": self.confidence,
            "exploitability": self.exploitability,
            "review_needed": self.review_needed,
        }


@dataclass
class AuditReport:
    """Collection of findings from scanning a repo."""

    repo_path: str
    platform: str = ""
    files_scanned: int = 0
    rules_loaded: int = 0
    findings: list[Finding] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict[str, Any])

    def add(self, finding: Finding):
        self.findings.append(finding)

    def summarize(self) -> dict[str, Any]:
        self.summary = {
            "total": len(self.findings),
            "CRITICAL": sum(1 for f in self.findings if f.severity == Severity.CRITICAL),
            "HIGH": sum(1 for f in self.findings if f.severity == Severity.HIGH),
            "MEDIUM": sum(1 for f in self.findings if f.severity == Severity.MEDIUM),
            "LOW": sum(1 for f in self.findings if f.severity == Severity.LOW),
            "INFO": sum(1 for f in self.findings if f.severity == Severity.INFO),
        }
        return self.summary

    def filter_severity(self, min_severity: Severity) -> None:
        # ENGINE-ERR findings represent silent coverage loss (file
        # unreadable, ReDoS cap hit, rule crashed) and must survive
        # every --min-severity filter — otherwise a CI gate set to
        # ``--min-severity HIGH`` would suppress the very signal that
        # tells the user the scan didn't actually run.
        self.findings = [
            f for f in self.findings if f.severity >= min_severity or f.rule_id == "ENGINE-ERR"
        ]
        self.summarize()

    def engine_errors(self) -> list[Finding]:
        """Return only the ENGINE-ERR findings.

        ENGINE-ERR is not a security finding; it's the scanner telling
        you it couldn't fully analyse a file.  Reporters surface this
        slice in dedicated channels (stderr, JSON ``errors`` array,
        SARIF ``invocations[*].toolExecutionNotifications``) so the
        signal reaches the user even when the regular findings stream
        is filtered or piped into a downstream tool that only knows
        about findings.
        """
        return [f for f in self.findings if f.rule_id == "ENGINE-ERR"]
