"""Unit tests for the taint analyzer and the TAINT-GH-00X rule family.

Current scope:

* TAINT-GH-001 — shallow env flow
  (``env: VAR: ${{ tainted }}`` then ``run: $VAR``).
* TAINT-GH-002 — multi-hop env propagation
  (``A: ${{ tainted }}``, ``B: ${{ env.A }}``, ...,
  then ``run: $<final>``).

Dynamic ``$GITHUB_ENV`` writes and step-output chains are still out
of scope here — they land in TAINT-GH-003 / TAINT-GH-004 in the
follow-up PRs.
"""

from __future__ import annotations

from textwrap import dedent

from taintly.rules.registry import load_all_rules
from taintly.taint import TaintPath, analyze


def _analyze(src: str) -> list[TaintPath]:
    src = dedent(src).lstrip("\n")
    return analyze(src, src.splitlines())


# ---------------------------------------------------------------------------
# Positive: canonical flows must be detected
# ---------------------------------------------------------------------------


def test_pr_title_into_echo_triggers():
    """Ultralytics-style: PR title -> env -> $PR_TITLE in run:."""
    paths = _analyze(
        """
        on: [pull_request_target]
        jobs:
          greet:
            runs-on: ubuntu-latest
            steps:
              - env:
                  PR_TITLE: ${{ github.event.pull_request.title }}
                run: echo "PR is $PR_TITLE"
        """
    )
    assert len(paths) == 1
    p = paths[0]
    assert p.env_var == "PR_TITLE"
    assert p.source_expr == "github.event.pull_request.title"
    assert "$PR_TITLE" in p.sink_snippet


def test_brace_reference_variant_triggers():
    """Same flow, but sink uses ${PR_TITLE} syntax."""
    paths = _analyze(
        """
        jobs:
          g:
            runs-on: ubuntu-latest
            steps:
              - env:
                  PR_TITLE: ${{ github.event.pull_request.title }}
                run: |
                  echo "title=${PR_TITLE}"
        """
    )
    assert len(paths) == 1
    assert paths[0].env_var == "PR_TITLE"
    assert "${PR_TITLE}" in paths[0].sink_snippet


def test_job_level_env_flows_to_step():
    """env: declared at job scope still taints steps in that job."""
    paths = _analyze(
        """
        jobs:
          build:
            runs-on: ubuntu-latest
            env:
              HEAD_REF: ${{ github.head_ref }}
            steps:
              - run: git checkout "$HEAD_REF"
        """
    )
    assert len(paths) == 1
    assert paths[0].env_var == "HEAD_REF"
    assert paths[0].source_expr == "github.head_ref"


# ---------------------------------------------------------------------------
# Negative: must NOT trigger
# ---------------------------------------------------------------------------


def test_non_tainted_context_does_not_trigger():
    """github.sha, secrets.*, etc. are not attacker-controlled."""
    assert (
        _analyze(
            """
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - env:
                      SHA: ${{ github.sha }}
                      TOKEN: ${{ secrets.GH_TOKEN }}
                    run: echo "$SHA $TOKEN"
            """
        )
        == []
    )


def test_env_var_used_only_in_if_does_not_trigger():
    """An if: expression is evaluated by the Actions engine, not by bash."""
    assert (
        _analyze(
            """
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - env:
                      PR_TITLE: ${{ github.event.pull_request.title }}
                    if: env.PR_TITLE != ''
            """
        )
        == []
    )


def test_tainted_env_declared_but_not_referenced_does_not_trigger():
    """Declared taint source with no downstream run: reference is inert."""
    assert (
        _analyze(
            """
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - env:
                      PR_TITLE: ${{ github.event.pull_request.title }}
                    run: echo hello world
            """
        )
        == []
    )


# ---------------------------------------------------------------------------
# Multi-hop env propagation (TAINT-GH-002)
# ---------------------------------------------------------------------------


def test_multi_hop_two_step_chain_triggers():
    """A -> B -> run: $B is reported as kind=multi_hop with a 3-hop chain."""
    paths = _analyze(
        """
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - env:
                  A: ${{ github.event.pull_request.title }}
                  B: ${{ env.A }}
                run: echo "$B"
        """
    )
    assert len(paths) == 1, paths
    p = paths[0]
    assert p.kind == "multi_hop"
    assert p.source_expr == "github.event.pull_request.title"
    assert p.env_var == "B"
    # Chain: env A (static) -> env B (indirect) -> sink
    kinds = [h.kind for h in p.hops]
    assert kinds == ["env_static", "env_indirect", "sink"]
    assert [h.name for h in p.hops] == ["A", "B", "B"]


def test_multi_hop_three_step_chain_triggers():
    """Longer chain A -> B -> C -> run: $C — fixed-point resolver handles it."""
    paths = _analyze(
        """
        jobs:
          build:
            runs-on: ubuntu-latest
            env:
              A: ${{ github.event.comment.body }}
              B: ${{ env.A }}
              C: ${{ env.B }}
            steps:
              - run: |
                  echo "$C"
        """
    )
    assert len(paths) == 1, paths
    p = paths[0]
    assert p.kind == "multi_hop"
    kinds = [h.kind for h in p.hops]
    # 3 env hops (A static, B + C indirect) then the sink.
    assert kinds == ["env_static", "env_indirect", "env_indirect", "sink"]


def test_multi_hop_declaration_order_independent():
    """Resolver uses a fixed-point loop, so declaring C before A must still
    produce a finding once A is resolved on a later iteration."""
    paths = _analyze(
        """
        jobs:
          build:
            runs-on: ubuntu-latest
            env:
              C: ${{ env.B }}
              B: ${{ env.A }}
              A: ${{ github.head_ref }}
            steps:
              - run: echo "$C"
        """
    )
    assert len(paths) == 1
    assert paths[0].kind == "multi_hop"
    assert paths[0].source_expr == "github.head_ref"


def test_multi_hop_mixed_non_tainted_env_does_not_trigger():
    """Indirection chain rooted at a non-tainted source must NOT trigger.

    `A: ${{ github.sha }}` is author/CI-controlled; B: ${{ env.A }} carries
    no attacker influence, and neither does `run: $B`.
    """
    paths = _analyze(
        """
        jobs:
          build:
            runs-on: ubuntu-latest
            env:
              A: ${{ github.sha }}
              B: ${{ env.A }}
            steps:
              - run: echo "$B"
        """
    )
    assert paths == []


def test_multi_hop_partial_expression_does_not_propagate():
    """`B: ${{ env.A }}-suffix` is a partial mix — we keep the resolver
    conservative and DO NOT propagate taint through such values so the
    cross-rule coverage with SEC4-GH-004 stays clean."""
    paths = _analyze(
        """
        jobs:
          build:
            runs-on: ubuntu-latest
            env:
              A: ${{ github.event.pull_request.title }}
              B: ${{ env.A }}-suffix
            steps:
              - run: echo "$B"
        """
    )
    assert paths == []


def test_multi_hop_chain_without_sink_does_not_trigger():
    """Taint propagates through A -> B but neither is referenced in run:."""
    paths = _analyze(
        """
        jobs:
          build:
            runs-on: ubuntu-latest
            env:
              A: ${{ github.event.pull_request.title }}
              B: ${{ env.A }}
            steps:
              - run: echo hello
        """
    )
    assert paths == []


def test_shallow_and_multi_hop_coexist_in_same_job():
    """Shallow ($A used) + multi-hop ($B = env.A, then $B used) should each
    land on the right rule.  The two paths share a source but differ by
    kind so the downstream rules can attribute them independently."""
    paths = _analyze(
        """
        jobs:
          build:
            runs-on: ubuntu-latest
            env:
              A: ${{ github.event.pull_request.title }}
              B: ${{ env.A }}
            steps:
              - run: |
                  echo "$A"
                  echo "$B"
        """
    )
    kinds = sorted(p.kind for p in paths)
    assert kinds == ["multi_hop", "shallow"], paths
    for p in paths:
        assert p.source_expr == "github.event.pull_request.title"


# ---------------------------------------------------------------------------
# $GITHUB_ENV dynamic writes (TAINT-GH-003)
# ---------------------------------------------------------------------------


def test_github_env_canonical_flow_triggers():
    """Step 1 launders PR title into $GITHUB_ENV as TITLE; step 2 echoes $TITLE."""
    paths = _analyze(
        """
        on: [pull_request_target]
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - name: launder
                env:
                  RAW: ${{ github.event.pull_request.title }}
                run: echo "TITLE=$RAW" >> $GITHUB_ENV
              - name: sink
                run: echo "$TITLE"
        """
    )
    assert len(paths) == 1, paths
    p = paths[0]
    assert p.kind == "github_env"
    assert p.source_expr == "github.event.pull_request.title"
    assert p.env_var == "TITLE"
    kinds = [h.kind for h in p.hops]
    # env_static RAW -> github_env TITLE -> sink TITLE
    assert kinds == ["env_static", "github_env", "sink"]
    assert [h.name for h in p.hops] == ["RAW", "TITLE", "TITLE"]


def test_github_env_direct_context_in_echo_triggers():
    """No intermediate env var — the echo string itself embeds the tainted context."""
    paths = _analyze(
        """
        on: [pull_request_target]
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - run: echo "PR=${{ github.event.pull_request.title }}" >> "$GITHUB_ENV"
              - run: echo "$PR"
        """
    )
    assert len(paths) == 1
    p = paths[0]
    assert p.kind == "github_env"
    assert [h.kind for h in p.hops] == ["github_env", "sink"]


def test_github_env_brace_form_is_recognised():
    """Redirect to ${GITHUB_ENV} (braces) must also be matched."""
    paths = _analyze(
        """
        on: [pull_request_target]
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - env:
                  RAW: ${{ github.head_ref }}
                run: echo "REF=$RAW" >> ${GITHUB_ENV}
              - run: git checkout "$REF"
        """
    )
    assert len(paths) == 1
    assert paths[0].kind == "github_env"


def test_github_env_write_is_only_visible_to_later_steps():
    """A step's own $GITHUB_ENV write must NOT taint its own run body.

    (The runner only writes the file back into the environment between
    steps; the shell that performed the echo cannot see it.)
    """
    paths = _analyze(
        """
        on: [pull_request_target]
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - env:
                  RAW: ${{ github.event.pull_request.title }}
                run: |
                  echo "TITLE=$RAW" >> $GITHUB_ENV
                  echo "$TITLE"
        """
    )
    # Only $RAW is visible to the run body; $TITLE is NOT (same-step
    # self-write doesn't propagate). Flow RAW -> shell is TAINT-GH-001
    # (shallow) via that `echo "$RAW"`... but we only write "TITLE=$RAW"
    # which does not count as a sink for $RAW (it's a $GITHUB_ENV write,
    # caught separately).  And `echo "$TITLE"` finds no taint.
    # So we should see ZERO taint paths here (no kind=github_env because
    # the sink is in the same step as the write).
    assert paths == [], paths


def test_github_env_sink_before_write_does_not_fire():
    """If the sink appears BEFORE the $GITHUB_ENV write, there is no
    taint: the runner has not yet persisted the write when the sink runs."""
    paths = _analyze(
        """
        on: [pull_request_target]
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - run: echo "$TITLE"
              - env:
                  RAW: ${{ github.event.pull_request.title }}
                run: echo "TITLE=$RAW" >> $GITHUB_ENV
        """
    )
    assert paths == []


def test_github_env_non_tainted_value_does_not_trigger():
    """Non-tainted $GITHUB_ENV write (`BUILD_ID=42`) must not taint anything."""
    paths = _analyze(
        """
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - run: echo "BUILD_ID=42" >> $GITHUB_ENV
              - run: echo "$BUILD_ID"
        """
    )
    assert paths == []


def test_github_env_write_unused_downstream_does_not_trigger():
    """$GITHUB_ENV write happens with tainted data but the name is never
    referenced in a later run: — no sink, no finding."""
    paths = _analyze(
        """
        on: [pull_request_target]
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - env:
                  RAW: ${{ github.event.pull_request.title }}
                run: echo "UNUSED=$RAW" >> $GITHUB_ENV
              - run: echo hello
        """
    )
    assert paths == []


def test_github_env_escaped_double_quotes_in_echo_body():
    """Real-world welcome workflows write messages like
    ``echo "MSG=... \\"$PR_TITLE\\" ..." >> $GITHUB_ENV`` — escaped
    embedded quotes used to kill the match and cause a false negative.
    """
    paths = _analyze(
        """
        on: [pull_request_target]
        jobs:
          welcome:
            runs-on: ubuntu-latest
            steps:
              - env:
                  PR_TITLE: ${{ github.event.pull_request.title }}
                  AUTHOR: ${{ github.event.pull_request.user.login }}
                run: |
                  echo "GREETING=Welcome @$AUTHOR! Your PR \\"$PR_TITLE\\" is being reviewed." >> $GITHUB_ENV
              - env:
                  MSG: ${{ env.GREETING }}
                run: echo "$MSG"
        """
    )
    # Exactly one finding — the chain should flow through the nested
    # multi-hop + $GITHUB_ENV + multi-hop + sink.
    assert len(paths) == 1, paths
    p = paths[0]
    assert p.kind == "github_env"
    kinds = [h.kind for h in p.hops]
    # env_static(PR_TITLE or AUTHOR) -> github_env(GREETING) ->
    # env_indirect(MSG) -> sink(MSG).
    assert "github_env" in kinds and "env_indirect" in kinds
    assert kinds[-1] == "sink"


def test_github_env_multiple_writes_on_one_line():
    """Bash allows ``echo "A=x" >> $GITHUB_ENV && echo "B=y" >> $GITHUB_ENV``.
    Both writes must be captured; the regex uses ``finditer`` to find
    every match on the line."""
    paths = _analyze(
        """
        on: [pull_request_target]
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - env:
                  RAW: ${{ github.event.pull_request.title }}
                run: echo "A=$RAW" >> $GITHUB_ENV && echo "B=$RAW" >> $GITHUB_ENV
              - run: |
                  echo "$A"
                  echo "$B"
        """
    )
    # Both $A and $B get tainted; step 2 references both → 2 findings.
    env_vars = sorted(p.env_var for p in paths)
    assert env_vars == ["A", "B"], paths
    assert all(p.kind == "github_env" for p in paths)


def test_github_env_single_quoted_shell_ref_does_not_taint():
    """Inside single quotes bash does NOT expand ``$RAW``.  A line like
    ``echo 'TITLE=$RAW' >> $GITHUB_ENV`` writes the literal bytes
    ``TITLE=$RAW`` into the file — no attacker data propagates.
    """
    paths = _analyze(
        """
        on: [pull_request_target]
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - env:
                  RAW: ${{ github.event.pull_request.title }}
                run: echo 'TITLE=$RAW' >> $GITHUB_ENV
              - run: echo "$TITLE"
        """
    )
    assert paths == []


def test_github_env_single_quoted_context_still_propagates():
    """${{ tainted }} is expanded by the workflow engine BEFORE the
    shell runs, so a single-quoted echo still carries taint when the
    workflow context is the expression inside — the quotes apply at
    shell parse time, not at workflow parse time."""
    paths = _analyze(
        """
        on: [pull_request_target]
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - run: echo 'PR=${{ github.event.pull_request.title }}' >> $GITHUB_ENV
              - run: echo "$PR"
        """
    )
    assert len(paths) == 1
    assert paths[0].kind == "github_env"


def test_github_env_chains_with_multi_hop():
    """A multi-hop chain feeding into a $GITHUB_ENV write should classify
    as github_env (the bridge), not multi_hop, because github_env is the
    more damning transition.  The provenance chain should still show the
    env_indirect hops for reviewer context."""
    paths = _analyze(
        """
        on: [pull_request_target]
        jobs:
          build:
            runs-on: ubuntu-latest
            env:
              RAW: ${{ github.event.comment.body }}
              MID: ${{ env.RAW }}
            steps:
              - run: echo "COMMENT=${MID}" >> ${GITHUB_ENV}
              - run: echo "body: $COMMENT"
        """
    )
    assert len(paths) == 1
    p = paths[0]
    assert p.kind == "github_env"
    kinds = [h.kind for h in p.hops]
    # env_static(RAW) -> env_indirect(MID) -> github_env(COMMENT) -> sink
    assert kinds == ["env_static", "env_indirect", "github_env", "sink"]


# ---------------------------------------------------------------------------
# Compound-expression patterns (real-world idioms)
# ---------------------------------------------------------------------------


def test_fallback_expression_in_env_is_tainted():
    """Real workflows use ``${{ github.head_ref || github.ref }}`` as the
    idiomatic "PR branch or default" fallback.  When head_ref is set
    (attacker-controlled PR), the whole expression resolves to the
    attacker's branch name — that value MUST be treated as tainted.
    Missing this was the dominant false-negative in real-world scans."""
    paths = _analyze(
        """
        on: [pull_request_target, push]
        jobs:
          build:
            runs-on: ubuntu-latest
            env:
              HEAD_BRANCH: ${{ github.head_ref || github.ref }}
            steps:
              - run: echo "HEAD_BRANCH ${HEAD_BRANCH}"
        """
    )
    assert len(paths) == 1
    p = paths[0]
    assert p.kind == "shallow"
    assert p.source_expr == "github.head_ref"
    assert p.env_var == "HEAD_BRANCH"


def test_fallback_expression_with_non_tainted_side_is_tainted():
    """Even when the fallback branch is non-tainted (``github.ref``),
    the primary operand decides — attackers control head_ref on PR events."""
    paths = _analyze(
        """
        on: [pull_request_target]
        jobs:
          build:
            runs-on: ubuntu-latest
            env:
              TITLE: ${{ github.event.pull_request.title || 'untitled' }}
            steps:
              - run: echo "$TITLE"
        """
    )
    assert len(paths) == 1
    assert paths[0].kind == "shallow"
    assert paths[0].source_expr == "github.event.pull_request.title"


def test_multiple_substitutions_in_value_picks_first_tainted():
    """``${{ github.sha }}-${{ github.head_ref }}`` mixes a non-tainted
    substitution with a tainted one; the tainted one wins."""
    paths = _analyze(
        """
        on: [pull_request_target]
        jobs:
          build:
            runs-on: ubuntu-latest
            env:
              COMBO: ${{ github.sha }}-${{ github.head_ref }}
            steps:
              - run: echo "$COMBO"
        """
    )
    assert len(paths) == 1
    assert paths[0].source_expr == "github.head_ref"


def test_purely_non_tainted_compound_expression_is_not_flagged():
    """``${{ github.sha || github.ref }}`` mentions only safe contexts
    and must not fire."""
    paths = _analyze(
        """
        jobs:
          build:
            runs-on: ubuntu-latest
            env:
              R: ${{ github.sha || github.ref }}
            steps:
              - run: echo "$R"
        """
    )
    assert paths == []


# ---------------------------------------------------------------------------
# Step output chains (TAINT-GH-004)
# ---------------------------------------------------------------------------


def test_step_output_canonical_flow_triggers():
    """Step ``extract`` writes a tainted value into $GITHUB_OUTPUT;
    a later step references ``${{ steps.extract.outputs.title }}``."""
    paths = _analyze(
        """
        on: [pull_request_target]
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - id: extract
                env:
                  RAW: ${{ github.event.pull_request.title }}
                run: echo "title=$RAW" >> $GITHUB_OUTPUT
              - run: echo "${{ steps.extract.outputs.title }}"
        """
    )
    assert len(paths) == 1, paths
    p = paths[0]
    assert p.kind == "step_output"
    assert p.source_expr == "github.event.pull_request.title"
    # env_static(RAW) -> step_output(extract.title) -> sink(extract.title)
    kinds = [h.kind for h in p.hops]
    assert kinds == ["env_static", "step_output", "sink"]
    assert p.env_var == "extract.title"


def test_step_output_direct_context_inlined():
    """Tainted context inlined into the echo body, no env: indirection."""
    paths = _analyze(
        """
        on: [pull_request_target]
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - id: bridge
                run: echo "pr=${{ github.event.pull_request.title }}" >> "$GITHUB_OUTPUT"
              - run: ./tool ${{ steps.bridge.outputs.pr }}
        """
    )
    assert len(paths) == 1
    p = paths[0]
    assert p.kind == "step_output"
    assert [h.kind for h in p.hops] == ["step_output", "sink"]


def test_step_output_legacy_set_output_form_triggers():
    """The deprecated ``::set-output`` form must still be matched."""
    paths = _analyze(
        """
        on: [pull_request_target]
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - id: legacy
                run: echo "::set-output name=ref::${{ github.head_ref }}"
              - run: git checkout "${{ steps.legacy.outputs.ref }}"
        """
    )
    assert len(paths) == 1
    assert paths[0].kind == "step_output"
    assert paths[0].source_expr == "github.head_ref"


def test_step_output_write_without_id_is_unreachable():
    """A step that writes to $GITHUB_OUTPUT but has no ``id:`` cannot
    be referenced by ``steps.<id>.outputs.<name>`` downstream — so no
    sink can exist and the analyzer must not invent one."""
    paths = _analyze(
        """
        on: [pull_request_target]
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - env:
                  RAW: ${{ github.event.pull_request.title }}
                run: echo "title=$RAW" >> $GITHUB_OUTPUT
              - run: echo "${{ steps.extract.outputs.title }}"
        """
    )
    assert paths == []


def test_step_output_sink_before_writer_does_not_fire():
    """If the sink references the output BEFORE the writing step runs,
    the runner has not persisted the output yet."""
    paths = _analyze(
        """
        on: [pull_request_target]
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - run: echo "${{ steps.late.outputs.title }}"
              - id: late
                env:
                  RAW: ${{ github.event.pull_request.title }}
                run: echo "title=$RAW" >> $GITHUB_OUTPUT
        """
    )
    assert paths == []


def test_step_output_in_if_only_does_not_fire():
    """When the output is consumed only inside an ``if:`` expression,
    the workflow expression engine evaluates it — no shell involved."""
    paths = _analyze(
        """
        on: [pull_request_target]
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - id: extract
                env:
                  RAW: ${{ github.event.pull_request.title }}
                run: echo "title=$RAW" >> $GITHUB_OUTPUT
              - if: startsWith(steps.extract.outputs.title, '[release]')
                run: ./release.sh
        """
    )
    assert paths == []


def test_step_output_chains_through_github_env():
    """Combining $GITHUB_OUTPUT writes with $GITHUB_ENV bridges and
    multi-hop env in one chain — kind must escalate to step_output
    (highest priority) and the chain must show every hop."""
    paths = _analyze(
        """
        on: [pull_request_target]
        jobs:
          build:
            runs-on: ubuntu-latest
            env:
              RAW: ${{ github.event.comment.body }}
              MID: ${{ env.RAW }}
            steps:
              - id: extract
                run: echo "body=${MID}" >> $GITHUB_OUTPUT
              - run: ./reply ${{ steps.extract.outputs.body }}
        """
    )
    assert len(paths) == 1
    p = paths[0]
    assert p.kind == "step_output"
    kinds = [h.kind for h in p.hops]
    # env_static(RAW) -> env_indirect(MID) -> step_output(extract.body) -> sink
    assert kinds == ["env_static", "env_indirect", "step_output", "sink"]


def test_step_output_non_tainted_does_not_fire():
    """A non-tainted ``echo build=42 >> $GITHUB_OUTPUT`` must not taint
    even when the output is referenced downstream."""
    paths = _analyze(
        """
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - id: number
                run: echo "build=42" >> $GITHUB_OUTPUT
              - run: echo "${{ steps.number.outputs.build }}"
        """
    )
    assert paths == []


# ---------------------------------------------------------------------------
# Rule-level: the packaged rule must load and be wired into the registry.
# ---------------------------------------------------------------------------


def test_taint_rule_is_registered():
    rules = load_all_rules()
    by_id = {r.id: r for r in rules}
    assert "TAINT-GH-001" in by_id
    rule = by_id["TAINT-GH-001"]
    assert rule.severity.value == "CRITICAL"
    assert rule.owasp_cicd == "CICD-SEC-4"
    # Pattern quacks like the engine contract
    assert hasattr(rule.pattern, "check")
    # Per the 2026-04-27 audit (verdict: split), TAINT-GH-001 fires
    # only when the shell reference is unquoted OR the line uses an
    # eval-class re-parsing command. Safely double-quoted references
    # move to TAINT-GH-012.
    matches = rule.pattern.check(
        "jobs:\n  b:\n    steps:\n      - env:\n          T: ${{ github.event.pull_request.title }}\n        run: echo $T\n",
        [
            "jobs:",
            "  b:",
            "    steps:",
            "      - env:",
            "          T: ${{ github.event.pull_request.title }}",
            "        run: echo $T",
        ],
    )
    assert len(matches) == 1


def test_taint_001_does_not_fire_on_safely_quoted_reference():
    """The django field-test FP shape: ``"$T"`` inside ``[[ ... ]]`` is
    the textbook-safe consumption pattern. Audit verdict (2026-04-27):
    rule must not fire here."""
    rules = load_all_rules()
    rule = next(r for r in rules if r.id == "TAINT-GH-001")
    src = (
        "jobs:\n"
        "  check:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - env:\n"
        "          T: ${{ github.event.pull_request.title }}\n"
        "        run: |\n"
        "          if [[ \"$T\" == \"main\" ]]; then echo on main; fi\n"
    )
    matches = rule.pattern.check(src, src.splitlines())
    assert matches == []


def test_taint_001_fires_on_eval_even_when_quoted():
    """Double-quoting does NOT save the value when fed to eval / sh -c —
    the value is re-parsed as code. Rule must keep firing in that case."""
    rules = load_all_rules()
    rule = next(r for r in rules if r.id == "TAINT-GH-001")
    src = (
        "jobs:\n"
        "  greet:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - env:\n"
        "          T: ${{ github.event.pull_request.title }}\n"
        "        run: eval \"$T\"\n"
    )
    matches = rule.pattern.check(src, src.splitlines())
    assert len(matches) == 1


def test_taint_001_does_not_fire_on_multi_hop():
    """A multi-hop chain is TAINT-GH-002's responsibility.  TAINT-GH-001
    must ignore paths whose kind is not 'shallow' so the two rules don't
    both light up on the same sink."""
    rules = load_all_rules()
    rule = next(r for r in rules if r.id == "TAINT-GH-001")
    src = (
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - env:\n"
        "          A: ${{ github.event.pull_request.title }}\n"
        "          B: ${{ env.A }}\n"
        "        run: echo \"$B\"\n"
    )
    matches = rule.pattern.check(src, src.splitlines())
    assert matches == []


def test_taint_002_rule_is_registered_and_fires_on_multi_hop():
    rules = load_all_rules()
    by_id = {r.id: r for r in rules}
    assert "TAINT-GH-002" in by_id
    rule = by_id["TAINT-GH-002"]
    assert rule.severity.value == "CRITICAL"
    assert rule.owasp_cicd == "CICD-SEC-4"
    # 2026-04-27 audit: rule now uses sink_quote_filter='unsafe_only',
    # so the test must use an UNQUOTED reference at the sink (the
    # safely-quoted variant became a no-fire under the audit verdict).
    src = (
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - env:\n"
        "          A: ${{ github.event.pull_request.title }}\n"
        "          B: ${{ env.A }}\n"
        "        run: echo $B\n"
    )
    matches = rule.pattern.check(src, src.splitlines())
    assert len(matches) == 1
    # The snippet should carry the full chain so reviewers can see the hops.
    line_no, snippet = matches[0]
    assert snippet.startswith("taint: github.event.pull_request.title")
    assert "env.A" in snippet and "env.B" in snippet


def test_taint_002_does_not_fire_on_shallow():
    rules = load_all_rules()
    rule = next(r for r in rules if r.id == "TAINT-GH-002")
    src = (
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - env:\n"
        "          T: ${{ github.event.pull_request.title }}\n"
        "        run: echo \"$T\"\n"
    )
    matches = rule.pattern.check(src, src.splitlines())
    assert matches == []


def test_taint_003_rule_is_registered_and_fires_on_github_env_flow():
    rules = load_all_rules()
    by_id = {r.id: r for r in rules}
    assert "TAINT-GH-003" in by_id
    rule = by_id["TAINT-GH-003"]
    assert rule.severity.value == "CRITICAL"
    assert rule.owasp_cicd == "CICD-SEC-4"
    # 2026-04-27 audit: rule now uses sink_quote_filter='unsafe_only',
    # so the downstream sink must reference $TITLE unquoted (the
    # safely-quoted variant became a no-fire under the audit verdict).
    src = (
        "on: [pull_request_target]\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - env:\n"
        "          RAW: ${{ github.event.pull_request.title }}\n"
        "        run: echo \"TITLE=$RAW\" >> $GITHUB_ENV\n"
        "      - run: echo $TITLE\n"
    )
    matches = rule.pattern.check(src, src.splitlines())
    assert len(matches) == 1
    line_no, snippet = matches[0]
    assert snippet.startswith("taint: github.event.pull_request.title")
    # Chain must name the $GITHUB_ENV bridge explicitly.
    assert "$GITHUB_ENV.TITLE" in snippet


def test_taint_003_does_not_fire_on_shallow_or_multi_hop():
    rules = load_all_rules()
    rule = next(r for r in rules if r.id == "TAINT-GH-003")
    # Shallow.
    src1 = (
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - env:\n"
        "          T: ${{ github.event.pull_request.title }}\n"
        "        run: echo \"$T\"\n"
    )
    assert rule.pattern.check(src1, src1.splitlines()) == []
    # Multi-hop without any $GITHUB_ENV bridge.
    src2 = (
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    env:\n"
        "      A: ${{ github.event.pull_request.title }}\n"
        "      B: ${{ env.A }}\n"
        "    steps:\n"
        "      - run: echo \"$B\"\n"
    )
    assert rule.pattern.check(src2, src2.splitlines()) == []


def test_taint_001_and_002_do_not_fire_on_github_env_bridge():
    """A $GITHUB_ENV-bridge flow must be classified as github_env, NOT
    shallow or multi_hop — so 001/002 don't double-fire with 003."""
    rules = load_all_rules()
    src = (
        "on: [pull_request_target]\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - env:\n"
        "          RAW: ${{ github.event.pull_request.title }}\n"
        "        run: echo \"TITLE=$RAW\" >> $GITHUB_ENV\n"
        "      - run: echo \"$TITLE\"\n"
    )
    rule_001 = next(r for r in rules if r.id == "TAINT-GH-001")
    rule_002 = next(r for r in rules if r.id == "TAINT-GH-002")
    assert rule_001.pattern.check(src, src.splitlines()) == []
    assert rule_002.pattern.check(src, src.splitlines()) == []


def test_taint_004_rule_is_registered_and_fires_on_step_output_flow():
    rules = load_all_rules()
    by_id = {r.id: r for r in rules}
    assert "TAINT-GH-004" in by_id
    rule = by_id["TAINT-GH-004"]
    assert rule.severity.value == "CRITICAL"
    assert rule.owasp_cicd == "CICD-SEC-4"
    src = (
        "on: [pull_request_target]\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - id: extract\n"
        "        env:\n"
        "          RAW: ${{ github.event.pull_request.title }}\n"
        "        run: echo \"title=$RAW\" >> $GITHUB_OUTPUT\n"
        "      - run: echo \"${{ steps.extract.outputs.title }}\"\n"
    )
    matches = rule.pattern.check(src, src.splitlines())
    assert len(matches) == 1
    line_no, snippet = matches[0]
    assert snippet.startswith("taint: github.event.pull_request.title")
    # Chain must name the step output bridge explicitly.
    assert "steps.extract.outputs.title" in snippet


def test_taint_004_does_not_fire_on_other_kinds():
    """TAINT-GH-004 must reject shallow / multi_hop / github_env paths
    so the four taint rules never double-fire on the same finding."""
    rules = load_all_rules()
    rule = next(r for r in rules if r.id == "TAINT-GH-004")
    # Shallow.
    src1 = (
        "jobs:\n"
        "  b:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - env:\n"
        "          T: ${{ github.event.pull_request.title }}\n"
        "        run: echo \"$T\"\n"
    )
    assert rule.pattern.check(src1, src1.splitlines()) == []
    # github_env bridge.
    src2 = (
        "on: [pull_request_target]\n"
        "jobs:\n"
        "  b:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - env:\n"
        "          RAW: ${{ github.event.pull_request.title }}\n"
        "        run: echo \"TITLE=$RAW\" >> $GITHUB_ENV\n"
        "      - run: echo \"$TITLE\"\n"
    )
    assert rule.pattern.check(src2, src2.splitlines()) == []


def test_taint_001_002_003_do_not_fire_on_step_output_bridge():
    """Symmetrical: a step_output flow must classify as step_output
    only — TAINT-GH-001/002/003 must reject it so all four rules
    stay disjoint."""
    rules = load_all_rules()
    src = (
        "on: [pull_request_target]\n"
        "jobs:\n"
        "  b:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - id: extract\n"
        "        env:\n"
        "          RAW: ${{ github.event.pull_request.title }}\n"
        "        run: echo \"title=$RAW\" >> $GITHUB_OUTPUT\n"
        "      - run: echo \"${{ steps.extract.outputs.title }}\"\n"
    )
    for rid in ("TAINT-GH-001", "TAINT-GH-002", "TAINT-GH-003"):
        rule = next(r for r in rules if r.id == rid)
        assert rule.pattern.check(src, src.splitlines()) == [], rid


# ---------------------------------------------------------------------------
# Shell-quoting precision: single-quoted references are not sinks.
# ---------------------------------------------------------------------------


def test_single_quoted_reference_is_not_a_sink():
    """``run: echo '$PR_TITLE'`` — bash never interpolates inside single
    quotes, so this is not an injection sink even though PR_TITLE carries
    attacker-controlled bytes."""
    paths = _analyze(
        """
        on: pull_request_target
        jobs:
          t:
            runs-on: ubuntu-latest
            steps:
              - env:
                  PR_TITLE: ${{ github.event.pull_request.title }}
                run: echo '$PR_TITLE'
        """
    )
    assert paths == []


def test_double_quoted_reference_is_a_sink():
    """``run: echo "$PR_TITLE"`` — double quotes interpolate; still a
    sink (attacker can break out with an embedded ``"`` and metacharacters)."""
    paths = _analyze(
        """
        on: pull_request_target
        jobs:
          t:
            runs-on: ubuntu-latest
            steps:
              - env:
                  PR_TITLE: ${{ github.event.pull_request.title }}
                run: echo "$PR_TITLE"
        """
    )
    assert len(paths) == 1
    assert paths[0].env_var == "PR_TITLE"


def test_unquoted_reference_is_a_sink():
    paths = _analyze(
        """
        on: pull_request_target
        jobs:
          t:
            runs-on: ubuntu-latest
            steps:
              - env:
                  PR_TITLE: ${{ github.event.pull_request.title }}
                run: echo $PR_TITLE
        """
    )
    assert len(paths) == 1


def test_mixed_single_then_unquoted_same_line_is_a_sink():
    """A line that quotes one occurrence safely but has another unquoted
    reference still fires — the unquoted one is the exploitable sink."""
    paths = _analyze(
        """
        on: pull_request_target
        jobs:
          t:
            runs-on: ubuntu-latest
            steps:
              - env:
                  PR_TITLE: ${{ github.event.pull_request.title }}
                run: echo 'label:' && echo $PR_TITLE
        """
    )
    assert len(paths) == 1


def test_brace_form_inside_single_quotes_is_not_a_sink():
    """``'${PR_TITLE}'`` — same single-quote rule applies to the
    braced form."""
    paths = _analyze(
        """
        on: pull_request_target
        jobs:
          t:
            runs-on: ubuntu-latest
            steps:
              - env:
                  PR_TITLE: ${{ github.event.pull_request.title }}
                run: echo '${PR_TITLE}'
        """
    )
    assert paths == []


def test_server_side_env_reference_not_affected_by_shell_quotes():
    """``${{ env.PR_TITLE }}`` is substituted by the runner *before*
    bash sees the line. The shell-quote wrapping the substituted value
    is irrelevant because the attacker bytes land inline, not as a
    variable. Surrounding single quotes do NOT make it safe."""
    paths = _analyze(
        """
        on: pull_request_target
        jobs:
          t:
            runs-on: ubuntu-latest
            env:
              PR_TITLE: ${{ github.event.pull_request.title }}
            steps:
              - run: echo '${{ env.PR_TITLE }}'
        """
    )
    assert len(paths) == 1


# Unit tests for the quote-context helper itself — small, focused,
# complement the end-to-end assertions above.


def test_shell_quote_context_walker():
    from taintly.taint import _shell_quote_context_at as ctx

    assert ctx("echo $X", len("echo ")) == "unquoted"
    assert ctx('echo "$X"', len('echo "')) == "double"
    assert ctx("echo '$X'", len("echo '")) == "single"
    # Nested: close-then-open single quotes
    assert ctx("echo 'safe' $X", len("echo 'safe' ")) == "unquoted"
    # Backslash escape before $
    assert ctx('echo "\\$X"', len('echo "\\')) == "double"
    # Unbalanced: open double, never closed — still double at end
    assert ctx('echo "hello $X', len('echo "hello ')) == "double"


def test_shell_quote_context_ansi_c_quoting():
    """Bash's ``$'...'`` (ANSI-C quoting) does NOT interpolate ``$VAR``.
    The walker should report ``"single"`` inside the quoted region and
    fall back to ``"unquoted"`` once the closing ``'`` is past."""
    from taintly.taint import _shell_quote_context_at as ctx

    # Inside $'...' — non-interpolating, treated as single.
    assert ctx("echo $'$X'", len("echo $'")) == "single"
    # After the closing ', context resets to unquoted.
    assert ctx("echo $'foo' $X", len("echo $'foo' ")) == "unquoted"
    # Embedded \' inside ANSI-C does NOT close the quote.
    assert ctx("echo $'a\\'b' $X", len("echo $'a\\'b' ")) == "unquoted"
    # $"..." (locale-translated string) DOES interpolate — must remain "double".
    assert ctx('echo $"$X"', len('echo $"')) == "double"


def test_ansi_c_quoted_reference_is_not_a_sink():
    """``run: echo $'$PR_TITLE'`` — bash never interpolates inside
    ANSI-C quotes either, so this must not be flagged as a sink."""
    paths = _analyze(
        """
        on: pull_request_target
        jobs:
          t:
            runs-on: ubuntu-latest
            steps:
              - env:
                  PR_TITLE: ${{ github.event.pull_request.title }}
                run: echo $'$PR_TITLE'
        """
    )
    assert paths == []


def test_locale_translated_string_reference_is_a_sink():
    """``$"..."`` is gettext-translated but bash still interpolates
    ``$VAR`` inside.  Must remain a sink."""
    paths = _analyze(
        """
        on: pull_request_target
        jobs:
          t:
            runs-on: ubuntu-latest
            steps:
              - env:
                  PR_TITLE: ${{ github.event.pull_request.title }}
                run: echo $"$PR_TITLE"
        """
    )
    assert len(paths) == 1
    assert paths[0].env_var == "PR_TITLE"


# ---------------------------------------------------------------------------
# TAINT-GH-009: cross-job needs.<j>.outputs.<n> propagation.
# ---------------------------------------------------------------------------


def test_cross_job_direct_needs_outputs_in_run_is_sink():
    """Producer's declared output is sourced from a tainted context;
    consumer references it inline in a run: line.  Canonical shape."""
    paths = _analyze(
        """
        on: pull_request_target
        jobs:
          produce:
            runs-on: ubuntu-latest
            outputs:
              title: ${{ github.event.pull_request.title }}
            steps:
              - run: echo hi
          consume:
            needs: produce
            runs-on: ubuntu-latest
            steps:
              - run: echo "${{ needs.produce.outputs.title }}"
        """
    )
    assert len(paths) == 1
    assert paths[0].kind == "cross_job"
    assert paths[0].env_var == "needs.produce.outputs.title"
    # Provenance should include both a job_output hop (producer side)
    # and a needs_ref hop (consumer side) before the sink.
    hop_kinds = [h.kind for h in paths[0].hops]
    assert "job_output" in hop_kinds
    assert "needs_ref" in hop_kinds
    assert hop_kinds[-1] == "sink"


def test_cross_job_through_step_output_then_env_mediated_consumer():
    """Producer launders attacker bytes through a step output; consumer
    binds the cross-job reference into env then echos $VAR."""
    paths = _analyze(
        """
        on: issue_comment
        jobs:
          produce:
            runs-on: ubuntu-latest
            outputs:
              body: ${{ steps.x.outputs.body }}
            steps:
              - id: x
                env:
                  RAW: ${{ github.event.comment.body }}
                run: echo "body=$RAW" >> $GITHUB_OUTPUT
          consume:
            needs: produce
            runs-on: ubuntu-latest
            steps:
              - env:
                  B: ${{ needs.produce.outputs.body }}
                run: echo "$B"
        """
    )
    assert len(paths) == 1
    assert paths[0].kind == "cross_job"
    # The consumer side bridges via env, so a needs_ref hop must
    # appear in the chain (env-mediated, not a direct interpolation).
    hop_kinds = [h.kind for h in paths[0].hops]
    assert "needs_ref" in hop_kinds


def test_cross_job_transitive_chain_a_to_b_to_c():
    """Three-job chain: a's output feeds b's output feeds c's run:.
    Fixed-point iteration must propagate taint two hops up the DAG."""
    paths = _analyze(
        """
        on: pull_request_target
        jobs:
          a:
            runs-on: ubuntu-latest
            outputs:
              x: ${{ github.event.pull_request.body }}
            steps:
              - run: echo hi
          b:
            needs: a
            runs-on: ubuntu-latest
            outputs:
              y: ${{ needs.a.outputs.x }}
            steps:
              - run: echo hi
          c:
            needs: b
            runs-on: ubuntu-latest
            steps:
              - run: echo "${{ needs.b.outputs.y }}"
        """
    )
    assert len(paths) == 1
    assert paths[0].kind == "cross_job"
    # The reported sink is b's output (the immediate producer of c's
    # reference); a's bytes still appear in source_expr because the
    # provenance chain is preserved through both job_output hops.
    assert paths[0].env_var == "needs.b.outputs.y"
    assert "pull_request" in paths[0].source_expr


def test_cross_job_static_output_is_not_a_sink():
    """If the producer's declared output isn't sourced from any
    tainted context, downstream interpolation must NOT fire."""
    paths = _analyze(
        """
        on: pull_request_target
        jobs:
          produce:
            runs-on: ubuntu-latest
            outputs:
              tag: v1.2.3
              rid: ${{ github.run_id }}
            steps:
              - run: echo hi
          consume:
            needs: produce
            runs-on: ubuntu-latest
            steps:
              - run: |
                  echo "${{ needs.produce.outputs.tag }}"
                  echo "${{ needs.produce.outputs.rid }}"
        """
    )
    assert paths == []


def test_cross_job_unreferenced_output_does_not_emit():
    """Producer carries attacker bytes in its output, but no consumer
    ever references it — there's no full source-to-sink chain so we
    must stay silent (low FP rate is the point of taint analysis)."""
    paths = _analyze(
        """
        on: pull_request_target
        jobs:
          produce:
            runs-on: ubuntu-latest
            outputs:
              title: ${{ github.event.pull_request.title }}
            steps:
              - run: echo hi
          consume:
            needs: produce
            runs-on: ubuntu-latest
            steps:
              - run: echo nothing
        """
    )
    assert paths == []


def test_cross_job_output_via_env_ref():
    """Producer's declared output references a tainted job-level env
    var via ``${{ env.X }}``; consumer interpolates the output."""
    paths = _analyze(
        """
        on: pull_request_target
        jobs:
          produce:
            runs-on: ubuntu-latest
            env:
              PR_TITLE: ${{ github.event.pull_request.title }}
            outputs:
              title: ${{ env.PR_TITLE }}
            steps:
              - run: echo hi
          consume:
            needs: produce
            runs-on: ubuntu-latest
            steps:
              - run: echo "${{ needs.produce.outputs.title }}"
        """
    )
    assert len(paths) == 1
    assert paths[0].kind == "cross_job"
