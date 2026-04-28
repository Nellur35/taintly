"""Unit tests for the GitLab CI taint analyzer and TAINT-GL-00X rules.

Mirror of ``tests/unit/test_taint.py`` for the GitLab side.  Current
scope:

* TAINT-GL-001 — shallow ``variables:`` flow
  (``variables: { LAUNDERED: $CI_TAINTED }`` then ``script: echo $LAUNDERED``).
* TAINT-GL-002 — multi-hop variable propagation
  (``A: $CI_TAINTED``, ``B: $A``, ..., then ``script: $FINAL``).
* TAINT-GL-003 — ``dotenv`` artefact bridge across jobs: a writer
  declares ``artifacts.reports.dotenv:`` and echoes tainted
  ``NAME=value`` into it; a consumer that ``needs:`` the writer then
  shell-expands ``$NAME``.
"""

from __future__ import annotations

from textwrap import dedent

from taintly.gitlab_taint import TaintPath, analyze
from taintly.rules.registry import load_all_rules


def _analyze(src: str) -> list[TaintPath]:
    src = dedent(src).lstrip("\n")
    return analyze(src, src.splitlines())


# ---------------------------------------------------------------------------
# Positive: canonical flows must be detected
# ---------------------------------------------------------------------------


def test_top_level_variables_flow_to_job_script():
    """Top-level ``variables:`` cascades to every job."""
    paths = _analyze(
        """
        variables:
          PR_TITLE: $CI_MERGE_REQUEST_TITLE
        build:
          script:
            - echo "$PR_TITLE"
        """
    )
    assert len(paths) == 1
    p = paths[0]
    assert p.kind == "shallow"
    assert p.source_var == "CI_MERGE_REQUEST_TITLE"
    assert p.laundered_var == "PR_TITLE"
    assert "$PR_TITLE" in p.sink_snippet
    # Hop chain: var_static + sink.
    kinds = [h.kind for h in p.hops]
    assert kinds == ["var_static", "sink"]


def test_job_level_variables_flow_to_same_job():
    """Job-level ``variables:`` are visible to that job's scripts."""
    paths = _analyze(
        """
        build:
          variables:
            HEAD: $CI_COMMIT_REF_NAME
          script:
            - git checkout "$HEAD"
        """
    )
    assert len(paths) == 1
    assert paths[0].source_var == "CI_COMMIT_REF_NAME"
    assert paths[0].laundered_var == "HEAD"


def test_brace_form_reference_in_script_triggers():
    """``${VAR}`` (braced) sink reference must be detected as well as
    bare ``$VAR``."""
    paths = _analyze(
        """
        variables:
          MSG: $CI_COMMIT_MESSAGE
        test:
          before_script:
            - echo "${MSG}"
        """
    )
    assert len(paths) == 1
    assert "${MSG}" in paths[0].sink_snippet


def test_after_script_is_a_sink_too():
    """``after_script:`` runs in the same shell context as ``script:``,
    so taint that lands there must also fire."""
    paths = _analyze(
        """
        variables:
          AUTHOR: $CI_COMMIT_AUTHOR
        deploy:
          script:
            - ./deploy.sh
          after_script:
            - mail -s "deploy by $AUTHOR" ops@example.com
        """
    )
    assert len(paths) == 1
    assert "$AUTHOR" in paths[0].sink_snippet


def test_windows_percent_var_form_triggers():
    """Windows runners reference variables with ``%VAR%``.  GitLab
    pipelines that target Windows must have that form caught too."""
    paths = _analyze(
        """
        variables:
          PR: $CI_MERGE_REQUEST_TITLE
        win-build:
          script:
            - echo %PR%
        """
    )
    assert len(paths) == 1


# ---------------------------------------------------------------------------
# Negative: must NOT trigger
# ---------------------------------------------------------------------------


def test_non_tainted_predefined_var_does_not_trigger():
    """``$CI_COMMIT_SHA`` is hex digits — no shell metachars possible.
    Same for ``$CI_PIPELINE_ID`` etc.  None of those are in the
    tainted-context list and must not trigger."""
    assert (
        _analyze(
            """
            variables:
              SHA: $CI_COMMIT_SHA
              PID: $CI_PIPELINE_ID
            build:
              script:
                - echo "$SHA $PID"
            """
        )
        == []
    )


def test_secrets_via_protected_var_do_not_trigger():
    """Variables sourced from CI/CD-settings (admin-controlled) are
    not in the tainted set — only attacker-influenced commit / MR
    variables are."""
    assert (
        _analyze(
            """
            variables:
              TOKEN: $CI_JOB_TOKEN
              REG_PASS: $CI_REGISTRY_PASSWORD
            push:
              script:
                - docker login -u user -p "$TOKEN"
            """
        )
        == []
    )


def test_tainted_var_only_in_rules_if_does_not_trigger():
    """``rules: - if:`` is evaluated by the GitLab engine, not the
    shell, so a reference there does NOT count as a taint sink."""
    assert (
        _analyze(
            """
            build:
              variables:
                PR: $CI_MERGE_REQUEST_TITLE
              rules:
                - if: '$PR != ""'
              script:
                - echo hello
            """
        )
        == []
    )


def test_tainted_var_declared_but_never_referenced():
    """No sink, no finding — the dead taint must not fire."""
    assert (
        _analyze(
            """
            variables:
              MSG: $CI_COMMIT_MESSAGE
            build:
              script:
                - echo no-reference
            """
        )
        == []
    )


def test_direct_unquoted_reference_is_not_this_rules_responsibility():
    """``script: echo $CI_COMMIT_MESSAGE`` (no project-variables
    indirection) is SEC4-GL-001's job, not this rule's.  We must NOT
    fabricate a taint flow here — the laundering step is required."""
    assert (
        _analyze(
            """
            build:
              script:
                - echo $CI_COMMIT_MESSAGE
            """
        )
        == []
    )


# ---------------------------------------------------------------------------
# Multi-hop variable propagation (TAINT-GL-002)
# ---------------------------------------------------------------------------


def test_multi_hop_two_step_chain_triggers():
    """A -> B -> script: $B is reported as kind=multi_hop with the
    expected 3-hop provenance chain (var_static, var_indirect, sink)."""
    paths = _analyze(
        """
        variables:
          A: $CI_COMMIT_TITLE
          B: $A
        build:
          script:
            - echo "$B"
        """
    )
    assert len(paths) == 1, paths
    p = paths[0]
    assert p.kind == "multi_hop"
    assert p.source_var == "CI_COMMIT_TITLE"
    assert p.laundered_var == "B"
    kinds = [h.kind for h in p.hops]
    assert kinds == ["var_static", "var_indirect", "sink"]


def test_multi_hop_three_hop_chain_triggers():
    """Longer chain A -> B -> C -> script: $C.  The fixed-point
    resolver should handle arbitrary depth."""
    paths = _analyze(
        """
        variables:
          A: $CI_COMMIT_MESSAGE
          B: $A
          C: $B
        build:
          script:
            - echo "$C"
        """
    )
    assert len(paths) == 1
    p = paths[0]
    assert p.kind == "multi_hop"
    kinds = [h.kind for h in p.hops]
    assert kinds == ["var_static", "var_indirect", "var_indirect", "sink"]


def test_multi_hop_declaration_order_independent():
    """Declaring C before A must still resolve correctly once the
    resolver picks up A on a later iteration."""
    paths = _analyze(
        """
        variables:
          C: $B
          B: $A
          A: $CI_COMMIT_BRANCH
        build:
          script:
            - echo "$C"
        """
    )
    assert len(paths) == 1
    assert paths[0].kind == "multi_hop"
    assert paths[0].source_var == "CI_COMMIT_BRANCH"


def test_multi_hop_across_top_and_job_scope():
    """Top-level declares A (tainted); job declares B: $A and then
    uses $B.  Should resolve via the outer-scope seed into the job
    resolver."""
    paths = _analyze(
        """
        variables:
          A: $CI_MERGE_REQUEST_TITLE
        build:
          variables:
            B: $A
          script:
            - echo "$B"
        """
    )
    assert len(paths) == 1
    p = paths[0]
    assert p.kind == "multi_hop"
    assert p.source_var == "CI_MERGE_REQUEST_TITLE"
    assert p.laundered_var == "B"


def test_multi_hop_non_tainted_root_does_not_propagate():
    """Chain rooted at a non-tainted var (``A: $CI_COMMIT_SHA``) must
    not propagate to the sink even when the downstream chain shape
    is identical to a tainted one."""
    paths = _analyze(
        """
        variables:
          A: $CI_COMMIT_SHA
          B: $A
          C: $B
        build:
          script:
            - echo "$C"
        """
    )
    assert paths == []


def test_multi_hop_partial_expression_does_not_propagate():
    """``B: $A-suffix`` is a partial mix — the resolver stays
    conservative and does NOT propagate taint through the
    user-inserted fragment.  Mirrors the GitHub analyzer's
    behaviour."""
    paths = _analyze(
        """
        variables:
          A: $CI_COMMIT_TITLE
          B: $A-suffix
        build:
          script:
            - echo "$B"
        """
    )
    assert paths == []


def test_multi_hop_chain_without_sink_does_not_trigger():
    """Taint propagates through A -> B but nothing references $B."""
    paths = _analyze(
        """
        variables:
          A: $CI_COMMIT_TITLE
          B: $A
        build:
          script:
            - echo hello
        """
    )
    assert paths == []


def test_shallow_and_multi_hop_coexist_in_same_file():
    """Shallow ($A used directly) + multi-hop ($B = $A, then $B used)
    should land on their respective rules via separate paths."""
    paths = _analyze(
        """
        variables:
          A: $CI_COMMIT_TITLE
          B: $A
        build:
          script:
            - echo "$A"
            - echo "$B"
        """
    )
    kinds = sorted(p.kind for p in paths)
    assert kinds == ["multi_hop", "shallow"]
    for p in paths:
        assert p.source_var == "CI_COMMIT_TITLE"


# ---------------------------------------------------------------------------
# Registry-level: the packaged rules must load and not double-fire.
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Rule-level: the packaged rule must load and be wired into the registry.
# ---------------------------------------------------------------------------


def test_taint_gl_001_rule_is_registered():
    rules = load_all_rules()
    by_id = {r.id: r for r in rules}
    assert "TAINT-GL-001" in by_id
    rule = by_id["TAINT-GL-001"]
    assert rule.severity.value == "CRITICAL"
    assert rule.owasp_cicd == "CICD-SEC-4"
    assert hasattr(rule.pattern, "check")
    # 2026-04-27 audit: sink_quote_filter='unsafe_only' applied. Use
    # an UNQUOTED reference at the sink (the safely-quoted variant
    # is intentionally a no-fire under the audit verdict — mirrors
    # TAINT-GH-001).
    src = (
        "variables:\n"
        "  PR: $CI_MERGE_REQUEST_TITLE\n"
        "build:\n"
        "  script:\n"
        "    - echo $PR\n"
    )
    matches = rule.pattern.check(src, src.splitlines())
    assert len(matches) == 1
    line_no, snippet = matches[0]
    assert snippet.startswith("taint: $CI_MERGE_REQUEST_TITLE")
    assert "variables.PR" in snippet


def test_taint_gl_001_does_not_fire_on_multi_hop():
    """A multi-hop chain must be routed to TAINT-GL-002; TAINT-GL-001
    must reject it so the two rules don't double-fire on one sink."""
    rules = load_all_rules()
    rule = next(r for r in rules if r.id == "TAINT-GL-001")
    src = (
        "variables:\n"
        "  A: $CI_COMMIT_TITLE\n"
        "  B: $A\n"
        "build:\n"
        "  script:\n"
        "    - echo $B\n"
    )
    matches = rule.pattern.check(src, src.splitlines())
    assert matches == []


def test_taint_gl_001_does_not_fire_on_safely_quoted_reference():
    """Audit follow-up (2026-04-27): the same FP class TAINT-GH-001
    addressed on GitHub now applies on GitLab. Safely-quoted shell
    sinks (echo "$VAR") must not fire CRITICAL — POSIX expansion
    doesn't re-tokenise the value's contents inside double quotes."""
    rules = load_all_rules()
    rule = next(r for r in rules if r.id == "TAINT-GL-001")
    src = (
        "variables:\n"
        "  PR: $CI_MERGE_REQUEST_TITLE\n"
        "build:\n"
        "  script:\n"
        "    - echo \"$PR\"\n"
    )
    matches = rule.pattern.check(src, src.splitlines())
    assert matches == []


def test_taint_gl_001_fires_on_eval_even_when_quoted():
    """eval / sh -c re-parse the value as code regardless of quoting."""
    rules = load_all_rules()
    rule = next(r for r in rules if r.id == "TAINT-GL-001")
    src = (
        "variables:\n"
        "  CMD: $CI_MERGE_REQUEST_TITLE\n"
        "build:\n"
        "  script:\n"
        "    - eval \"$CMD\"\n"
    )
    matches = rule.pattern.check(src, src.splitlines())
    assert len(matches) == 1


def test_taint_gl_002_rule_is_registered_and_fires_on_multi_hop():
    rules = load_all_rules()
    by_id = {r.id: r for r in rules}
    assert "TAINT-GL-002" in by_id
    rule = by_id["TAINT-GL-002"]
    assert rule.severity.value == "CRITICAL"
    assert rule.owasp_cicd == "CICD-SEC-4"
    # 2026-04-27 audit: sink_quote_filter='unsafe_only' applied.
    src = (
        "variables:\n"
        "  RAW: $CI_MERGE_REQUEST_TITLE\n"
        "  TITLE: $RAW\n"
        "build:\n"
        "  script:\n"
        "    - echo $TITLE\n"
    )
    matches = rule.pattern.check(src, src.splitlines())
    assert len(matches) == 1
    line_no, snippet = matches[0]
    assert snippet.startswith("taint: $CI_MERGE_REQUEST_TITLE")
    # Chain must show every hop, not just the final laundering.
    assert "variables.RAW" in snippet
    assert "variables.TITLE" in snippet


def test_taint_gl_002_does_not_fire_on_shallow():
    """TAINT-GL-002 must reject shallow paths."""
    rules = load_all_rules()
    rule = next(r for r in rules if r.id == "TAINT-GL-002")
    src = (
        "variables:\n"
        "  T: $CI_COMMIT_TITLE\n"
        "build:\n"
        "  script:\n"
        "    - echo \"$T\"\n"
    )
    matches = rule.pattern.check(src, src.splitlines())
    assert matches == []


# ---------------------------------------------------------------------------
# Dotenv artefact bridge across jobs (TAINT-GL-003)
# ---------------------------------------------------------------------------


def test_dotenv_bridge_canonical_flow_triggers():
    """Writer launders PR title into a dotenv artefact; consumer
    needs: the writer and echoes the resulting env var."""
    paths = _analyze(
        """
        producer:
          variables:
            RAW: $CI_MERGE_REQUEST_TITLE
          script:
            - echo "TITLE=$RAW" > build.env
          artifacts:
            reports:
              dotenv: build.env
        consumer:
          needs: [producer]
          script:
            - echo "title is $TITLE"
        """
    )
    assert len(paths) == 1, paths
    p = paths[0]
    assert p.kind == "dotenv"
    assert p.source_var == "CI_MERGE_REQUEST_TITLE"
    assert p.laundered_var == "TITLE"
    kinds = [h.kind for h in p.hops]
    # var_static(RAW) -> dotenv(producer.TITLE) -> sink(TITLE)
    assert kinds == ["var_static", "dotenv", "sink"]


def test_dotenv_bridge_direct_context_in_echo():
    """Tainted context inlined into the echo-to-file body (no
    intermediate ``variables:`` indirection)."""
    paths = _analyze(
        """
        producer:
          script:
            - echo "REF=$CI_COMMIT_REF_NAME" > build.env
          artifacts:
            reports:
              dotenv: build.env
        consumer:
          needs: [producer]
          script:
            - git checkout "$REF"
        """
    )
    assert len(paths) == 1
    p = paths[0]
    assert p.kind == "dotenv"
    assert p.source_var == "CI_COMMIT_REF_NAME"
    assert [h.kind for h in p.hops] == ["dotenv", "sink"]


def test_dotenv_bridge_needs_block_list_form():
    """``needs:`` block-list form with ``job:`` entries is also supported."""
    paths = _analyze(
        """
        producer:
          variables:
            RAW: $CI_COMMIT_MESSAGE
          script:
            - echo "MSG=$RAW" > env.env
          artifacts:
            reports:
              dotenv: env.env
        consumer:
          needs:
            - job: producer
          script:
            - echo "$MSG"
        """
    )
    assert len(paths) == 1
    assert paths[0].kind == "dotenv"


def test_dotenv_bridge_artifacts_false_blocks_propagation():
    """When the consumer's ``needs:`` entry has ``artifacts: false``
    the runner does NOT inherit the dotenv, and the sink must not fire."""
    paths = _analyze(
        """
        producer:
          variables:
            RAW: $CI_MERGE_REQUEST_TITLE
          script:
            - echo "TITLE=$RAW" > build.env
          artifacts:
            reports:
              dotenv: build.env
        consumer:
          needs:
            - job: producer
              artifacts: false
          script:
            - echo "$TITLE"
        """
    )
    assert paths == []


def test_dotenv_bridge_without_needs_does_not_fire():
    """No ``needs:`` on the consumer -> no inheritance -> no sink."""
    paths = _analyze(
        """
        producer:
          variables:
            RAW: $CI_MERGE_REQUEST_TITLE
          script:
            - echo "TITLE=$RAW" > build.env
          artifacts:
            reports:
              dotenv: build.env
        consumer:
          script:
            - echo "$TITLE"
        """
    )
    assert paths == []


def test_dotenv_bridge_non_tainted_value_does_not_fire():
    """``echo "SHA=$CI_COMMIT_SHA" > build.env`` is clean; SHA is not
    a tainted-context variable."""
    paths = _analyze(
        """
        producer:
          script:
            - echo "SHA=$CI_COMMIT_SHA" > build.env
          artifacts:
            reports:
              dotenv: build.env
        consumer:
          needs: [producer]
          script:
            - echo "$SHA"
        """
    )
    assert paths == []


def test_dotenv_bridge_unused_downstream_does_not_fire():
    """Writer taints dotenv.TITLE, consumer runs but never echoes
    $TITLE; no sink, no finding."""
    paths = _analyze(
        """
        producer:
          variables:
            RAW: $CI_MERGE_REQUEST_TITLE
          script:
            - echo "TITLE=$RAW" > build.env
          artifacts:
            reports:
              dotenv: build.env
        consumer:
          needs: [producer]
          script:
            - echo hello
        """
    )
    assert paths == []


def test_dotenv_bridge_does_not_double_fire_shallow_on_writer():
    """The writer's own ``echo "TITLE=$RAW" > build.env`` line must
    NOT also fire TAINT-GL-001 on ``$RAW`` — shell expansion inside
    an echo-to-file is safe.  Without the dotenv-write skip, both
    rules would light up on the same sink."""
    paths = _analyze(
        """
        producer:
          variables:
            RAW: $CI_MERGE_REQUEST_TITLE
          script:
            - echo "TITLE=$RAW" > build.env
          artifacts:
            reports:
              dotenv: build.env
        consumer:
          needs: [producer]
          script:
            - echo "$TITLE"
        """
    )
    # Exactly one finding — the dotenv bridge on the consumer's echo.
    assert len(paths) == 1
    assert paths[0].kind == "dotenv"


def test_dotenv_bridge_chains_through_multi_hop():
    """A multi-hop chain feeding into the dotenv write classifies as
    ``"dotenv"`` (highest priority), and the full provenance chain is
    preserved in hops."""
    paths = _analyze(
        """
        variables:
          RAW: $CI_COMMIT_MESSAGE
          MID: $RAW
        producer:
          script:
            - echo "OUT=$MID" > build.env
          artifacts:
            reports:
              dotenv: build.env
        consumer:
          needs: [producer]
          script:
            - echo "$OUT"
        """
    )
    assert len(paths) == 1
    p = paths[0]
    assert p.kind == "dotenv"
    kinds = [h.kind for h in p.hops]
    # var_static(RAW) -> var_indirect(MID) -> dotenv(producer.OUT) -> sink
    assert kinds == ["var_static", "var_indirect", "dotenv", "sink"]


def test_taint_gl_003_rule_is_registered_and_fires_on_dotenv_flow():
    rules = load_all_rules()
    by_id = {r.id: r for r in rules}
    assert "TAINT-GL-003" in by_id
    rule = by_id["TAINT-GL-003"]
    assert rule.severity.value == "CRITICAL"
    assert rule.owasp_cicd == "CICD-SEC-4"
    src = (
        "producer:\n"
        "  variables:\n"
        "    RAW: $CI_MERGE_REQUEST_TITLE\n"
        "  script:\n"
        "    - echo \"TITLE=$RAW\" > build.env\n"
        "  artifacts:\n"
        "    reports:\n"
        "      dotenv: build.env\n"
        "consumer:\n"
        "  needs: [producer]\n"
        "  script:\n"
        "    - echo \"$TITLE\"\n"
    )
    matches = rule.pattern.check(src, src.splitlines())
    assert len(matches) == 1
    line_no, snippet = matches[0]
    assert snippet.startswith("taint: $CI_MERGE_REQUEST_TITLE")
    # Chain must name the dotenv bridge explicitly.
    assert "dotenv(producer).TITLE" in snippet


def test_taint_gl_003_does_not_fire_on_other_kinds():
    """TAINT-GL-003 must reject shallow / multi_hop paths so the
    three rules stay disjoint."""
    rules = load_all_rules()
    rule = next(r for r in rules if r.id == "TAINT-GL-003")
    shallow = (
        "build:\n"
        "  variables:\n"
        "    T: $CI_COMMIT_TITLE\n"
        "  script:\n"
        "    - echo \"$T\"\n"
    )
    assert rule.pattern.check(shallow, shallow.splitlines()) == []
    multihop = (
        "variables:\n"
        "  A: $CI_COMMIT_TITLE\n"
        "  B: $A\n"
        "build:\n"
        "  script:\n"
        "    - echo \"$B\"\n"
    )
    assert rule.pattern.check(multihop, multihop.splitlines()) == []


def test_taint_gl_001_002_do_not_fire_on_dotenv_bridge():
    """A dotenv flow must classify as dotenv only — 001 and 002 must
    reject it so the three rules never double-fire on the same sink."""
    rules = load_all_rules()
    src = (
        "producer:\n"
        "  variables:\n"
        "    RAW: $CI_MERGE_REQUEST_TITLE\n"
        "  script:\n"
        "    - echo \"TITLE=$RAW\" > build.env\n"
        "  artifacts:\n"
        "    reports:\n"
        "      dotenv: build.env\n"
        "consumer:\n"
        "  needs: [producer]\n"
        "  script:\n"
        "    - echo \"$TITLE\"\n"
    )
    for rid in ("TAINT-GL-001", "TAINT-GL-002"):
        rule = next(r for r in rules if r.id == rid)
        assert rule.pattern.check(src, src.splitlines()) == [], rid
