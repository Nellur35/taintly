"""FP-audit class C (2026-05-17): multi-line GitLab ``rules:if:`` blocks.

GitLab's ``rules: - if: ...`` accepts a small boolean-expression DSL
evaluated by the GitLab CI engine.  When the expression is written as a
block scalar (``if: |``) the continuation lines look like shell
``$VAR`` references but have no shell-injection surface.  The pre-fix
SEC4-GL-001 / SEC4-GL-003 excludes only matched the first line of the
block (``^\\s*-?\\s*if:``) so continuation lines fired as FPs.

This test pins:
  - ``_gitlab_rules_if_body_lines`` correctly masks continuation lines
    for block-scalar (``|``, ``>``, with chomp indicators) and
    implicit plain-scalar continuation shapes.
  - SEC4-GL-001 / SEC4-GL-003 produce zero findings against the
    real-world gitlabhq ``.gitlab/ci/rules.gitlab-ci.yml`` shape.
  - Inline ``if:`` values and shell ``script:`` lines are NOT masked
    — only the value of an ``if:`` key is suppressed.
"""

from __future__ import annotations

import textwrap

from taintly.engine import scan_file
from taintly.models import RegexPattern, _gitlab_rules_if_body_lines
from taintly.rules.registry import load_all_rules


def _split(text: str) -> list[str]:
    return textwrap.dedent(text).strip("\n").splitlines()


# =============================================================================
# Helper-level tests
# =============================================================================


def test_block_scalar_pipe_masks_continuation_lines():
    lines = _split(
        """
        rules:
          - if: |
              $SCHEDULE_TYPE != "weekly"
              && $CI_COMMIT_REF_NAME == $CI_DEFAULT_BRANCH
              || $CI_COMMIT_TAG
          script:
            - echo $CI_COMMIT_REF_NAME
        """
    )
    skip = _gitlab_rules_if_body_lines(lines)
    # The three deeper-indented body lines (indices 2, 3, 4) are masked.
    assert {2, 3, 4} == skip
    # The shell ``script:`` line (index 6) is NOT masked.
    assert 6 not in skip
    # The ``if:`` opener itself (index 1) is NOT masked — same-line
    # excludes already cover it.
    assert 1 not in skip


def test_block_scalar_folded_and_chomp_indicators():
    for indicator in ("|", "|+", "|-", ">", ">+", ">-"):
        lines = _split(
            f"""
            rules:
              - if: {indicator}
                  $CI_COMMIT_REF_NAME == "main"
                  && $CI_COMMIT_BRANCH != "stable"
            """
        )
        skip = _gitlab_rules_if_body_lines(lines)
        assert 2 in skip and 3 in skip, f"indicator {indicator!r} missed continuations"


def test_inline_if_value_is_not_masked():
    lines = _split(
        """
        rules:
          - if: $CI_COMMIT_BRANCH == "main"
          - if: $CI_COMMIT_REF_NAME =~ /^v/
        """
    )
    # Inline ``if:`` has no continuation lines — helper returns empty.
    assert _gitlab_rules_if_body_lines(lines) == set()


def test_script_block_scalar_is_not_masked():
    # A ``script: |`` block IS shell and must keep firing — the helper
    # only masks ``if:`` keys.
    lines = _split(
        """
        job:
          script: |
            echo $CI_COMMIT_REF_NAME
            deploy.sh $CI_COMMIT_TAG
        """
    )
    assert _gitlab_rules_if_body_lines(lines) == set()


def test_sibling_key_terminates_block():
    # Indentation returning to the ``if:`` level or shallower ends the
    # block; subsequent ``when:`` line is NOT masked.
    lines = _split(
        """
        rules:
          - if: |
              $CI_COMMIT_REF_NAME == "main"
              || $CI_COMMIT_TAG
            when: manual
        """
    )
    skip = _gitlab_rules_if_body_lines(lines)
    # body lines (indices 2, 3) masked; when: (index 4) not masked.
    assert {2, 3} == skip


def test_helper_on_empty_input():
    assert _gitlab_rules_if_body_lines([]) == set()


# =============================================================================
# RegexPattern integration — gitlab_if_block_aware flag
# =============================================================================


def test_regex_pattern_flag_suppresses_continuation_match():
    pattern_off = RegexPattern(
        match=r"\$CI_COMMIT_REF_NAME",
        exclude=[r"^\s*-?\s*if:"],
    )
    pattern_on = RegexPattern(
        match=r"\$CI_COMMIT_REF_NAME",
        exclude=[r"^\s*-?\s*if:"],
        gitlab_if_block_aware=True,
    )
    lines = _split(
        """
        rules:
          - if: |
              $CI_COMMIT_REF_NAME == $CI_DEFAULT_BRANCH
              || $CI_COMMIT_REF_NAME =~ /^v/
        """
    )
    content = "\n".join(lines)
    assert len(pattern_off.check(content, lines)) == 2
    assert len(pattern_on.check(content, lines)) == 0


# =============================================================================
# Rule-level integration — SEC4-GL-001 / SEC4-GL-003 on the audit repro
# =============================================================================


def test_sec4_gl_001_and_003_zero_findings_on_gitlabhq_shape(tmp_path):
    """End-to-end: feed the gitlabhq-shape fixture to the engine and
    assert SEC4-GL-001 / SEC4-GL-003 produce zero findings.

    Pre-fix counts (May-17 audit): 5 SEC4-GL-003 + 4 SEC4-GL-001 = 9.
    Post-fix: 0.
    """
    fixture = tmp_path / "rules.gitlab-ci.yml"
    fixture.write_text(
        textwrap.dedent(
            """
            .if-default-branch-or-stable:
              rules:
                - if: |
                    $SCHEDULE_TYPE != "weekly"
                    && $TRIGGERED_BY_AI_GATEWAY_PROJECT != "true"
                    &&
                    (
                      $CI_COMMIT_REF_NAME == $CI_DEFAULT_BRANCH
                      || $CI_COMMIT_REF_NAME =~ /^[\\d-]+-stable(-ee)?$/
                      || $CI_COMMIT_REF_NAME =~ /^\\d+-\\d+-auto-deploy-\\d+$/
                      || $CI_COMMIT_TAG
                      || $CI_MERGE_REQUEST_TITLE =~ /Revert "/
                      || $CI_COMMIT_BRANCH == "main"
                      || $CI_COMMIT_MESSAGE =~ /chore: release/
                    )
            """
        ).lstrip("\n"),
        encoding="utf-8",
    )
    rules = [r for r in load_all_rules() if r.id in ("SEC4-GL-001", "SEC4-GL-003")]
    findings = scan_file(str(fixture), rules)
    assert findings == [], (
        f"expected 0 findings, got {len(findings)}: "
        + ", ".join(f"{f.rule_id}@L{f.line}" for f in findings)
    )


def test_sec4_gl_003_still_fires_on_real_shell_usage(tmp_path):
    """Negative-of-negative: don't over-suppress.  An unquoted
    ``$CI_COMMIT_REF_NAME`` in an actual ``script:`` block must still
    fire even when the same file also contains a multi-line ``if: |``.
    """
    fixture = tmp_path / ".gitlab-ci.yml"
    fixture.write_text(
        textwrap.dedent(
            """
            deploy:
              rules:
                - if: |
                    $CI_COMMIT_REF_NAME == $CI_DEFAULT_BRANCH
              script:
                - docker tag image:latest image:$CI_COMMIT_REF_NAME
            """
        ).lstrip("\n"),
        encoding="utf-8",
    )
    rules = [r for r in load_all_rules() if r.id == "SEC4-GL-003"]
    findings = scan_file(str(fixture), rules)
    assert len(findings) == 1, (
        f"expected 1 finding on the script line, got {len(findings)}: "
        + ", ".join(f"L{f.line}: {f.snippet}" for f in findings)
    )
    assert findings[0].line == 6
