"""Family-level negative-corpus tests for GitLab CI.

Each test fires a specific high-blast-radius GitLab rule **family**
against a safe idiom harvested from real-world public GitLab CI
files (gitlab-org/gitlab-runner, gitlab-org/cli, fdroid/fdroidserver,
GNOME/glib, gitlabhq, etc.) and asserts that **no rule in the family
fires**.

The rationale follows from
``feedback_rule_drift_defenses`` headline:

> Three of five May-18 audit bugs were rules drifting away from
> production after they shipped, not rules broken at ship time.
> The defense isn't tighter initial review — it's a corpus-refresh
> cadence that locks in safe idioms as test obligations.

Family-level tests (vs per-rule tests) are deliberate: when rule
clusters claim coverage of a threat domain, a safe idiom must not
fire ANY rule in the family.  Adding a new rule to the family that
accidentally re-introduces a known FP is detected here, even if the
old rule was hardened away.

Fixture conventions:
  * ``tests/fixtures/gitlab/safe/negative_corpus/<rule>_<shape>.yml``
  * One safe idiom per fixture, header comment cites the source
    repo + line and the bash/YAML semantic that makes it safe.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from taintly.engine import scan_file
from taintly.models import Platform
from taintly.rules.registry import load_rules_for_platform

NEG_CORPUS = (
    Path(__file__).parent.parent / "fixtures" / "gitlab" / "safe" / "negative_corpus"
)


@pytest.fixture(scope="module")
def gitlab_rules():
    return load_rules_for_platform(Platform.GITLAB)


def _findings_for_family(filepath: Path, rules, family_prefix: str) -> list[str]:
    """Return rule_ids in ``family_prefix`` that fired on ``filepath``."""
    findings = scan_file(str(filepath), rules)
    return sorted(f.rule_id for f in findings if f.rule_id.startswith(family_prefix))


# ---------------------------------------------------------------------------
# SEC4-GL family — user-controlled GitLab CI variable in shell
# ---------------------------------------------------------------------------


def test_sec4_gl_family_silent_on_bash_double_bracket(gitlab_rules):
    """``[[ \\$CI_COMMIT_BRANCH =~ pattern ]]`` is safe — Bash §3.2.5.2
    explicitly disables word splitting and pathname expansion inside
    ``[[ ]]``.  No injection surface, no SEC4-GL-* fire.

    Source: gitlab-org/cli, gitlab-org/gitlab-runner qa.gitlab-ci.yml.
    """
    fp = NEG_CORPUS / "sec4_gl_001_bash_double_bracket.yml"
    fired = _findings_for_family(fp, gitlab_rules, "SEC4-GL-")
    assert fired == [], (
        f"SEC4-GL family fired on Bash [[ ]] conditional: {fired}. "
        "Word splitting is disabled inside [[ ]] per Bash §3.2.5.2; "
        "the SEC4-GL-003 exclude already encodes this rule for the "
        "CI_COMMIT_REF_NAME family — SEC4-GL-001 should too."
    )


def test_sec4_gl_family_silent_on_bash_assignment(gitlab_rules):
    """``BRANCH_NAME=\\$CI_COMMIT_BRANCH`` is safe — Bash §3.5.6
    explicitly disables word splitting on the RHS of a variable
    assignment.  ``VAR=\\$X`` is equivalent to ``VAR="\\$X"``.

    Source: gitlab-org/cli, gitlab-org/gitlab-runner qa.gitlab-ci.yml.
    """
    fp = NEG_CORPUS / "sec4_gl_001_bash_assignment.yml"
    fired = _findings_for_family(fp, gitlab_rules, "SEC4-GL-")
    assert fired == [], (
        f"SEC4-GL family fired on bash variable assignment: {fired}. "
        "Per Bash §3.5.6 the RHS of an assignment is implicitly "
        "single-string; word splitting and globbing are disabled."
    )


def test_sec4_gl_family_silent_on_wrapping_quoted_curl_form(gitlab_rules):
    """Multi-arg ``curl --form description="${A} / ${B}"`` idiom
    used by Coverity / Sonar / release-notification jobs everywhere.

    Per Bash manual §3.5.7, parameter expansion inside double quotes
    does NOT undergo word splitting — the entire ``"${A} / ${B}"``
    is one argument regardless of internal whitespace in the values.

    Source: GNOME/glib `.gitlab-ci.yml:1090` (Coverity Scan upload).
    Closed by the May-18 audit batch; this fixture locks the safe
    idiom against future regressions.
    """
    fp = NEG_CORPUS / "sec4_gl_001_wrapping_quoted_curl_form.yml"
    fired = _findings_for_family(fp, gitlab_rules, "SEC4-GL-")
    assert fired == [], (
        f"SEC4-GL family fired on wrapping ``curl --form`` idiom: {fired}. "
        "Wrapping-quote exclude in SEC4-GL-001 (May-18 audit) and the "
        "long-standing SEC4-GL-003 wrapping-quote exclude must keep "
        "this safe shape silent."
    )


def test_sec4_gl_family_silent_on_multi_line_if_flow_continuation(gitlab_rules):
    """GitLab CI ``rules: if:`` with plain-style flow continuation
    via hanging ``&&`` / ``||`` operators — common idiom for complex
    branch/tag/event conditionals.  The ``if:`` expression is the
    GitLab engine's expression DSL, not a shell — no injection.

    Source: GNOME/glib `.gitlab-ci.yml:65-72`.  Closed by the May-18
    audit (``_gitlab_rules_if_body_lines`` continuation walk now runs
    for any ``if:`` regardless of inline-value vs block-scalar).
    """
    fp = NEG_CORPUS / "sec4_gl_001_multi_line_if_flow_continuation.yml"
    fired = _findings_for_family(fp, gitlab_rules, "SEC4-GL-")
    assert fired == [], (
        f"SEC4-GL family fired on multi-line `if:` flow continuation: {fired}. "
        "The gitlab_if_block_aware helper must mask every continuation "
        "line indented under the `if:` key, regardless of inline-value "
        "vs block-scalar opener."
    )


# ---------------------------------------------------------------------------
# SEC3-GL family — project includes
# ---------------------------------------------------------------------------


def test_sec3_gl_002_silent_on_sha_pinned_project_include(gitlab_rules):
    """``include: project: ... ref: <40-char SHA>`` is the documented
    safe form per https://docs.gitlab.com/ci/yaml/includes/ — the
    include is immutable.  Must NOT fire SEC3-GL-002 regardless of
    whether the project namespace is GitLab-internal or third-party.

    Source: GitLab CI docs canonical example + real-world configs that
    follow it.  Locks the rule's negative case so future precision
    work (e.g. tag-pin acceptance, allowlist) doesn't accidentally
    silence the legitimate SHA-pin path.
    """
    fp = NEG_CORPUS / "sec3_gl_002_sha_pinned_project_include.yml"
    fired = _findings_for_family(fp, gitlab_rules, "SEC3-GL-002")
    assert fired == [], (
        f"SEC3-GL-002 fired on SHA-pinned project includes: {fired}. "
        "40-char hex refs are immutable per git semantics; rule "
        "must distinguish them from mutable tag / branch refs."
    )


# ---------------------------------------------------------------------------
# SEC9-GL family — artifact access posture
# ---------------------------------------------------------------------------


def test_sec9_gl_001_silent_on_explicit_access_developer(gitlab_rules):
    """``artifacts: access: developer`` is the documented safe form
    per https://docs.gitlab.com/ci/yaml/#artifactsaccess.  The rule
    fires on missing ``access:``; the explicit-value form must not.

    Source: gitlab-org/cli (test-coverage job uses
    ``access: "developer"`` with a quoted value).
    """
    fp = NEG_CORPUS / "sec9_gl_001_artifacts_access_developer.yml"
    fired = _findings_for_family(fp, gitlab_rules, "SEC9-GL-001")
    assert fired == [], (
        f"SEC9-GL-001 fired on explicit ``access: developer``: {fired}. "
        "Quoted and unquoted forms must both be accepted by the rule's "
        "exclude."
    )


def test_sec9_gl_001_silent_on_access_none_and_maintainer(gitlab_rules):
    """GitLab 17.x added ``access: maintainer`` alongside the existing
    ``developer`` / ``none`` / ``all`` values.  The rule's exclude
    list must cover all three documented restrictive values
    (developer / none / maintainer) in quoted and unquoted form.

    Source: GitLab CI docs §artifactsaccess.
    """
    fp = NEG_CORPUS / "sec9_gl_001_artifacts_access_none_and_maintainer.yml"
    fired = _findings_for_family(fp, gitlab_rules, "SEC9-GL-001")
    assert fired == [], (
        f"SEC9-GL-001 fired on ``access: none`` / ``access: maintainer``: "
        f"{fired}.  Both are documented restrictive values; both quoted "
        "and unquoted variants must be silent."
    )


# ---------------------------------------------------------------------------
# LOTP-GL family — trigger-gating
# ---------------------------------------------------------------------------


def test_lotp_gl_001_silent_on_tag_only_release_job(gitlab_rules):
    """Tag-only release jobs (``rules: - if: $CI_COMMIT_TAG``) are
    NOT MR-reachable — fork-MRs cannot create tags on the parent
    project.  LOTP-GL-001's threat model requires an MR-event
    pipeline; tag-only jobs are out of scope even when they invoke
    build tools (``npm ci``, ``npm publish``, etc.).

    Source: synthesised from gitlab-org/cli release stage and the
    goreleaser/maven-publish patterns.  Locks the rule's trigger-
    gating: the build-tool anchor matches but the rule must not
    fire because the job is not MR-event-triggered.
    """
    fp = NEG_CORPUS / "lotp_gl_001_tag_only_release_job.yml"
    fired = _findings_for_family(fp, gitlab_rules, "LOTP-GL-")
    assert fired == [], (
        f"LOTP-GL family fired on tag-only release job: {fired}. "
        "Tag-only jobs are not MR-reachable; the LOTP-GL trigger "
        "gating must keep them silent."
    )


# ---------------------------------------------------------------------------
# Cross-family — combined real-fixture sanity
# ---------------------------------------------------------------------------


def test_no_lotp_gl_or_sec4_gl_fire_on_any_negative_corpus_fixture(gitlab_rules):
    """Sweep: scan every fixture under ``negative_corpus/`` and assert
    that no rule in the LOTP-GL or SEC4-GL families fires on any of
    them.  This is the family-level coverage guarantee from
    ``feedback_rule_drift_defenses`` (point #3): when a rule cluster
    claims coverage of a threat domain, **none** of the safe idioms
    in the negative corpus should fire **any** rule in the cluster.

    Adding a new rule to LOTP-GL or SEC4-GL that re-introduces a
    known FP (because the new rule's regex matches the safe shape)
    surfaces here as a test failure, even if the per-rule positive
    samples still pass.
    """
    fixtures = sorted(NEG_CORPUS.glob("*.yml"))
    assert fixtures, "no negative-corpus fixtures found — wiring broken"
    fired_anywhere: dict[str, list[str]] = {}
    for fp in fixtures:
        fired = sorted(
            f.rule_id
            for f in scan_file(str(fp), gitlab_rules)
            if f.rule_id.startswith(("LOTP-GL-", "SEC4-GL-"))
        )
        if fired:
            fired_anywhere[fp.name] = fired
    assert not fired_anywhere, (
        "LOTP-GL / SEC4-GL family fired on safe idioms harvested from "
        f"real public GitLab CI corpora: {fired_anywhere}.  "
        "Each fixture cites its source repo + line + the Bash/YAML "
        "semantic that makes it safe — fix the rule, do not weaken "
        "the test."
    )
