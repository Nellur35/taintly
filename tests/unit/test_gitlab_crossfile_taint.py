"""Tests for GitLab cross-file / inheritance taint (gitlab_inherit +
TAINT-GL-008).

Two layers:

* Unit tests over ``gitlab_inherit`` — the inheritance / reference /
  include resolver and the cross-boundary edge emitter, exercised on
  in-memory ``(filepath, content)`` lists (no disk needed).
* Integration tests over the engine — TAINT-GL-008 fires (and does NOT
  double-fire with the single-file TAINT-GL-* rules) on tmp_path repos
  with realistic ``.gitlab-ci.yml`` + included files.
"""

from __future__ import annotations

from pathlib import Path

from taintly.engine import scan_repo
from taintly.gitlab_inherit import find_cross_file_taint, resolve_pipeline
from taintly.models import Platform
from taintly.rules.registry import load_all_rules


# ---------------------------------------------------------------------------
# Resolver unit tests
# ---------------------------------------------------------------------------


def test_extends_merges_parent_variables_and_script() -> None:
    entry = (
        ".base:\n"
        "  script:\n"
        '    - echo "$VAR"\n'
        "consumer:\n"
        "  variables:\n"
        "    VAR: $CI_COMMIT_TITLE\n"
        "  extends: .base\n"
    )
    graph = resolve_pipeline([("ci.yml", entry)])
    job = graph.jobs["consumer"]
    # The inherited script leaf is present and tagged via extends.
    script_leaves = [leaf for leaf in job.leaves if leaf.path and leaf.path[0] == "script"]
    assert script_leaves, "extends: should pull in the parent's script"
    assert all(leaf.via == "extends" for leaf in script_leaves)
    # Hidden template jobs are not surfaced as runnable jobs.
    assert ".base" not in graph.jobs


def test_extends_list_left_to_right_precedence() -> None:
    entry = (
        ".a:\n  variables:\n    V: clean-a\n"
        ".b:\n  variables:\n    V: clean-b\n"
        "job:\n  extends:\n    - .a\n    - .b\n  script:\n    - echo hi\n"
    )
    graph = resolve_pipeline([("ci.yml", entry)])
    var_leaves = {
        leaf.path[1]: leaf.value
        for leaf in graph.jobs["job"].leaves
        if len(leaf.path) == 2 and leaf.path[0] == "variables"
    }
    # Later parent (.b) overrides earlier (.a) per GitLab merge order.
    assert var_leaves["V"] == "clean-b"


def test_reference_tag_splices_variable_value() -> None:
    entry = (
        ".vars:\n  variables:\n    SRC: $CI_MERGE_REQUEST_TITLE\n"
        "job:\n"
        "  variables:\n"
        "    LAUNDERED: !reference [.vars, variables]\n"
        '  script:\n    - echo "$SRC"\n'
    )
    graph = resolve_pipeline([("ci.yml", entry)])
    # The !reference splice surfaces the referenced job's variables.
    ref_leaves = [leaf for leaf in graph.jobs["job"].leaves if leaf.via == "reference"]
    assert ref_leaves, "!reference [job, key] should splice the referenced block"


def test_extends_cycle_terminates() -> None:
    # A pathological mutual-extends cycle must not loop forever.
    entry = (
        ".a:\n  extends: .b\n  variables:\n    X: 1\n"
        ".b:\n  extends: .a\n  variables:\n    Y: 2\n"
        "job:\n  extends: .a\n  script:\n    - echo hi\n"
    )
    graph = resolve_pipeline([("ci.yml", entry)])
    assert "job" in graph.jobs  # resolved without hanging


def test_top_level_cascade_visible_in_inherited_script() -> None:
    entry = (
        "variables:\n  TOPV: $CI_COMMIT_TITLE\n"
        ".base:\n  script:\n    - echo $TOPV\n"
        "job:\n  extends: .base\n"
    )
    graph = resolve_pipeline([("ci.yml", entry)])
    cascade_leaves = [leaf for leaf in graph.jobs["job"].leaves if leaf.via == "cascade"]
    assert any(leaf.path == ("variables", "TOPV") for leaf in cascade_leaves)


# ---------------------------------------------------------------------------
# Cross-boundary edge tests
# ---------------------------------------------------------------------------


def test_cross_file_flow_via_include_and_extends() -> None:
    entry = (
        "include:\n  - local: base.yml\n"
        "consumer:\n"
        "  variables:\n"
        "    DEST: $CI_COMMIT_REF_SLUG\n"
        "  extends: .docker_base\n"
    )
    base = ".docker_base:\n  script:\n    - echo \"build ${DEST}\"\n"
    flows = find_cross_file_taint([("/repo/.gitlab-ci.yml", entry), ("/repo/base.yml", base)])
    assert len(flows) == 1
    f = flows[0]
    assert f.job == "consumer"
    assert f.source_var == "CI_COMMIT_REF_SLUG"
    assert f.laundered_var == "DEST"
    # Source assignment is in the entry file; sink is in the included file.
    assert f.source_file.endswith(".gitlab-ci.yml")
    assert f.sink_file.endswith("base.yml")
    assert "include" in f.boundary and "extends" in f.boundary


def test_same_file_same_job_flow_does_not_double_fire() -> None:
    # A purely single-file flow (variable + sink in the same job, same
    # file, no inheritance) is the single-file engine's job — the
    # cross-file emitter must NOT report it.
    entry = (
        "job:\n"
        "  variables:\n"
        "    V: $CI_COMMIT_TITLE\n"
        '  script:\n    - echo "$V"\n'
    )
    flows = find_cross_file_taint([("/repo/.gitlab-ci.yml", entry)])
    assert flows == []


def test_extends_laundered_flow_within_one_file_fires() -> None:
    # Source var + sink both in a hidden template the single-file pass
    # skips, surfaced into a consumer via extends — invisible to the
    # single-file engine, so the cross-file emitter should report it.
    entry = (
        ".base:\n"
        "  variables:\n"
        "    V: $CI_COMMIT_MESSAGE\n"
        "  script:\n"
        "    - echo $V\n"
        "job:\n"
        "  extends: .base\n"
    )
    flows = find_cross_file_taint([("/repo/.gitlab-ci.yml", entry)])
    assert any(f.laundered_var == "V" and f.source_var == "CI_COMMIT_MESSAGE" for f in flows)


def test_clean_literal_does_not_fire() -> None:
    entry = (
        "include:\n  - local: base.yml\n"
        "consumer:\n"
        "  variables:\n"
        "    DEST: registry.example.com/ci/base:1.2.3\n"
        "  extends: .docker_base\n"
    )
    base = ".docker_base:\n  script:\n    - echo \"build ${DEST}\"\n"
    flows = find_cross_file_taint([("/repo/.gitlab-ci.yml", entry), ("/repo/base.yml", base)])
    assert flows == []


def test_image_sink_across_extends() -> None:
    entry = (
        ".base:\n  image: $IMG\n  script:\n    - echo hi\n"
        "job:\n  variables:\n    IMG: $CI_MERGE_REQUEST_TITLE\n  extends: .base\n"
    )
    flows = find_cross_file_taint([("/repo/.gitlab-ci.yml", entry)])
    assert any(f.sink_kind == "image" and f.laundered_var == "IMG" for f in flows)


# ---------------------------------------------------------------------------
# Engine integration — TAINT-GL-008
# ---------------------------------------------------------------------------


def _gl_findings(tmp_path: Path, rule_id: str) -> list:
    rules = load_all_rules()
    reports = scan_repo(str(tmp_path), rules, Platform.GITLAB)
    return [f for r in reports for f in r.findings if f.rule_id == rule_id]


def test_taint_gl_008_fires_end_to_end(tmp_path: Path) -> None:
    (tmp_path / ".gitlab-ci.yml").write_text(
        "include:\n  - local: docker.yml\n"
        "container_build:\n"
        "  variables:\n"
        "    DOCKER_DEST: $CI_REGISTRY_IMAGE:${CI_COMMIT_REF_SLUG}\n"
        "  extends: .docker_base\n"
    )
    (tmp_path / "docker.yml").write_text(
        ".docker_base:\n  script:\n    - echo \"pushing ${DOCKER_DEST}\"\n"
    )
    findings = _gl_findings(tmp_path, "TAINT-GL-008")
    assert findings, "TAINT-GL-008 should fire on a cross-file laundered flow"
    # The finding is cited at the sink file (the executable surface).
    assert any(f.file.endswith("docker.yml") for f in findings)
    assert all(f.review_needed for f in findings)


def test_taint_gl_008_no_fire_on_pure_single_file(tmp_path: Path) -> None:
    # A single-file shallow flow (TAINT-GL-001 territory): TAINT-GL-008
    # must NOT also fire — no double-counting.
    (tmp_path / ".gitlab-ci.yml").write_text(
        "job:\n"
        "  variables:\n"
        "    PR: $CI_MERGE_REQUEST_TITLE\n"
        '  script:\n    - echo "$PR"\n'
    )
    assert _gl_findings(tmp_path, "TAINT-GL-008") == []
