"""Unit tests for AI-GH-036 — agent-instruction-file inventory.

The rule fires once per scan when a repository contains any of a
fixed set of files / directories that AI agent harnesses (Claude
Code, Cursor, Aider, GitHub Copilot, Gemini Code, Windsurf) auto-
load as user-trust-tier instructions.  These tests pin both the
fire/no-fire decision (via real tmp_path-built repos) and the
engine-level project-scope dedup behaviour that collapses fan-out
across multi-workflow repos.

The rule's self-test path uses a fixture-marker fallback when the
filepath context is unbound (see ``taintly.rules.github.ai.
_SELF_TEST_FIXTURE_MARKER``); these unit tests exercise the
real-engine path through ``scan_file`` / ``scan_repo`` so the
marker is not required.
"""

from __future__ import annotations

from pathlib import Path

from taintly.engine import scan_file, scan_repo
from taintly.models import Platform
from taintly.rules.github.ai import RULES as AI_RULES

_AI_GH_036 = next(r for r in AI_RULES if r.id == "AI-GH-036")


def _build_repo(tmp_path: Path, agent_files: dict[str, str]) -> Path:
    """Build a tmp repo containing a ``.git/`` marker, a workflow
    file, and any agent-instruction files supplied via
    ``agent_files`` (``relative-path -> contents``).
    Returns the workflow file path so callers can pass it to the
    scanner.
    """
    (tmp_path / ".git").mkdir()
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    workflow = wf_dir / "ci.yml"
    workflow.write_text(
        "name: ci\n"
        "on: push\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "      - run: make\n"
    )
    for rel, contents in agent_files.items():
        target = tmp_path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(contents)
    return workflow


def _findings_for_036(findings):
    return [f for f in findings if f.rule_id == "AI-GH-036"]


def test_fires_when_claude_md_present(tmp_path):
    """A repo with a top-level CLAUDE.md fires AI-GH-036 once."""
    workflow = _build_repo(tmp_path, {"CLAUDE.md": "# project memory\n"})
    findings = scan_file(str(workflow), [_AI_GH_036])
    hits = _findings_for_036(findings)
    assert len(hits) == 1, f"expected 1 fire, got {len(hits)}: {hits}"
    assert hits[0].file == str(workflow)


def test_fires_when_cursorrules_present(tmp_path):
    """``.cursorrules`` (the legacy single-file Cursor form) is in
    the inventory list."""
    workflow = _build_repo(tmp_path, {".cursorrules": "always run pytest\n"})
    findings = scan_file(str(workflow), [_AI_GH_036])
    hits = _findings_for_036(findings)
    assert len(hits) == 1
    assert ".cursorrules" in hits[0].snippet


def test_fires_when_cursor_rules_dir_present(tmp_path):
    """``.cursor/rules/`` (Cursor's directory-of-rules form) fires
    via the ``_AGENT_INSTRUCTION_DIRS`` arm of the inventory."""
    (tmp_path / ".git").mkdir()
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    workflow = wf_dir / "ci.yml"
    workflow.write_text("on: push\njobs: {}\n")
    rules_dir = tmp_path / ".cursor" / "rules"
    rules_dir.mkdir(parents=True)
    (rules_dir / "core.md").write_text("# rule body\n")

    findings = scan_file(str(workflow), [_AI_GH_036])
    hits = _findings_for_036(findings)
    assert len(hits) == 1
    # Snippet renders dirs with a trailing slash to distinguish them
    # from file-form siblings (``.cursor/rules/`` vs ``.cursorrules``).
    assert ".cursor/rules/" in hits[0].snippet


def test_fires_when_gitlab_duo_instructions_present(tmp_path):
    """``.gitlab/duo/instructions.md`` (GitLab Duo agent-instruction
    file, added in PR #32 for Phase 8 Track C) fires via the
    ``_AGENT_INSTRUCTION_FILES`` arm.  The probe walks up to the
    repo root and verifies the path under it."""
    workflow = _build_repo(
        tmp_path,
        {".gitlab/duo/instructions.md": "# duo instructions\n"},
    )
    findings = scan_file(str(workflow), [_AI_GH_036])
    hits = _findings_for_036(findings)
    assert len(hits) == 1
    assert ".gitlab/duo/instructions.md" in hits[0].snippet


def test_fires_when_gitlab_ci_local_dir_present(tmp_path):
    """``.gitlab-ci-local/`` directory fires via the
    ``_AGENT_INSTRUCTION_DIRS`` arm.  Directories are rendered with
    a trailing slash in the snippet."""
    (tmp_path / ".git").mkdir()
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    workflow = wf_dir / "ci.yml"
    workflow.write_text("on: push\njobs: {}\n")
    local_dir = tmp_path / ".gitlab-ci-local"
    local_dir.mkdir()
    (local_dir / "prompt.md").write_text("# local agent prompt\n")

    findings = scan_file(str(workflow), [_AI_GH_036])
    hits = _findings_for_036(findings)
    assert len(hits) == 1
    assert ".gitlab-ci-local/" in hits[0].snippet


def test_no_fire_on_clean_repo(tmp_path):
    """A workflow file in a repo with NO agent-instruction file
    must not fire — the rule's only signal is the file's presence."""
    workflow = _build_repo(tmp_path, {})
    findings = scan_file(str(workflow), [_AI_GH_036])
    hits = _findings_for_036(findings)
    assert hits == []


def test_dedupes_across_multiple_workflows(tmp_path):
    """Three workflow files in a repo with one CLAUDE.md fire only
    ONCE in aggregate — the engine's ``_PROJECT_SCOPE_RULES`` dedup
    collapses fan-out because the underlying repo-root state is the
    same regardless of how many YAML files exist."""
    (tmp_path / ".git").mkdir()
    (tmp_path / "CLAUDE.md").write_text("# project memory\n")
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    for name in ("ci.yml", "release.yml", "deploy.yml"):
        (wf_dir / name).write_text(
            "on: push\njobs:\n  x:\n    runs-on: ubuntu-latest\n    steps: []\n"
        )

    reports = scan_repo(str(tmp_path), [_AI_GH_036], platform=Platform.GITHUB)
    assert reports, "scan_repo returned no reports"
    hits = [f for f in reports[0].findings if f.rule_id == "AI-GH-036"]
    assert len(hits) == 1, (
        f"project-scope dedup should keep exactly 1 fire across 3 "
        f"workflows; got {len(hits)}: {[(f.file, f.line) for f in hits]}"
    )


def test_snippet_names_the_file(tmp_path):
    """The finding's snippet must mention the actual file name(s)
    detected so a reviewer can audit the right paths without
    re-scanning the repo."""
    workflow = _build_repo(
        tmp_path,
        {
            "CLAUDE.md": "# memory\n",
            "AGENTS.md": "# multi-vendor\n",
        },
    )
    findings = scan_file(str(workflow), [_AI_GH_036])
    hits = _findings_for_036(findings)
    assert len(hits) == 1
    snippet = hits[0].snippet
    assert "CLAUDE.md" in snippet
    assert "AGENTS.md" in snippet
