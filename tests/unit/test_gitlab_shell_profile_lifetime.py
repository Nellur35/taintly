"""Bound full-solver work without weakening GitLab source validation."""

import pytest

import taintly.rules.gitlab.shell_role as shell_role
from taintly.gitlab_taint import analyze
from taintly.models import scan_session

_CONTENT = (
    "variables:\n  TITLE: $CI_MERGE_REQUEST_TITLE\ncheck:\n  script:\n"
    "    - printf '%s\\n' \"$TITLE\" | sh\n"
    "    - printf '%s\\n' \"$TITLE\" | sh\n"
    "    - printf '%s\\n' \"$TITLE\" | sh\n"
)


def _check_paths(content: str, filepath: str):
    paths = analyze(content, content.splitlines())
    assert len(paths) == 3
    evidence = [shell_role.classify_gitlab_shallow_use(content, filepath, path) for path in paths]
    assert all(witness.role is shell_role.GitLabShellRole.CODE for witness in evidence)
    assert all(
        shell_role.validate_gitlab_shallow_use(witness, content, filepath, witness.sink_line)
        for witness in evidence
    )
    return evidence


def test_full_solver_work_is_per_profile_and_scan_lifetime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0
    real_analyze = shell_role.analyze_gitlab_taint

    def counted_analyze(content, lines):
        nonlocal calls
        calls += 1
        return real_analyze(content, lines)

    monkeypatch.setattr(shell_role, "analyze_gitlab_taint", counted_analyze)
    with scan_session():
        _check_paths(_CONTENT, ".gitlab-ci.yml")
        assert calls == 1, "each occurrence must not repeat the full GitLab solver"
    with scan_session():
        _check_paths(_CONTENT, ".gitlab-ci.yml")
        assert calls == 2, "a new scan must derive its own trusted source profile"
    path = analyze(_CONTENT, _CONTENT.splitlines())[0]
    shell_role.classify_gitlab_shallow_use(_CONTENT, ".gitlab-ci.yml", path)
    assert calls > 2, "a profile must not persist globally outside scan lifetime"


def test_profile_reuse_preserves_content_file_and_backend_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with scan_session():
        original = _check_paths(_CONTENT, ".gitlab-ci.yml")[0]
        other_file = _check_paths(_CONTENT, "other/.gitlab-ci.yml")[0]
        assert other_file.filepath == "other/.gitlab-ci.yml"
        assert not shell_role.validate_gitlab_shallow_use(
            original, _CONTENT, other_file.filepath, original.sink_line
        )
        changed = _CONTENT.replace(
            r"""printf '%s\n' "$TITLE" | sh""",
            r"""printf '%s\n' $TITLE""",
        )
        changed_paths = analyze(changed, changed.splitlines())
        assert len(changed_paths) == 3
        changed_evidence = shell_role.classify_gitlab_shallow_use(
            changed, ".gitlab-ci.yml", changed_paths[0]
        )
        assert changed_evidence.role is shell_role.GitLabShellRole.DATA
        assert shell_role.validate_gitlab_shallow_use(
            changed_evidence, changed, ".gitlab-ci.yml", changed_evidence.sink_line
        )
        assert not shell_role.validate_gitlab_shallow_use(
            original, changed, original.filepath, original.sink_line
        )
        monkeypatch.setenv("TAINTLY_TAINT_BACKEND", "line")
        line_paths = analyze(_CONTENT, _CONTENT.splitlines())
        assert len(line_paths) == 3
        line_evidence = shell_role.classify_gitlab_shallow_use(
            _CONTENT, ".gitlab-ci.yml", line_paths[0]
        )
        assert line_evidence.role is shell_role.GitLabShellRole.CODE
        assert shell_role.validate_gitlab_shallow_use(
            line_evidence, _CONTENT, line_evidence.filepath, line_evidence.sink_line
        )
