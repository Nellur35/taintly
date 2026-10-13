"""End-to-end controls for absorbed cross-job authority alternatives."""

from pathlib import Path

import pytest

from taintly.engine import scan_repo
from taintly.models import Platform
from taintly.rules.registry import load_all_rules


def _authority_steps(guards: list[str]) -> str:
    return "".join(
        f"      - name: authority {index}\n"
        f"        if: {guard}\n"
        "        run: gh issue edit 1 --add-label constant\n"
        for index, guard in enumerate(guards)
    )


def _workflow(producer_ref: str, authority_guards: list[str]) -> str:
    return (
        "on: issues\n"
        "jobs:\n"
        "  produce:\n"
        "    runs-on: ubuntu-latest\n"
        "    permissions:\n"
        "      contents: read\n"
        f"    if: github.ref == 'refs/heads/{producer_ref}'\n"
        "    outputs:\n"
        "      val: ${{ steps.source.outputs.val }}\n"
        "    steps:\n"
        "      - id: source\n"
        '        run: echo "val=hello" >> $GITHUB_OUTPUT\n'
        "  consume:\n"
        "    runs-on: ubuntu-latest\n"
        "    needs: produce\n"
        "    permissions:\n"
        "      contents: write\n"
        "    env:\n"
        "      VALUE: ${{ needs.produce.outputs.val }}\n"
        "    steps:\n" + _authority_steps(authority_guards)
    )


def _chain_present(tmp_path: Path, body: str) -> bool:
    target = tmp_path / ".github" / "workflows" / "case.yml"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(body, encoding="utf-8")
    reports = scan_repo(str(tmp_path), load_all_rules(), Platform.GITHUB)
    findings = [finding for report in reports for finding in report.findings]
    assert not [finding for finding in findings if finding.rule_id == "ENGINE-ERR"]
    return any(finding.rule_id == "CHAIN-GH-105" for finding in findings)


def _redundant_main_guards(count: int, *, broad_first: bool) -> list[str]:
    broad = "github.ref == 'refs/heads/main'"
    restricted = [
        f"{broad} && github.ref != 'refs/heads/other-{index}'" for index in range(count - 1)
    ]
    return [broad, *restricted] if broad_first else [*restricted, broad]


@pytest.mark.parametrize("broad_first", [True, False], ids=["broad-first", "broad-last"])
def test_65_absorbed_authorities_do_not_keep_disjoint_crossjob_chain(
    tmp_path: Path, broad_first: bool
) -> None:
    body = _workflow("release", _redundant_main_guards(65, broad_first=broad_first))
    assert not _chain_present(tmp_path, body)


def test_64_disjoint_authorities_remain_provably_incompatible(tmp_path: Path) -> None:
    broad = "github.ref == 'refs/heads/main'"
    guards = [f"{broad} && github.ref != 'refs/heads/other-{index}'" for index in range(64)]
    assert len(guards) == 64
    assert not _chain_present(tmp_path, _workflow("release", guards))


def test_65_compatible_authorities_still_keep_the_crossjob_chain(tmp_path: Path) -> None:
    body = _workflow("main", _redundant_main_guards(65, broad_first=True))
    assert _chain_present(tmp_path, body)


def test_incomparable_overflow_remains_unknown_and_keeps_candidate(tmp_path: Path) -> None:
    guards = [f"github.ref == 'refs/heads/owner-{index}'" for index in range(65)]
    assert _chain_present(tmp_path, _workflow("release", guards))


def test_opaque_authority_alternative_still_keeps_candidate(tmp_path: Path) -> None:
    guards = _redundant_main_guards(65, broad_first=True) + ["inputs.should_run"]
    assert _chain_present(tmp_path, _workflow("release", guards))


def test_single_disjoint_authority_remains_provably_incompatible(tmp_path: Path) -> None:
    guard = "github.ref == 'refs/heads/main'"
    assert not _chain_present(tmp_path, _workflow("release", [guard]))


def test_unconstrained_authority_alternative_still_keeps_candidate(tmp_path: Path) -> None:
    guards = ["github.ref == 'refs/heads/main'", "true"]
    assert _chain_present(tmp_path, _workflow("release", guards))
