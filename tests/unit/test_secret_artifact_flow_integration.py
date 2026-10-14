"""Product registry, CLI and mixed-coverage artifact-file contracts."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from taintly._pattern_contract import assert_snippet_matches_line
from taintly.models import IncompletePatternMatches, Platform, Severity
from taintly.rules.registry import load_rules_for_platform
from taintly.testing.mutations import MUTATION_OPERATORS
from taintly.testing.self_test import run_self_test
from tests.unit.test_secret_artifact_flow_contract import _SAME_JOB, _WRITER_LINE

import taintly
from taintly.rules.github.secret_artifact_flow import _SEALED_FLOW_KEY_EQUIVALENT


class SecretArtifactFlowIntegration(unittest.TestCase):
    def test_registry_pattern_contract_and_builtin_self_test(self) -> None:
        rules = [
            rule for rule in load_rules_for_platform(Platform.GITHUB) if rule.id == "SEC6-GH-016"
        ]
        assert len(rules) == 1
        rule = rules[0]
        assert rule.severity is Severity.MEDIUM
        assert rule.review_needed
        assert len(rule.test_positive) == 2
        assert len(rule.test_negative) == 1

        sample = rule.test_positive[0]
        lines = sample.splitlines()
        findings = rule.pattern.check(sample, lines)
        assert len(findings) == 1
        line_number, snippet = findings[0]
        assert_snippet_matches_line(line_number, snippet, lines)

        self_test = run_self_test(rules)
        assert len(self_test) == 3
        assert all(result.passed for result in self_test), self_test

    def test_quoted_flow_mapping_fixture_matches_block_form(self) -> None:
        rules = [
            rule for rule in load_rules_for_platform(Platform.GITHUB) if rule.id == "SEC6-GH-016"
        ]
        findings = rules[0].pattern.check(
            _SEALED_FLOW_KEY_EQUIVALENT, _SEALED_FLOW_KEY_EQUIVALENT.splitlines()
        )
        assert len(findings) == 1, findings

    def test_mixed_jobs_keep_only_complete_jobs_findings_in_both_orders(self) -> None:
        uncertain_job = """  unknown:
    runs-on: ubuntu-latest
    steps:
      - name: Write candidate report
        env:
          REPORT_TOKEN: ${{ secrets.REPORT_TOKEN }}
        run: |
          printf 'credential=%s\\n' "$REPORT_TOKEN" > reports/candidate.txt
      - name: Upload candidate report
        uses: actions/upload-artifact@v7
        with:
          path: reports/candidate.txt
      - name: Unsupported writer
        env:
          REPORT_TOKEN: ${{ secrets.REPORT_TOKEN }}
        run: |
          date
          printf 'credential=%s\\n' "$REPORT_TOKEN" > reports/unknown.txt
      - name: Upload uncertain report
        uses: actions/upload-artifact@v7
        with:
          path: reports/unknown.txt
"""
        rules = [
            rule for rule in load_rules_for_platform(Platform.GITHUB) if rule.id == "SEC6-GH-016"
        ]
        header, report_body = _SAME_JOB.split("  report:\n", 1)
        report_job = "  report:\n" + report_body
        for source in (header + report_job + uncertain_job, header + uncertain_job + report_job):
            result = rules[0].pattern.check(source, source.splitlines())
            assert isinstance(result, IncompletePatternMatches)
            assert result.reason
            assert len(result) == 1, result
            line_number, snippet = result[0]
            assert_snippet_matches_line(line_number, snippet, source.splitlines())
            assert line_number == source.splitlines().index(_WRITER_LINE) + 1
            assert "candidate.txt" not in snippet
            assert "unknown.txt" not in snippet

    def test_duplicate_global_owner_still_discards_all_candidate_proofs(self) -> None:
        source = _SAME_JOB + "jobs: {}\n"
        rules = [
            rule for rule in load_rules_for_platform(Platform.GITHUB) if rule.id == "SEC6-GH-016"
        ]
        result = rules[0].pattern.check(source, source.splitlines())
        assert isinstance(result, IncompletePatternMatches)
        assert result.reason
        assert len(result) == 0

    def test_cli_mixed_flow_reports_proven_finding_and_incomplete_diagnostic(self) -> None:
        uncertain_job = """  unknown:
    runs-on: ubuntu-latest
    steps:
      - name: Write candidate report
        env:
          REPORT_TOKEN: ${{ secrets.REPORT_TOKEN }}
        run: |
          printf 'credential=%s\\n' "$REPORT_TOKEN" > reports/candidate.txt
      - name: Upload candidate report
        uses: actions/upload-artifact@v7
        with:
          path: reports/candidate.txt
      - name: Unsupported writer
        env:
          REPORT_TOKEN: ${{ secrets.REPORT_TOKEN }}
        run: |
          date
          printf 'credential=%s\\n' "$REPORT_TOKEN" > reports/unknown.txt
      - name: Upload uncertain report
        uses: actions/upload-artifact@v7
        with:
          path: reports/unknown.txt
"""
        package_root = str(Path(taintly.__file__).resolve().parent.parent)
        environment = {
            key: os.environ[key]
            for key in ("PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP")
            if key in os.environ
        }
        environment["PYTHONPATH"] = package_root
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        with tempfile.TemporaryDirectory(prefix="taintly-sec6-gh-016-") as tmp:
            repo = Path(tmp)
            workflows = repo / ".github" / "workflows"
            workflows.mkdir(parents=True)
            (workflows / "ci.yml").write_text(_SAME_JOB + uncertain_job, encoding="utf-8")
            completed = subprocess.run(
                [
                    sys.executable,
                    "-S",
                    "-m",
                    "taintly",
                    str(repo),
                    "--platform",
                    "github",
                    "--no-config",
                    "--no-color",
                    "--format",
                    "json",
                ],
                check=False,
                capture_output=True,
                text=True,
                env=environment,
                timeout=30,
            )
        assert completed.returncode != 0, (completed.stdout, completed.stderr)
        payload = json.loads(completed.stdout)
        findings = [item for item in payload["findings"] if item["rule_id"] == "SEC6-GH-016"]
        assert len(findings) == 1, payload
        expected_line = _SAME_JOB.splitlines().index(_WRITER_LINE) + 1
        assert findings[0]["line"] == expected_line, findings[0]
        assert "candidate.txt" not in findings[0]["snippet"]
        assert "unknown.txt" not in findings[0]["snippet"]
        assert payload["coverage_status"] == "incomplete", payload
        assert any("SEC6-GH-016" in item.get("title", "") for item in payload["errors"]), payload
        assert "SEC6-GH-016" in completed.stderr, completed.stderr

    def test_equivalent_mutations_without_rule_specific_allowlist(self) -> None:
        rules = [
            rule for rule in load_rules_for_platform(Platform.GITHUB) if rule.id == "SEC6-GH-016"
        ]
        assert len(rules) == 1
        rule = rules[0]
        checks: list[tuple[str, str, bool]] = []
        for operator, mutate in MUTATION_OPERATORS.items():
            if operator == "quote_swap":
                continue
            for sample, expect_match in [
                *((sample, True) for sample in rule.test_positive),
                *((sample, False) for sample in rule.test_negative),
            ]:
                for mutant in mutate(sample):
                    matches = rule.pattern.check(mutant, mutant.splitlines())
                    checks.append((operator, mutant[:80], bool(matches) is expect_match))
        assert checks, "expected semantic-preserving mutations to reach both samples"
        assert all(passed for _operator, _sample, passed in checks), checks

        # The inert format-quote swap remains emitted; the separately proved
        # variable-argument quote swap is excluded by the generic source premise.
        positive = rule.test_positive[0]
        quote_mutants = MUTATION_OPERATORS["quote_swap"](positive)
        assert len(quote_mutants) == 1, quote_mutants
        mutant = quote_mutants[0]
        assert 'printf "credential=%s\\n" "$REPORT_TOKEN"' in mutant
        matches = rule.pattern.check(mutant, mutant.splitlines())
        assert len(matches) == 1, matches

        # Direct source-semantic controls stay outside the generated mutant roster.
        for positive_sample in rule.test_positive:
            literal_argument = positive_sample.replace(
                '"$REPORT_TOKEN"', "'$REPORT_TOKEN'"
            )
            assert literal_argument != positive_sample
            assert not rule.pattern.check(
                literal_argument, literal_argument.splitlines()
            )


if __name__ == "__main__":
    unittest.main()
