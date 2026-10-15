from __future__ import annotations

import unittest
from pathlib import Path

from taintly.models import IncompletePatternMatches
from taintly.parsers.structural import EventKind, walk_workflow
from taintly.rules.github.secret_artifact_flow import (
    SecretArtifactFlowPattern,
    _run_writer_profile,
)

SOURCE_ROOT = Path(__file__).resolve().parents[1] / "fixtures"
THREAT = (SOURCE_ROOT / "N09-threat-ci.yml").read_text(encoding="utf-8")
SAFE = (SOURCE_ROOT / "N09-safe-ci.yml").read_text(encoding="utf-8")
WRITER = "        run: printf '%s\\n' \"$REPORT_TOKEN\" > report.txt"


class InlineWriterProfileContract(unittest.TestCase):
    def setUp(self) -> None:
        self.pattern = SecretArtifactFlowPattern()

    def check(self, source: str):
        return self.pattern.check(source, source.splitlines())

    def assert_incomplete(self, source: str) -> None:
        result = self.check(source)
        self.assertIsInstance(result, IncompletePatternMatches)
        self.assertEqual(list(result), [])
        self.assertTrue(result.reason)

    def assert_complete_no_finding(self, source: str) -> None:
        result = self.check(source)
        self.assertNotIsInstance(result, IncompletePatternMatches)
        self.assertEqual(list(result), [])

    def test_original_n09_sources_keep_physical_line_and_safe_control(self) -> None:
        result = self.check(THREAT)
        self.assertEqual(len(result), 1)
        line_no, snippet = result[0]
        self.assertEqual(line_no, 13)
        self.assertTrue(snippet.startswith(WRITER.strip()))
        self.assert_complete_no_finding(SAFE)

    def test_equivalent_yaml_scalar_styles_preserve_command_and_physical_origin(
        self,
    ) -> None:
        single = THREAT.replace(
            WRITER,
            "        run: 'printf ''%s\\n'' \"$REPORT_TOKEN\" > report.txt'",
        )
        double = THREAT.replace(
            WRITER,
            '        run: "printf \'%s\\\\n\' \\"$REPORT_TOKEN\\" > report.txt"',
        )
        profiles = []
        for source in (THREAT, single, double):
            with self.subTest(source=source.splitlines()[12]):
                events = [
                    event
                    for event in walk_workflow(
                        "workflow.yml", content=source, include_keys=True, recover=True
                    )
                    if event.kind is EventKind.LEAF_SCALAR
                    and event.path == ("jobs", "check", "steps", 0, "run")
                ]
                self.assertEqual(len(events), 1)
                profiles.append(_run_writer_profile(events[0], source.splitlines()))
                result = self.check(source)
                self.assertEqual(len(result), 1)
                self.assertEqual(result[0][0], 13)
                self.assertEqual(
                    result[0][1].split(" [literal artifact path", 1)[0],
                    source.splitlines()[12].strip(),
                )
        self.assertEqual(profiles, [(13, "REPORT_TOKEN", "report.txt")] * 3)

    def test_one_inert_percent_s_argument_is_data_under_supported_shell(self) -> None:
        source = THREAT.replace(WRITER, "        run: printf '%s\\n' redacted > report.txt")
        self.assert_complete_no_finding(source)

        quoted_data = THREAT.replace(
            WRITER, "        run: printf '%s\\n' '$REPORT_TOKEN' > report.txt"
        )
        self.assert_complete_no_finding(quoted_data)

    def test_secret_variable_argument_remains_a_finding(self) -> None:
        result = self.check(THREAT)
        self.assertEqual(len(result), 1)
        self.assertIn('"$REPORT_TOKEN"', result[0][1])

    def test_template_interpolation_is_unknown_even_inside_shell_single_quotes(
        self,
    ) -> None:
        source = THREAT.replace(
            WRITER,
            "        run: printf '%s\\n' '${{ secrets.REPORT_TOKEN }}' > report.txt",
        )
        self.assert_incomplete(source)

    def test_dynamic_or_unsupported_printf_arguments_are_incomplete(self) -> None:
        commands = (
            "printf '%s\\n' \"$(id)\" > report.txt",
            "printf '%s\\n' \"safe $REPORT_TOKEN\" > report.txt",
            "printf '%b' redacted > report.txt",
            "printf '%s%s' redacted > report.txt",
            "printf '%s\\n' redacted other > report.txt",
        )
        for command in commands:
            with self.subTest(command=command):
                self.assert_incomplete(THREAT.replace(WRITER, "        run: " + command))

    def test_literal_data_requires_known_bash_or_sh_profile(self) -> None:
        literal = "        run: printf '%s\\n' redacted > report.txt"
        for shell_line in (
            "        shell: pwsh\n",
            "        shell: custom-shell {0}\n",
        ):
            source = THREAT.replace("        run:", shell_line + "        run:").replace(
                WRITER, literal
            )
            with self.subTest(shell_line=shell_line.strip()):
                self.assert_incomplete(source)

        unknown_runner = THREAT.replace(
            "    runs-on: ubuntu-latest\n", "    runs-on: self-hosted\n"
        ).replace(WRITER, literal)
        self.assert_incomplete(unknown_runner)

    def test_multiline_plain_scalar_cannot_be_mistaken_for_one_physical_command(self) -> None:
        source = THREAT.replace(
            WRITER,
            "        run: printf '%s\\n'\n          \"$REPORT_TOKEN\" > report.txt",
        )
        self.assert_incomplete(source)

    def test_run_and_uses_owner_coexistence_is_incomplete(self) -> None:
        cases = (
            "        uses: actions/checkout@v4",
            "        uses: null",
            "        uses: actions/checkout@v4\n        uses: null",
        )
        for uses in cases:
            with self.subTest(uses=uses):
                self.assert_incomplete(THREAT.replace(WRITER, WRITER + "\n" + uses))

    def test_malformed_upload_run_owner_is_incomplete(self) -> None:
        for run_line in ("        run: echo noop\n", "        run: null\n"):
            with self.subTest(run_line=run_line.strip()):
                source = THREAT.replace(
                    "      - uses: actions/upload-artifact@v4\n",
                    "      - uses: actions/upload-artifact@v4\n" + run_line,
                )
                self.assert_incomplete(source)

    def test_data_writer_with_uses_owner_is_incomplete(self) -> None:
        redacted = THREAT.replace(
            WRITER, "        run: printf '%s\\n' redacted > report.txt"
        ).replace(
            "        run: printf '%s\\n' redacted > report.txt\n",
            "        run: printf '%s\\n' redacted > report.txt\n"
            "        uses: actions/checkout@v4\n",
            1,
        )
        self.assert_incomplete(redacted)

    def test_folded_scalar_stays_incomplete(self) -> None:
        source = THREAT.replace(
            WRITER, "        run: >\n          printf '%s\\n' redacted > report.txt"
        )
        self.assert_incomplete(source)

    def test_original_conditional_redaction_control_stays_incomplete(self) -> None:
        source = """name: redacted-report-artifact
on:
  workflow_dispatch:
jobs:
  report:
    runs-on: ubuntu-latest
    steps:
      - name: Write redacted report
        env:
          REPORT_TOKEN: ${{ secrets.REPORT_TOKEN }}
        run: |
          if [ -n "$REPORT_TOKEN" ]; then state=present; else state=missing; fi
          printf 'credential_state=%s\\ncredential=[REDACTED]\\n' "$state" > report.txt
      - uses: actions/upload-artifact@v4
        with:
          path: report.txt
"""
        self.assert_incomplete(source)


if __name__ == "__main__":
    unittest.main()
