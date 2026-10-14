"""Source-bound contracts for the SEC6-GH-016 artifact-file analysis.

The test exercises the analyzer against synthetic YAML only. It never runs a
workflow, shell body, action, or secret payload.
"""
from __future__ import annotations

import hashlib
import unittest

from taintly.rules.github.secret_artifact_flow import SecretArtifactFlowPattern

_SAME_JOB = """name: report-artifact-contrast
on:
  workflow_dispatch:
permissions:
  contents: read
jobs:
  report:
    runs-on: ubuntu-latest
    steps:
      - name: Write report
        env:
          REPORT_TOKEN: ${{ secrets.REPORT_TOKEN }}
        run: |
          mkdir -p reports
          printf 'credential=%s\\n' "$REPORT_TOKEN" > reports/build-report.txt
      - name: Upload report
        uses: actions/upload-artifact@v7
        with:
          name: build-report
          path: reports/build-report.txt
          if-no-files-found: error
"""

_WRITER_LINE = next(line for line in _SAME_JOB.splitlines() if "printf 'credential=%s" in line)
_WRITER_INDENT = _WRITER_LINE[: len(_WRITER_LINE) - len(_WRITER_LINE.lstrip())]


def _with_writer(command: str) -> str:
    return _SAME_JOB.replace(_WRITER_LINE, _WRITER_INDENT + command)


_REDACTED_SUPPORTED = _with_writer("printf 'credential=[REDACTED]\\n' > reports/build-report.txt")
_REDACTED_UNSUPPORTED = """name: redacted-report-artifact
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
          printf 'credential_state=%s\\ncredential=[REDACTED]\\n' "$state" > reports/build-report.txt
      - name: Upload report
        uses: actions/upload-artifact@v7
        with:
          name: report
          path: reports/build-report.txt
"""


class SecretArtifactFlowContract(unittest.TestCase):
    def setUp(self) -> None:
        self.pattern = SecretArtifactFlowPattern()

    def check(self, source: str):
        return self.pattern.check(source, source.splitlines())

    def assert_finding(self, source: str) -> None:
        result = self.check(source)
        self.assertFalse(getattr(result, "reason", ""), getattr(result, "reason", ""))
        self.assertEqual(len(result), 1)

    def assert_complete_no_finding(self, source: str) -> None:
        result = self.check(source)
        self.assertFalse(getattr(result, "reason", ""), getattr(result, "reason", ""))
        self.assertEqual(list(result), [])

    def assert_incomplete(self, source: str) -> None:
        result = self.check(source)
        self.assertEqual(list(result), [])
        self.assertTrue(getattr(result, "reason", ""))

    def test_sealed_source_hash_and_direct_secret_to_exact_nonhidden_path(self) -> None:
        self.assertEqual(hashlib.sha256(_SAME_JOB.encode()).hexdigest(), "532e891bdf26ad93aab14902545e4caa28e7c60309dc05444930779b9f844038")
        self.assert_finding(_SAME_JOB)

    def test_supported_redacted_printf_is_complete_and_has_no_secret_transport(self) -> None:
        self.assert_complete_no_finding(_REDACTED_SUPPORTED)

    def test_original_redacted_control_is_incomplete_due_to_unmodeled_shell_conditional(self) -> None:
        self.assert_incomplete(_REDACTED_UNSUPPORTED)

    def test_custom_bash_template_that_ignores_script_is_unknown(self) -> None:
        source = _SAME_JOB.replace("      - name: Write report\n", "      - name: Write report\n        shell: bash -c 'true' {0}\n")
        self.assert_incomplete(source)

    def test_echo_escape_and_printf_b_control_sequences_are_unknown(self) -> None:
        line = next(line for line in _SAME_JOB.splitlines() if "printf 'credential=%s" in line)
        self.assert_incomplete(_SAME_JOB.replace(line, "          echo -e '\\c' \"$REPORT_TOKEN\" > reports/build-report.txt"))
        self.assert_incomplete(_SAME_JOB.replace(line, "          printf '%b' '\\c' \"$REPORT_TOKEN\" > reports/build-report.txt"))

    def test_literal_analysis_marker_and_unrelated_secret_do_not_forge_provenance(self) -> None:
        source = _SAME_JOB.replace(
            "REPORT_TOKEN: ${{ secrets.REPORT_TOKEN }}",
            "REPORT_TOKEN: __taintly_secret__\n          UNUSED: ${{ secrets.DUMMY }}",
        )
        self.assert_complete_no_finding(source)

    def test_static_redaction_with_direct_secret_available_is_not_a_finding(self) -> None:
        self.assert_complete_no_finding(_REDACTED_SUPPORTED)

    def test_secret_in_inline_script_or_bracket_form_is_unknown(self) -> None:
        line = next(line for line in _SAME_JOB.splitlines() if "printf 'credential=%s" in line)
        inline = _SAME_JOB.replace(line, "          printf 'credential=%s\\n' \"${{ secrets.REPORT_TOKEN }}\" > reports/build-report.txt")
        bracket = _SAME_JOB.replace("secrets.REPORT_TOKEN", "secrets['REPORT_TOKEN']")
        self.assert_incomplete(inline)
        self.assert_incomplete(bracket)

    def test_github_token_is_unknown_not_silently_treated_as_nonsecret(self) -> None:
        source = _SAME_JOB.replace("${{ secrets.REPORT_TOKEN }}", "${{ github.token }}")
        self.assert_incomplete(source)

    def test_step_override_removes_inherited_secret_source(self) -> None:
        source = _SAME_JOB.replace(
            "jobs:\n  report:\n",
            "env:\n  REPORT_TOKEN: ${{ secrets.REPORT_TOKEN }}\njobs:\n  report:\n",
        ).replace(
            "        env:\n          REPORT_TOKEN: ${{ secrets.REPORT_TOKEN }}\n",
            "        env:\n          REPORT_TOKEN: ordinary-status\n",
        )
        self.assert_complete_no_finding(source)

    def test_secret_in_sibling_step_does_not_supply_writer_provenance(self) -> None:
        source = _SAME_JOB.replace(
            "      - name: Upload report\n",
            "      - name: Separate credential step\n        env:\n          OTHER: ${{ secrets.OTHER }}\n      - name: Upload report\n",
        ).replace("REPORT_TOKEN: ${{ secrets.REPORT_TOKEN }}", "REPORT_TOKEN: ordinary-status")
        self.assert_complete_no_finding(source)

    def test_job_and_workflow_environment_inheritance_is_resolved(self) -> None:
        workflow_env = _SAME_JOB.replace(
            "jobs:\n  report:\n",
            "env:\n  REPORT_TOKEN: ${{ secrets.REPORT_TOKEN }}\njobs:\n  report:\n",
        ).replace("        env:\n          REPORT_TOKEN: ${{ secrets.REPORT_TOKEN }}\n", "")
        job_env = _SAME_JOB.replace(
            "    runs-on: ubuntu-latest\n",
            "    runs-on: ubuntu-latest\n    env:\n      REPORT_TOKEN: ${{ secrets.REPORT_TOKEN }}\n",
        ).replace("        env:\n          REPORT_TOKEN: ${{ secrets.REPORT_TOKEN }}\n", "")
        self.assert_finding(workflow_env)
        self.assert_finding(job_env)

    def test_job_false_guard_disables_writer_and_upload(self) -> None:
        self.assert_complete_no_finding(_SAME_JOB.replace("  report:\n    runs-on:", "  report:\n    if: false\n    runs-on:"))

    def test_mutually_exclusive_event_guards_do_not_join(self) -> None:
        source = _SAME_JOB.replace("  workflow_dispatch:\n", "  workflow_dispatch:\n  push:\n")
        source = source.replace(
            "      - name: Write report\n", "      - name: Write report\n        if: github.event_name == 'push'\n"
        ).replace(
            "      - name: Upload report\n", "      - name: Upload report\n        if: github.event_name == 'workflow_dispatch'\n"
        )
        self.assert_complete_no_finding(source)

    def test_unquoted_custom_shell_and_self_hosted_runner_are_unknown(self) -> None:
        custom = _SAME_JOB.replace("      - name: Write report\n", "      - name: Write report\n        shell: bash {0}\n")
        self_hosted = _SAME_JOB.replace("runs-on: ubuntu-latest", "runs-on: [self-hosted, ubuntu-24.04]")
        self.assert_incomplete(custom)
        self.assert_incomplete(self_hosted)

    def test_container_default_sh_and_explicit_bash_are_supported(self) -> None:
        container = _SAME_JOB.replace("    runs-on: ubuntu-latest\n", "    runs-on: ubuntu-latest\n    container: ubuntu:24.04\n")
        explicit = container.replace("      - name: Write report\n", "      - name: Write report\n        shell: bash\n")
        self.assert_finding(container)
        self.assert_finding(explicit)

    def test_conditional_semicolon_and_folded_scripts_are_unknown(self) -> None:
        line = next(line for line in _SAME_JOB.splitlines() if "printf 'credential=%s" in line)
        conditional = _SAME_JOB.replace(line, "          if [ -n \"$REPORT_TOKEN\" ]; then printf 'credential=%s\\n' \"$REPORT_TOKEN\" > reports/build-report.txt; fi")
        semicolon = _SAME_JOB.replace(line, line + "; :")
        folded = _SAME_JOB.replace("        run: |\n", "        run: >\n")
        self.assert_incomplete(conditional)
        self.assert_incomplete(semicolon)
        self.assert_incomplete(folded)

    def test_unsupported_prior_command_and_later_overwrite_clear_partial_proof(self) -> None:
        line = next(line for line in _SAME_JOB.splitlines() if "printf 'credential=%s" in line)
        prior = _SAME_JOB.replace("          mkdir -p reports\n", "          date\n          mkdir -p reports\n")
        later = _SAME_JOB.replace(line, line + "\n          rm reports/build-report.txt")
        self.assert_incomplete(prior)
        self.assert_incomplete(later)

    def test_hidden_paths_dynamic_selectors_and_unsupported_action_refs_are_unknown(self) -> None:
        hidden = _SAME_JOB.replace("reports/build-report.txt", "reports/.build-report.txt")
        dynamic = _SAME_JOB.replace("path: reports/build-report.txt", "path: reports/*.txt")
        sha = _SAME_JOB.replace("actions/upload-artifact@v7", "actions/upload-artifact@0123456789012345678901234567890123456789")
        self.assert_incomplete(hidden)
        self.assert_incomplete(dynamic)
        self.assert_incomplete(sha)

    def test_adjacent_same_job_literal_selector_is_required(self) -> None:
        nonadjacent = _SAME_JOB.replace(
            "      - name: Upload report\n",
            "      - name: Intervening step\n        run: printf 'done\\n'\n      - name: Upload report\n",
        )
        other_path = _SAME_JOB.replace("path: reports/build-report.txt", "path: reports/public.txt")
        self.assert_complete_no_finding(nonadjacent)
        self.assert_complete_no_finding(other_path)

    def test_other_job_does_not_share_workspace_file_by_needs(self) -> None:
        source = _SAME_JOB.replace(
            "      - name: Upload report\n        uses: actions/upload-artifact@v7\n        with:\n          name: build-report\n          path: reports/build-report.txt\n          if-no-files-found: error\n",
            "    other:\n      runs-on: ubuntu-latest\n      needs: report\n      steps:\n        - uses: actions/upload-artifact@v7\n          with:\n            name: build-report\n            path: reports/build-report.txt\n",
        )
        self.assert_complete_no_finding(source)

    def test_duplicate_ancestors_empty_maps_and_aliases_are_incomplete_for_candidate(self) -> None:
        self.assert_incomplete(_SAME_JOB + "jobs: {}\n")
        self.assert_incomplete(_SAME_JOB.replace("on:\n  workflow_dispatch:\n", "on: &trigger [workflow_dispatch]\n"))

    def test_malformed_or_duplicate_trigger_owner_is_incomplete(self) -> None:
        duplicate = _SAME_JOB + "on: push\n"
        malformed = _SAME_JOB.replace("on:\n  workflow_dispatch:\n", "on: [\n")
        self.assert_incomplete(duplicate)
        self.assert_incomplete(malformed)

    def test_path_directory_and_hidden_files_are_not_claimed_as_exact_file_selection(self) -> None:
        directory = _SAME_JOB.replace("path: reports/build-report.txt", "path: reports/")
        hidden_enabled = _SAME_JOB.replace("reports/build-report.txt", "reports/.build-report.txt").replace(
            "          path: reports/.build-report.txt\n", "          path: reports/.build-report.txt\n          include-hidden-files: true\n"
        )
        self.assert_incomplete(directory)
        self.assert_incomplete(hidden_enabled)


    def test_false_writer_or_upload_step_guard_prevents_candidate_flow(self) -> None:
        writer_disabled = _SAME_JOB.replace(
            "      - name: Write report\n", "      - name: Write report\n        if: false\n"
        )
        upload_disabled = _SAME_JOB.replace(
            "      - name: Upload report\n", "      - name: Upload report\n        if: false\n"
        )
        self.assert_complete_no_finding(writer_disabled)
        self.assert_complete_no_finding(upload_disabled)

    def test_contradictory_supported_event_guards_do_not_join_writer_and_upload(self) -> None:
        source = _SAME_JOB.replace("  workflow_dispatch:\n", "  workflow_dispatch:\n  push:\n")
        source = source.replace(
            "      - name: Write report\n", "      - name: Write report\n        if: github.event_name == 'push'\n"
        ).replace(
            "      - name: Upload report\n",
            "      - name: Upload report\n        if: github.event_name == 'workflow_dispatch'\n",
        )
        self.assert_complete_no_finding(source)

    def test_step_working_directory_resolves_relative_writer_path(self) -> None:
        source = _SAME_JOB.replace(
            "      - name: Write report\n", "      - name: Write report\n        working-directory: reports\n"
        ).replace("reports/build-report.txt", "build-report.txt", 1)
        self.assert_finding(source)


    def test_reusable_workflow_call_and_mixed_event_domains_are_incomplete(self) -> None:
        reusable = _SAME_JOB.replace(
            "  workflow_dispatch:\n",
            "  workflow_call:\n",
        ).replace(
            "      - name: Write report\n",
            "      - name: Write report\n        if: github.event_name == 'push'\n",
        )
        mixed = _SAME_JOB.replace(
            "  workflow_dispatch:\n",
            "  workflow_call: {}\n  push: {}\n",
        ).replace(
            "      - name: Write report\n",
            "      - name: Write report\n        if: github.event_name == 'push'\n",
        )
        self.assert_incomplete(reusable)
        self.assert_incomplete(mixed)

    def test_supported_literal_event_guard_still_excludes_candidate(self) -> None:
        source = _SAME_JOB.replace(
            "      - name: Write report\n",
            "      - name: Write report\n        if: github.event_name == 'push'\n",
        )
        self.assert_complete_no_finding(source)

    def test_printf_leading_hyphen_format_is_incomplete(self) -> None:
        self.assert_incomplete(_with_writer("printf '-%s' \"$REPORT_TOKEN\" > reports/build-report.txt"))

    def test_inert_double_quoted_printf_format_is_supported(self) -> None:
        double_quoted = _with_writer(
            'printf "credential=%s\\n" "$REPORT_TOKEN" > reports/build-report.txt'
        )
        self.assert_finding(double_quoted)

        for format_text in (
            'credential=$HOME%s\\n',
            'credential=`id`%s\\n',
            'credential=\\q%s\\n',
        ):
            source = _with_writer(
                f'printf "{format_text}" "$REPORT_TOKEN" > reports/build-report.txt'
            )
            self.assert_incomplete(source)

    def test_empty_printf_formats_are_complete_static_writes(self) -> None:
        for quote in ("'", '"'):
            with self.subTest(quote=quote):
                source = _with_writer(
                    f"printf {quote}{quote} > reports/build-report.txt"
                )
                self.assert_complete_no_finding(source)

    def test_present_non_scalar_shell_and_run_defaults_are_incomplete(self) -> None:
        step_shell = _SAME_JOB.replace(
            "      - name: Write report\n", "      - name: Write report\n        shell: [pwsh]\n"
        )
        job_shell_default = _SAME_JOB.replace(
            "    runs-on: ubuntu-latest\n",
            "    runs-on: ubuntu-latest\n    defaults:\n      run:\n        shell: [bash]\n",
        )
        workflow_shell_default = _SAME_JOB.replace(
            "jobs:\n",
            "defaults:\n  run:\n    shell: [bash]\njobs:\n",
        )
        self.assert_incomplete(step_shell)
        self.assert_incomplete(job_shell_default)
        self.assert_incomplete(workflow_shell_default)

    def test_present_non_scalar_working_directory_and_defaults_are_incomplete(self) -> None:
        step_cwd = _SAME_JOB.replace(
            "      - name: Write report\n", "      - name: Write report\n        working-directory: [reports]\n"
        )
        job_cwd = _SAME_JOB.replace(
            "    runs-on: ubuntu-latest\n",
            "    runs-on: ubuntu-latest\n    defaults:\n      run:\n        working-directory: [reports]\n",
        )
        workflow_defaults = _SAME_JOB.replace(
            "jobs:\n",
            "defaults: [invalid-owner]\njobs:\n",
        )
        self.assert_incomplete(step_cwd)
        self.assert_incomplete(job_cwd)
        self.assert_incomplete(workflow_defaults)


    def test_non_scalar_step_env_mapping_override_of_inherited_secret_is_incomplete(self) -> None:
        source = _SAME_JOB.replace(
            "jobs:\n  report:\n",
            "env:\n  REPORT_TOKEN: ${{ secrets.REPORT_TOKEN }}\njobs:\n  report:\n",
        ).replace(
            "        env:\n          REPORT_TOKEN: ${{ secrets.REPORT_TOKEN }}\n",
            "        env:\n          REPORT_TOKEN:\n            value: ordinary-status\n",
        )
        self.assert_incomplete(source)

    def test_sequence_step_env_cannot_silently_preserve_inherited_secret(self) -> None:
        source = _SAME_JOB.replace(
            "jobs:\n  report:\n",
            "env:\n  REPORT_TOKEN: ${{ secrets.REPORT_TOKEN }}\njobs:\n  report:\n",
        ).replace(
            "        env:\n          REPORT_TOKEN: ${{ secrets.REPORT_TOKEN }}\n",
            "        env:\n          - ordinary-status\n",
        )
        self.assert_incomplete(source)

    def test_non_scalar_job_env_override_of_workflow_secret_is_incomplete(self) -> None:
        source = _SAME_JOB.replace(
            "jobs:\n  report:\n",
            "env:\n  REPORT_TOKEN: ${{ secrets.REPORT_TOKEN }}\njobs:\n  report:\n",
        ).replace(
            "    runs-on: ubuntu-latest\n",
            "    runs-on: ubuntu-latest\n    env:\n      REPORT_TOKEN:\n        value: ordinary-status\n",
        ).replace(
            "        env:\n          REPORT_TOKEN: ${{ secrets.REPORT_TOKEN }}\n",
            "",
        )
        self.assert_incomplete(source)

    def test_malformed_workflow_env_with_secret_value_is_unknown(self) -> None:
        source = _SAME_JOB.replace(
            "jobs:\n  report:\n",
            "env:\n  - \"${{ secrets.REPORT_TOKEN }}\"\njobs:\n  report:\n",
        ).replace(
            "        env:\n          REPORT_TOKEN: ${{ secrets.REPORT_TOKEN }}\n",
            "",
        )
        self.assert_incomplete(source)

    def test_empty_mapping_override_preserves_inherited_secret(self) -> None:
        source = _SAME_JOB.replace(
            "jobs:\n  report:\n",
            "env:\n  REPORT_TOKEN: ${{ secrets.REPORT_TOKEN }}\njobs:\n  report:\n",
        ).replace(
            "        env:\n          REPORT_TOKEN: ${{ secrets.REPORT_TOKEN }}\n",
            "        env: {}\n",
        )
        self.assert_finding(source)


if __name__ == "__main__":
    unittest.main()
