"""CLI entry point for taintly."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections.abc import Callable
from gettext import gettext
from pathlib import Path
from typing import Any

from ._gitlab_transport import GitLabTransportError
from .baseline import (
    BASELINE_FILENAME,
    BaselineError,
    apply_diff,
    classify_diff_kind,
    detect_ref_drift,
    format_baseline_summary,
    format_diff_summary,
    iter_action_refs,
    load_baseline,
    ref_key,
    save_baseline,
)
from .config import (
    DEFAULT_CONFIG,
    ConfigError,
    apply_config_ignores,
    audit_ignores,
    find_config,
    load_config,
)
from .deployment_context import (
    DeploymentContext,
    apply_context_notes_to_findings,
    load_deployment_context,
)
from .engine import (
    coalesce_input_script_findings,
    detect_platform,
    scan_file,
    scan_repo,
    validate_scan_seconds,
)
from .ingestion.gitlab_registry_job import RegistryJobError, load_registry_job
from .models import Finding, Platform, Severity, _defer_context_regex_compilation
from .reporters._encoding import ensure_utf8_stdout
from .reporters.json_report import format_json
from .reporters.sarif import format_sarif, format_sarif_reports
from .reporters.text import format_text
from .rules import registry as _rule_registry
from .rules.registry import load_all_rules, load_rules_for_platform

# Map AuditReport.platform string to the Platform enum the scorer
# uses for bonus gating. Keeps the call sites readable.
_PLATFORM_LOOKUP: dict[str, Platform] = {platform.value: platform for platform in Platform}


def _scan_seconds(value: str) -> float:
    """Use the same checked budget for CLI and programmatic scanning."""
    try:
        return validate_scan_seconds(float(value))
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


class _VersionAction(argparse.Action):
    """Keep version discovery out of ordinary scans and help output."""

    def __init__(self, option_strings, dest=argparse.SUPPRESS, default=argparse.SUPPRESS, **kwargs):
        if kwargs.get("help") is None:
            kwargs["help"] = gettext("show program's version number and exit")
        super().__init__(
            option_strings=option_strings, dest=dest, nargs=0, default=default, **kwargs
        )

    def __call__(self, parser, _namespace, _values, _option_string=None):
        from . import __version__

        formatter = parser._get_formatter()
        formatter.add_text(f"%(prog)s {__version__}")
        parser._print_message(formatter.format_help(), sys.stdout)
        parser.exit()


def _platforms_for_reports(*reports) -> set[Platform]:
    """Set of platforms the given AuditReport(s) covered. Empty when
    the platform field isn't recognised — falls through to the
    scorer's inference path."""
    out: set[Platform] = set()
    for r in reports:
        plat = _PLATFORM_LOOKUP.get(getattr(r, "platform", ""))
        if plat is not None:
            out.add(plat)
    return out


def _resolve_current_refs(findings: list[Any]) -> dict[str, str]:
    """Resolve every mutable ``uses:`` ref in ``findings`` to its current
    upstream SHA -> ``{"owner/repo@ref": sha}``. Returns ``{}`` (no network)
    when --check-ref-drift is disabled; skips refs that don't resolve."""
    from taintly.platform import github_ref_resolve

    if not github_ref_resolve.is_enabled():
        return {}
    resolved: dict[str, str] = {}
    for owner, repo, ref in iter_action_refs(findings):
        sha = github_ref_resolve.resolve_ref_to_sha(owner, repo, ref)
        if sha:
            resolved[ref_key(owner, repo, ref)] = sha
    return resolved


def _find_ref_source(findings: list[Any], key: str) -> Any:
    """First finding whose snippet contains ``key`` (``owner/repo@ref``), to
    anchor a drift finding to a file/line. Returns None if none match."""
    for f in findings:
        if key in (getattr(f, "snippet", "") or ""):
            return f
    return None


def _build_drift_findings(drift: list[tuple[str, str, str]], findings: list[Any]) -> list[Any]:
    """Turn ``(ref_key, old_sha, new_sha)`` drift tuples into CRITICAL
    SEC3-GH-T02 findings, anchored to the ``uses:`` line that drifted."""
    from .models import Finding, Severity

    out: list[Any] = []
    for key, old_sha, new_sha in drift:
        src = _find_ref_source(findings, key)
        out.append(
            Finding(
                rule_id="SEC3-GH-T02",
                severity=Severity.CRITICAL,
                title="Mutable action ref repointed to a new upstream SHA (no local change)",
                description=(
                    f"`{key}` resolved to commit {old_sha[:12]} at baseline time "
                    f"but now resolves to {new_sha[:12]}, with no change to the "
                    f"local workflow. A mutable tag/branch silently repointed to a "
                    f"new commit is the tj-actions/changed-files (CVE-2025-30066) "
                    f"supply-chain pattern: the ref in your YAML is unchanged, but "
                    f"the code it runs has changed upstream."
                ),
                file=(getattr(src, "file", "") if src else ""),
                line=(getattr(src, "line", 0) if src else 0),
                snippet=(getattr(src, "snippet", "") if src else f"uses: {key}"),
                remediation=(
                    "Verify the upstream change is legitimate, then pin to a full "
                    "40-char commit SHA you have reviewed: "
                    "`uses: owner/repo@<40-char-sha>`. If the repoint is "
                    "unexpected, treat it as a potential upstream compromise."
                ),
                reference=(
                    "https://www.cisa.gov/news-events/alerts — tj-actions/"
                    "changed-files CVE-2025-30066"
                ),
            )
        )
    return out


def main():
    # Reconfigure stdout/stderr to UTF-8 where possible so box-drawing / arrow
    # glyphs render on Windows terminals whose default encoding is cp1252.
    # The per-char helpers in reporters._encoding provide a second line of
    # defence for environments where reconfigure() is unavailable.
    ensure_utf8_stdout()

    parser = argparse.ArgumentParser(
        prog="taintly",
        description="Zero-dependency CI/CD pipeline security auditor",
        epilog="Because trusting a third-party tool to audit your third-party tools is the problem.",
    )
    parser.add_argument("--version", action=_VersionAction)
    parser.add_argument("path", nargs="?", default=".", help="Path to repository")
    parser.add_argument(
        "--format", "-f", choices=["text", "json", "csv", "sarif", "html"], default="text"
    )
    parser.add_argument("--no-color", action="store_true")
    parser.add_argument(
        "--platform", choices=[platform.value for platform in Platform], default=None
    )
    evidence_input = parser.add_mutually_exclusive_group()
    evidence_input.add_argument(
        "--codebuild-project-snapshot",
        nargs=3,
        metavar=("JSON", "PROJECT_ARN", "GITHUB_ORIGIN"),
        help="Scan one configured CodeBuild default from a full local BatchGetProjects response.",
    )
    evidence_input.add_argument(
        "--codebuild-public-build",
        nargs=3,
        metavar=("JSON", "BUILD_ID", "GITHUB_ORIGIN"),
        help="Scan one pinned buildspec from a trusted, saved CodeBuild public build response.",
    )
    evidence_input.add_argument(
        "--codebuild-webhook-snapshot",
        nargs=4,
        metavar=("JSON", "PUBLIC_PROJECT_ID", "GITHUB_ORIGIN", "PR_EVENT"),
        help="Assess one GitHub PR event against trusted, saved CodeBuild project filters.",
    )
    evidence_input.add_argument(
        "--codebuild-public-s3-observation",
        nargs=3,
        metavar=("JSON", "BUILD_ARN_OR_ID", "GITHUB_ORIGIN"),
        help="Corroborate saved CodeBuild S3 output or a direct PutObject request.",
    )
    evidence_input.add_argument(
        "--codebuild-public-deploy-observation",
        nargs=3,
        metavar=("JSON", "BUILD_ID", "GITHUB_ORIGIN"),
        help="Compare a saved CodeBuild deployment skip with its selected source.",
    )
    evidence_input.add_argument(
        "--codebuild-start-observation",
        nargs=4,
        metavar=("JSON", "GITHUB_ORIGIN", "RUN", "JOB"),
        help="Bind a saved GitHub caller job to its observed CodeBuild start or guard stop.",
    )
    parser.add_argument(
        "--codebuild-webhook-sender",
        metavar="ID",
        help="GitHub webhook sender account ID for --codebuild-webhook-snapshot.",
    )
    evidence_input.add_argument(
        "--jenkins-incrementals-observation",
        nargs=4,
        metavar=("JSON", "OWNER/REPO", "PR", "JENKINS_CHECK"),
        help="Corroborate a saved Jenkins Incrementals publication with exact registry bytes.",
    )
    evidence_input.add_argument(
        "--jenkins-maven-snapshot-observation",
        nargs=4,
        metavar=("OWNER/REPO", "PR", "JENKINS_JOB", "OBJECT_URL"),
        help="Corroborate a saved ASF Jenkins fork build and Maven snapshot object.",
    )
    evidence_input.add_argument(
        "--gitlab-job-evidence",
        nargs=3,
        metavar=("JSON", "PROJECT_ID", "JOB_ID"),
        help="Compare one trusted, saved GitLab MR registry job receipt with this local source scan.",
    )
    evidence_input.add_argument(
        "--gitlab-mr-artifact-observation",
        nargs=4,
        metavar=("JSON", "PROJECT", "PIPELINE", "JOB"),
        help="Check saved target-project fork MR artifact or manual job evidence.",
    )
    evidence_input.add_argument(
        "--gitlab-fork-admission-observation",
        nargs=3,
        metavar=("JSON", "PROJECT", "PIPELINE"),
        help="Check whether a saved GitLab.com fork MR pipeline stopped before any job.",
    )
    parser.add_argument(
        "--gitlab-artifact-origin",
        metavar="HTTPS_ORIGIN",
        help="Bind a saved detached archive observation to its GitLab origin.",
    )
    parser.add_argument(
        "--gitlab-mr-publish-job",
        metavar="NAME",
        help="Also assess admission of an npm publisher in the saved GitLab MR pipeline.",
    )
    evidence_input.add_argument(
        "--github-release-observation",
        nargs=4,
        metavar=("JSON", "OWNER/REPO", "PRODUCER_RUN", "RELEASE_RUN"),
        help="Corroborate a saved GitHub workflow_run publication and its recorded uploader.",
    )
    evidence_input.add_argument(
        "--github-pages-observation",
        nargs=4,
        metavar=("JSON", "OWNER/REPO", "PRODUCER_RUN", "CONSUMER_RUN"),
        help="Corroborate a supported historical GitHub Pages publication offline.",
    )
    evidence_input.add_argument(
        "--github-release-request-observation",
        nargs=4,
        metavar=("JSON", "OWNER/REPO", "RUN", "JOB"),
        help="Check a saved GitHub draft-release creation outcome offline.",
    )
    evidence_input.add_argument(
        "--github-preview-observation",
        nargs=4,
        metavar=("JSON", "OWNER/REPO", "PRODUCER_RUN", "CONSUMER_RUN"),
        help="Check one saved GitHub fork artifact and Wrangler Preview observation offline.",
    )
    evidence_input.add_argument(
        "--github-version-upload-observation",
        nargs=4,
        metavar=("JSON", "OWNER/REPO", "RUN", "JOB"),
        help="Check a saved GitHub same-run Wrangler version upload or fork skip offline.",
    )
    parser.add_argument(
        "--min-severity", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"], default=None
    )
    parser.add_argument(
        "--max-scan-seconds",
        type=_scan_seconds,
        default=None,
        help=(
            "Finite nonnegative per-file rule-loop budget in seconds (default 30; "
            "zero skips the loop). Checked between rules; not a process deadline. On "
            "exceed, remaining rules are skipped and an ENGINE-ERR notice is "
            "emitted. Raise for large generated / monorepo CI files."
        ),
    )
    parser.add_argument(
        "--fix",
        action="store_true",
        help="Level 1: Apply deterministic auto-fixes (pin SHAs, add persist-credentials, add permissions)",
    )
    parser.add_argument(
        "--fix-dry-run",
        action="store_true",
        help="Level 1: Show what --fix would change without modifying files",
    )
    parser.add_argument(
        "--fix-npm-ignore-scripts",
        action="store_true",
        help=(
            "Opt-in: add --ignore-scripts to every npm/yarn/pnpm install command "
            "in workflow files. Disables preinstall/install/postinstall lifecycle "
            "hooks — the single most exploited LOTP vector for JavaScript "
            "pipelines (LOTP-GH-003). NOT part of the default --fix safe set "
            "because it changes build semantics: packages that legitimately rely "
            "on postinstall (husky, electron-builder, some native-addon builds) "
            "will stop working. Combine with --fix or --fix-dry-run."
        ),
    )
    parser.add_argument(
        "--fix-jenkins-cap-add-hint",
        action="store_true",
        help=(
            "Opt-in: inject a Groovy `// taintly hint (SEC8-JK-004): ...` "
            "comment above each `--privileged` line in a Jenkinsfile, "
            "pointing at `--cap-add=<NAME>` as the narrower alternative. "
            "Pure comment injection — no semantic change — but decorates "
            "the file with review-reminder comments.  Combine with --fix "
            "or --fix-dry-run."
        ),
    )
    parser.add_argument(
        "--fix-github-ai-allowed-tools-scaffold",
        action="store_true",
        help=(
            "Opt-in: add step-scoped vendor-specific AI tool-boundary review "
            "comments for recognized agent action steps. Does not change "
            "workflow policy values or enforce a restriction. Pairs with AI-GH-020."
        ),
    )
    parser.add_argument(
        "--fix-hoist-service-credentials",
        action="store_true",
        help=(
            "Opt-in: rewrite `POSTGRES_PASSWORD: <literal>` and friends "
            "(MYSQL / REDIS / RABBITMQ / etc.) to `POSTGRES_PASSWORD: "
            "$POSTGRES_PASSWORD` in GitLab pipeline files, leaving a "
            "comment pointing at Settings > CI/CD > Variables as the "
            "place to configure the Masked + Protected value.  The next "
            "pipeline run will fail until the variable is configured — "
            "failing fast is the point.  Pairs with SEC2-GL-003."
        ),
    )
    parser.add_argument(
        "--fix-egress-allowlist-scaffold",
        action="store_true",
        help=(
            "Opt-in: inject a step-security/harden-runner egress allow-list "
            "scaffold as the first step of each GitHub-workflow job, in 'audit' "
            "mode, with allowed-endpoints derived from the workflow's actions and "
            "run-steps.  Review-first: SHA-pin the action and switch to 'block' "
            "after an audit run confirms the list.  Combine with --fix or "
            "--fix-dry-run."
        ),
    )
    parser.add_argument(
        "--suggest",
        action="store_true",
        help="Level 2: Generate suggested patches for findings that need human review",
    )
    parser.add_argument(
        "--guide",
        nargs="?",
        const="list",
        help="Level 3: Print step-by-step remediation guide for a rule ID (e.g., --guide SEC4-GH-001), or --guide all",
    )
    parser.add_argument("--self-test", action="store_true", help="Run rule self-tests")
    parser.add_argument(
        "--mutate", action="store_true", help="Run mutation tests (use with --self-test)"
    )
    parser.add_argument("--rule", help="Test specific rule ID (use with --self-test)")
    parser.add_argument(
        "--fp-simulate",
        action="store_true",
        help=(
            "Run the FP simulator (advisory): benignise each rule's own "
            "positive samples and report rules that still fire. Pairs with "
            "--self-test. Reports only — does not affect the exit code."
        ),
    )
    parser.add_argument(
        "--self-test-json",
        action="store_true",
        help=(
            "Emit self-test / mutation results as JSON instead of human-"
            "readable text. Pairs with --self-test [--mutate] for CI "
            "dashboards: per-rule kill-rate over time is invisible in the "
            "pass/fail text format."
        ),
    )
    parser.add_argument(
        "--mutate-semantic",
        action="store_true",
        help=(
            "Also run advisory semantic-equivalence mutation operators "
            "(YAML boolean synonyms, trigger shape, quoted scalars). "
            "These exercise rule resilience to format-equivalent inputs; "
            "survivors are rule-engineering gaps, not gated by the "
            "100%% kill-rate CI step. Pairs with --mutate."
        ),
    )
    parser.add_argument(
        "--github-org", help="Scan all repos in a GitHub org (requires GITHUB_TOKEN env var)"
    )
    parser.add_argument(
        "--gitlab-group", help="Scan all projects in a GitLab group (requires GITLAB_TOKEN env var)"
    )
    parser.add_argument(
        "--jenkins-url",
        metavar="URL",
        help=(
            "Jenkins instance URL for platform posture audit "
            "(e.g. https://jenkins.example.com). Requires JENKINS_USER "
            "and JENKINS_TOKEN env vars for authentication."
        ),
    )
    parser.add_argument(
        "--platform-audit",
        action="store_true",
        help=(
            "Platform posture mode: inspect repository / organization settings "
            "via the GitHub REST API and emit findings for misconfigurations "
            "that make workflows more dangerous than their YAML alone suggests "
            "(branch protection, default GITHUB_TOKEN permission, fork-PR "
            "approval gate, CODEOWNERS coverage). Requires --github-repo "
            "OWNER/REPO and an authenticated token (see --token-stdin, "
            "GITHUB_TOKEN env var, or interactive prompt)."
        ),
    )
    parser.add_argument(
        "--github-repo",
        metavar="OWNER/REPO",
        help=(
            "Repository identity in OWNER/REPO form. Used in two contexts: "
            "(1) targets the repository for --platform-audit; "
            "(2) provides explicit identity to the static-guard evaluator "
            "on the scan path (overrides ``git remote`` auto-detection). "
            "Useful when scanning a directory that isn't a git checkout "
            "or whose remote is not named ``origin``."
        ),
    )
    parser.add_argument(
        "--gitlab-project",
        metavar="ID_OR_PATH",
        help=(
            "Project to target with --platform-audit on GitLab. Accepts a "
            "numeric project ID (e.g. 12345) or a namespaced path "
            "(e.g. my-group/my-project). Honours the GITLAB_URL env var for "
            "self-hosted instances."
        ),
    )
    parser.add_argument(
        "--token-stdin",
        action="store_true",
        help=(
            "Read the API token from stdin instead of the environment or a prompt. "
            "Lets you pipe from a secrets manager: "
            "`vault kv get -field=token secret/github | taintly --token-stdin ...`"
        ),
    )
    parser.add_argument(
        "--exclude-rule",
        action="append",
        dest="exclude_rule",
        metavar="RULE_ID",
        help="Exclude a rule ID from the scan (repeatable, e.g. --exclude-rule SEC2-GH-002)",
    )
    parser.add_argument(
        "--strict-config",
        action="store_true",
        help=(
            "Exit non-zero if the local ``.taintly.yml`` excludes any rule "
            "from the scan.  Recommended for invocations on protected "
            "branches where checked-in exclusions should be visible to "
            "reviewers (the summary block lists excluded rules in any "
            "case; ``--strict-config`` makes the presence of any "
            "exclusion fail the scan)."
        ),
    )
    parser.add_argument(
        "--no-inline-suppressions",
        action="store_true",
        help=(
            "Disregard inline suppression comments, including opted-in foreign "
            "markers. Config-file exceptions still apply."
        ),
    )
    parser.add_argument(
        "--score",
        action="store_true",
        help="Compute a 0-100 security score and per-category breakdown after scanning",
    )
    parser.add_argument(
        "--integration-test",
        action="store_true",
        help="Run integration tests: false positives, known bypasses, structural variants, realistic workflows",
    )
    parser.add_argument(
        "--category",
        help="Filter --integration-test by category: false_positive, known_bypass, structural, realistic",
    )
    parser.add_argument(
        "--config",
        metavar="PATH",
        help="Load config from this path instead of auto-discovering .taintly.yml",
    )
    parser.add_argument(
        "--no-config",
        action="store_true",
        help="Do not load any config file; run with CLI flags only",
    )
    parser.add_argument(
        "--fail-on",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
        default=None,
        dest="fail_on",
        help="Exit 1 if any finding is at this severity or above (independent of --min-severity)",
    )
    parser.add_argument(
        "--review-advisory",
        action="store_true",
        help="Keep review-needed findings in reports but exclude them from the exit severity gate",
    )
    parser.add_argument(
        "--require-files",
        action="store_true",
        help="In a local scan, exit 11 and report incomplete coverage if no CI files are found",
    )
    baseline_mode = parser.add_mutually_exclusive_group()
    baseline_mode.add_argument(
        "--baseline",
        nargs="?",
        const=BASELINE_FILENAME,
        metavar="FILE",
        help=(
            f"Write current findings as a baseline to FILE "
            f"(default: {BASELINE_FILENAME}). "
            "Commit the baseline file to suppress these findings in future --diff scans. "
            "Security findings are accepted for this snapshot; incomplete analysis still exits 11."
        ),
    )
    baseline_mode.add_argument(
        "--diff",
        nargs="?",
        const=BASELINE_FILENAME,
        metavar="FILE",
        help=(
            f"Only report findings not present in the baseline FILE "
            f"(default: {BASELINE_FILENAME}). "
            "Use after --baseline to surface only new issues."
        ),
    )
    parser.add_argument(
        "--transitive",
        action="store_true",
        help=(
            "Analyse transitive action dependencies: for each SHA-pinned action, "
            "fetch its action.yml via GitHub API and check for unpinned sub-actions "
            "(composite actions only). Requires GITHUB_TOKEN env var."
        ),
    )
    parser.add_argument(
        "--advisory-check",
        action="store_true",
        help=(
            "Augment SEC3-GH-004 (known-vulnerable action versions) with live "
            "queries against the GitHub Advisory Database. Catches advisories "
            "published after taintly's last release. GITHUB_TOKEN env var "
            "raises the rate-limit ceiling but is optional. Bundled coverage "
            "applies regardless; this flag adds new entries on top."
        ),
    )
    parser.add_argument(
        "--no-taint",
        action="store_true",
        help=(
            "Suppress the shallow taint-analysis rule (TAINT-GH-001) only. "
            "This analysis is deliberately narrow in scope: it detects flows "
            "where an attacker-controlled ${{ }} context is assigned to a "
            "step or job env: variable and the same variable is later "
            "expanded inside a run: block in the same job. It does NOT "
            "handle multi-hop (VAR->VAR2->run), $GITHUB_ENV writes, step "
            "outputs, or artefact/cross-workflow propagation. Default: on."
        ),
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help=(
            "Expand every finding in the text report. Without this flag, "
            "any rule that fires more than 5 times collapses to a single "
            "summary block listing the affected files."
        ),
    )
    parser.add_argument(
        "--check-imposter-commits",
        action="store_true",
        help=(
            "Enable SEC3-GH-009: per-action SHA-reachability check. "
            "For each ``uses: owner/repo@<sha>`` reference pinned to a "
            "40-char SHA, query the GitHub Commits API to confirm the "
            "SHA is still reachable from a ref in the action's repo. "
            "Requires GITHUB_TOKEN in the environment for authenticated "
            "requests; recommended on a weekly cron rather than per-PR "
            "because of the per-action API cost."
        ),
    )
    parser.add_argument(
        "--check-ref-drift",
        action="store_true",
        help=(
            "Enable SEC3-GH-T02: mutable-ref-repoint detection (the "
            "tj-actions/changed-files CVE-2025-30066 class). Records the "
            "resolved upstream SHA of each ``uses: owner/repo@<mutable-ref>`` in "
            "the --baseline, and on a later --diff scan flags any ref that now "
            "resolves to a DIFFERENT SHA with no local YAML change as CRITICAL. "
            "Requires GITHUB_TOKEN; use with --baseline then --diff on a cron. "
            "Cannot fire on a cold-start first scan (no prior resolution)."
        ),
    )
    parser.add_argument(
        "--check-archived-actions",
        action="store_true",
        help=(
            "Enable SEC3-GH-010: per-action archived-repo check. "
            "For each ``uses: owner/repo@<ref>`` reference (skipping "
            "first-party orgs), query GET /repos/{owner}/{repo} to read "
            "the ``archived`` flag.  Archived repos receive no new "
            "releases or security patches.  Requires GITHUB_TOKEN; "
            "recommended on a weekly cron rather than per-PR."
        ),
    )
    parser.add_argument(
        "--check-archived-gitlab-projects",
        action="store_true",
        help=(
            "Enable SEC3-GL-008: per-include archived-project check. "
            "For each ``include:project: namespace/project`` reference, "
            "query GitLab's projects API to read the ``archived`` flag. "
            "Archived GitLab projects receive no new releases or "
            "security patches.  Requires GITLAB_TOKEN; recommended on "
            "a weekly cron rather than per-pipeline."
        ),
    )
    parser.add_argument(
        "--respect-zizmor-ignores",
        action="store_true",
        help=(
            "Honour foreign-scanner inline ignore comments that match "
            "zizmor's format (``# zizmor: ignore`` / "
            "``# zizmor: ignore[<rule-id>]``).  A small mapping table "
            "translates well-known zizmor rule IDs onto the taintly "
            "rules that detect the same threat shape; unmapped IDs "
            "fall through to broad-line suppression so a maintainer "
            "who already reviewed the line under another tool isn't "
            "asked to re-review under taintly.  Default off — taintly "
            "doesn't change behaviour based on another tool's "
            "suppressions without explicit opt-in."
        ),
    )

    args = parser.parse_args()

    if args.codebuild_webhook_snapshot:
        _assess_codebuild_webhook(parser, args)
        return
    if args.codebuild_webhook_sender is not None:
        parser.error("--codebuild-webhook-sender requires --codebuild-webhook-snapshot")
    if args.jenkins_incrementals_observation:
        _check_jenkins_incrementals(parser, args)
        return
    if args.jenkins_maven_snapshot_observation:
        _check_jenkins_maven_snapshot(parser, args)
        return
    if args.gitlab_mr_artifact_observation:
        _check_gitlab_mr_artifact(parser, args)
        return
    if args.gitlab_fork_admission_observation:
        _check_gitlab_fork_admission(parser, args)
        return
    if args.gitlab_mr_publish_job is not None:
        parser.error("--gitlab-mr-publish-job requires --gitlab-mr-artifact-observation")
    if args.gitlab_artifact_origin is not None:
        parser.error("--gitlab-artifact-origin requires --gitlab-mr-artifact-observation")
    if args.codebuild_public_s3_observation:
        _assess_codebuild_s3(parser, args)
        return
    if args.codebuild_public_deploy_observation:
        _assess_codebuild_deploy(parser, args)
        return
    if args.codebuild_start_observation:
        _assess_codebuild_start(parser, args)
        return
    if (
        args.github_preview_observation
        or args.github_version_upload_observation
        or args.github_release_observation
        or args.github_pages_observation
        or args.github_release_request_observation
    ):
        _check_github_observation(parser, args)
        return

    if args.codebuild_project_snapshot or args.codebuild_public_build:
        _scan_codebuild_snapshot(parser, args)
        return

    registry_job = None
    if args.gitlab_job_evidence:
        if args.platform not in (None, Platform.GITLAB.value) or not Path(args.path).is_dir():
            parser.error("--gitlab-job-evidence requires a local GitLab repository directory")
        if any(
            (
                args.self_test,
                args.integration_test,
                args.guide,
                args.fix,
                args.fix_dry_run,
                args.platform_audit,
                args.github_org,
                args.gitlab_group,
                args.jenkins_url,
                args.diff,
                args.baseline,
            )
        ):
            parser.error("--gitlab-job-evidence is supported only in a local source scan")
        snapshot, project_id, job_id = args.gitlab_job_evidence
        try:
            registry_job = load_registry_job(Path(snapshot), project_id, job_id)
        except RegistryJobError as exc:
            parser.error(str(exc))
        args.platform = Platform.GITLAB.value

    if args.require_files and any(
        (
            args.self_test,
            args.integration_test,
            args.guide,
            args.fix,
            args.fix_dry_run,
            args.platform_audit,
            args.github_org,
            args.gitlab_group,
            args.jenkins_url,
        )
    ):
        parser.error("--require-files is only supported for local scans")

    if args.score or args.format == "html":
        from .scorer import compute_score

        if args.format == "text":
            from .reporters.score_text import format_score

    if args.check_imposter_commits:
        from taintly.platform import github_sha_verify

        github_sha_verify.set_enabled(True)

    if args.check_ref_drift:
        from taintly.platform import github_ref_resolve

        github_ref_resolve.set_enabled(True)

    if args.check_archived_actions:
        from taintly.platform import github_archived_check

        github_archived_check.set_enabled(True)

    if args.check_archived_gitlab_projects:
        from taintly.platform import gitlab_archived_check

        gitlab_archived_check.set_enabled(True)

    if args.respect_zizmor_ignores:
        from taintly.suppressions import zizmor_compat

        zizmor_compat.set_respect_zizmor_ignores(True)

    # Auto-disable ANSI colour when stdout is not a TTY (piped / redirected)
    # so `taintly > report.txt` and `taintly --format html > report.html`
    # don't dump raw escape sequences like "\x1b[91m" into the saved file.
    # Saved files were showing literal ANSI codes because use_color defaulted
    # to True regardless of whether stdout was a terminal.
    #
    # Honour FORCE_COLOR (de-facto standard, also used by ripgrep / eslint /
    # pytest) so users who really want colour in a non-TTY context can opt
    # back in.  Passing --no-color already wins; we only downgrade from the
    # default.
    if not args.no_color and not os.environ.get("FORCE_COLOR"):
        try:
            stdout_is_tty = sys.stdout.isatty()
        except (AttributeError, ValueError):
            stdout_is_tty = False
        if not stdout_is_tty:
            args.no_color = True

    # Opt-in fixes are only meaningful in fix mode.  Each opt-in flag
    # requires pairing with --fix or --fix-dry-run; the error message
    # names the offending flag so the user knows which one to pair.
    _OPT_IN_FLAGS = [
        ("fix_npm_ignore_scripts", "--fix-npm-ignore-scripts"),
        ("fix_jenkins_cap_add_hint", "--fix-jenkins-cap-add-hint"),
        ("fix_github_ai_allowed_tools_scaffold", "--fix-github-ai-allowed-tools-scaffold"),
        ("fix_hoist_service_credentials", "--fix-hoist-service-credentials"),
        ("fix_egress_allowlist_scaffold", "--fix-egress-allowlist-scaffold"),
    ]
    for _attr, _flag in _OPT_IN_FLAGS:
        if getattr(args, _attr, False) and not (args.fix or args.fix_dry_run):
            print(
                f"Error: {_flag} must be combined with --fix "
                "(to apply) or --fix-dry-run (to preview).",
                file=sys.stderr,
            )
            sys.exit(3)

    # ------------------------------------------------------------------
    # Config resolution
    # ------------------------------------------------------------------
    audit_config = DEFAULT_CONFIG
    if not args.no_config:
        config_path = args.config
        if config_path is None:
            # Auto-discover only in local scan mode (not org/group remotes)
            if not args.github_org and not args.gitlab_group:
                config_path = find_config(args.path)
        if config_path is not None:
            try:
                audit_config = load_config(config_path)
            except FileNotFoundError:
                if args.config:
                    print(f"Config error: file not found: {config_path}", file=sys.stderr)
                    sys.exit(3)
            except ConfigError as exc:
                print(f"Config error: {exc}", file=sys.stderr)
                sys.exit(3)

            # Emit one-line warnings for expired / unjustified suppressions
            # so hidden exceptions don't accumulate silently.  Non-fatal —
            # the suppression still applies so CI doesn't break overnight.
            for warning in audit_ignores(audit_config.ignores):
                print(f"taintly: suppression warning: {warning}", file=sys.stderr)

    # CLI flags win over config; config wins over hard defaults
    effective_min_sev = (
        Severity[args.min_severity]
        if args.min_severity
        else (Severity[audit_config.min_severity] if audit_config.min_severity else Severity.INFO)
    )

    effective_platform = args.platform or audit_config.platform

    effective_fail_on = (
        Severity[args.fail_on]
        if args.fail_on
        else (Severity[audit_config.fail_on] if audit_config.fail_on else None)
    )

    # Load rules.  Cold start dominates wallclock on small repos: the
    # GitLab and Jenkins rule packs together carry ~150 AI-family rules
    # whose import cost is wasted on a GitHub-only repo.  When we know
    # the platform (either explicitly via --platform or via filesystem
    # detection) load just that pack.  Modes that genuinely need every
    # rule (--self-test, --integration-test, mutation testing) fall
    # through to the all-platforms loader.
    if args.self_test or args.integration_test or args.mutate:
        all_rules = load_all_rules()
    else:
        with _defer_context_regex_compilation():
            if effective_platform:
                all_rules = load_rules_for_platform(Platform(effective_platform))
            else:
                detected = (
                    detect_platform(args.path)
                    if os.path.isdir(args.path) or os.path.isfile(args.path)
                    else None
                )
                if detected is not None:
                    all_rules = load_rules_for_platform(detected)
                else:
                    # Mixed (.github + .gitlab-ci.yml in one repo) or undetectable
                    # — load everything; engine will scope per platform.
                    all_rules = load_all_rules()

    # A partial registry cannot establish a clean scan or a passing self-test.
    # This must run before exclusions, testing modes and report generation.
    if _rule_registry._IMPORT_FAILURES:
        print(
            "taintly: rule loading failed; cannot continue with incomplete coverage: "
            + ", ".join(_rule_registry._IMPORT_FAILURES),
            file=sys.stderr,
        )
        sys.exit(3)

    # Apply rule exclusions (CLI + config, merged)
    cli_excluded = set(args.exclude_rule or [])
    config_excluded = set(audit_config.exclude_rules)
    excluded = cli_excluded | config_excluded
    if args.no_taint:
        # --no-taint is a targeted off-switch for the shallow taint analysis
        # rule only.  Taint defaults to on per the v2 plan; users who find it
        # too noisy can silence just this rule without reaching for
        # --exclude-rule TAINT-GH-001.
        excluded.add("TAINT-GH-001")
    if excluded:
        all_rules = [r for r in all_rules if r.id not in excluded]
    # ``--strict-config`` makes the presence of any config-driven
    # exclusion fail the scan.  The intent is for protected-branch CI
    # invocations: the summary always lists excluded rules, but
    # strict mode escalates that disclosure to a non-zero exit.
    if args.strict_config and config_excluded:
        rules_list = ", ".join(sorted(config_excluded))
        print(
            f"taintly: --strict-config set; .taintly.yml excludes "
            f"{len(config_excluded)} rule(s) ({rules_list}). Exit.",
            file=sys.stderr,
        )
        sys.exit(3)

    # Integration test mode
    if args.integration_test:
        from .testing.integration_tests import format_integration_results, run_integration_tests

        categories = [args.category] if args.category else None
        results = run_integration_tests(all_rules, categories=categories)
        print(format_integration_results(results))
        non_bypass = [r for r in results if r.case.category != "known_bypass"]
        if not all(r.passed for r in non_bypass):
            sys.exit(10)
        sys.exit(0)

    # Self-test mode
    if args.self_test:
        from .testing.self_test import format_test_results, run_mutation_tests, run_self_test

        rules_to_test = all_rules
        if args.rule:
            rules_to_test = [r for r in all_rules if r.id == args.rule]
            if not rules_to_test:
                print(f"Rule {args.rule} not found", file=sys.stderr)
                sys.exit(3)

        # Filter rules that have test samples
        testable = [r for r in rules_to_test if r.test_positive or r.test_negative]
        self_results = run_self_test(testable)

        mutation_results = None
        if args.mutate:
            mutation_results = run_mutation_tests(testable, include_semantic=args.mutate_semantic)

        if args.self_test_json:
            from .testing.self_test import format_test_results_json

            print(format_test_results_json(self_results, mutation_results))
        else:
            print(format_test_results(self_results, mutation_results))

        # FP simulator — advisory, never affects the exit code.
        if args.fp_simulate:
            from .testing.fp_simulator import format_fp_results, run_fp_simulation

            print(format_fp_results(run_fp_simulation(testable), testable))

        # Exit codes
        if not all(r.passed for r in self_results):
            sys.exit(10)
        if mutation_results and not all(r.passed for r in mutation_results):
            sys.exit(12)
        sys.exit(0)

    # Guide mode
    if args.guide:
        from .guides import format_guide_list, get_all_guided_rules, get_guide

        if args.guide == "list":
            print(format_guide_list())
        elif args.guide == "all":
            for rule_id in get_all_guided_rules():
                print(get_guide(rule_id))
        else:
            guide = get_guide(args.guide)
            if guide:
                print(guide)
            else:
                print(f"No guide available for {args.guide}", file=sys.stderr)
                print(format_guide_list())
                sys.exit(3)
        sys.exit(0)

    # Fix mode
    if args.fix or args.fix_dry_run:
        from .engine import discover_files
        from .fixes import apply_fixes, format_fix_results

        dry_run = args.fix_dry_run
        # Work out which platforms to fix.  The old behaviour silently
        # defaulted to GitHub when both GitHub and GitLab CI lived in the
        # same repo — fix mode would then only touch the GitHub files and
        # exit 0, giving the operator no signal that half the repo was
        # untouched.  New behaviour:
        #   * --platform X wins (explicit)
        #   * otherwise process every platform that has discoverable files
        #   * if nothing is discoverable, fall back to GitHub so a bare
        #     --fix in an empty repo doesn't crash
        if args.platform:
            platforms_to_fix = [Platform(args.platform)]
        else:
            platforms_to_fix = [p for p in Platform if discover_files(args.path, p)]
            if not platforms_to_fix:
                platforms_to_fix = [Platform.GITHUB]

        extra_fix_types: list[str] = []
        if args.fix_npm_ignore_scripts:
            extra_fix_types.append("npm_ignore_scripts")
        if args.fix_jenkins_cap_add_hint:
            extra_fix_types.append("jenkins_cap_add_hint")
        if args.fix_github_ai_allowed_tools_scaffold:
            extra_fix_types.append("github_ai_allowed_tools_scaffold")
        if args.fix_hoist_service_credentials:
            extra_fix_types.append("hoist_service_credentials")
        if args.fix_egress_allowlist_scaffold:
            extra_fix_types.append("egress_allowlist_scaffold")

        default_fix_types = {
            Platform.GITHUB: [
                "pin_sha",
                "persist_credentials",
                "add_permissions",
                "remove_insecure_commands",
                "remove_debug_logging",
                "disable_setup_cache_in_release",
                "quote_github_refs",
            ],
            Platform.GITLAB: ["quote_gitlab_refs", "quote_gitlab_ci_vars"],
            Platform.JENKINS: [],
            Platform.CODEBUILD: [],
        }
        opt_in_fix_types = {
            Platform.GITHUB: {
                "npm_ignore_scripts",
                "github_ai_allowed_tools_scaffold",
                "hoist_service_credentials",
                "egress_allowlist_scaffold",
            },
            Platform.GITLAB: {
                "npm_ignore_scripts",
                "hoist_service_credentials",
                "egress_allowlist_scaffold",
            },
            Platform.JENKINS: {"jenkins_cap_add_hint"},
            Platform.CODEBUILD: {"npm_ignore_scripts"},
        }

        files: list[tuple[str, Platform]] = []
        for plat in platforms_to_fix:
            files.extend((path, plat) for path in discover_files(args.path, plat))
        all_results = []
        for fpath, plat in files:
            supported_opt_ins = [
                fix_type for fix_type in extra_fix_types if fix_type in opt_in_fix_types[plat]
            ]
            all_results.extend(
                apply_fixes(
                    fpath,
                    dry_run=dry_run,
                    fix_types=default_fix_types[plat],
                    extra_fix_types=supported_opt_ins,
                )
            )

        print(format_fix_results(all_results, dry_run=dry_run))
        sys.exit(0)

    # Platform posture audit mode — API-based, requires a token
    if args.platform_audit:
        targets = [bool(args.github_repo), bool(args.gitlab_project)]
        if sum(targets) == 0:
            print(
                "Error: --platform-audit requires either --github-repo OWNER/REPO "
                "or --gitlab-project ID_OR_PATH.",
                file=sys.stderr,
            )
            sys.exit(3)
        if sum(targets) > 1:
            print(
                "Error: --platform-audit accepts only one of --github-repo / "
                "--gitlab-project at a time.",
                file=sys.stderr,
            )
            sys.exit(3)

        from .models import AuditReport
        from .platform.token import TokenError, describe_source_for_user, load_token

        if args.github_repo:
            if "/" not in args.github_repo:
                print("Error: --github-repo must be in OWNER/REPO form.", file=sys.stderr)
                sys.exit(3)

            from .platform.github_checks import run_all_checks as gh_run
            from .platform.github_client import GitHubClient

            try:
                token = load_token(
                    "GITHUB_TOKEN",
                    from_stdin=args.token_stdin,
                    interactive=True,
                    platform_name="GitHub",
                )
            except TokenError as exc:
                print(f"Token error: {exc}", file=sys.stderr)
                sys.exit(3)

            print(describe_source_for_user(token), file=sys.stderr)
            print(f"Auditing platform posture for {args.github_repo}...", file=sys.stderr)

            gh_client = GitHubClient(token)
            findings = gh_run(args.github_repo, gh_client)
            token.clear()

            report = AuditReport(repo_path=f"github:{args.github_repo}", platform="github")

        else:  # --gitlab-project
            from .platform.gitlab_checks import GitLabPostureIncomplete
            from .platform.gitlab_checks import run_all_checks as gl_run
            from .platform.gitlab_client import GitLabClient

            try:
                token = load_token(
                    "GITLAB_TOKEN",
                    from_stdin=args.token_stdin,
                    interactive=True,
                    platform_name="GitLab",
                )
            except TokenError as exc:
                print(f"Token error: {exc}", file=sys.stderr)
                sys.exit(3)

            print(describe_source_for_user(token), file=sys.stderr)
            print(
                f"Auditing platform posture for {args.gitlab_project}...",
                file=sys.stderr,
            )

            try:
                gl_client = GitLabClient(token)
                findings = gl_run(args.gitlab_project, gl_client)
            except GitLabPostureIncomplete as exc:
                findings = [*exc.findings, exc.diagnostic()]
            except GitLabTransportError as exc:
                print(f"Error: {exc}; GitLab posture analysis was not completed.", file=sys.stderr)
                sys.exit(3)
            finally:
                token.clear()

            report = AuditReport(repo_path=f"gitlab:{args.gitlab_project}", platform="gitlab")

        report.files_scanned = 1  # one project/repo audited
        for f in findings:
            report.add(f)
        report.filter_severity(effective_min_sev)
        report.summarize()

        score_report = (
            compute_score(
                report.findings,
                files_scanned=report.files_scanned,
                platforms_scanned=_platforms_for_reports(report),
                families_with_surface=report.families_with_surface,
                families_with_ctx_coverage=report.families_with_ctx_coverage,
            )
            if (args.score or args.format == "html")
            else None
        )
        _output_report(report, args, score_report=score_report)
        if score_report is not None and args.format == "text":
            print(format_score(score_report, use_color=not args.no_color))
        _exit_for_severity(report, effective_fail_on, review_advisory=args.review_advisory)
        return

    # GitHub org scan mode
    if args.github_org:
        github_token = os.environ.get("GITHUB_TOKEN")
        if not github_token:
            print(
                "Error: GITHUB_TOKEN environment variable required for --github-org",
                file=sys.stderr,
            )
            sys.exit(3)

        from .ingestion.github_api import fetch_org_workflows, list_org_repos
        from .models import AuditReport

        print(f"Fetching workflows from org: {args.github_org} ...", file=sys.stderr)
        try:
            workflow_files = fetch_org_workflows(args.github_org, github_token)
        except Exception as e:
            print(f"Error fetching org workflows: {e}", file=sys.stderr)
            sys.exit(3)

        platform_rules = [r for r in all_rules if r.platform == Platform.GITHUB]

        report = AuditReport(repo_path=f"github-org:{args.github_org}", platform="github")
        report.files_scanned = len(workflow_files.items)
        for issue in workflow_files.issues:
            report.add(issue.finding())

        for virtual_path, content in workflow_files.items:
            for finding in scan_file(
                virtual_path,
                platform_rules,
                _content=content,
                max_scan_seconds=args.max_scan_seconds,
                respect_inline_suppressions=not args.no_inline_suppressions,
                local_repository_available=False,
            ):
                report.add(finding)

        # --- Platform posture checks across all repos in the org ---
        from .platform.github_checks import run_all_checks
        from .platform.token import TokenManager

        print("Running platform posture checks ...", file=sys.stderr)
        try:
            repos = list_org_repos(args.github_org, github_token)
            # Reuse the already-loaded token string rather than
            # re-reading from the env — keeps one source of truth and
            # matches the value/source contract of TokenManager.
            tm = TokenManager(value=github_token, source="GITHUB_TOKEN")
            from .platform.github_client import GitHubClient

            client = GitHubClient(tm)
            for repo_name in repos:
                try:
                    for finding in run_all_checks(repo_name, client):
                        report.add(finding)
                except Exception:
                    continue  # nosec B112 — best-effort per-repo

            # --- Account-level checks ---
            from .platform.github_checks import run_account_checks

            for finding in run_account_checks(args.github_org, client):
                report.add(finding)
        except Exception as e:
            print(f"Warning: platform checks failed: {e}", file=sys.stderr)

        report.findings = apply_config_ignores(report.findings, audit_config.ignores, args.path)
        report.filter_severity(effective_min_sev)
        report.findings = coalesce_input_script_findings(report.findings)
        report.summarize()
        score_report = (
            compute_score(
                report.findings,
                files_scanned=report.files_scanned,
                platforms_scanned=_platforms_for_reports(report),
                scanned_config=report.files_scanned > 0 or bool(report.findings),
                families_with_surface=report.families_with_surface,
                families_with_ctx_coverage=report.families_with_ctx_coverage,
            )
            if (args.score or args.format == "html")
            else None
        )
        _output_report(report, args, score_report=score_report)
        if score_report is not None and args.format == "text":
            print(format_score(score_report, use_color=not args.no_color))
        _exit_for_severity(report, effective_fail_on, review_advisory=args.review_advisory)
        return

    # GitLab group scan mode
    if args.gitlab_group:
        gitlab_token = os.environ.get("GITLAB_TOKEN")
        if not gitlab_token:
            print(
                "Error: GITLAB_TOKEN environment variable required for --gitlab-group",
                file=sys.stderr,
            )
            sys.exit(3)

        from .ingestion.gitlab_api import (
            GitLabSourceIncomplete,
            fetch_group_pipelines,
            list_group_projects,
        )
        from .models import AuditReport

        source_refusal: GitLabSourceIncomplete | None = None
        print(f"Fetching pipelines from group: {args.gitlab_group} ...", file=sys.stderr)
        try:
            pipeline_files = fetch_group_pipelines(args.gitlab_group, gitlab_token)
        except GitLabSourceIncomplete as exc:
            if not exc.inventory.items:
                print(f"Error fetching group pipelines: {exc}", file=sys.stderr)
                sys.exit(3)
            pipeline_files = exc.inventory
            source_refusal = exc
        except Exception as e:
            print(f"Error fetching group pipelines: {e}", file=sys.stderr)
            sys.exit(3)

        platform_rules = [r for r in all_rules if r.platform == Platform.GITLAB]

        report = AuditReport(repo_path=f"gitlab-group:{args.gitlab_group}", platform="gitlab")
        report.files_scanned = len(pipeline_files.items)
        for issue in pipeline_files.issues:
            report.add(issue.finding())

        for virtual_path, content in pipeline_files.items:
            for finding in scan_file(
                virtual_path,
                platform_rules,
                _content=content,
                max_scan_seconds=args.max_scan_seconds,
                respect_inline_suppressions=not args.no_inline_suppressions,
                local_repository_available=False,
            ):
                report.add(finding)

        if source_refusal is None:
            # --- Platform posture checks across all projects in the group ---
            from .platform.gitlab_checks import GitLabPostureIncomplete, run_group_checks
            from .platform.gitlab_checks import run_all_checks as gl_run_all_checks
            from .platform.token import TokenManager

            print("Running platform posture checks ...", file=sys.stderr)
            gl_tm: TokenManager | None = None
            try:
                projects = list_group_projects(args.gitlab_group, gitlab_token)
                gl_tm = TokenManager(value=gitlab_token, source="GITLAB_TOKEN")
                from .platform.gitlab_client import GitLabClient

                gl_client = GitLabClient(gl_tm)
                for proj in projects:
                    proj_id = str(proj.get("id", ""))
                    try:
                        for finding in gl_run_all_checks(proj_id, gl_client):
                            report.add(finding)
                    except GitLabTransportError:
                        raise
                    except Exception:
                        continue  # nosec B112

                # Group-level checks
                for finding in run_group_checks(args.gitlab_group, gl_client):
                    report.add(finding)
            except GitLabTransportError as exc:
                # Source analysis may already have established useful findings.
                if isinstance(exc, GitLabPostureIncomplete):
                    for finding in exc.findings:
                        report.add(finding)
                    report.add(exc.diagnostic())
                else:
                    report.add(
                        Finding(
                            rule_id="ENGINE-ERR",
                            severity=Severity.LOW,
                            title=f"GitLab group posture incomplete: {exc}",
                            description=(
                                "Credential transport refused a recipient, so the affected "
                                "posture questions were not completed. Existing source "
                                "findings remain reportable."
                            ),
                            file=f"gitlab-group:{args.gitlab_group}",
                        )
                    )
            except Exception as e:
                print(f"Warning: platform checks failed: {e}", file=sys.stderr)
            finally:
                if gl_tm is not None:
                    gl_tm.clear()

        report.findings = apply_config_ignores(report.findings, audit_config.ignores, args.path)
        report.filter_severity(effective_min_sev)
        report.findings = coalesce_input_script_findings(report.findings)
        report.summarize()
        score_report = (
            compute_score(
                report.findings,
                files_scanned=report.files_scanned,
                platforms_scanned=_platforms_for_reports(report),
                scanned_config=report.files_scanned > 0 or bool(report.findings),
                families_with_surface=report.families_with_surface,
                families_with_ctx_coverage=report.families_with_ctx_coverage,
            )
            if (args.score or args.format == "html")
            else None
        )
        _output_report(report, args, score_report=score_report)
        if score_report is not None and args.format == "text":
            print(format_score(score_report, use_color=not args.no_color))
        _exit_for_severity(report, effective_fail_on, review_advisory=args.review_advisory)
        return

    # Jenkins instance posture audit
    if getattr(args, "jenkins_url", None):
        from .models import AuditReport
        from .platform.jenkins_checks import run_all_checks as jk_run_all_checks
        from .platform.jenkins_client import JenkinsClient
        from .source_inventory import SourceIssue

        jenkins_url = args.jenkins_url.rstrip("/")
        jenkins_user = os.environ.get("JENKINS_USER", "")
        jenkins_token = os.environ.get("JENKINS_TOKEN", "")

        print(f"Running Jenkins posture audit on {jenkins_url} ...", file=sys.stderr)
        jk_client = JenkinsClient(jenkins_url, user=jenkins_user, token=jenkins_token)

        report = AuditReport(repo_path=f"jenkins:{jenkins_url}", platform="jenkins")
        report.files_scanned = 0

        try:
            for finding in jk_run_all_checks(jenkins_url, jk_client):
                report.add(finding)
        except Exception:
            report.add(
                SourceIssue(
                    report.repo_path, "The Jenkins posture audit ended before checks completed."
                ).finding()
            )

        report.findings = apply_config_ignores(report.findings, audit_config.ignores, args.path)
        report.filter_severity(effective_min_sev)
        report.findings = coalesce_input_script_findings(report.findings)
        report.summarize()
        score_report = (
            compute_score(
                report.findings,
                files_scanned=report.files_scanned,
                platforms_scanned=_platforms_for_reports(report),
                scanned_config=report.files_scanned > 0 or bool(report.findings),
                families_with_surface=report.families_with_surface,
                families_with_ctx_coverage=report.families_with_ctx_coverage,
            )
            if (args.score or args.format == "html")
            else None
        )
        _output_report(report, args, score_report=score_report)
        if score_report is not None and args.format == "text":
            print(format_score(score_report, use_color=not args.no_color))
        _exit_for_severity(report, effective_fail_on, review_advisory=args.review_advisory)
        return

    # ------------------------------------------------------------------
    # Baseline: load before scanning (--diff) or after (--baseline)
    # ------------------------------------------------------------------
    baseline = None
    if args.diff:
        try:
            baseline = load_baseline(args.diff)
        except FileNotFoundError:
            print(
                f"Error: baseline file not found: {args.diff}\n"
                f"Run with --baseline first to create one.",
                file=sys.stderr,
            )
            sys.exit(3)
        except BaselineError as exc:
            print(f"Baseline error: {exc}", file=sys.stderr)
            sys.exit(3)

    # Scan mode (local path)
    platform = Platform(effective_platform) if effective_platform else None

    # --advisory-check: augment the bundled compromised-action list with
    # a live GHSA query before scanning. Only meaningful for GitHub
    # workflows (the ecosystem the GHSA Actions DB covers); skip for
    # GitLab/Jenkins-only scans.
    if args.advisory_check:
        from .advisories import augment_cache_with_live
        from .engine import discover_files

        gh_files: list[str] = []
        if platform is None or platform == Platform.GITHUB:
            gh_files = discover_files(args.path, Platform.GITHUB)
        if gh_files:
            uses_re = re.compile(r"uses:\s*([^@\s]+)@\S+")
            packages: set[str] = set()
            for fpath in gh_files:
                try:
                    with open(fpath, encoding="utf-8") as fh:
                        for line in fh:
                            m = uses_re.search(line)
                            if m and "/" in m.group(1):
                                packages.add(m.group(1))
                except OSError:
                    continue
            if packages:
                advisory_token = os.environ.get("GITHUB_TOKEN")
                added = augment_cache_with_live(packages, advisory_token)
                print(
                    f"--advisory-check: queried {len(packages)} action(s); "
                    f"{added} live advisor{'y' if added == 1 else 'ies'} added "
                    f"to bundled list.",
                    file=sys.stderr,
                )

    explicit_repoctx = None
    if getattr(args, "github_repo", None) and "/" in args.github_repo:
        from .staticguard import WorkflowContext

        owner = args.github_repo.split("/", 1)[0]
        explicit_repoctx = WorkflowContext(repository=args.github_repo, repository_owner=owner)

    reports = scan_repo(
        args.path,
        all_rules,
        platform,
        explicit_github_repoctx=explicit_repoctx,
        max_scan_seconds=args.max_scan_seconds,
        coalesce_overlaps=False,
        respect_inline_suppressions=not args.no_inline_suppressions,
        gitlab_registry_job=registry_job,
    )

    missing_scan_files = args.require_files and not any(report.files_scanned for report in reports)
    if missing_scan_files:
        reports[0].add(
            Finding(
                rule_id="ENGINE-ERR",
                severity=Severity.LOW,
                title="No CI configuration files found (--require-files)",
                description="Check the scan path and platform selection before relying on this report.",
                file=reports[0].repo_path,
            )
        )

    # Surface config-driven exclusions on every report so the summary
    # reporter can disclose them.  CLI-only exclusions are operator
    # choices and not surfaced; config exclusions are
    # repository-checked-in trust events that reviewers should see.
    if config_excluded:
        sorted_config_exc = sorted(config_excluded)
        for report in reports:
            report.excluded_rules_from_config = sorted_config_exc

    all_findings = []
    deployment_contexts: dict[str, DeploymentContext] = {}
    for report in reports:
        deployment_context = deployment_contexts.setdefault(
            report.repo_path, load_deployment_context(report.repo_path)
        )
        apply_context_notes_to_findings(report.findings, deployment_context)
        report.findings = apply_config_ignores(report.findings, audit_config.ignores, args.path)
        report.filter_severity(effective_min_sev)
        report.findings = coalesce_input_script_findings(report.findings)
        report.summarize()
        all_findings.extend(report.findings)

    # --transitive: analyse composite action sub-dependencies via GitHub API
    if args.transitive:
        transitive_token = os.environ.get("GITHUB_TOKEN")
        if not transitive_token:
            print(
                "Error: GITHUB_TOKEN environment variable required for --transitive",
                file=sys.stderr,
            )
            sys.exit(3)

        from .engine import discover_files
        from .transitive import run_transitive_analysis

        print("Running transitive action dependency analysis...", file=sys.stderr)
        gh_files = discover_files(args.path, Platform.GITHUB)
        transitive_findings = run_transitive_analysis(gh_files, transitive_token, args.path)

        if transitive_findings:
            # Inject transitive findings into the first GitHub report (or create one)
            gh_report = next((r for r in reports if r.platform == "github"), None)
            if gh_report is None:
                from .models import AuditReport

                gh_report = AuditReport(repo_path=args.path, platform="github")
                reports.append(gh_report)
            for f in transitive_findings:
                gh_report.add(f)
            gh_report.summarize()
            all_findings.extend(transitive_findings)
            print(
                f"Transitive analysis: {len(transitive_findings)} finding(s) from "
                f"{len(set(f.snippet for f in transitive_findings))} unique action(s).",
                file=sys.stderr,
            )
        else:
            print("Transitive analysis: no issues found.", file=sys.stderr)

    # Save observations after requested analysis, then use the same report
    # dispatch as ordinary scanning, including aggregate machine formats.
    if args.baseline and not missing_scan_files:
        baseline_path = args.baseline
        resolved_refs = _resolve_current_refs(all_findings)
        try:
            bl = save_baseline(all_findings, args.path, baseline_path, resolved_refs)
        except OSError as exc:
            print(f"Error: unable to write baseline {baseline_path}: {exc}", file=sys.stderr)
            sys.exit(3)
        print(format_baseline_summary(bl, baseline_path), file=sys.stderr)

    # --diff: suppress known findings, show only new ones
    total_suppressed = 0
    if baseline is not None:
        # Mutable-ref-repoint (SEC3-GH-T02): resolve refs from the FULL pre-diff
        # finding set — a drifted ref's static finding is "unchanged" and gets
        # suppressed below, so it must be captured before apply_diff filters it.
        pre_diff_findings = [f for report in reports for f in report.findings]
        drift = detect_ref_drift(_resolve_current_refs(pre_diff_findings), baseline.resolved_refs)
        drift_findings = _build_drift_findings(drift, pre_diff_findings)

        filtered = []
        for report in reports:
            new_findings, suppressed = apply_diff(report.findings, baseline, args.path)
            total_suppressed += suppressed
            # Annotate the title for SHA bumps / new dependencies so the
            # operator can tell at a glance whether a "new" finding is
            # an entirely new third-party action or a routine version
            # bump on one they already approved.
            for f in new_findings:
                kind = classify_diff_kind(f, baseline.fingerprints, baseline.snippets, args.path)
                if kind == "sha_bump":
                    f.title = "[SHA BUMP] " + f.title
                elif kind == "new_dependency":
                    f.title = "[NEW DEPENDENCY] " + f.title
            report.findings = new_findings
            filtered.extend(new_findings)

        # Inject mutable-ref-repoint findings: genuinely new signal even though
        # the YAML is unchanged (the upstream code moved out from under the ref).
        if drift_findings:
            gh_report = next((r for r in reports if r.platform == "github"), None)
            if gh_report is None:
                from .models import AuditReport

                gh_report = AuditReport(repo_path=args.path, platform="github")
                reports.append(gh_report)
            for f in drift_findings:
                gh_report.add(f)
            gh_report.summarize()
            filtered.extend(drift_findings)

        all_findings = filtered
        print(
            format_diff_summary(total_suppressed, len(all_findings), args.diff),
            file=sys.stderr,
        )

    score_report = None
    # HTML output is ~useless without the score panel, so compute it implicitly
    # when --format html is used even if the user didn't pass --score.
    if args.score or args.format == "html":
        total_files = sum(r.files_scanned for r in reports)
        # Surface-evaluation tracking: union across all reports so the
        # debt profile sees every family any platform's engine reported
        # a candidate for.
        agg_surface: set[str] = set()
        agg_ctx_coverage: set[str] = set()
        for r in reports:
            agg_surface |= getattr(r, "families_with_surface", set())
            agg_ctx_coverage |= getattr(r, "families_with_ctx_coverage", set())
        score_report = compute_score(
            all_findings,
            files_scanned=total_files,
            platforms_scanned=_platforms_for_reports(*reports),
            # No config files found (empty repo / no CI/CD) → "not scored"
            # rather than a fabricated 100/100. Findings can only come from
            # scanned files here, so total_files is the authoritative signal.
            scanned_config=total_files > 0,
            families_with_surface=agg_surface,
            families_with_ctx_coverage=agg_ctx_coverage,
        )

    # JSON format with multiple reports needs a wrapper to stay
    # well-formed.  Without it, ``--format json`` on a multi-platform
    # repo (e.g. GH workflows + Jenkinsfile) emitted two concatenated
    # top-level objects: invalid JSON, breaking ``json.load`` / ``jq``
    # and the docs/AI_TRIAGE.md paste-ready prompt that assumes a
    # parseable document.  Single-platform output is unchanged for
    # backwards compatibility; multi-platform wraps in
    # ``{"reports": [...]}``.
    if args.format == "json" and len(reports) > 1:
        for report in reports:
            _print_engine_errors_to_stderr(report)
        wrapped = {
            "reports": [
                json.loads(format_json(report, score_report=score_report)) for report in reports
            ],
        }
        print(json.dumps(wrapped, indent=2))
    elif args.format == "csv" and len(reports) > 1:
        from .reporters.csv_report import format_csv_reports

        for report in reports:
            _print_engine_errors_to_stderr(report)
        print(format_csv_reports(reports))
    elif args.format == "sarif" and len(reports) > 1:
        for report in reports:
            _print_engine_errors_to_stderr(report)
        print(format_sarif_reports(reports))
    else:
        for report in reports:
            _output_report(report, args, score_report=score_report)

    if score_report is not None and args.format == "text":
        print(format_score(score_report, use_color=not args.no_color))

    if args.baseline:
        # Accepting existing security debt does not waive incomplete analysis.
        sys.exit(11 if any(f.rule_id == "ENGINE-ERR" for f in all_findings) else 0)

    _exit_for_findings(all_findings, effective_fail_on, review_advisory=args.review_advisory)


def _assess_codebuild_webhook(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    from dataclasses import asdict
    from pathlib import Path

    from .ingestion.codebuild_snapshot import SnapshotError
    from .ingestion.codebuild_webhook import (
        WEBHOOK_PR_EVENTS,
        WEBHOOK_PROJECT_ID,
        WEBHOOK_SENDER_ID,
        assess_webhook_snapshot,
    )

    allowed = {
        "codebuild_webhook_snapshot",
        "codebuild_webhook_sender",
        "platform",
        "format",
        "no_color",
        "no_config",
    }
    for name, value in vars(args).items():
        if name not in allowed and value != parser.get_default(name):
            option = "the scan path" if name == "path" else "--" + name.replace("_", "-")
            parser.error(f"{option} is unavailable in CodeBuild webhook assessment mode")
    if args.platform not in (None, "codebuild") or args.format not in ("text", "json"):
        parser.error(
            "CodeBuild webhook assessment requires the codebuild platform and text or JSON"
        )

    snapshot, project_id, origin, event = args.codebuild_webhook_snapshot
    sender = args.codebuild_webhook_sender
    if not WEBHOOK_PROJECT_ID.fullmatch(project_id):
        parser.error("CodeBuild webhook assessment requires a regional public project alias digest")
    if event not in WEBHOOK_PR_EVENTS:
        parser.error("CodeBuild webhook assessment requires a supported GitHub PR event")
    if sender is not None and not WEBHOOK_SENDER_ID.fullmatch(sender):
        parser.error("CodeBuild webhook assessment requires a numeric webhook sender ID")

    scope = (
        "Saved webhook filters for the supplied event and sender. Capture authenticity, "
        "approval, actual execution and effective publication permissions are unverified."
    )
    try:
        assessment = assess_webhook_snapshot(Path(snapshot), project_id, origin, event, sender)
    except SnapshotError as exc:
        decision = None
        result = {
            "project_id": project_id,
            "event": event,
            "sender_id": sender,
            "filter_outcome": "unresolved",
            "reason": str(exc),
        }
    else:
        decision = assessment
        result = asdict(decision)

    if args.format == "json":
        print(
            json.dumps(
                {
                    "codebuild_webhook": {
                        **result,
                        "scope": scope,
                        "approval": "unverified",
                        "execution": "unverified",
                        "publication_authority": "unverified",
                    }
                },
                indent=2,
            )
        )
    else:
        print(f"CodeBuild webhook filters: {result['filter_outcome']}\n{scope}")
        print(f"Project identity: {project_id}\nEvent: {event}\nSender: {sender or 'unknown'}")
        if decision is None:
            print(result["reason"])
        else:
            print(f"Project: {result['project_name']} ({result['repository']})")
            print(f"Observed: {result['observed_at']}")
            for group in decision.groups:
                group_status = (
                    "unknown" if group.matches is None else "match" if group.matches else "miss"
                )
                print(f"  Group {group.index}: {group_status}")
                for check in group.filters:
                    status = (
                        "unknown" if check.matches is None else "match" if check.matches else "miss"
                    )
                    print(
                        f"  Group {group.index}, filter {check.index} ({check.kind}): {status}. {check.reason}"
                    )
    sys.exit(11 if result["filter_outcome"] == "unresolved" else 0)


def _check_jenkins_incrementals(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    from pathlib import Path

    from .ingestion.jenkins_incrementals import incrementals_observation

    mode = "jenkins_incrementals_observation"
    allowed = {"path", mode, "platform", "format", "no_config", "no_color"}
    for name, value in vars(args).items():
        if name not in allowed and value != parser.get_default(name):
            parser.error(f"--{name.replace('_', '-')} is unavailable in Jenkins observation mode")
    if args.platform not in (None, "jenkins") or args.format not in ("text", "json"):
        parser.error(
            "Jenkins observation mode requires the jenkins platform and text or JSON format"
        )
    snapshot, repository, pr, check = args.jenkins_incrementals_observation
    if any(
        not value.isascii() or not value.isdecimal() or len(value) > 19 for value in (pr, check)
    ):
        parser.error("Jenkins observation mode requires decimal PR and Jenkins check IDs")
    result = incrementals_observation(
        Path(snapshot), Path(args.path), repository, int(pr), int(check)
    )
    resolved = result["state"] == "publication-observed"
    if args.format == "json":
        print(json.dumps({mode: result}, indent=2))
    elif resolved:
        publication = result["publication"]
        print(
            f"Saved evidence corroborates an Incrementals publication for "
            f"{result['repository']} PR #{result['pr']}, revision {result['head']}.\n"
            f"  Registry writer: {publication['registry_actor']}.\n"
            f"  Object: {publication['object_url']}\n  SHA-256: {publication['sha256']}\n"
            f"  Jenkins reported a successful PR job at {result['jenkins']['job_url']}.\n"
            f"{result['scope']}"
        )
    else:
        print(f"Jenkins publication unresolved: {result['reason']}.\n{result['scope']}")
    sys.exit(0 if resolved else 11)


def _check_jenkins_maven_snapshot(
    parser: argparse.ArgumentParser, args: argparse.Namespace
) -> None:
    from pathlib import Path

    from .ingestion.jenkins_maven_snapshot import maven_snapshot_observation

    mode = "jenkins_maven_snapshot_observation"
    allowed = {"path", mode, "platform", "format", "no_config", "no_color"}
    for name, value in vars(args).items():
        if name not in allowed and value != parser.get_default(name):
            parser.error(
                f"--{name.replace('_', '-')} is unavailable in Maven snapshot observation mode"
            )
    if args.platform not in (None, "jenkins") or args.format not in ("text", "json"):
        parser.error(
            "Maven snapshot observation mode requires the jenkins platform and text or JSON format"
        )
    repo, pr, job, target = args.jenkins_maven_snapshot_observation
    if not pr.isascii() or not pr.isdecimal() or not 1 <= len(pr) <= 12:
        parser.error("Maven snapshot observation mode requires a decimal PR ID")
    result = maven_snapshot_observation(Path(args.path), repo, int(pr), job, target)
    resolved = result["state"] in {
        "snapshot-write-observed",
        "upstream-checkout-observed",
        "remote-publisher-excluded",
        "remote-matrix-publisher-skipped",
        "remote-shared-library-publisher-excluded",
    }
    comparison = result.get("comparison", {})
    registry_record = comparison.get("registry_record", {})
    incomplete_comparison = "unresolved" in (comparison.get("state"), registry_record.get("state"))
    credential_selection = result.get("maven_credential_selection")
    credential_details = ""
    if (
        credential_selection
        and credential_selection["state"] == "authentication-selection-reported"
    ):
        credential_details = (
            f"  Maven log reports authentication for {credential_selection['server_id']} at "
            f"{credential_selection['repository_url']} (node log line {credential_selection['line']}).\n"
            "  Jenkins credential identity and wider permissions remain unresolved.\n"
        )
    elif credential_selection:
        credential_details = (
            f"  Maven authentication selection unresolved: {credential_selection['reason']}.\n"
        )
    workspace_allocation = result.get("workspace_allocation")
    if workspace_allocation and workspace_allocation["state"] == "controller-allocation-correlated":
        credential_details += (
            f"  Jenkins assigned agent {workspace_allocation['agent']} "
            f"and workspace {workspace_allocation['workspace']} "
            f"(allocation node {workspace_allocation['allocation_node']}).\n"
        )
    elif workspace_allocation:
        credential_details += (
            f"  Jenkins workspace allocation unresolved: {workspace_allocation['reason']}.\n"
        )
    if args.format == "json":
        print(json.dumps({mode: result}, indent=2))
    elif result["state"] == "remote-matrix-publisher-skipped":
        remote = result["remote_publisher"]
        source = result["source"]
        stash = result["stash"]
        print(
            f"Jenkins PR #{result['pr']} reported {stash['reported_restores']} restores of "
            f"stash {stash['name']} from node {stash['producer_node']}.\n"
            f"  All {len(remote['stage_ids'])} Deploy stages were skipped by their conditions.\n"
            f"  The loaded definition requires {remote['condition']} ({source['path']}:{source['line']}).\n"
            f"  Candidate snapshot repository: {remote['candidate_repository']}.\n{result['scope']}"
        )
        if comparison.get("state") == "deploy-command-observed":
            print(
                f"  Main comparison: Maven deploy command observed in node {comparison['node']} at {comparison['job']}."
            )
        if registry_record.get("state") == "same-window-stored-record":
            print(
                f"  Nexus records {registry_record['recorded_writer']} for a matching module and version "
                f"during that command's time window. Run-to-object attribution is unverified."
            )
        if incomplete_comparison:
            print(
                f"  Comparison unresolved: {registry_record.get('reason') or comparison['reason']}."
            )
    elif result["state"] == "remote-shared-library-publisher-excluded":
        remote = result["remote_publisher"]
        library = result["library"]
        print(
            f"Jenkins PR #{result['pr']} checked out {result['checkout']} and ran Maven verify "
            f"(node {result['node']}).\n"
            f"  The remote publisher requires {remote['required_branch']}. "
            f"The selected {result['branch']} run has no {remote['stage']} stage.\n"
            f"  Guard: {library['repository']}@{library['revision']} "
            f"{library['path']}:{library['line']}.\n"
            f"  Configured destination: {remote['target']}.\n{result['scope']}"
        )
    elif result["state"] == "remote-publisher-excluded":
        remote = result["remote_publisher"]
        print(
            f"Jenkins PR #{result['pr']} ran Maven against "
            f"{result['local_staging']['destination']} (node {result['node']}).\n"
            f"  The configured remote publisher stage was absent. "
            f"Its guard requires {remote['required_branch']}. The job ran {result['branch']}.\n"
            f"  The configured destination was {remote['target']}.\n"
            f"{result['scope']}\n{result['review_action']}"
        )
    elif result["state"] == "upstream-checkout-observed":
        checkout = result["checkout"]
        artifact = result["snapshot_evidence"]
        print(
            f"Maven in {result['repository']} PR #{result['pr']} used the reported upstream "
            f"checkout {checkout['revision']} ({checkout['ref']}).\n"
            f"  PR head: {result['head']}.\n"
            f"  Jenkins job: {result['job']} (node {result['node']}).\n"
            f"{credential_details}"
            f"  Matching snapshot bytes: {artifact['object_url']} ({artifact['sha256']}).\n"
            f"{result['scope']}"
        )
    elif resolved:
        publication = result["publication"]
        source = result["source"]
        failed_run_details = (
            "  Jenkins reported overall FAILURE. The selected Maven deployment node succeeded.\n"
            if result.get("jenkins_run_result") == "FAILURE"
            else ""
        )
        print(
            f"Saved evidence corroborates a Maven snapshot write from {result['repository']} PR "
            f"#{result['pr']}, revision {result['head']}.\n"
            f"  Command: {result['command']} ({source['path']}:{source['line']}).\n"
            f"  Jenkins job: {result['job']} (node {result['node']}).\n"
            f"{failed_run_details}{credential_details}"
            f"  Nexus writer: {publication['registry_actor']}.\n"
            f"  Object: {publication['object_url']}\n  SHA-256: {publication['sha256']}\n"
            f"{result['scope']}\n{result['review_action']}"
        )
    elif "requested_snapshot" in result:
        source = result["source"]
        revision = result["checkout"]["revision"]
        checkout_summary = (
            f"fork checkout {revision}."
            if revision == result["head"]
            else f"upstream checkout {revision} instead of PR head {result['head']}."
        )
        print(
            f"Maven in {result['repository']} PR #{result['pr']} used the reported {checkout_summary}\n"
            f"  The Jenkins run ended with {result['jenkins_run_result']}. "
            f"The selected Maven node {result['node']} completed successfully.\n"
            f"  Command: {result['command']} ({source['path']}:{source['line']}).\n"
            f"{credential_details}"
            f"  Jenkins archive: {result['jenkins_artifact']} ({result['jenkins_archive_sha256']}).\n"
            f"  Requested snapshot: {result['requested_snapshot']}.\n"
            f"Maven snapshot write unresolved: {result['reason']}.\n{result['scope']}"
        )
    elif "snapshot_evidence" in result:
        snapshot = result["snapshot_evidence"]
        source = result["source"]
        print(
            f"Maven in {result['repository']} PR #{result['pr']} used the reported fork "
            f"checkout {result['head']}.\n"
            f"  Command: {result['command']} ({source['path']}:{source['line']}).\n"
            f"  Jenkins job: {result['job']} (node {result['node']}).\n"
            f"{credential_details}"
            f"  Matching snapshot bytes: {snapshot['object_url']} ({snapshot['sha256']}).\n"
            f"Maven snapshot write unresolved: {result['reason']}.\n{result['scope']}"
        )
    else:
        print(f"Maven snapshot write unresolved: {result['reason']}.\n{result['scope']}")
    sys.exit(0 if resolved and not incomplete_comparison else 11)


def _check_gitlab_fork_admission(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    from taintly.ingestion.gitlab_fork_admission import fork_admission_observation

    mode = "gitlab_fork_admission_observation"
    allowed = {"path", mode, "platform", "format", "no_config", "no_color"}
    for name, value in vars(args).items():
        if name not in allowed and value != parser.get_default(name):
            parser.error(f"--{name.replace('_', '-')} is unavailable in GitLab fork admission mode")
    if args.platform not in (None, "gitlab") or args.format not in ("text", "json"):
        parser.error("GitLab fork admission mode requires gitlab and text or JSON format")
    snapshot, project, pipeline = args.gitlab_fork_admission_observation
    if any(
        not value.isascii() or not value.isdecimal() or len(value) > 18
        for value in (project, pipeline)
    ):
        parser.error("GitLab fork admission mode requires decimal project and pipeline IDs")
    report = fork_admission_observation(Path(snapshot), int(project), int(pipeline))
    unresolved = report["state"] == "unresolved"
    if args.format == "json":
        print(json.dumps({mode: report}, indent=2))
    elif unresolved:
        print(f"GitLab fork admission unresolved: {report['reason']}.\n{report['scope']}")
    else:
        print(
            f"GitLab fork pipeline {report['pipeline']} stopped before any job.\n"
            f"  {report['repository']} at {report['revision']} for MR !{report['mr']} "
            f"in target project {report['target_project']}.\n"
            "  GitLab reported a user verification requirement. No archive upload was reached.\n"
            f"{report['scope']}"
        )
    sys.exit(11 if unresolved else 0)


def _check_gitlab_mr_artifact(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    from .ingestion.gitlab_mr_artifact import mr_artifact_observation

    mode = "gitlab_mr_artifact_observation"
    allowed = {
        "path",
        mode,
        "platform",
        "format",
        "no_config",
        "no_color",
        "gitlab_mr_publish_job",
        "gitlab_artifact_origin",
    }
    for name, value in vars(args).items():
        if name not in allowed and value != parser.get_default(name):
            parser.error(f"--{name.replace('_', '-')} is unavailable in GitLab observation mode")
    if args.platform not in (None, "gitlab") or args.format not in ("text", "json"):
        parser.error("GitLab observation mode requires gitlab and text or JSON format")
    snapshot, project, pipeline, job = args.gitlab_mr_artifact_observation
    if any(
        not value.isascii() or not value.isdecimal() or len(value) > 18
        for value in (project, pipeline, job)
    ):
        parser.error("GitLab observation mode requires decimal project, pipeline and job IDs")
    report = mr_artifact_observation(
        Path(snapshot),
        Path(args.path),
        int(project),
        int(pipeline),
        int(job),
        publisher=args.gitlab_mr_publish_job,
        origin=args.gitlab_artifact_origin,
    )
    state = report["state"]
    admission = report.get("publication_admission")
    preview = report.get("pages_preview")
    preview_account = preview.get("account") if preview is not None else None
    archive_download = report.get("archive_download")
    archive_authority = report.get("archive_runner_authority")
    member_origin = report.get("archive_member_origin")
    handoff = report.get("pages_handoff")
    pages_publication = report.get("pages_publication")
    pages_authority = (
        pages_publication.get("archive_runner_authority") if pages_publication else None
    )
    if args.format == "json":
        print(json.dumps({mode: report}, indent=2))
    elif state == "job-artifact-observed":
        publication = report["publication"]
        print(
            f"GitLab job {report['job']} built a target-project merge of fork MR !{report['mr']}.\n"
            f"  Pipeline {report['pipeline']} checked out merged revision {report['revision']}.\n"
            f"  Fork head: {report['fork_head']}.\n"
            f"  {report['source_path']}:{report['command_line']}: {report['command']}\n"
            f"  Managed artifact: {publication['target']}\n"
            f"  SHA-256: {publication['sha256']}\n{report['scope']}\n{report['review_action']}"
        )
    elif state == "job-artifact-accepted-canceled-job":
        publication = report["publication"]
        print(
            f"GitLab job {report['job']} is recorded as canceled. "
            f"The coordinator accepted its archive in {report['upload_phase']} (HTTP 201).\n"
            f"  Fork MR !{report['mr']}, pipeline {report['pipeline']}, "
            f"checkout {report['revision']}.\n"
            f"  Job archive target: {publication['target']}\n{report['scope']}"
        )
    elif state == "target-project-head-archive-accepted-canceled-job":
        publication = report["publication"]
        print(
            f"GitLab job {report['job']} in {report['repository']} is recorded as canceled. "
            f"The coordinator accepted its archive in {report['upload_phase']} (HTTP 201).\n"
            f"  MR !{report['mr']}, pipeline {report['pipeline']}, "
            f"checkout {report['revision']} from fork {report['source_repository']}.\n"
            f"  Job archive target: {publication['target']}\n{report['scope']}"
        )
    elif state == "target-project-head-archive-upload-observed":
        publication = report["publication"]
        print(
            f"GitLab accepted the archive for job {report['job']} "
            f"in target project {report['repository']} (HTTP 201).\n"
            f"  MR !{report['mr']}, pipeline {report['pipeline']}, "
            f"checkout {report['revision']} from fork {report['source_repository']}.\n"
            f"  Job archive target: {publication['target']}\n{report['scope']}"
        )
    elif state == "fork-project-archive-upload-observed":
        publication = report["publication"]
        historical = report.get("historical_pipeline")
        source_reference = (
            f"  Saved detached pipeline: {historical['url']}\n"
            f"  Recorded current MR head: {historical['current_mr_head']}\n"
            if historical is not None
            else ""
        )
        upload_label = (
            f"archive in {report['upload_phase']}"
            if report["job_status"] == "success"
            else "failure-path archive"
        )
        print(
            f"GitLab accepted the {upload_label} for job {report['job']} "
            f"in fork {report['repository']} (HTTP 201).\n"
            f"  MR !{report['mr']} targets {report['target_repository']}. "
            f"Fork pipeline {report['pipeline']} checked out {report['revision']}.\n"
            f"{source_reference}"
            f"  Fork job archive target: {publication['target']}\n{report['scope']}"
        )
    elif state == "job-artifact-uploaded-after-failure":
        publication = report["publication"]
        print(
            f"GitLab job {report['job']} checked out merged-result revision {report['revision']} "
            f"for fork MR !{report['mr']}.\n"
            f"  The runner logged {report['command']} in the failed job. "
            f"The coordinator accepted its failure-path archive (HTTP 201).\n"
            f"  Retrieved member: {publication['target']}\n"
            f"  SHA-256: {publication['sha256']}\n{report['scope']}"
        )
    elif state in ("registry-image-push-observed", "registry-image-push-reported"):
        operation, source = report["operation"], report["configured"]
        print(
            f"GitLab runner reports pushing {operation['target']} "
            f"at {operation['reported_digest']}.\n"
            f"  MR !{report['mr']}, pipeline {report['pipeline']}, job {report['job']} "
            f"({report['job_status']}), checkout {report['revision']}.\n"
            f"  Source: {source['path']}:{source['push_line']}; "
            f"Dockerfile: {source['dockerfile']}.\n"
            f"  Registry digest confirmation: {operation['registry_confirmation']}.\n"
            f"{report['scope']}"
        )
    elif state == "manual-job-not-started":
        print(
            f"GitLab job {report['job']} remained unstarted on its manual fallback.\n"
            f"  The guard excludes this fork when evaluated using the recorded project IDs "
            f"({report['source_path']}:{report['guard_line']}).\n"
            f"Manual start permission is unverified.\n{report['scope']}"
        )
    else:
        print(f"GitLab observation unresolved: {report['reason']}.\n{report['scope']}")
    if admission is not None and args.format == "text":
        if admission["state"] == "publish-job-absent":
            print(
                f"  npm publisher {admission['job_name']} is absent from pipeline {report['pipeline']}.\n"
                f"  Matching archived file: {admission['matching_archive']}.\n"
                f"  Local npm command at {report['source_path']}:{admission['command_line']}. "
                f"OIDC audience: {admission['configured_oidc_audience']}.\n"
                f"{admission['scope']}"
            )
        else:
            print(f"npm job admission unresolved: {admission['reason']}.")
    if preview is not None and args.format == "text":
        if preview["state"] == "pages-preview-deployment-recorded":
            print(
                f"GitLab records preview deployment {preview['deployment_id']} "
                f"for the selected job at {preview['target']}.\n"
                f"  Environment {preview['environment_id']}: {preview['environment_state']}. "
                f"Source: {report['source_path']}:{preview['source_line']}.\n{preview['scope']}"
            )
            if preview_account is not None:
                if preview_account["state"] == "deployment-account-recorded":
                    print(
                        f"  GitLab recorded account {preview_account['account_id']} "
                        "on this deployment and its job.\n"
                        f"{preview_account['scope']}"
                    )
                else:
                    print(f"Pages deployment account unresolved: {preview_account['reason']}.")
        else:
            print(f"Pages preview unresolved: {preview['reason']}.")
    if archive_download is not None and args.format == "text":
        if archive_download["state"] != "unresolved":
            print(f"  Retrieved ZIP SHA-256: {archive_download['sha256']}.")
        else:
            archive_label = (
                "Target-project archive"
                if state == "target-project-head-archive-upload-observed"
                else "Fork archive"
            )
            print(f"{archive_label} retrieval unresolved: {archive_download['reason']}.")
    if member_origin is not None and args.format == "text":
        if member_origin["state"] == "fork-source-display-matched":
            print(
                f"  Coverage ZIP member: {member_origin['member']}.\n"
                f"  Displayed {member_origin['path']} matches the recorded fork checkout "
                f"{member_origin['revision']}. The parent {member_origin['parent']} differs.\n"
                f"{member_origin['scope']}"
            )
        else:
            print(f"Fork archive source comparison unresolved: {member_origin['reason']}.")
    if archive_authority is not None and args.format == "text":
        if archive_authority["state"] == "native-archive-write-observed":
            print(
                f"  Runner job token used for POST {archive_authority['route']} "
                f"(HTTP {archive_authority['http_status']}).\n"
                f"  Archive response: {archive_authority['correlation_id']} "
                f"(runner log line {archive_authority['archive_response_line']}).\n"
                f"{archive_authority['scope']}"
            )
        else:
            print(f"GitLab archive runner authority unresolved: {archive_authority['reason']}.")
    if handoff is not None and args.format == "text":
        if handoff["state"] == "upstream-pages-handoff-observed":
            print(
                f"  Fork pipeline {report['pipeline']} had no job named pages in its saved inventory.\n"
                f"  Upstream Pages job {handoff['pages_job']} downloaded the archive from "
                f"job {handoff['artifact_producer_job']} in pipeline {handoff['upstream_pipeline']}.\n"
                f"  Pages uploaded its own archive (HTTP 201). "
                f"{handoff['matched_members']} website members match.\n{handoff['scope']}"
            )
        else:
            print(f"GitLab Pages handoff unresolved: {handoff['reason']}.")
    if pages_publication is not None and args.format == "text":
        if pages_publication["state"] == "post-merge-pages-publication-observed":
            print(
                f"  A separate push after the merge ran Pages job {pages_publication['pages_job']}.\n"
                f"  Pages downloaded the archive from job {pages_publication['source_job']} "
                f"in pipeline {pages_publication['upstream_pipeline']}.\n"
                f"  {pages_publication['move']['command']} (runner log line "
                f"{pages_publication['move']['trace_line']}).\n"
                f"  {len(pages_publication['members'])} public responses match the selected archive "
                f"members at {pages_publication['publication']['target']}.\n"
                f"{pages_publication['scope']}"
            )
        else:
            print(f"GitLab Pages publication unresolved: {pages_publication['reason']}.")
    if pages_authority is not None and args.format == "text":
        if pages_authority["state"] == "native-archive-write-observed":
            print(
                f"  Pages runner job token used for POST {pages_authority['route']} "
                f"(HTTP {pages_authority['http_status']}, runner log line "
                f"{pages_authority['archive_response_line']}).\n{pages_authority['scope']}"
            )
        else:
            print(f"GitLab Pages archive runner authority unresolved: {pages_authority['reason']}.")
    incomplete = state in {"unresolved", "registry-image-push-reported"} or any(
        item is not None and item["state"] == "unresolved"
        for item in (
            admission,
            preview,
            preview_account,
            archive_download,
            member_origin,
            archive_authority,
            handoff,
            pages_publication,
            pages_authority,
        )
    )
    sys.exit(11 if incomplete else 0)


def _assess_codebuild_s3(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    from pathlib import Path

    from .ingestion.codebuild_s3 import codebuild_s3_observation

    allowed = {
        "path",
        "codebuild_public_s3_observation",
        "platform",
        "format",
        "no_config",
        "no_color",
    }
    for name, value in vars(args).items():
        if name not in allowed and value != parser.get_default(name):
            parser.error(
                f"--{name.replace('_', '-')} is unavailable in CodeBuild S3 observation mode"
            )
    if args.platform not in (None, "codebuild") or args.format not in ("text", "json"):
        parser.error("CodeBuild S3 observation requires codebuild and text or JSON format")
    capture, build_arn, origin = args.codebuild_public_s3_observation
    result = codebuild_s3_observation(Path(capture), Path(args.path), build_arn, origin)
    comparison = result.get("policy_comparison")
    if args.format == "json":
        print(json.dumps({"codebuild_s3_observation": result}, indent=2))
    elif result["state"] in ("direct-s3-write-observed", "direct-s3-write-denied"):
        publication = result["publication"]
        outcome = (
            "wrote"
            if result["state"] == "direct-s3-write-observed"
            else "was denied access to write"
        )
        print(f"CodeBuild {result['build']} {outcome} {publication['object_arn']}.")
        print(f"  S3 operation: {publication['operation']}.")
        if "input_object" in result:
            supplied = result["input_object"]
            influence = result["influence"]
            print(
                f"  Selected input ZIP: {supplied['object_arn']} (version {supplied['version']})."
            )
            print(
                f"  Input file {influence['path']} matches {result['repository']} "
                f"at {influence['revision']}."
            )
        else:
            print(
                f"  Source {result['repository']} at {result['head']}, file {result['influence']['path']}."
            )
        if "pull_request" in result:
            print(
                f"  GitHub PR #{result['pull_request']} head repository: {result['head_repository']}."
            )
        print(f"  Build role: {publication['service_role']}.")
        if "launch" in result:
            launch = result["launch"]
            print(
                f"  CloudTrail StartBuild caller: {launch['actor']} (event {launch['event_id']})."
            )
        if publication["audit"] == "unresolved-version-binding":
            print("  CloudTrail did not identify the observed S3 object version.")
        else:
            print(f"  Independent S3 data event: {publication['audit']}.")
        if publication["acting_session"] == "unverified":
            print("  S3 request actor: unverified.")
            print(f"  Runner-reported STS session: {result['reported_sts_session']}.")
        else:
            print(
                f"  S3 request actor: {publication['acting_session']} (bound to the S3 data event)."
            )
        source_plan = result.get("source_plan", {})
        workspace = source_plan.get("workspace")
        if workspace is not None:
            print(f"  CodeBuild recorded entry into source workspace {workspace}.")
        reported_shell = source_plan.get("reported_shell")
        if reported_shell is not None:
            print(f"  CodeBuild reported selecting {reported_shell} for the inline buildspec.")
        transport = publication.get("transport", {})
        if "http_status" in transport:
            print(f"  Reported S3 HTTP status: {transport['http_status']}.")
        if publication.get("denial_reason") == "explicit-resource-policy-deny":
            print("  AWS reported an explicit deny in a resource-based policy.")
        if "runtime_credential" in publication:
            print("  CloudTrail ties the build's STS identity call to the same S3 credential.")
        if "workspace_identity" in result:
            print("  The workspace STS event identifies the workspace session only.")
        if comparison is not None:
            if comparison["state"] == "unresolved":
                print(f"  Policy comparison unresolved: {comparison['reason']}.")
            else:
                event = comparison["policy_event"]
                print(
                    f"  CloudTrail PutBucketPolicy {event['event_id']} at {event['time']} "
                    "installed the matching deny between the saved builds."
                )
                if comparison["state"] == "earlier-writer-unverified":
                    print(
                        "  The earlier S3 write is observed, but its request actor is unverified."
                    )
                else:
                    print(
                        "  Independent S3 data events identify both requests under this build role."
                    )
                print(comparison["scope"])
        print(result["scope"])
    elif result["state"] == "managed-s3-link-unverified":
        print(
            f"Build {result['build']} and the retrieved ZIP are consistent with a managed upload."
        )
        print("  Exact linkage requires independent evidence for this specific object.")
        if "provider_checksum_scope" in result["publication"]:
            print("  The supplied provider checksum has unverified scope for this file.")
        print(f"  S3 object: {result['publication']['target']}")
        print(f"  Changed source in ZIP: {result['influence']['archive_member']}")
        print(result["scope"])
        print(result["next_evidence"])
    elif result["state"] == "managed-s3-zip-reported":
        publication = result["publication"]
        source = result["source_plan"]
        observation = source["command"]
        print(
            f"CodeBuild {result['build']} reported a primary S3 ZIP.\n"
            f"  Selected commit {result['head']} matches the supplied fork PR "
            f"#{result['pull_request']} head.\n"
            f"  Build status: {result['build_status']}. Upload phase: SUCCEEDED.\n"
            f"  Reported command: {observation['text']} ({source['path']}:{observation['line']}).\n"
            f"  Primary paths selected: {publication['primary_paths_reported']}.\n"
            f"  Reported object: {publication['object_arn']}\n"
            f"  CodeBuild-reported ZIP SHA-256: {publication['provider_reported_sha256']}\n"
            f"{result['scope']}\n{result['next_evidence']}"
        )
    elif result["state"] == "primary-artifact-paths-unmatched":
        print(f"CodeBuild {result['build']} reported no matches for its primary S3 artifact paths.")
        print(
            f"  Selected source: {result['repository']} {result['source_ref']} ({result['head']})."
        )
        for selector in result["source_plan"]["artifact_selectors"]:
            print(f"  Inline buildspec line {selector['line']}: {selector['path']}")
        print(f"  CodeBuild-reported directory: {result['publication']['directory_arn']}")
        print(result["scope"])
    else:
        print(f"CodeBuild S3 observation unresolved: {result['reason']}")
        print(result["scope"])
    complete = result["state"] in ("direct-s3-write-observed", "direct-s3-write-denied")
    if comparison is not None:
        complete = complete and comparison["state"] == "matched-policy-change"
    sys.exit(0 if complete else 11)


def _assess_codebuild_deploy(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    from pathlib import Path

    from .ingestion.codebuild_deploy import codebuild_deploy_observation

    allowed = {
        "path",
        "codebuild_public_deploy_observation",
        "platform",
        "format",
        "no_config",
        "no_color",
    }
    for name, value in vars(args).items():
        if name not in allowed and value != parser.get_default(name):
            parser.error(
                f"--{name.replace('_', '-')} is unavailable in CodeBuild deployment observation mode"
            )
    if args.platform not in (None, "codebuild") or args.format not in ("text", "json"):
        parser.error("CodeBuild deployment observation requires codebuild and text or JSON format")
    capture, build_id, origin = args.codebuild_public_deploy_observation
    result = codebuild_deploy_observation(Path(capture), Path(args.path), origin, build_id)
    resolved = result["state"] == "guard-skip-reported"
    if args.format == "json":
        print(json.dumps({"codebuild_deploy_observation": result}, indent=2))
    elif resolved:
        print(
            f"Build {result['build']} has saved records consistent with a configured deployment skip for {result['pull_request_ref']}."
        )
        print(f"  Source: {result['source']['path']}:{result['source']['line']}")
        for operation in result["configured_operations"]:
            print(
                f"  Guarded operation in committed script: {operation['operation']} -> {operation['target']}"
            )
        print(result["scope"])
    else:
        print(f"CodeBuild deployment observation unresolved: {result['reason']}")
        print(result["scope"])
    sys.exit(0 if resolved else 11)


def _assess_codebuild_start(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    from pathlib import Path

    from .ingestion.codebuild_start import codebuild_start_observation

    allowed = {"path", "codebuild_start_observation", "platform", "format", "no_config", "no_color"}
    for name, value in vars(args).items():
        if name not in allowed and value != parser.get_default(name):
            parser.error(
                f"--{name.replace('_', '-')} is unavailable in CodeBuild start observation mode"
            )
    if args.platform not in (None, "codebuild") or args.format not in ("text", "json"):
        parser.error(
            "CodeBuild start observation mode requires the codebuild platform and text or JSON format"
        )
    capture, origin, run, job = args.codebuild_start_observation
    if any(not value.isascii() or not value.isdecimal() or len(value) > 19 for value in (run, job)):
        parser.error("CodeBuild start observation mode requires decimal run and job IDs")
    result = codebuild_start_observation(Path(capture), Path(args.path), origin, int(run), int(job))
    state = result["state"]
    if args.format == "json":
        print(json.dumps({"codebuild_start_observation": result}, indent=2))
    elif state == "starts-observed":
        print(
            f"Saved run {result['run']}, job {result['job']} reports CodeBuild starts for {result['pull_request_ref']}."
        )
        for build in result["builds"]:
            print(f"  {build['build_id']} selected {build['revision']} using {build['buildspec']}.")
            request = build["start_request"]
            print(
                f"    Launcher requests {request['project']} in {request['region']} for "
                f"{request['source_version']} ({result['caller']['launcher']['path']}:"
                f"{request['launcher_line']})."
            )
            if build["provider_build_arn"] is None:
                print("    The saved provider response did not include a build ARN.")
            for copy in build["configured_publication"]:
                print(
                    f"    Configured Nix cache copy to {copy['bucket']}: object write unverified."
                )
                if copy["reported_nix_paths"] is not None:
                    print(
                        f"    The saved command output reports {copy['reported_nix_paths']} Nix paths to copy."
                    )
            if publication_limit := build.get("publication_analysis_limit"):
                print(f"    Publication unresolved. {publication_limit}")
        print(result["scope"])
        print(result["review"])
    elif state == "automatic-start-blocked":
        print(
            f"Saved run {result['run']}, job {result['job']} records the PR guard stopping automatic CodeBuild start."
        )
        print(result["scope"])
    else:
        print(f"CodeBuild start unresolved: {result['reason']}.\n{result['scope']}")
    sys.exit(11 if state == "unresolved" else 0)


def _check_github_observation(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    from pathlib import Path

    from .ingestion.github_preview import preview_observation

    mode = next(
        name
        for name in (
            "github_preview_observation",
            "github_version_upload_observation",
            "github_release_observation",
            "github_pages_observation",
            "github_release_request_observation",
        )
        if getattr(args, name)
    )
    allowed = {"path", mode, "platform", "format", "no_config", "no_color"}
    for name, value in vars(args).items():
        if name not in allowed and value != parser.get_default(name):
            parser.error(f"--{name.replace('_', '-')} is unavailable in GitHub observation mode")
    if args.platform not in (None, "github") or args.format not in ("text", "json"):
        parser.error("GitHub observation mode requires the github platform and text or JSON format")
    snapshot, repository, first, second = getattr(args, mode)
    if any(
        not value.isascii() or not value.isdecimal() or len(value) > 19 for value in (first, second)
    ):
        parser.error("GitHub observation mode requires two decimal IDs")
    inputs = Path(snapshot), Path(args.path), repository, int(first), int(second)
    if mode == "github_release_observation":
        from .ingestion.github_release_observation import release_observation

        result = release_observation(*inputs)
    elif mode == "github_pages_observation":
        from .ingestion.github_pages_publication import pages_observation

        result = pages_observation(*inputs)
    elif mode == "github_release_request_observation":
        from .ingestion.github_release_request import release_request_observation

        result = release_request_observation(*inputs)
    elif mode == "github_version_upload_observation":
        from .ingestion.github_version_upload import version_upload_observation

        result = version_upload_observation(*inputs)
    else:
        result = preview_observation(*inputs)
    state = result["state"]
    artifact_authority = result.get("producer_artifact_authority")
    if args.format == "json":
        print(json.dumps({mode: result}, indent=2))
    elif state == "release-patch-comparison-reported":
        operation = result["operation"]
        print(
            f"Saved GitHub job {result['job']} reports {operation['method']} {operation['url']}.\n"
            f"  Run {result['run']}, attempt {result['attempt']}. "
            f"Job conclusion: {result['job_conclusion']}. "
            "Job setup reports GITHUB_TOKEN Contents: write."
        )
        execution = result["execution"]
        print(
            f"  Runner shell {execution['shell']} reported at job log lines "
            f"{execution['first_log_line']}-{execution['last_log_line']}."
        )
        for request in result["requests"]:
            field = request["field"] or "no fields"
            target = request["target_commitish"]
            printed_field = f"{field}={target}" if target else field
            print(
                f"  {printed_field}: HTTP {request['status']} "
                f"({result['source']['path']}:{request['source_line']}, "
                f"job log line {request['response_line']})."
            )
        print(result["scope"])
    elif state in ("reusable-draft-dry-run-reported", "reusable-draft-write-reported"):
        operation = result["operation"]
        invocation = result["reusable_invocation"]
        called = invocation["source"]
        grant = result["effective_permission"]
        outcome = (
            "dry-run before draft creation"
            if state == "reusable-draft-dry-run-reported"
            else f"completed draft {operation['kind']}"
        )
        target_ref = operation.get("target_ref")
        selection = f" (merge ref {target_ref})" if target_ref else ""
        print(
            f"The saved reusable Release Drafter action reports {outcome} for "
            f"{operation['requested_tag']} targeting {operation['target_commitish']}{selection}.\n"
            f"  Run {result['run']}, job {result['job']}, attempt {result['attempt']}. "
            f"Runner reports GITHUB_TOKEN Contents: {grant['contents']}.\n"
            f"  Caller token binding: {result['source']['path']}:{invocation['binding_line']}. "
            f"Selected workflow: {invocation['repository']}/{called['path']} "
            f"at {called['revision']} (consumer at line {result['configured']['credential_line']}).\n"
            f"{result['scope']}"
        )
    elif state == "draft-release-create-denied":
        operation = result["operation"]
        configured = result["configured"]
        invocation = result.get("reusable_invocation")
        if invocation is None:
            source_detail = (
                f"  Fork-head source requests {configured['requested_permission']} and configures "
                f"{configured['credential_binding']} "
                f"({result['source']['path']}:{configured['credential_line']}).\n"
            )
        else:
            called = invocation["source"]
            source_detail = (
                f"  Fork-head caller passes {configured['credential_binding']} through a named input "
                f"({result['source']['path']}:{invocation['binding_line']}).\n"
                f"  The saved run selects {invocation['repository']}/{called['path']} "
                f"at {called['revision']} (consumer at line {configured['credential_line']}).\n"
            )
        grant = result.get("effective_permission")
        grant_line = (
            f"  Job setup reports {grant['credential']} Contents: {grant['contents']}.\n"
            if grant
            else ""
        )
        print(
            f"The saved GitHub check annotation reports HTTP {operation['status']} "
            f"for {operation['method']} "
            f"{operation['url']} targeting {operation['target_commitish']}.\n"
            f"  Run {result['run']}, job {result['job']}, attempt {result['attempt']}. "
            f"Job conclusion: {result['job_conclusion']}.\n"
            f"{source_detail}"
            f"{grant_line}"
            f"{result['scope']}"
        )
    elif state == "draft-release-create-rejection-reported":
        operation = result["operation"]
        configured = result["configured"]
        grant = result["effective_permission"]
        print(
            f"The saved GitHub job reports rejection of {operation['method']} "
            f"{operation['url']} for a draft targeting {operation['target_commitish']}.\n"
            f"  Run {result['run']}, job {result['job']}, attempt {result['attempt']}. "
            f"Job conclusion: {result['job_conclusion']}.\n"
            f"  Workflow requests {configured['requested_permission']} "
            f"({result['source']['path']}:{configured['permission_line']}). "
            f"Job setup reports {grant['credential']} Contents: {grant['contents']}.\n"
            f"{result['scope']}"
        )
    elif state == "draft-release-create-reported":
        operation = result["operation"]
        configured = result["configured"]
        grant = result.get("effective_permission")
        grant_text = (
            f"  Job setup reports {grant['credential']} Contents: {grant['contents']}.\n"
            if grant is not None
            else ""
        )
        tag = operation["requested_tag"]
        tag_text = f" for {tag}" if tag is not None else " (tag absent from the log)"
        permission = configured["requested_permission"]
        configured_text = (
            f"Push workflow requests {permission} and configures"
            if permission is not None
            else "Push workflow declares no Contents grant and configures"
        )
        token_input = configured.get("action_credential_input")
        token_text = (
            f"  Pinned action uses the default {token_input} input.\n" if token_input else ""
        )
        print(
            f"The saved Release Drafter log reports draft creation{tag_text} "
            f"via {operation['method']} {operation['url']} targeting {operation['target_commitish']}.\n"
            f"  Run {result['run']}, job {result['job']}, attempt {result['attempt']}.\n"
            f"  {configured_text} {configured['credential_binding']} "
            f"({result['source']['path']}:{configured['credential_line']}).\n"
            f"{token_text}"
            f"{grant_text}"
            f"{result['scope']}"
        )
    elif state == "pages-deployment-observed":
        update = result["publication"]
        deployment = result["deployment"]
        benchmark = result["benchmark_execution"]
        if benchmark["state"] == "fork-sample-observed-in-published-graph":
            benchmark_text = (
                f"  ASV reports {benchmark['benchmark']} for {benchmark['commit']}. "
                f"The published graph includes the recorded sample ({benchmark['seconds']} s).\n"
                f"  {benchmark['scope']}\n"
            )
        else:
            benchmark_text = f"  Fork benchmark sample unverified. {benchmark['reason']}.\n"
        authority_text = ""
        if authority := result.get("push_authority"):
            if authority["state"] == "push-actor-observed":
                authority_text = (
                    f"  GitHub attributes the recorded push to {authority['actor']['login']} "
                    f"(event {authority['event_id']}).\n  {authority['scope']}\n"
                )
            else:
                authority_text = f"  Push account unverified. {authority['reason']}.\n"
        print(
            f"Saved records link fork build {result['producer_run']} and archive "
            f"{result['artifact_id']} to job {result['job']}.\n"
            f"  {update['repository']} {update['target']} at {update['commit']}.\n"
            f"  {update['matched_files']} selected archive files match Git under {update['prefix']}.\n"
            f"  Historical Pages deployment {deployment['id']} succeeded at "
            f"{deployment['succeeded_at']} for {deployment['site']}.\n"
            f"{benchmark_text}{authority_text}{result['scope']}"
        )
    elif state == "pages-publication-skipped":
        print(
            f"Job {result['job']} downloaded archive {result['artifact_id']} from "
            f"fork build {result['producer_run']}.\n{result['scope']}"
        )
    elif state == "release-asset-observed":
        publication = result["publication"]
        configured = result["configured_publish"]
        pr = result["pr"]
        source = result["source"]
        print(
            f"GitHub records {publication['recorded_uploader']['login']} as uploader of "
            f"{publication['asset']} to {publication['target_repository']} at {publication['tag']}.\n"
            f"  PR #{pr['number']}, producer run {result['producer_run']}, "
            f"publishing run {result['consumer_run']}.\n"
            f"  PR head: {pr['source_repository']} at {pr['source_head']}.\n"
            f"  Publishing workflow: {source['path']}:{configured['line']} at {source['revision']}.\n"
            f"  Configured credential: {configured['credential_binding']} "
            f"({source['path']}:{configured.get('credential_line', configured['line'])}).\n"
            f"{result['scope']}"
        )
        if "review_action" in result:
            print(result["review_action"])
    elif state == "release-tag-push-observed":
        publication = result["publication"]
        configured = result["configured_publish"]
        print(
            f"GitHub records corroborate the push of {publication['ref']} to "
            f"{publication['target_repository']} before publishing run {result['consumer_run']} failed.\n"
            f"  PR #{result['pr']['number']} revision {publication['commit']}, "
            f"job {result['consumer_job']}.\n"
            f"  Git push command: {result['source']['path']}:{configured['line']}.\n"
            f"  Configured credential: {configured['credential_binding']} "
            f"({result['source']['path']}:{configured['credential_line']}).\n"
            f"{result['scope']}\n{result['review_action']}"
        )
    elif state == "preview-reported":
        build = result["producer"]
        deploy = result["consumer"]
        print(
            f"Saved records report Preview of fork PR #{result['pr']['number']} "
            f"for {result['repository']}.\n"
            f"  Run {build['run']} selected {result['artifact']['name']} "
            f"at {build['path']}:{build['upload_line']}.\n"
            f"  Run {deploy['run']} reported Worker {deploy['worker']} at "
            f"{deploy['version_url']} ({deploy['path']}:{deploy['command_line']}).\n"
            f"  Configured apiToken uses a GitHub Actions secret reference "
            f"({deploy['path']}:{deploy['credential_line']}).\n"
            f"{result['scope']}\n{result['review']}"
        )
    elif state == "version-upload-reported":
        publication = result["publication"]
        print(
            f"Saved records report Worker version {publication['version_id']} for "
            f"{publication['worker']} in run {result['run']}, job {result['job']}.\n"
            f"  {publication['command']} using the configured "
            f"{publication['credential_binding']} binding "
            f"({result['source']['path']}:{publication['command_line']}).\n{result['scope']}"
        )
    elif state == "fork-job-skipped":
        print(
            f"Run {result['run']}, job {result['job']} was skipped. "
            f"The supplied source excludes this fork "
            f"({result['source']['path']}:{result['guard_line']}).\n"
            f"The historical cause of the skip is unverified.\n{result['scope']}"
        )
    else:
        print(f"GitHub observation unresolved: {result['reason']}.\n{result['scope']}")
    if args.format == "text" and artifact_authority is not None:
        if artifact_authority["state"] == "unresolved":
            print(f"  Producer archive authority unresolved: {artifact_authority['reason']}.")
        else:
            print(
                f"  Producer job {artifact_authority['job']} uploaded archive "
                f"{artifact_authority['artifact_id']} using the run artifact service credential. "
                "The job's repository GITHUB_TOKEN was reported read-only."
            )
            print(f"  {artifact_authority['scope']}")
    unresolved = state == "unresolved" or (
        artifact_authority is not None and artifact_authority["state"] == "unresolved"
    )
    sys.exit(11 if unresolved else 0)


def _scan_codebuild_snapshot(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    """Scan a selected Git blob using the existing CodeBuild rule pack."""
    from pathlib import Path

    from .ingestion.codebuild_snapshot import (
        BUILD_ID,
        PROJECT_ARN,
        BoundBuildspec,
        SnapshotError,
        bind_buildspec,
        bind_public_build,
    )
    from .models import AuditReport
    from .source_inventory import SourceIssue

    allowed = {
        "path",
        "codebuild_project_snapshot",
        "codebuild_public_build",
        "platform",
        "format",
        "no_config",
        "no_color",
        "verbose",
        "min_severity",
        "fail_on",
        "review_advisory",
        "max_scan_seconds",
        "require_files",
    }
    for name, value in vars(args).items():
        if name not in allowed and value != parser.get_default(name):
            parser.error(f"--{name.replace('_', '-')} is unavailable in CodeBuild snapshot mode")
    if args.platform not in (None, "codebuild") or args.format not in ("text", "json"):
        parser.error(
            "CodeBuild snapshot mode requires the codebuild platform and text or JSON format"
        )

    bind: Callable[[Path, str, Path, str], BoundBuildspec]
    if args.codebuild_public_build:
        snapshot, subject, origin = args.codebuild_public_build
        if not BUILD_ID.fullmatch(subject):
            parser.error("CodeBuild public build mode requires a full build ID")
        bind = bind_public_build
        report_key = "codebuild_run"
        subject_key = "build_id"
        subject_label = "CodeBuild public build"
        scope = (
            "Trusted saved public build response and committed source only. "
            "Capture authenticity, AWS account, command execution, secret delivery "
            "and effective IAM are unverified."
        )
    else:
        snapshot, subject, origin = args.codebuild_project_snapshot
        if not PROJECT_ARN.fullmatch(subject):
            parser.error("CodeBuild snapshot mode requires a full project ARN")
        bind = bind_buildspec
        report_key = "codebuild_project"
        subject_key = "arn"
        subject_label = "CodeBuild project"
        scope = "Configured buildspec only. Build overrides, execution, secret delivery and effective IAM are unverified."
    report = AuditReport(repo_path=subject, platform=Platform.CODEBUILD.value)
    selection = None
    try:
        selection = bind(Path(snapshot), subject, Path(args.path).resolve(), origin)
    except (OSError, RuntimeError):
        reason = "The supplied local checkout could not be resolved"
    except SnapshotError as exc:
        reason = str(exc)
    else:
        reason = selection.analysis_limit or ""

    if reason:
        finding = SourceIssue(selection.path if selection else subject, reason).finding()
        finding.title = f"{'Buildspec scan incomplete' if selection else 'Buildspec selection unresolved'}: {reason}"
        report.add(finding)
    elif selection is not None:
        rules = load_rules_for_platform(Platform.CODEBUILD)
        if not rules or _rule_registry._IMPORT_FAILURES:
            print(
                "taintly: CodeBuild rule loading failed; cannot continue with incomplete coverage",
                file=sys.stderr,
            )
            sys.exit(3)
        report.rules_loaded = len(rules)
        report.findings.extend(
            scan_file(
                selection.path,
                rules,
                _content=selection.content,
                local_repository_available=False,
                respect_inline_suppressions=False,
                max_scan_seconds=args.max_scan_seconds,
            )
        )
        report.files_scanned = 1

    report.filter_severity(Severity[args.min_severity] if args.min_severity else Severity.INFO)
    _print_engine_errors_to_stderr(report)
    script_scope = (
        "The selected buildspec asks Bash to source these relative paths. Review "
        "whether the PR can change the script and what authority it receives. The "
        "Git blob identifies a tree entry at the selected commit. Runtime resolution "
        "depends on the working directory and filesystem state. Execution and "
        "authority are unverified."
    )
    if args.format == "json":
        data = json.loads(format_json(report))
        data[report_key] = {
            subject_key: subject,
            "selection_state": "bound" if selection else "unresolved",
            "scope": scope,
            "buildspec": {
                "repository": selection.repository,
                "commit": selection.commit,
                "path": selection.path,
                "sha256": selection.sha256,
            }
            if selection
            else None,
        }
        if selection and selection.checkout_scripts:
            data[report_key]["checkout_scripts"] = {
                "scope": script_scope,
                "pull_request_ref": selection.pull_request_ref,
                "references": [
                    {
                        "phase": item.reference.phase,
                        "command_index": item.reference.command_index,
                        "line": item.reference.line,
                        "column": item.reference.column,
                        "path": item.reference.path,
                        "git_blob": item.git_blob,
                    }
                    for item in selection.checkout_scripts
                ],
            }
        print(json.dumps(data, indent=2))
    else:
        print(f"{subject_label} {subject}\n{scope}")
        if selection:
            print(f"Buildspec: {selection.repository}@{selection.commit}:{selection.path}")
            print(f"SHA-256: {selection.sha256}")
            if selection.checkout_scripts:
                print(f"Requested source: {selection.pull_request_ref}")
                print(script_scope)
                for item in selection.checkout_scripts:
                    ref = item.reference
                    blob = item.git_blob or "regular blob unresolved"
                    print(
                        f"  {selection.path}:{ref.line}:{ref.column} "
                        f"({ref.phase}.commands[{ref.command_index}]) -> ./{ref.path} ({blob})"
                    )
        print(
            format_text(
                report, use_color=not args.no_color and sys.stdout.isatty(), verbose=args.verbose
            )
        )
    # An absent finding must not make an INFO threshold mask a source diagnostic.
    threshold = (
        Severity[args.fail_on]
        if args.fail_on and any(f.rule_id != "ENGINE-ERR" for f in report.findings)
        else None
    )
    _exit_for_findings(report.findings, threshold, review_advisory=args.review_advisory)


def _print_engine_errors_to_stderr(report) -> None:
    """Always surface ENGINE-ERR findings to stderr, regardless of
    ``--min-severity``.  An engine error means the scanner could not
    fully analyse a file (file unreadable, ReDoS cap hit, rule
    crashed) — the user must see this even if their CI gate filters
    out everything below HIGH, otherwise a green run can hide that
    no scanning happened at all.

    Errors remain in the structured report (JSON ``errors`` array,
    SARIF ``invocations[*].toolExecutionNotifications``); this is the
    human-readable channel.
    """
    seen: set[tuple[str, str]] = set()
    for f in report.engine_errors():
        key = (f.file or "", f.title)
        if key in seen:
            continue
        seen.add(key)
        loc = f"{f.file}: " if f.file else ""
        print(f"taintly: engine error: {loc}{f.title}", file=sys.stderr)


def _output_report(report, args, score_report=None):
    """Write a report to stdout in the requested format."""
    _print_engine_errors_to_stderr(report)
    if args.format == "text":
        print(
            format_text(
                report,
                use_color=not args.no_color,
                score_report=score_report,
                verbose=getattr(args, "verbose", False),
            )
        )
    elif args.format == "json":
        print(format_json(report, score_report=score_report))
    elif args.format == "csv":
        from .reporters.csv_report import format_csv

        print(format_csv(report))
    elif args.format == "sarif":
        print(format_sarif(report))
    elif args.format == "html":
        from .reporters.html_report import format_html

        print(format_html(report, score_report=score_report))


def _exit_for_severity(report, fail_on: Severity | None = None, *, review_advisory: bool = False):
    _exit_for_findings(report.findings, fail_on, review_advisory=review_advisory)


def _exit_for_findings(
    findings: list[Finding], fail_on: Severity | None, *, review_advisory: bool
) -> None:
    """Apply the exit gate separately from reporting and coverage."""
    blocking = [
        finding.severity
        for finding in findings
        if finding.rule_id != "ENGINE-ERR" and not (review_advisory and finding.review_needed)
    ]
    worst = max(blocking, default=Severity.INFO)
    if worst == Severity.CRITICAL:
        sys.exit(2)
    if worst == Severity.HIGH or (fail_on is not None and blocking and worst >= fail_on):
        sys.exit(1)
    if any(finding.rule_id == "ENGINE-ERR" for finding in findings):
        sys.exit(11)
    sys.exit(0)


if __name__ == "__main__":
    main()
