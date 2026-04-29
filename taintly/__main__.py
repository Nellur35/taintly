"""CLI entry point for taintly."""

from __future__ import annotations

import argparse
import os
import re
import sys

from . import __version__
from .baseline import (
    BASELINE_FILENAME,
    BaselineError,
    apply_diff,
    classify_diff_kind,
    format_baseline_summary,
    format_diff_summary,
    load_baseline,
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
from .engine import detect_platform, scan_file, scan_repo
from .models import Platform, Severity
from .reporters._encoding import ensure_utf8_stdout
from .reporters.csv_report import format_csv
from .reporters.html_report import format_html
from .reporters.json_report import format_json
from .reporters.sarif import format_sarif
from .reporters.score_text import format_score
from .reporters.text import format_text
from .rules.registry import load_all_rules, load_rules_for_platform
from .scorer import compute_score
from .testing.self_test import format_test_results, run_mutation_tests, run_self_test


# Map AuditReport.platform string to the Platform enum the scorer
# uses for bonus gating. Keeps the call sites readable.
_PLATFORM_LOOKUP: dict[str, Platform] = {
    "github": Platform.GITHUB,
    "gitlab": Platform.GITLAB,
    "jenkins": Platform.JENKINS,
}


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
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("path", nargs="?", default=".", help="Path to repository")
    parser.add_argument(
        "--format", "-f", choices=["text", "json", "csv", "sarif", "html"], default="text"
    )
    parser.add_argument("--no-color", action="store_true")
    parser.add_argument("--platform", choices=["github", "gitlab", "jenkins"], default=None)
    parser.add_argument(
        "--min-severity", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"], default=None
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
            "Opt-in: inject an `allowed_tools:` scaffold under any AI-agent "
            "action step (claude-code-action, run-gemini-cli, copilot-*-action, "
            "aider-action, openhands-action, coderabbit-action) that doesn't "
            "declare one.  Scaffold is deliberately restrictive (one inline-"
            "comment tool) to surface the review gate — widen the list manually "
            "to match the workflow's actual needs.  Pairs with AI-GH-020."
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
        help="Repository to target with --platform-audit (e.g. octocat/hello-world).",
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
        "--baseline",
        nargs="?",
        const=BASELINE_FILENAME,
        metavar="FILE",
        help=(
            f"Write current findings as a baseline to FILE "
            f"(default: {BASELINE_FILENAME}). "
            "Commit the baseline file to suppress these findings in future --diff scans."
        ),
    )
    parser.add_argument(
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

    if args.check_imposter_commits:
        from taintly.platform import github_sha_verify

        github_sha_verify.set_enabled(True)

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
    elif effective_platform:
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

    # Apply rule exclusions (CLI + config, merged)
    excluded = set(args.exclude_rule or []) | set(audit_config.exclude_rules)
    if args.no_taint:
        # --no-taint is a targeted off-switch for the shallow taint analysis
        # rule only.  Taint defaults to on per the v2 plan; users who find it
        # too noisy can silence just this rule without reaching for
        # --exclude-rule TAINT-GH-001.
        excluded.add("TAINT-GH-001")
    if excluded:
        all_rules = [r for r in all_rules if r.id not in excluded]

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
            mutation_results = run_mutation_tests(testable)

        print(format_test_results(self_results, mutation_results))

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
            platforms_to_fix = [
                p
                for p in (Platform.GITHUB, Platform.GITLAB, Platform.JENKINS)
                if discover_files(args.path, p)
            ]
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

        files: list[str] = []
        for plat in platforms_to_fix:
            files.extend(discover_files(args.path, plat))
        all_results = []
        for fpath in files:
            all_results.extend(apply_fixes(fpath, dry_run=dry_run, extra_fix_types=extra_fix_types))

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

            gl_client = GitLabClient(token)
            findings = gl_run(args.gitlab_project, gl_client)
            token.clear()

            report = AuditReport(repo_path=f"gitlab:{args.gitlab_project}", platform="gitlab")

        report.files_scanned = 1  # one project/repo audited
        for f in findings:
            report.add(f)
        report.filter_severity(effective_min_sev)
        report.summarize()

        score_report = (
            compute_score(report.findings, files_scanned=report.files_scanned, platforms_scanned=_platforms_for_reports(report), families_with_surface=report.families_with_surface, families_with_ctx_coverage=report.families_with_ctx_coverage)
            if (args.score or args.format == "html")
            else None
        )
        _output_report(report, args, score_report=score_report)
        if score_report is not None and args.format != "html":
            print(format_score(score_report, use_color=not args.no_color))
        _exit_for_severity(report, effective_fail_on)
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
        report.files_scanned = len(workflow_files)

        for virtual_path, content in workflow_files:
            for finding in scan_file(virtual_path, platform_rules, _content=content):
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
        report.summarize()
        score_report = (
            compute_score(report.findings, files_scanned=report.files_scanned, platforms_scanned=_platforms_for_reports(report), families_with_surface=report.families_with_surface, families_with_ctx_coverage=report.families_with_ctx_coverage)
            if (args.score or args.format == "html")
            else None
        )
        _output_report(report, args, score_report=score_report)
        if score_report is not None and args.format != "html":
            print(format_score(score_report, use_color=not args.no_color))
        _exit_for_severity(report, effective_fail_on)
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

        from .ingestion.gitlab_api import fetch_group_pipelines, list_group_projects
        from .models import AuditReport

        print(f"Fetching pipelines from group: {args.gitlab_group} ...", file=sys.stderr)
        try:
            pipeline_files = fetch_group_pipelines(args.gitlab_group, gitlab_token)
        except Exception as e:
            print(f"Error fetching group pipelines: {e}", file=sys.stderr)
            sys.exit(3)

        platform_rules = [r for r in all_rules if r.platform == Platform.GITLAB]

        report = AuditReport(repo_path=f"gitlab-group:{args.gitlab_group}", platform="gitlab")
        report.files_scanned = len(pipeline_files)

        for virtual_path, content in pipeline_files:
            for finding in scan_file(virtual_path, platform_rules, _content=content):
                report.add(finding)

        # --- Platform posture checks across all projects in the group ---
        from .platform.gitlab_checks import run_all_checks as gl_run_all_checks
        from .platform.gitlab_checks import run_group_checks
        from .platform.token import TokenManager

        print("Running platform posture checks ...", file=sys.stderr)
        try:
            projects = list_group_projects(args.gitlab_group, gitlab_token)
            tm = TokenManager(value=gitlab_token, source="GITLAB_TOKEN")
            from .platform.gitlab_client import GitLabClient

            gl_client = GitLabClient(tm)
            for proj in projects:
                proj_id = str(proj.get("id", ""))
                try:
                    for finding in gl_run_all_checks(proj_id, gl_client):
                        report.add(finding)
                except Exception:
                    continue  # nosec B112

            # Group-level checks
            for finding in run_group_checks(args.gitlab_group, gl_client):
                report.add(finding)
        except Exception as e:
            print(f"Warning: platform checks failed: {e}", file=sys.stderr)

        report.findings = apply_config_ignores(report.findings, audit_config.ignores, args.path)
        report.filter_severity(effective_min_sev)
        report.summarize()
        score_report = (
            compute_score(report.findings, files_scanned=report.files_scanned, platforms_scanned=_platforms_for_reports(report), families_with_surface=report.families_with_surface, families_with_ctx_coverage=report.families_with_ctx_coverage)
            if (args.score or args.format == "html")
            else None
        )
        _output_report(report, args, score_report=score_report)
        if score_report is not None and args.format != "html":
            print(format_score(score_report, use_color=not args.no_color))
        _exit_for_severity(report, effective_fail_on)
        return

    # Jenkins instance posture audit
    if getattr(args, "jenkins_url", None):
        from .models import AuditReport
        from .platform.jenkins_checks import run_all_checks as jk_run_all_checks
        from .platform.jenkins_client import JenkinsClient

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
        except Exception as e:
            print(f"Warning: Jenkins posture checks failed: {e}", file=sys.stderr)

        report.findings = apply_config_ignores(report.findings, audit_config.ignores, args.path)
        report.filter_severity(effective_min_sev)
        report.summarize()
        score_report = (
            compute_score(report.findings, files_scanned=report.files_scanned, platforms_scanned=_platforms_for_reports(report), families_with_surface=report.families_with_surface, families_with_ctx_coverage=report.families_with_ctx_coverage)
            if (args.score or args.format == "html")
            else None
        )
        _output_report(report, args, score_report=score_report)
        if score_report is not None and args.format != "html":
            print(format_score(score_report, use_color=not args.no_color))
        _exit_for_severity(report, effective_fail_on)
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

    reports = scan_repo(args.path, all_rules, platform)

    all_findings = []
    for report in reports:
        report.findings = apply_config_ignores(report.findings, audit_config.ignores, args.path)
        report.filter_severity(effective_min_sev)
        all_findings.extend(report.findings)

    # --baseline: write fingerprints and exit
    if args.baseline:
        baseline_path = args.baseline
        bl = save_baseline(all_findings, args.path, baseline_path)
        print(format_baseline_summary(bl, baseline_path))
        # Still output the full report so the user can review what was baselined
        for report in reports:
            _output_report(report, args)
        sys.exit(0)

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

    # --diff: suppress known findings, show only new ones
    total_suppressed = 0
    if baseline is not None:
        filtered = []
        for report in reports:
            new_findings, suppressed = apply_diff(report.findings, baseline, args.path)
            total_suppressed += suppressed
            # Annotate the title for SHA bumps / new dependencies so the
            # operator can tell at a glance whether a "new" finding is
            # an entirely new third-party action or a routine version
            # bump on one they already approved.
            for f in new_findings:
                kind = classify_diff_kind(
                    f, baseline.fingerprints, baseline.snippets, args.path
                )
                if kind == "sha_bump":
                    f.title = "[SHA BUMP] " + f.title
                elif kind == "new_dependency":
                    f.title = "[NEW DEPENDENCY] " + f.title
            report.findings = new_findings
            filtered.extend(new_findings)
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
            families_with_surface=agg_surface,
            families_with_ctx_coverage=agg_ctx_coverage,
        )

    for report in reports:
        _output_report(report, args, score_report=score_report)

    if score_report is not None and args.format != "html":
        print(format_score(score_report, use_color=not args.no_color))

    # Exit code: built-in CRITICAL=2/HIGH=1 logic + optional fail-on threshold
    worst = Severity.INFO
    for f in all_findings:
        if f.severity > worst:
            worst = f.severity

    if effective_fail_on and worst >= effective_fail_on:
        sys.exit(1)
    elif worst == Severity.CRITICAL:
        sys.exit(2)
    elif worst == Severity.HIGH:
        sys.exit(1)
    else:
        sys.exit(0)


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
        print(format_csv(report))
    elif args.format == "sarif":
        print(format_sarif(report))
    elif args.format == "html":
        print(format_html(report, score_report=score_report))


def _exit_for_severity(report, fail_on: Severity | None = None):
    """Exit with an appropriate code based on the worst finding in the report.

    Exit codes:
      * 0  — clean scan, no findings or only INFO-grade
      * 1  — HIGH finding, or fail-on threshold reached
      * 2  — CRITICAL finding
      * 11 — scanned cleanly BUT one or more files exceeded the
             scanner cap and file-scope rule coverage was degraded
             (ENGINE-ERR findings present). Distinct from 0 so CI can
             distinguish "scanned and found nothing" from "scanned
             with reduced coverage" — the field-test report flagged
             this as a missing signal on monolithic GitLab CI configs.
             Real-finding exit codes (1/2) take precedence: if
             findings AND coverage warnings both exist, the finding
             code wins.
    """
    # Exclude ENGINE-ERR (severity LOW) from the "worst finding" logic
    # so a coverage warning alone doesn't masquerade as a LOW finding.
    real = [f for f in report.findings if f.rule_id != "ENGINE-ERR"]
    worst = Severity.INFO
    for f in real:
        if f.severity > worst:
            worst = f.severity
    has_coverage_warning = any(f.rule_id == "ENGINE-ERR" for f in report.findings)
    if fail_on and worst >= fail_on:
        sys.exit(1)
    elif worst == Severity.CRITICAL:
        sys.exit(2)
    elif worst == Severity.HIGH:
        sys.exit(1)
    elif has_coverage_warning:
        sys.exit(11)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
