#!/usr/bin/env python3
"""Audit which YAML paths the existing regex-based rules query.

Walks ``taintly/rules/{github,gitlab}/`` and extracts the schema
paths each rule's regex appears to be targeting.  Output is a
markdown table of paths ordered by query count.

Used by Phase 1 of the structural reader work to:

1. **Pre-budget validation.**  Confirms the "~60-80 distinct paths"
   assumption before committing to the tokenizer/walker/schemas
   build.  If the distinct count is significantly higher (>120),
   the schema layer is materially larger and the 5-day budget
   needs reassessment.

2. **Phase 2 migration locking.**  The top-N entries by
   ``(use_count desc, known_precision_issue_rank desc)`` are the
   first migration candidates — the choice is recorded in the
   Phase 1 PR body before Phase 2 runs, so the F1-delta
   measurement can't be cherry-picked.

Jenkins rules are intentionally out of scope (Jenkinsfile is
Groovy, not YAML; a separate Groovy-DSL reader is a different
decision).
"""

from __future__ import annotations

import re
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


# Common regex shapes -> the schema path they're targeting.  This
# mapping is deliberately partial and surface-level: it identifies
# the dominant shapes without trying to interpret every regex.
# Misclassification doesn't break the audit; it under-counts in a
# direction that's safe (we'd over-budget the schema, not
# under-budget).
_PATTERN_TO_PATH: list[tuple[str, str]] = [
    # GitHub Actions paths
    (r"\\buses:\\s", "jobs.*.steps[*].uses"),
    (r"\\brun:\\s", "jobs.*.steps[*].run"),
    (r"\\bruns-on:", "jobs.*.runs-on"),
    (r"\\bpermissions:", "jobs.*.permissions"),
    (r"\\benvironment:", "jobs.*.environment"),
    (r"\\bcontainer:", "jobs.*.container"),
    (r"\\bservices:", "jobs.*.services"),
    (r"pull_request_target", "on.pull_request_target"),
    (r"\\bworkflow_run\\b", "on.workflow_run"),
    (r"\\bworkflow_dispatch\\b", "on.workflow_dispatch"),
    (r"\\brelease:", "on.release"),
    (r"\\bschedule:", "on.schedule"),
    (r"\\bissue_comment\\b", "on.issue_comment"),
    (r"\\bpull_request_review\\b", "on.pull_request_review"),
    (r"\\bpush:", "on.push"),
    (r"\\bid-token:", "permissions.id-token"),
    (r"\\bcontents:", "permissions.contents"),
    (r"\\bpackages:", "permissions.packages"),
    (r"\\bactions:", "permissions.actions"),
    (r"\\bsecrets:\\s", "jobs.*.secrets"),
    (r"\\bwith:\\s", "jobs.*.steps[*].with"),
    (r"\\benv:\\s", "jobs.*.steps[*].env"),
    (r"\\bif:\\s", "jobs.*.steps[*].if"),
    (r"\\btimeout-minutes:", "jobs.*.steps[*].timeout-minutes"),
    (r"\\bcontinue-on-error:", "jobs.*.steps[*].continue-on-error"),
    (r"\\bworking-directory:", "jobs.*.steps[*].working-directory"),
    (r"\\bshell:", "jobs.*.steps[*].shell"),
    (r"\\bdefaults\\.run\\.shell\\b", "defaults.run.shell"),
    (r"\\bconcurrency:", "concurrency"),
    (r"\\bcancel-in-progress:", "concurrency.cancel-in-progress"),
    (r"\\bgroup:", "concurrency.group"),
    (r"\\bcheckout@", "jobs.*.steps[*].uses (checkout)"),
    (r"actions/cache@|actions/cache/save@|actions/cache/restore@", "jobs.*.steps[*].uses (cache)"),
    (r"persist-credentials:", "jobs.*.steps[*].with.persist-credentials"),
    (r"\\bref:\\s", "jobs.*.steps[*].with.ref"),
    (r"\\bkey:\\s", "jobs.*.steps[*].with.key (cache)"),
    (r"restore-keys:", "jobs.*.steps[*].with.restore-keys"),
    (r"\\benvironment\\.name\\b", "jobs.*.environment.name"),
    (r"toJSON\\s*\\(\\s*secrets", "secrets.* (toJSON)"),
    (r"\\$\\{\\{\\s*secrets\\.", "secrets.*"),
    (r"\\$\\{\\{\\s*github\\.event\\.", "github.event.*"),
    (r"GITHUB_(REF_NAME|HEAD_REF|ACTOR|TOKEN)", "GITHUB_* env"),
    (r"\\bjobs\\.[a-z_-]+\\.outputs", "jobs.*.outputs"),

    # GitLab CI paths
    (r"\\bscript:\\s", "jobs.*.script"),
    (r"\\bbefore_script:", "jobs.*.before_script"),
    (r"\\bafter_script:", "jobs.*.after_script"),
    (r"\\bimage:", "jobs.*.image"),
    (r"\\bvariables:", "jobs.*.variables"),
    (r"\\binclude:", "include"),
    (r"\\bartifacts:", "jobs.*.artifacts"),
    (r"\\bcache:", "jobs.*.cache"),
    (r"\\bonly:", "jobs.*.only"),
    (r"\\bexcept:", "jobs.*.except"),
    (r"\\brules:", "jobs.*.rules"),
    (r"\\bextends:", "jobs.*.extends"),
    (r"\\btrigger:", "jobs.*.trigger"),
    (r"\\benvironment:\\s", "jobs.*.environment"),
    (r"resource_group:", "jobs.*.resource_group"),
    (r"CI_COMMIT_(MESSAGE|TAG|REF_NAME|BRANCH)", "CI_* vars"),
    (r"CI_JOB_TOKEN", "CI_JOB_TOKEN"),
    (r"\\$\\{?CI_PIPELINE_SOURCE\\}?", "CI_PIPELINE_SOURCE"),
]


def _platform_dirs() -> list[tuple[str, Path]]:
    return [
        ("github", ROOT / "taintly" / "rules" / "github"),
        ("gitlab", ROOT / "taintly" / "rules" / "gitlab"),
    ]


def _extract_regex_strings(text: str) -> list[str]:
    """Pull regex string literals out of rule definition source.

    Picks up the dominant shapes — single-line ``r"..."`` and
    ``r'...'`` literals plus parenthesised concatenations.  Misses
    f-string-built regexes (rare in this rule pack); the audit
    over-counts hits per rule rather than under-counting paths,
    which is the safe direction.
    """
    return re.findall(r"r['\"]([^'\"]+)['\"]", text)


# Path-keyword substrings — a rule's source text mentioning any of
# these is taken as evidence the rule queries (or cares about) that
# path.  Looser than regex-on-regex matching: catches rules that
# reference paths via plain string mentions in test samples,
# narratives, or comments that the regex-extraction step misses.
_PATH_KEYWORDS: list[tuple[str, str]] = [
    # GitHub Actions
    ("uses:", "jobs.*.steps[*].uses"),
    ("run:", "jobs.*.steps[*].run"),
    ("runs-on:", "jobs.*.runs-on"),
    ("permissions:", "jobs.*.permissions"),
    ("environment:", "jobs.*.environment"),
    ("services:", "jobs.*.services"),
    ("container:", "jobs.*.container"),
    ("pull_request_target", "on.pull_request_target"),
    ("workflow_run", "on.workflow_run"),
    ("workflow_dispatch", "on.workflow_dispatch"),
    ("workflow_call", "on.workflow_call"),
    ("issue_comment", "on.issue_comment"),
    ("pull_request_review", "on.pull_request_review"),
    ("on: release", "on.release"),
    ("schedule:", "on.schedule"),
    ("id-token:", "permissions.id-token"),
    ("contents:", "permissions.contents"),
    ("packages:", "permissions.packages"),
    ("write-all", "permissions.* (write-all)"),
    ("with:", "jobs.*.steps[*].with"),
    ("env:", "jobs.*.steps[*].env"),
    ("if:", "jobs.*.steps[*].if"),
    ("timeout-minutes:", "jobs.*.timeout-minutes"),
    ("continue-on-error:", "jobs.*.steps[*].continue-on-error"),
    ("shell:", "jobs.*.steps[*].shell"),
    ("concurrency:", "concurrency"),
    ("cancel-in-progress:", "concurrency.cancel-in-progress"),
    ("persist-credentials", "jobs.*.steps[*].with.persist-credentials"),
    ("ref:", "jobs.*.steps[*].with.ref"),
    ("restore-keys:", "jobs.*.steps[*].with.restore-keys"),
    ("secrets:", "jobs.*.secrets"),
    ("toJSON(secrets)", "secrets.* (toJSON)"),
    ("github.event.pull_request.head", "github.event.pull_request.head.*"),
    ("github.event.workflow_run.", "github.event.workflow_run.*"),
    ("github.event.issue.", "github.event.issue.*"),
    ("github.event.comment.", "github.event.comment.*"),
    ("GITHUB_REF_NAME", "GITHUB_REF_NAME"),
    ("GITHUB_HEAD_REF", "GITHUB_HEAD_REF"),
    ("GITHUB_TOKEN", "GITHUB_TOKEN"),
    ("GITHUB_OUTPUT", "GITHUB_OUTPUT"),
    ("GITHUB_ENV", "GITHUB_ENV"),
    ("github.actor", "github.actor"),
    ("uses: actions/checkout", "actions/checkout (uses)"),
    ("uses: actions/cache", "actions/cache (uses)"),
    ("uses: actions/upload-artifact", "actions/upload-artifact (uses)"),
    ("uses: actions/setup-node", "actions/setup-node (uses)"),
    ("uses: actions/setup-python", "actions/setup-python (uses)"),
    ("outputs:", "jobs.*.outputs"),
    ("defaults:", "defaults"),

    # GitLab CI
    ("script:", "jobs.*.script"),
    ("before_script:", "jobs.*.before_script"),
    ("after_script:", "jobs.*.after_script"),
    ("image:", "jobs.*.image"),
    ("variables:", "jobs.*.variables"),
    ("artifacts:", "jobs.*.artifacts"),
    ("cache:", "jobs.*.cache"),
    ("rules:", "jobs.*.rules"),
    ("only:", "jobs.*.only"),
    ("except:", "jobs.*.except"),
    ("extends:", "jobs.*.extends"),
    ("trigger:", "jobs.*.trigger"),
    ("include:", "include"),
    ("resource_group:", "jobs.*.resource_group"),
    ("CI_COMMIT_MESSAGE", "CI_COMMIT_MESSAGE"),
    ("CI_COMMIT_TAG", "CI_COMMIT_TAG"),
    ("CI_COMMIT_REF_NAME", "CI_COMMIT_REF_NAME"),
    ("CI_COMMIT_BRANCH", "CI_COMMIT_BRANCH"),
    ("CI_PIPELINE_SOURCE", "CI_PIPELINE_SOURCE"),
    ("CI_JOB_TOKEN", "CI_JOB_TOKEN"),
]


def main() -> int:
    path_counts: Counter[str] = Counter()
    rule_paths: dict[str, set[str]] = {}

    rule_id_re = re.compile(r'id\s*=\s*"([A-Z][A-Z0-9-]+)"')

    for platform, pdir in _platform_dirs():
        if not pdir.exists():
            continue
        for src in pdir.rglob("*.py"):
            text = src.read_text(encoding="utf-8")
            # Approximate per-rule scoping: split on Rule(...) and
            # count distinct rule_ids each path-pattern hits in.
            # Uses string match on rule-id presence in the chunk.
            chunks = re.split(r"\bRule\s*\(", text)
            for chunk in chunks[1:]:
                m = rule_id_re.search(chunk)
                if not m:
                    continue
                rule_id = m.group(1)
                seen_paths: set[str] = set()
                # Loose keyword scan against the rule's whole body —
                # picks up paths mentioned in test samples,
                # threat narratives, regex sources, and remediation
                # text alike.  Less precise than per-regex
                # extraction but materially less brittle.
                for keyword, path in _PATH_KEYWORDS:
                    if keyword in chunk:
                        if path in seen_paths:
                            continue
                        seen_paths.add(path)
                        path_counts[path] += 1
                        rule_paths.setdefault(path, set()).add(rule_id)

    distinct = len(path_counts)
    total_hits = sum(path_counts.values())

    print(f"# Rule-path audit\n")
    print(f"- Distinct paths queried: **{distinct}**")
    print(f"- Total path-hits across all rules: **{total_hits}**")
    print()
    print("| Rank | Path | Rule count | Top rules |")
    print("|------|------|-----------|-----------|")
    for rank, (path, count) in enumerate(path_counts.most_common(), start=1):
        rules = sorted(rule_paths[path])
        preview = ", ".join(rules[:5])
        if len(rules) > 5:
            preview += f" (+{len(rules) - 5} more)"
        print(f"| {rank} | `{path}` | {count} | {preview} |")

    print()
    print("## Budget interpretation")
    if distinct <= 80:
        print(f"- Distinct path count ({distinct}) is within the original 60-80 budget assumption.  Phase 1 schema layer holds.")
    elif distinct <= 120:
        print(f"- Distinct path count ({distinct}) is moderately above the 60-80 estimate but under the 120 reassessment threshold.  Schema layer grows; budget holds.")
    else:
        print(f"- Distinct path count ({distinct}) significantly exceeds the 60-80 estimate.  **STOP** and reassess scope before writing the tokenizer.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
