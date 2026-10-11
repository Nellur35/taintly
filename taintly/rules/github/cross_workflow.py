"""GitHub Actions — cross-workflow rules (XF-GH-*).

The XF-GH family fires when a finding's evidence requires reading
TWO OR MORE workflow files together.  Each rule's pattern is a
:class:`taintly.workflow_corpus.CorpusPattern` whose callback walks
the pre-built :class:`WorkflowCorpus` indexes (cache_keys,
concurrency_groups, environments, reusable_uses, permissions,
triggers).

Rules in this module:
  * XF-GH-001  — Generic cache poisoning across privilege tiers
                 (MEDIUM, review_needed — exploit chain depends on
                 what the cache is used for).
  * XF-GH-001A — Package/build cache sharing (HIGH, review_needed;
                 names indicate potential impact, not execution proof).
  * XF-GH-002  — Concurrency-cancel cross-workflow (LOW —
                 wild-scan-rare antipattern; kept as a defensive
                 lint).
  * XF-GH-003  — Reusable-fanout hub (MEDIUM — the strongest
                 wild-scan TP set; 21 hits across 4 OSS repos).
  * XF-GH-004  — PWN-request shape: ``pull_request_target`` /
                 ``issue_comment`` / ``pull_request_review`` caller
                 invokes a reusable workflow that holds write
                 permissions or ``secrets: inherit`` (HIGH, no
                 review_needed — canonical "Preventing pwn requests"
                 pattern from GitHub Security Lab).

Numbering note: an earlier draft had a separate environment-name-
aliasing rule between XF-GH-002 and the reusable-fanout rule.  It
was removed in the cleanup pass (audit-hygiene linter, not security;
0 wild-scan hits) and the reusable-fanout rule was renumbered from
XF-GH-004 down to XF-GH-003 to keep the family contiguous.  The
rename shipped before any external baseline / suppression config
could reference the old ID.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from taintly.cache_context import CacheSite, cache_sites
from taintly.cross_workflow_facts import find_cross_file_taint
from taintly.local_call_graph import flow_evidence
from taintly.models import Platform, Rule, Severity
from taintly.workflow_corpus import (
    CorpusEvidence,
    CorpusFindings,
    CorpusPattern,
    TriggerFamily,
    WorkflowCorpus,
    _cache_key_prefix,
)

# ---------------------------------------------------------------------------
# XF-GH-001 — Cache poisoning across privilege tiers
# ---------------------------------------------------------------------------

# Names associated with package/build caches indicate potential impact only.
# They do not establish saved content, attacker control or subsequent execution.
# Retain the existing severity split with review required in both families.
_HIGH_BLAST_RADIUS_CACHE_TOKENS: tuple[str, ...] = (
    "node_modules",
    "pnpm-store",
    "yarn-cache",
    "npm-cache",
    "pip-cache",
    "pip-",
    "pypi-",
    "cargo-",
    "go-mod-",
    "gradle-",
    "maven-",
    "bundler-",
    "composer-",
    "apt-",
    "docker-layer",
    "buildx-cache",
)


def _cache_prefix_is_high_blast_radius(prefix: str) -> bool:
    """Return True when the cache prefix names an executable-cache
    pattern (package store, compiled toolchain, runtime module dir).

    HIGH means conditional package/build impact; both tiers require review.
    """
    p = prefix.lower()
    return any(tok in p for tok in _HIGH_BLAST_RADIUS_CACHE_TOKENS)


@dataclass(frozen=True)
class _CacheMatch:
    file: str
    reader: CacheSite
    prefix: str
    writer_file: str
    writer: CacheSite
    writer_prefix: str
    notes: tuple[str, ...]


def _collect_xf_gh_001_matches(corpus: WorkflowCorpus) -> list[_CacheMatch]:
    """Join possible direct cache operations; never certify content execution.

    Ordinary PR saves are merge-ref isolated from base/push readers. Other
    external events require owning guards and access mode; unknown scope or
    evaluated keys remain review evidence. Primary keys also prefix-match.
    """
    writes: list[tuple[str, CacheSite, str, tuple[str, ...]]] = []
    for workflow in corpus.by_trigger(TriggerFamily.FORK_REACHABLE):
        for event in sorted(workflow.raw_event_names):
            if event not in {
                "pull_request_target",
                "issue_comment",
                "issues",
                "discussion",
                "discussion_comment",
                "fork",
                "watch",
                "workflow_run",
            }:
                continue
            if (
                event == "workflow_run"
                and corpus.workflow_run_parent_fork_reachable(workflow) is False
            ):
                continue
            for site in cache_sites(workflow):
                if site.role not in {"write", "both"}:
                    continue
                allowed, notes = site.access(event, save=True)
                prefix = _cache_key_prefix(site.key)
                if allowed is not False and prefix:
                    writes.append((workflow.filepath, site, prefix, notes))

    matches: list[_CacheMatch] = []
    writes.sort(
        key=lambda item: (
            not _cache_prefix_is_high_blast_radius(item[2]),
            item[1].mode not in {"write", "write-only"},
            item[0],
            item[1].line,
            item[3],
        )
    )
    seen: set[tuple[str, int]] = set()
    for workflow in corpus.all():
        for event in sorted(
            workflow.raw_event_names
            & {
                "push",
                "release",
                "deployment",
                "deployment_status",
                "registry_package",
                "branch_protection_rule",
                "create",
                "delete",
                "page_build",
                "status",
                "milestone",
                "label",
                "project",
                "project_card",
                "project_column",
                "schedule",
                "workflow_dispatch",
                "repository_dispatch",
                "workflow_run",
            }
        ):
            for site in cache_sites(workflow):
                if site.role not in {"read", "both"}:
                    continue
                allowed, reader_notes = site.access(event, save=False)
                if allowed is False:
                    continue
                for query in (site.key, *site.restore_keys):
                    prefix = _cache_key_prefix(query)
                    if not prefix:
                        continue
                    for file, writer, writer_prefix, writer_notes in writes:
                        # A dynamic writer suffix may complete a longer query prefix.
                        overlap = writer_prefix.startswith(prefix) or (
                            writer_prefix != writer.key and prefix.startswith(writer_prefix)
                        )
                        if not overlap or (workflow.filepath, site.line) in seen:
                            continue
                        seen.add((workflow.filepath, site.line))
                        notes = (
                            f"Writer: {file}:{writer.line}.",
                            *writer_notes,
                            f"Reader: {workflow.filepath}:{site.line}.",
                            *reader_notes,
                            "Representative matching writer/event evidence; other candidate paths may exist.",
                            "Current GitHub.com cache policy profile; provider/version applicability must be verified.",
                            "Evaluated keys, branch/default-ref compatibility, cache version (paths/compression), save success and restore selection remain unverified.",
                            "External event reachability does not prove attacker control over cached files or downstream execution/authority. Reusable invocation cache ceilings are not resolved by this direct-job profile.",
                        )
                        matches.append(
                            _CacheMatch(
                                workflow.filepath, site, prefix, file, writer, writer_prefix, notes
                            )
                        )
                        break
    return matches


def _cache_evidence(match: _CacheMatch, executable_name: bool) -> CorpusEvidence:
    title = (
        "Possible package/build cache sharing needs poisoning review"
        if executable_name
        else "Possible cross-workflow cache sharing needs poisoning review"
    )
    return CorpusEvidence(
        match.file,
        match.reader.line,
        f"Cache query prefix '{match.prefix}' may overlap saved prefix '{match.writer_prefix}' at {match.writer_file}:{match.writer.line}",
        title,
        f"Review cache save at {match.writer_file}:{match.writer.line} and restore at {match.file}:{match.reader.line}. "
        "Keep externally triggered jobs read-only (cache-mode: read or none) where supported. "
        "Verify branch scope, cache version, attacker control of saved paths and subsequent use before treating this as an exploit. "
        "If sharing is required, separate trust domains in evaluated primary keys and every fallback; removing restore-keys alone does not prevent primary-key prefix matching. "
        "If poisoning is verified, clear affected caches and assess exposed credentials/artifacts.",
        True,
        match.notes,
        ("cache-sharing-review", "direct-cache-context"),
        "Key overlap is a candidate, not proof of attacker-controlled restored or executed bytes.",
    )


def _xf_gh_001_callback(corpus: WorkflowCorpus) -> CorpusFindings:
    return [
        _cache_evidence(match, False)
        for match in _collect_xf_gh_001_matches(corpus)
        if not (
            _cache_prefix_is_high_blast_radius(match.writer_prefix)
            or _cache_prefix_is_high_blast_radius(match.prefix)
        )
    ]


def _xf_gh_001a_callback(corpus: WorkflowCorpus) -> CorpusFindings:
    return [
        _cache_evidence(match, True)
        for match in _collect_xf_gh_001_matches(corpus)
        if _cache_prefix_is_high_blast_radius(match.writer_prefix)
        or _cache_prefix_is_high_blast_radius(match.prefix)
    ]


RULES: list[Rule] = [
    # XF-GH-001A — package/build cache candidate (HIGH, review_needed).
    # The package-store / runtime-module variant of cross-workflow
    # cache poisoning.  Calls into the same _collect_xf_gh_001_matches
    # collector but only emits findings whose prefix names an
    # executable cache (pnpm-store, node_modules, pip-, cargo-, etc.).
    Rule(
        id="XF-GH-001A",
        title="Possible package/build cache sharing across privilege tiers",
        severity=Severity.HIGH,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-3",
        description=(
            "Direct cache save and restore sites have potentially overlapping key prefixes across "
            "an externally triggered workflow and a privileged consumer. Ordinary pull_request saves "
            "are merge-ref isolated from base-branch consumers. Current GitHub.com default-branch "
            "low-trust saves are read-only unless explicitly overridden; owning job mode and guards "
            "matter. Unknown branch identity and policy applicability remain review-needed. "
            "Matching names do not prove cache-version compatibility, attacker control of saved "
            "files, restore selection, subsequent execution or credential access. Primary keys "
            "also participate in prefix matching without restore-keys."
        ),
        pattern=CorpusPattern(callback=_xf_gh_001a_callback),
        remediation=(
            "Keep externally triggered cache writers read-only or disabled where supported. "
            "Verify owning event/guards, effective cache-mode, branch scope, evaluated key and "
            "path/compression version at both sites. Separate trust domains in primary keys "
            "and every fallback; removing restore-keys alone is insufficient. Establish "
            "attacker control and downstream use before assessing impact; clear affected "
            "caches if poisoning is verified."
        ),
        reference=(
            "https://adnanthekhan.com/2024/05/06/the-monsters-in-your-build-cache-github-actions-cache-poisoning/; "
            "https://docs.github.com/en/actions/reference/workflows-and-actions/dependency-caching"
        ),
        test_positive=[],
        test_negative=[],
        stride=["T", "E"],
        threat_narrative=(
            "If an externally triggered job can save attacker-controlled files into a cache "
            "namespace and version a privileged consumer can restore, poisoned content may "
            "cross the trust boundary. Code execution additionally requires subsequent use as "
            "code; a package/build-looking cache name alone cannot establish that step. "
            "Ordinary pull_request merge-ref writes are unavailable to base-branch runs. "
            "Cache scope, access overrides and the originating event must be verified."
        ),
        confidence="medium",
        # Name-based impact remains conditional; require review.
        review_needed=True,
        finding_family="script_injection",
    ),
    # XF-GH-001 — generic data cache (MEDIUM, review_needed=True).
    # Same engine, but emits only the non-executable-cache hits (mypy,
    # mkdocs, hypothesis, etc.) where the exploit chain depends on
    # what the cache is used for.
    Rule(
        id="XF-GH-001",
        title="Possible cache sharing across privilege tiers (cross-workflow)",
        severity=Severity.MEDIUM,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-3",
        description=(
            "Direct cache save and restore sites have potentially overlapping key prefixes across "
            "an externally triggered workflow and a privileged consumer. Ordinary pull_request saves "
            "are merge-ref isolated from base-branch consumers. Current GitHub.com default-branch "
            "low-trust saves are read-only unless explicitly overridden; owning job mode and guards "
            "matter. Unknown branch identity and policy applicability remain review-needed. "
            "Matching names do not prove cache-version compatibility, attacker control of saved "
            "files, restore selection, subsequent execution or credential access. Primary keys "
            "also participate in prefix matching without restore-keys."
        ),
        pattern=CorpusPattern(callback=_xf_gh_001_callback),
        remediation=(
            "Keep externally triggered cache writers read-only or disabled where supported. "
            "Verify owning event/guards, effective cache-mode, branch scope, evaluated key and "
            "path/compression version at both sites. Separate trust domains in primary keys "
            "and every fallback; removing restore-keys alone is insufficient. Establish "
            "attacker control and downstream use before assessing impact; clear affected "
            "caches if poisoning is verified."
        ),
        reference=(
            "https://adnanthekhan.com/2024/05/06/the-monsters-in-your-build-cache-github-actions-cache-poisoning/; "
            "https://docs.github.com/en/actions/reference/workflows-and-actions/dependency-caching"
        ),
        # Self-test samples are full repos, not single-file YAML —
        # CorpusPattern rules are exercised by the integration tests
        # in tests/unit/test_cross_workflow_rules.py rather than by
        # the per-file self-test harness.
        test_positive=[],
        test_negative=[],
        stride=["T", "E"],
        threat_narrative=(
            "If an externally triggered job can save attacker-controlled files into a cache "
            "namespace and version a privileged consumer can restore, poisoned content may "
            "cross the trust boundary. Code execution additionally requires subsequent use as "
            "code; a package/build-looking cache name alone cannot establish that step. "
            "Ordinary pull_request merge-ref writes are unavailable to base-branch runs. "
            "Cache scope, access overrides and the originating event must be verified."
        ),
        confidence="medium",
        # Cross-workflow rules need design review: a legitimate "shared
        # cache across triggers" pattern can match this rule, and a
        # one-line audit of the keys is faster than re-architecting.
        review_needed=True,
        finding_family="script_injection",
    ),
]


# ---------------------------------------------------------------------------
# XF-GH-002 — Concurrency-cancel cross-workflow
# ---------------------------------------------------------------------------


def _xf_gh_002_callback(corpus: WorkflowCorpus) -> CorpusFindings:
    """Detect cross-workflow concurrency-group collisions where one
    side is fork-reachable, another is privileged, and at least one
    declares ``cancel-in-progress: true``.

    Threat model:

      * GitHub Actions schedules at most one running job per
        ``concurrency.group`` value across an entire repository.  When
        ``cancel-in-progress: true`` is set on the new run, GitHub
        cancels the existing in-flight run that shares the group.
      * If a fork-reachable workflow shares its group string with a
        privileged workflow, an attacker triggering the fork-side
        run can cancel the privileged run.  In release / deployment
        pipelines this is a denial-of-service primitive that lets a
        contributor stall production rollouts at will.
      * The dual-trigger same-workflow case (one workflow file with
        ``on: [push, pull_request]`` and a single ``concurrency:``
        block) is also a true positive — a PR-event run uses the
        same group as the in-progress push-event run and cancels it.

    Match rule:

      * Build a map ``group_string → list[(workflow, ref)]`` from
        every concurrency block (workflow- AND job-scope) in the
        corpus.
      * For each group whose signers include AT LEAST ONE
        fork-reachable workflow AND AT LEAST ONE privileged workflow
        AND any cited ref has ``cancel_in_progress=True``, fire on
        the privileged ref's ``group:`` line citing the fork file.
      * A single workflow whose own trigger set includes both
        FORK_REACHABLE and PRIVILEGED is treated as both endpoints
        of the collision (the dual-trigger TP).
      * Empty group strings are dropped — that's an extractor
        artefact (``concurrency:\\n  cancel-in-progress: true`` with
        no group), not a meaningful join point.

    Skipped (intentional FP guards):

      * No ``cancel_in_progress=True`` ref in the colliding set —
        without cancellation the worst the collision causes is
        queueing, which is annoying but not a security primitive.
      * Single-file collisions where the file does NOT carry both
        trigger families AND no other workflow shares the group —
        the rule is cross-workflow; an isolated workflow that
        cancels itself is benign.
    """
    from taintly.workflow_corpus import ConcurrencyRef

    findings: CorpusFindings = []

    # group → list of (filepath, ref, fork_reachable, privileged).
    by_group: dict[str, list[tuple[str, ConcurrencyRef, bool, bool]]] = {}
    for w in corpus.all():
        for ref in w.concurrency_groups:
            if not ref.group:
                continue
            by_group.setdefault(ref.group, []).append(
                (
                    w.filepath,
                    ref,
                    TriggerFamily.FORK_REACHABLE in w.triggers,
                    TriggerFamily.PRIVILEGED in w.triggers,
                )
            )

    seen: set[tuple[str, int]] = set()
    for group, entries in by_group.items():
        # Two textually-equal group templates can still resolve to
        # DIFFERENT runtime values at scheduling time depending on
        # which context tokens the template uses.
        #
        # Cross-FILE FP guard: ``github.workflow`` resolves to the
        # workflow's ``name:`` so it differs across files;
        # ``github.run_id`` is unique per run.  When either token is
        # in the group, two distinct workflow files using the same
        # template don't collide.
        cross_file_safe = "github.workflow" not in group and "github.run_id" not in group

        # Same-FILE (dual-trigger) FP guard: tokens that resolve to
        # DIFFERENT values for a PR-event run vs a push-event run of
        # the same workflow.  Their presence in the template means
        # the dual-trigger collision the rule looks for doesn't
        # actually happen — the author has scoped by event.
        #
        # Verified against the GitHub Actions context docs:
        #   * ``github.ref`` — PR head-merge ref vs push branch ref.
        #   * ``github.head_ref`` — populated only on PR events; the
        #     common ``head_ref || run_id`` fallback gives a fresh
        #     unique run-id on push events.
        #   * ``github.event_name`` — literally the event name.
        #   * ``github.event.pull_request.number`` — PR number on PR
        #     events; null on push (often paired with ``|| sha``).
        #   * ``github.sha`` — the commit SHA, distinct between PR
        #     merge commits and pushed commits.
        #   * ``github.run_id`` — unique per run, always.
        scope_by_event_tokens = (
            "github.ref",
            "github.head_ref",
            "github.event_name",
            "github.event.pull_request.number",
            "github.sha",
            "github.run_id",
        )
        same_file_safe = not any(tok in group for tok in scope_by_event_tokens)

        any_fork = any(e[2] for e in entries)
        any_priv = any(e[3] for e in entries)
        any_cancel = any(getattr(e[1], "cancel_in_progress", False) for e in entries)
        if not (any_fork and any_priv and any_cancel):
            continue

        for filepath, ref, _fork, priv in entries:
            if not priv:
                continue
            line = getattr(ref, "line", 1)
            key = (filepath, line)
            if key in seen:
                continue

            wf = corpus.by_filepath(filepath)
            same_file_dual_trigger = wf is not None and TriggerFamily.FORK_REACHABLE in wf.triggers

            # Decide which fork-side run to cite, in preference order:
            #   1. If THIS file is dual-trigger AND the group template
            #      doesn't scope-by-event, self-cite — the same
            #      workflow's PR-event run and push-event run share
            #      the group and the PR can cancel the push.
            #   2. Otherwise, cross-file citation only when the group
            #      template doesn't break cross-file runtime equality
            #      (no github.workflow / github.run_id token).
            #   3. Otherwise, drop — the textual match is not a real
            #      runtime collision.
            if same_file_dual_trigger and same_file_safe:
                cite = "this workflow's own fork-trigger run"
            elif cross_file_safe:
                fork_files = [e[0] for e in entries if e[2] and e[0] != filepath]
                if not fork_files:
                    continue  # no other fork file; not cross-file
                cite = fork_files[0]
            else:
                continue

            seen.add(key)
            cancel_note = "" if ref.cancel_in_progress else " (peer ref carries cancel-in-progress)"
            snippet = (
                f"concurrency group '{group}' shared with fork-reachable "
                f"{cite}{cancel_note} — cancel-in-progress lets the fork side "
                f"cancel this privileged run."
            )
            findings.append((filepath, line, snippet))
    return findings


RULES.append(
    Rule(
        id="XF-GH-002",
        title="Cross-workflow concurrency-cancel collision",
        # Demoted to LOW after wild-scan: across 16 OSS repos / 362
        # workflow files the rule produced 0 hits because every mature
        # project already scopes concurrency by event token
        # (github.ref / head_ref / run_id / event_name), making
        # textually-equal groups across files runtime-distinct.  The
        # threat model is real but the antipattern is rare in the wild;
        # keeping the rule at LOW + review_needed avoids polluting
        # higher-tier findings volume while still catching the case
        # where a junior engineer writes `concurrency: production`.
        severity=Severity.LOW,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-1",
        description=(
            "A privileged workflow (push / release / deployment) shares its "
            "`concurrency.group` value with a fork-reachable workflow "
            "(pull_request / pull_request_target / issue_comment), and at "
            "least one side has `cancel-in-progress: true`.  GitHub Actions "
            "treats the group string as a global lock per-repository: the "
            "newer run with the same group cancels the older one when the "
            "flag is set.  An attacker who can fire the fork-side trigger "
            "(any contributor opening a PR) can therefore cancel privileged "
            "runs at will — turning the cancel-in-progress feature into a "
            "denial-of-service primitive against release deployments, "
            "scheduled production rebuilds, or branch-protection-bypass "
            "rollback workflows.  The dual-trigger same-workflow case "
            "(one file `on: [push, pull_request]` with a single "
            "`concurrency:` block) is the dominant real-world shape: a "
            "PR-event run shares the group with the in-progress push-event "
            "run and cancels it."
        ),
        pattern=CorpusPattern(callback=_xf_gh_002_callback),
        remediation=(
            "Either (a) scope the concurrency group by trigger so fork\n"
            "and privileged runs never collide:\n"
            "    group: ${{ github.event_name }}-${{ github.workflow }}-${{ github.ref }}\n"
            "    cancel-in-progress: true\n"
            "or (b) drop `cancel-in-progress: true` from the privileged\n"
            "workflow — letting the privileged run finish is almost always\n"
            "preferable to letting an attacker abort it.\n"
            "Run `taintly --guide XF-GH-002` for the full checklist."
        ),
        reference=(
            "https://docs.github.com/en/actions/using-jobs/using-concurrency; "
            "https://github.blog/changelog/2021-04-19-github-actions-limit-workflow-run-or-job-concurrency/"
        ),
        test_positive=[],
        test_negative=[],
        stride=["D"],
        threat_narrative=(
            "An attacker opens a no-op PR against the repo — they don't "
            "need write access; opening a PR is a fork operation any user "
            "can perform.  The PR's CI fires the fork-reachable workflow "
            "whose `concurrency.group` matches the privileged release "
            "workflow's group.  The fork-side run becomes the new owner "
            "of the lock; with `cancel-in-progress: true` the in-flight "
            "release is cancelled mid-deploy.  Repeat as needed to keep "
            "production stuck on the previous version."
        ),
        confidence="medium",
        review_needed=True,
        finding_family="resource_controls",
    )
)


# ---------------------------------------------------------------------------
# XF-GH-003 — Reusable-fanout hub
# ---------------------------------------------------------------------------

# Threshold for "many callers with inherit" — three or more distinct
# caller workflows passing ``secrets: inherit`` to the same reusable
# target makes the reusable workflow a fanout hub.  Two callers is
# common (a release + a preview deploy sharing one reusable build job)
# and not yet a meaningful blast-radius increase; three is the point
# where union-of-secrets exposure exceeds the trust boundary one
# reviewer can hold in their head.
_FANOUT_THRESHOLD = 3


def _xf_gh_003_callback(corpus: WorkflowCorpus) -> CorpusFindings:
    """Detect reusable workflows called as a fanout hub.

    A reusable workflow becomes a "fanout hub" when N caller
    workflows all reference it with ``secrets: inherit``.  The
    reusable workflow inherits the UNION of every caller's secret
    scope at runtime — repo secrets, environment secrets, and any
    inherited org secrets.  Two impacts:

      1. **Blast radius**: a malicious commit to the reusable
         workflow exposes every secret across the union.  The hub
         is a single point whose compromise compounds.
      2. **Fork-reachable surfacing**: when even ONE caller is fork-
         reachable AND passes ``secrets: inherit``, the reusable
         workflow runs with that caller's full secret scope on PR
         events — turning the hub into a PR-controlled secret leak
         primitive (the canonical ``pull_request_target`` + reusable
         workflow shape).

    Match rule:

      * Group all :class:`ReusableRef` entries by ``target`` (the
        full ``uses:`` value) and count distinct caller filepaths
        carrying ``secrets_inherit=True``.
      * Fire when:
          - inherit-caller count >= :data:`_FANOUT_THRESHOLD`, OR
          - any inherit-caller is in a fork-reachable workflow.
      * Cite the LOCAL reusable workflow file (when the target is
        ``./.github/workflows/X.yml`` and X.yml exists in the corpus);
        otherwise cite the first caller as the attribution point.

    Skipped (intentional):

      * Targets without ``secrets: inherit`` callers — the rule is
        about the inherit shape specifically.  Per-secret pinning
        (``secrets: SECRET_NAME``) is the safe pattern.
      * Local reusable refs that don't have a corresponding file in
        the corpus (broken reference; another rule's domain).
    """
    findings: CorpusFindings = []

    # target → list of (caller_filepath, fork_reachable, ref)
    by_target: dict[str, list[tuple[str, bool, object]]] = {}
    for w in corpus.all():
        is_fork = TriggerFamily.FORK_REACHABLE in w.triggers
        for ref in w.reusable_uses:
            if not ref.secrets_inherit:
                continue
            by_target.setdefault(ref.target, []).append((w.filepath, is_fork, ref))

    for target, callers in by_target.items():
        unique_caller_files = {c[0] for c in callers}
        n_inherit = len(unique_caller_files)
        any_fork_caller = any(c[1] for c in callers)

        if n_inherit < _FANOUT_THRESHOLD and not any_fork_caller:
            continue

        # Pick the citation point.  For local refs, find the actual
        # reusable file in the corpus so the finding lands on the
        # hub itself.  For cross-repo refs, fall back to the first
        # caller (we can't introspect the target).
        cite_file = None
        cite_line = 1
        if target.startswith("./"):
            target_path = target.removeprefix("./")
            for w in corpus.all():
                # WorkflowSummary.filepath is absolute; match on the
                # canonical-relative suffix.  Normalise the filepath
                # side to forward slashes before comparing — on Windows
                # ``os.path.join`` produces ``\``-separated paths but
                # the YAML ``uses:`` ref always uses ``/``, so a naïve
                # endswith fails.
                if w.filepath.replace("\\", "/").endswith(target_path):
                    cite_file = w.filepath
                    cite_line = 1
                    break
        if cite_file is None:
            # Cross-repo or missing-local — cite the first caller.
            cite_file = callers[0][0]
            # Use the ref's line for the caller-side citation.
            ref0 = callers[0][2]
            cite_line = getattr(ref0, "line", 1)

        caller_basenames = sorted({c[0].rsplit("/", 1)[-1] for c in callers})
        callers_summary = ", ".join(caller_basenames[:5])
        if len(caller_basenames) > 5:
            callers_summary += f" (+{len(caller_basenames) - 5} more)"

        if any_fork_caller:
            shape = "FORK-REACHABLE caller passes secrets: inherit"
        else:
            shape = f"{n_inherit} callers all pass secrets: inherit (>= fanout threshold)"

        snippet = (
            f"reusable workflow target '{target}' is a fanout hub: "
            f"{shape}. callers: {callers_summary}. "
            "Compromise of the hub or its sub-actions exposes the union "
            "of all callers' secrets."
        )
        findings.append((cite_file, cite_line, snippet))
    return findings


RULES.append(
    Rule(
        id="XF-GH-003",
        title="Reusable-workflow fanout hub (secrets: inherit)",
        severity=Severity.MEDIUM,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-2",
        description=(
            "A reusable workflow is called from many caller workflows, "
            "each passing `secrets: inherit`.  At runtime the reusable "
            "workflow holds the UNION of every caller's secret scope — "
            "repo secrets, environment secrets, and inherited org "
            "secrets.  Two failure modes amplify each other: "
            "(1) a malicious commit (or compromised SHA reference) to "
            "the reusable workflow can read or exfiltrate the union of "
            "all callers' secrets; "
            "(2) when even ONE caller is fork-reachable "
            "(pull_request_target / issue_comment) and uses "
            "`secrets: inherit`, the reusable workflow runs with that "
            "caller's full secret scope on attacker-triggered events — "
            "turning the hub into a PR-controlled secret-leak "
            "primitive.  The fix is to drop `secrets: inherit` and "
            "instead pass per-secret `secrets: { NAME: ${{ secrets.NAME "
            "}} }` mappings, narrowing each caller's scope to exactly "
            "the secrets the reusable workflow actually needs."
        ),
        pattern=CorpusPattern(callback=_xf_gh_003_callback),
        remediation=(
            "Replace `secrets: inherit` with an explicit per-secret\n"
            "mapping in each caller:\n"
            "    uses: ./.github/workflows/build.yml\n"
            "    secrets:\n"
            "      DEPLOY_KEY: ${{ secrets.DEPLOY_KEY }}\n"
            "      NPM_TOKEN: ${{ secrets.NPM_TOKEN }}\n"
            "Audit each caller's mapping to confirm the reusable\n"
            "workflow only receives the secrets it genuinely needs.\n"
            "Run `taintly --guide XF-GH-003` for the full checklist."
        ),
        reference=(
            "https://docs.github.com/en/actions/sharing-automations/reusing-workflows#"
            "passing-inputs-and-secrets-to-a-reusable-workflow; "
            "https://github.blog/changelog/2022-05-03-github-actions-simplify-using-secrets-with-reusable-workflows/"
        ),
        test_positive=[],
        test_negative=[],
        stride=["I", "E"],
        threat_narrative=(
            "An attacker who gains commit rights to the reusable "
            "workflow file (or who tags a malicious commit at a ref "
            "any caller pins to) can add a step that exfiltrates "
            "${{ secrets.* }} via curl-to-paste-bin.  The exfil step "
            "runs once per caller invocation, with the caller's full "
            "inherited secret scope.  Across N callers, the attacker "
            "harvests the union — release tokens, deployment keys, "
            "npm publish credentials, environment-scoped secrets — "
            "all from one compromise of the hub."
        ),
        confidence="medium",
        review_needed=True,
        finding_family="identity_access",
    )
)


# ---------------------------------------------------------------------------
# XF-GH-004 — PWN-request shape (pull_request_target + reusable + write)
# ---------------------------------------------------------------------------

# Events that GRANT THE WORKFLOW write permissions and inject secrets
# despite running in response to a PR.  These are the "pwn-request"
# class per GitHub Security Lab — they evaluate the workflow definition
# from the BASE repo (so an attacker can't change it via PR), but the
# workflow runs against attacker-controlled inputs (PR title, body,
# branch ref, file contents) with full repo write context.
#
# The threat:
#   1. Maintainer's main branch carries a workflow with one of these
#      events that calls a reusable workflow.
#   2. The reusable workflow either declares `permissions: write-*`
#      OR the caller passes `secrets: inherit`.
#   3. An attacker opens a PR (or posts a triggering comment) that
#      reaches the reusable workflow with the maintainer's write
#      context — privileged operations under attacker influence.
#
# `pull_request` is NOT in this set: it runs on the FORK's commit
# with a read-only GITHUB_TOKEN by default and no secret injection,
# so the reusable workflow inherits no privileged context.
_PWN_REQUEST_EVENTS: frozenset[str] = frozenset(
    {
        "pull_request_target",
        "issue_comment",
        "pull_request_review",
        "pull_request_review_comment",
        # workflow_run is dual-natured: when the parent is fork-reachable
        # it carries the same risk profile (the parent's PR commit
        # appears in github.event.workflow_run).  We include it
        # conservatively.
        "workflow_run",
    }
)


def _permission_block_has_write(block: object) -> bool:
    """Return True when a :class:`PermissionBlock` grants any write
    capability.  ``write-all`` and any ``key: write`` grant qualify;
    ``read-all`` and the empty-mapping deny-default do not.
    """
    if block is None:
        return False
    if getattr(block, "is_write_all", False):
        return True
    grants = getattr(block, "grants", {}) or {}
    return any(v == "write" for v in grants.values())


def _xf_gh_004_callback(corpus: WorkflowCorpus) -> CorpusFindings:
    """Detect the canonical "pwn-request" shape across two workflows.

    Match rule:

      * Caller workflow W has at least one event in
        :data:`_PWN_REQUEST_EVENTS` (``pull_request_target``,
        ``issue_comment``, ``pull_request_review``,
        ``pull_request_review_comment``, ``workflow_run``).  These
        events run with write context and inject secrets.
      * W contains a reusable ``uses:`` reference (corpus.reusable_uses).
      * The target reusable workflow holds privileged context, via
        EITHER:
          - the caller passes ``secrets: inherit``, OR
          - the target is a LOCAL reusable file in the corpus AND
            its workflow-level ``permissions:`` block grants any
            ``write`` capability (or ``write-all``).

    Cross-repo reusable refs whose target file isn't in the corpus
    fall back to the ``secrets: inherit`` signal alone — we can't
    introspect the cross-repo workflow's permissions block.

    The finding cites the CALLER's ``uses:`` line because the caller
    is the attacker handle: removing or hardening the
    ``pull_request_target`` trigger or the ``secrets: inherit`` /
    write-permission grant breaks the chain.
    """
    findings: CorpusFindings = []
    seen: set[tuple[str, int]] = set()

    for caller in corpus.all():
        if not (caller.raw_event_names & _PWN_REQUEST_EVENTS):
            continue

        for ref in caller.reusable_uses:
            # Determine the privileged-context signal.
            grants_write = False
            target_file = ""
            if ref.is_local:
                # Match the local file in the corpus to inspect its
                # workflow-level permissions block.  Normalise the
                # filepath side to forward slashes before comparing —
                # ``os.path.join`` produces ``\``-separated paths on
                # Windows but the YAML-derived ``ref.workflow_path``
                # always uses ``/``, so a naïve endswith fails on
                # Windows.
                for w in corpus.all():
                    if w.filepath.replace("\\", "/").endswith(ref.workflow_path):
                        target_file = w.filepath
                        if _permission_block_has_write(w.workflow_permissions):
                            grants_write = True
                        # Per-job permission block can also grant write.
                        for jp in w.job_permissions:
                            if _permission_block_has_write(jp):
                                grants_write = True
                                break
                        break

            privileged = grants_write or ref.secrets_inherit
            if not privileged:
                continue

            key = (caller.filepath, ref.line)
            if key in seen:
                continue
            seen.add(key)

            event_hits = sorted(caller.raw_event_names & _PWN_REQUEST_EVENTS)
            event_str = ", ".join(event_hits)
            if grants_write and ref.secrets_inherit:
                signal = "reusable holds write permissions AND caller passes secrets: inherit"
            elif grants_write:
                signal = (
                    f"reusable workflow ({target_file}) holds workflow- or "
                    "job-level write permissions"
                )
            else:
                signal = "caller passes secrets: inherit to the reusable workflow"

            snippet = (
                f"PWN-request shape: caller fires on {{{event_str}}} (write context "
                f"+ secret injection) and invokes reusable '{ref.target}' — {signal}. "
                f"An attacker-triggered PR / comment reaches the reusable workflow "
                f"with the caller's privileged context."
            )
            # Title names the event(s) that ACTUALLY fired rather than a
            # hardcoded ``pull_request_target`` — an issue_comment- or
            # workflow_run-triggered caller would otherwise be mislabelled
            # in the report, sending the analyst looking for a
            # pull_request_target trigger that isn't there.
            title = f"PWN-request shape: {event_str} caller invokes write-context reusable"
            findings.append((caller.filepath, ref.line, snippet, title))
    return findings


RULES.append(
    Rule(
        id="XF-GH-004",
        # Static fallback title — event-agnostic so it never misreports
        # the trigger. The callback emits a per-finding title naming the
        # specific event(s) that fired (pull_request_target / issue_comment
        # / workflow_run / …); this constant is only used if that override
        # is ever dropped.
        title="PWN-request shape: write-context caller invokes write-context reusable",
        severity=Severity.HIGH,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-4",
        description=(
            "A workflow uses an event that grants WRITE context with "
            "secret injection (`pull_request_target`, `issue_comment`, "
            "`pull_request_review`, `pull_request_review_comment`, or "
            "`workflow_run`) and invokes a reusable workflow that "
            "holds privileged scope — either through a write-granting "
            "`permissions:` block or via `secrets: inherit`.  This is "
            "the canonical 'pwn-request' shape documented by GitHub "
            "Security Lab: an attacker who can fire the event (anyone "
            "with a PR or a comment) reaches the reusable workflow "
            "with the maintainer's write context, turning the chain "
            "into a primitive for privileged side-effects (writing to "
            "main, posting comments as the bot, force-pushing tags, "
            "exfiltrating secrets).  The fix is to narrow the trigger "
            "(use plain `pull_request` for fork-author CI, gate "
            "`pull_request_target` jobs by same-repo identity), drop "
            "`secrets: inherit` in favour of explicit per-secret "
            "mappings, and audit the reusable workflow's `permissions:` "
            "block to remove any unneeded write capability."
        ),
        pattern=CorpusPattern(callback=_xf_gh_004_callback),
        remediation=(
            "Pick one of:\n"
            "  1. Switch the caller's trigger from `pull_request_target`\n"
            "     to plain `pull_request` — the latter runs on the\n"
            "     fork's commit with a read-only GITHUB_TOKEN.\n"
            "  2. Gate the privileged job by same-repo identity:\n"
            "       if: github.event.pull_request.head.repo.full_name\n"
            "           == github.repository\n"
            "  3. Replace `secrets: inherit` with an explicit per-secret\n"
            "     mapping that excludes high-impact secrets.\n"
            "  4. Drop `permissions: write-all` from the reusable\n"
            "     workflow and grant only the specific scopes it needs.\n"
            "Run `taintly --guide XF-GH-004` for the full checklist."
        ),
        reference=(
            "https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/; "
            "https://docs.github.com/en/actions/writing-workflows/choosing-when-workflows-run/"
            "events-that-trigger-workflows#pull_request_target"
        ),
        test_positive=[],
        test_negative=[],
        stride=["E", "T", "I"],
        threat_narrative=(
            "An attacker opens a PR against the maintainer repo.  The "
            "PR triggers a `pull_request_target` workflow that calls a "
            "reusable workflow with `secrets: inherit`.  The reusable "
            "workflow runs against the attacker's PR ref but with the "
            "maintainer's write GITHUB_TOKEN and full secret scope.  "
            "If the reusable workflow checks out the PR ref via "
            "`actions/checkout@v4 with: { ref: ${{ github.event.pull_request.head.sha }} }` "
            "and runs anything build-related, it now executes the "
            "attacker's code with maintainer permissions — direct "
            "code-execution against the base repo."
        ),
        confidence="medium",
        # The combination is narrow enough to fire as a confirmed risk;
        # not review_needed.  Wild-scan validation pending.
        review_needed=False,
        finding_family="privileged_pr_trigger",
    )
)

# XF-GH-005 — configured local input flow with per-path execution evidence.
# ---------------------------------------------------------------------------


def _xf_gh_005_callback(corpus: WorkflowCorpus) -> CorpusFindings:
    """Caller -> reusable-workflow -> sink candidates with source evidence.

    TAINT-GH-006 flags the callee side (a reusable workflow uses
    ``${{ inputs.X }}`` — review-needed, the caller is unknown).
    TAINT-GH-007 flags the caller side (a ``with:`` arg looks
    attacker-controlled — review-needed, the callee is unknown).
    Invocation traversal joins these halves across local workflow/action
    calls. Known contracts, events, guards and shell source uses establish
    a configured byte path. Unresolved contracts or execution semantics
    retain explicit review state; token grants and secrets are separate.

    The finding is cited at the caller's ``uses:`` line — that is
    where the maintainer acts (stop forwarding the attacker context,
    or sanitise it before the call).
    """
    findings: CorpusFindings = []
    for flow in find_cross_file_taint(corpus):
        chain = " -> ".join(f"{os.path.basename(c)}:{ln}" for c, ln, _ in flow.hop_chain)
        snippet = (
            f"{flow.source_expr} forwarded via {chain} into "
            f"{os.path.basename(flow.callee)} input '{flow.input}', "
            f"reaching sink {os.path.basename(flow.callee)}:"
            f"{flow.sink_line}: {flow.sink_snippet}"
        )
        findings.append(flow_evidence(flow, snippet))
    return findings


RULES.append(
    Rule(
        id="XF-GH-005",
        title="Configured cross-file input flow through a reusable workflow",
        severity=Severity.HIGH,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-4",
        description=(
            "A workflow passes an attacker-controlled GitHub context "
            "(`github.event.pull_request.title`, `github.head_ref`, "
            "an issue / comment / review body, ...) as a `with:` "
            "input to a local reusable workflow (`uses: "
            "./.github/workflows/X.yml`), and that reusable workflow "
            "launders the input through `env:` / `$GITHUB_ENV` / "
            "`$GITHUB_OUTPUT` / a declared output into a shell sink.\n"
            "\n"
            "TAINT-GH-006 and TAINT-GH-017 flag the callee side and "
            "TAINT-GH-007 the caller side — each as review-needed, "
            "because in isolation neither file proves the other "
            "half.  This rule closes the loop across the corpus: the "
            "caller forwards an attacker context and the callee has a "
            "configured shell-source or argument-use candidate. Each "
            "invocation carries its own event, inputs and source lines "
            "through local calls. Unknown guards, expression results "
            "and command reinterpretation remain review-needed. "
            "Resource limits produce incomplete-scan diagnostics."
        ),
        pattern=CorpusPattern(callback=_xf_gh_005_callback),
        remediation=(
            "Treat the forwarded context as untrusted at the call\n"
            "site: do not pass `github.event.*` / `github.head_ref`\n"
            "directly into a reusable workflow's `with:` inputs.\n"
            "Either sanitise / allow-list the value before the call,\n"
            "or change the reusable workflow to consume the input as\n"
            'quoted data (bind it to an env var, reference `"$VAR"`)\n'
            "rather than interpolating it into a shell command.  See\n"
            "TAINT-GH-006 / TAINT-GH-007 / TAINT-GH-017 for the\n"
            "single-file halves of this flow."
        ),
        reference="https://docs.github.com/en/actions/using-workflows/reusing-workflows",
        # CorpusPattern rule — exercised by tests/unit/test_cross_workflow_rules.py
        # (multi-file fixtures), not by single-YAML self-test samples.
        stride=["T", "E"],
        threat_narrative=(
            "An attacker opens a PR whose title is a shell payload.  "
            "A caller workflow forwards `github.event.pull_request."
            "title` straight into a reusable workflow's `with:` "
            "input, and the reusable workflow interpolates that "
            "input into a `run:` block. The configured path may execute "
            "attacker-supplied shell source if its input contract and guards "
            "permit it. Argument uses without established reinterpretation "
            "remain review-needed. Effective token grants and available secrets "
            "require separate evidence. The source and sink span local files."
        ),
        finding_family="User-controlled input reaching shell execution",
        confidence="medium",
    )
)
