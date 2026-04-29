"""Integration tests for the XF-GH-* cross-workflow rules.

CorpusPattern rules don't fit the single-file self-test harness
(positive/negative samples are full multi-file repos), so they're
tested here against tmp_path repos with realistic .github/workflows/
layouts.  Each test asserts both the positive case (rule fires) and
the relevant FP guard (rule does NOT fire when the precondition is
absent).
"""

from __future__ import annotations

from pathlib import Path

from taintly.engine import scan_repo
from taintly.models import Platform
from taintly.rules.registry import load_all_rules


def _write_workflow(tmp_path: Path, name: str, content: str) -> Path:
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True, exist_ok=True)
    p = wf_dir / name
    p.write_text(content)
    return p


def _xf_findings(tmp_path: Path, rule_id: str) -> list:
    rules = load_all_rules()
    reports = scan_repo(str(tmp_path), rules, Platform.GITHUB)
    return [f for r in reports for f in r.findings if f.rule_id == rule_id]


# ---------------------------------------------------------------------------
# XF-GH-001 — Cache poisoning across privilege tiers
# ---------------------------------------------------------------------------


def test_xf_gh_001_fires_on_fork_write_privileged_restore_key_match(tmp_path: Path) -> None:
    # Fork-reachable workflow writes a cache prefixed `linux-build-`.
    fork = _write_workflow(
        tmp_path,
        "pr.yml",
        "on: pull_request\n"
        "jobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: actions/cache@v3\n"
        "        with:\n"
        "          key: linux-build-${{ hashFiles('go.sum') }}\n"
        "          path: ~/.cache\n",
    )
    # Privileged workflow restores via the same prefix.
    privileged = _write_workflow(
        tmp_path,
        "release.yml",
        "on: push\n"
        "jobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: actions/cache/restore@v4\n"
        "        with:\n"
        "          key: linux-build-${{ github.sha }}\n"
        "          restore-keys: |\n"
        "            linux-build-\n"
        "            linux-\n"
        "          path: ~/.cache\n",
    )

    findings = _xf_findings(tmp_path, "XF-GH-001")
    assert len(findings) == 1
    # The finding fires on the privileged file (the receiving side).
    assert findings[0].file == str(privileged)
    # And the snippet cites the fork file's write location.
    assert "pr.yml" in findings[0].snippet
    assert findings[0].origin == "cross-workflow"
    # Cache-poisoning rule is review_needed=True.
    assert findings[0].review_needed is True
    # Smoke-test the fork is on disk for sanity.
    assert fork.exists()


def test_xf_gh_001_does_not_fire_when_no_fork_workflow(tmp_path: Path) -> None:
    # Two privileged workflows — no fork-reachable trigger exists,
    # so there's nothing to poison from.
    _write_workflow(
        tmp_path,
        "build.yml",
        "on: push\n"
        "jobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: actions/cache@v3\n"
        "        with:\n"
        "          key: linux-build-${{ github.sha }}\n",
    )
    _write_workflow(
        tmp_path,
        "release.yml",
        "on: push\n"
        "jobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: actions/cache/restore@v4\n"
        "        with:\n"
        "          key: linux-build-x\n"
        "          restore-keys: linux-build-\n",
    )
    assert _xf_findings(tmp_path, "XF-GH-001") == []


def test_xf_gh_001_does_not_fire_when_prefixes_disjoint(tmp_path: Path) -> None:
    # Fork prefix `pr-build-` and privileged prefix `linux-build-`
    # don't overlap — restore-keys won't match the fork's writes.
    _write_workflow(
        tmp_path,
        "pr.yml",
        "on: pull_request\n"
        "jobs:\n  b:\n    steps:\n"
        "      - uses: actions/cache@v3\n"
        "        with:\n          key: pr-build-${{ github.sha }}\n",
    )
    _write_workflow(
        tmp_path,
        "release.yml",
        "on: push\n"
        "jobs:\n  b:\n    steps:\n"
        "      - uses: actions/cache/restore@v4\n"
        "        with:\n"
        "          key: linux-build-x\n"
        "          restore-keys: linux-build-\n",
    )
    assert _xf_findings(tmp_path, "XF-GH-001") == []


def test_xf_gh_001_fires_on_dual_trigger_workflow(tmp_path: Path) -> None:
    """The dominant real-world cache-poisoning shape: ONE workflow
    file `on: [push, pull_request]` runs on both trigger types and
    shares the cache namespace.  The PR-event run writes, the
    push-event run reads — the rule MUST fire on this case.

    Adnan Khan (2024) documents this as the primary cache-poisoning
    pattern.  An earlier version of this rule wrongly skipped
    dual-trigger workflows; the wild scan against flask, transformers,
    and openai-cookbook produced 0 hits exactly because of that
    guard.  Removing the guard recovers all the real-world TPs.

    The cache block carries ``restore-keys:`` because the practically
    reachable cross-privilege poisoning chain depends on prefix-match
    restoration — the rule's gate skips exact-match-only caches.
    """
    wf = _write_workflow(
        tmp_path,
        "tests.yml",
        "on: [push, pull_request]\n"
        "jobs:\n  b:\n    steps:\n"
        "      - uses: actions/cache@v3\n"
        "        with:\n"
        "          key: mypy|${{ hashFiles('pyproject.toml') }}\n"
        "          restore-keys: mypy|\n"
        "          path: ./.mypy_cache\n",
    )
    findings = _xf_findings(tmp_path, "XF-GH-001")
    assert len(findings) == 1
    assert findings[0].file == str(wf)


def test_xf_gh_001_skips_template_at_start_of_restore_key(tmp_path: Path) -> None:
    # Privileged restore-key starts with `${{ ... }}` so its literal
    # prefix is empty — we can't reason about it, so don't fire.
    _write_workflow(
        tmp_path,
        "pr.yml",
        "on: pull_request\n"
        "jobs:\n  b:\n    steps:\n"
        "      - uses: actions/cache@v3\n"
        "        with:\n          key: shared-${{ github.sha }}\n",
    )
    _write_workflow(
        tmp_path,
        "main.yml",
        "on: push\n"
        "jobs:\n  b:\n    steps:\n"
        "      - uses: actions/cache/restore@v4\n"
        "        with:\n"
        "          key: ${{ runner.os }}-x\n"
        "          restore-keys: ${{ runner.os }}-\n",
    )
    assert _xf_findings(tmp_path, "XF-GH-001") == []


def test_xf_gh_001_fires_on_bare_actions_cache_in_privileged_path(tmp_path: Path) -> None:
    # Privileged side uses bare `actions/cache@*` (not /restore@*) —
    # bare cache reads on miss, so the rule must include role="both"
    # on the read side.
    _write_workflow(
        tmp_path,
        "pr.yml",
        "on: pull_request\n"
        "jobs:\n  b:\n    steps:\n"
        "      - uses: actions/cache@v3\n"
        "        with:\n          key: linux-${{ github.sha }}\n",
    )
    privileged = _write_workflow(
        tmp_path,
        "main.yml",
        "on: push\n"
        "jobs:\n  b:\n    steps:\n"
        "      - uses: actions/cache@v3\n"
        "        with:\n"
        "          key: linux-deadbeef\n"
        "          restore-keys: linux-\n",
    )
    findings = _xf_findings(tmp_path, "XF-GH-001")
    assert len(findings) == 1
    assert findings[0].file == str(privileged)


def test_xf_gh_001_does_not_fire_on_save_only_in_privileged(tmp_path: Path) -> None:
    # Privileged side uses `actions/cache/save@*` — write only, no
    # read, so it can't restore an attacker's cache entry.
    _write_workflow(
        tmp_path,
        "pr.yml",
        "on: pull_request\n"
        "jobs:\n  b:\n    steps:\n"
        "      - uses: actions/cache@v3\n"
        "        with:\n          key: linux-${{ github.sha }}\n",
    )
    _write_workflow(
        tmp_path,
        "main.yml",
        "on: push\n"
        "jobs:\n  b:\n    steps:\n"
        "      - uses: actions/cache/save@v3\n"
        "        with:\n          key: linux-y\n",
    )
    assert _xf_findings(tmp_path, "XF-GH-001") == []


def test_xf_gh_001_does_not_fire_when_privileged_cache_has_no_restore_keys(
    tmp_path: Path,
) -> None:
    """Without ``restore-keys:``, GitHub requires an exact key match
    on restoration — the prefix-overlap chain this rule detects is
    not reachable, so no finding is emitted.
    """
    _write_workflow(
        tmp_path,
        "pr.yml",
        "on: pull_request\n"
        "jobs:\n  b:\n    steps:\n"
        "      - uses: actions/cache@v3\n"
        "        with:\n          key: linux-build-${{ github.sha }}\n",
    )
    _write_workflow(
        tmp_path,
        "release.yml",
        "on: push\n"
        "jobs:\n  b:\n    steps:\n"
        "      - uses: actions/cache/restore@v4\n"
        "        with:\n          key: linux-build-${{ github.sha }}\n",
    )
    assert _xf_findings(tmp_path, "XF-GH-001") == []


def test_xf_gh_001_does_not_fire_when_privileged_key_is_per_ref_scoped(
    tmp_path: Path,
) -> None:
    """Per-ref-scoped privileged-side keys (containing
    ``${{ github.ref }}``) draw from a runtime namespace partitioned
    by ref — the fork PR's writes land in a different keyspace and
    cannot overlap.
    """
    _write_workflow(
        tmp_path,
        "pr.yml",
        "on: pull_request\n"
        "jobs:\n  b:\n    steps:\n"
        "      - uses: actions/cache@v3\n"
        "        with:\n          key: docs-${{ hashFiles('docs/**') }}\n",
    )
    _write_workflow(
        tmp_path,
        "build-docs.yml",
        "on: push\n"
        "jobs:\n  b:\n    steps:\n"
        "      - uses: actions/cache/restore@v4\n"
        "        with:\n"
        "          key: docs-${{ github.ref }}-${{ hashFiles('docs/**') }}\n"
        "          restore-keys: docs-\n",
    )
    assert _xf_findings(tmp_path, "XF-GH-001") == []


def test_xf_gh_001_does_not_fire_when_fork_write_is_per_ref_scoped(
    tmp_path: Path,
) -> None:
    """Per-ref-scoped fork-side writes (key embeds
    ``${{ github.ref }}``) cannot poison main's namespace — the
    runtime keyspace is partitioned per-ref.
    """
    _write_workflow(
        tmp_path,
        "pr.yml",
        "on: pull_request\n"
        "jobs:\n  b:\n    steps:\n"
        "      - uses: actions/cache@v3\n"
        "        with:\n          key: linux-build-${{ github.ref }}\n",
    )
    _write_workflow(
        tmp_path,
        "release.yml",
        "on: push\n"
        "jobs:\n  b:\n    steps:\n"
        "      - uses: actions/cache/restore@v4\n"
        "        with:\n"
        "          key: linux-build-deadbeef\n"
        "          restore-keys: linux-build-\n",
    )
    assert _xf_findings(tmp_path, "XF-GH-001") == []


# ---------------------------------------------------------------------------
# XF-GH-001A — Executable-content cache poisoning (HIGH split)
# ---------------------------------------------------------------------------


def test_xf_gh_001a_fires_on_pnpm_store_cache(tmp_path: Path) -> None:
    """`pnpm-store-` matches the executable-cache allowlist —
    poisoning installs attacker-supplied package contents into the
    privileged build.  HIGH severity, no review_needed.
    """
    _write_workflow(
        tmp_path,
        "pr.yml",
        "on: pull_request\n"
        "jobs:\n  b:\n    steps:\n"
        "      - uses: actions/cache@v3\n"
        "        with:\n          key: pnpm-store-${{ hashFiles('pnpm-lock.yaml') }}\n",
    )
    privileged = _write_workflow(
        tmp_path,
        "release.yml",
        "on: push\n"
        "jobs:\n  b:\n    steps:\n"
        "      - uses: actions/cache/restore@v4\n"
        "        with:\n"
        "          key: pnpm-store-deadbeef\n"
        "          restore-keys: pnpm-store-\n",
    )
    a_findings = _xf_findings(tmp_path, "XF-GH-001A")
    generic_findings = _xf_findings(tmp_path, "XF-GH-001")
    assert len(a_findings) == 1
    assert a_findings[0].file == str(privileged)
    assert "executable-content cache" in a_findings[0].snippet
    assert a_findings[0].review_needed is False
    # The same match must NOT also fire the generic rule —
    # the high-blast-radius case is routed exclusively to XF-GH-001A.
    assert generic_findings == []


def test_xf_gh_001a_fires_on_node_modules_cache(tmp_path: Path) -> None:
    _write_workflow(
        tmp_path,
        "pr.yml",
        "on: pull_request\n"
        "jobs:\n  b:\n    steps:\n"
        "      - uses: actions/cache@v3\n"
        "        with:\n          key: linux-node_modules-${{ github.sha }}\n",
    )
    _write_workflow(
        tmp_path,
        "main.yml",
        "on: push\n"
        "jobs:\n  b:\n    steps:\n"
        "      - uses: actions/cache@v3\n"
        "        with:\n"
        "          key: linux-node_modules-x\n"
        "          restore-keys: linux-node_modules-\n",
    )
    assert len(_xf_findings(tmp_path, "XF-GH-001A")) == 1
    assert _xf_findings(tmp_path, "XF-GH-001") == []


def test_xf_gh_001a_does_not_fire_on_generic_cache(tmp_path: Path) -> None:
    """A `mypy|` prefix is not in the executable-cache allowlist —
    XF-GH-001A stays silent; XF-GH-001 (generic) fires.

    The cache block carries ``restore-keys:`` so the prefix-match
    poisoning chain is reachable — without it the rule's gate would
    skip the entry as exact-match-only.
    """
    _write_workflow(
        tmp_path,
        "tests.yml",
        "on: [push, pull_request]\n"
        "jobs:\n  b:\n    steps:\n"
        "      - uses: actions/cache@v3\n"
        "        with:\n"
        "          key: mypy|${{ hashFiles('pyproject.toml') }}\n"
        "          restore-keys: mypy|\n",
    )
    assert _xf_findings(tmp_path, "XF-GH-001A") == []
    assert len(_xf_findings(tmp_path, "XF-GH-001")) == 1


# ---------------------------------------------------------------------------
# XF-GH-002 — Concurrency-cancel cross-workflow
# ---------------------------------------------------------------------------


def test_xf_gh_002_fires_on_cross_workflow_group_collision(tmp_path: Path) -> None:
    fork = _write_workflow(
        tmp_path,
        "pr.yml",
        "on: pull_request\n"
        "concurrency:\n"
        "  group: deploy-${{ github.ref }}\n"
        "  cancel-in-progress: true\n"
        "jobs: {}\n",
    )
    privileged = _write_workflow(
        tmp_path,
        "release.yml",
        "on: push\n"
        "concurrency:\n"
        "  group: deploy-${{ github.ref }}\n"
        "  cancel-in-progress: true\n"
        "jobs: {}\n",
    )
    findings = _xf_findings(tmp_path, "XF-GH-002")
    assert len(findings) == 1
    assert findings[0].file == str(privileged)
    # The snippet cites the fork-side workflow.
    assert "pr.yml" in findings[0].snippet
    assert findings[0].review_needed is True
    assert fork.exists()


def test_xf_gh_002_fires_on_dual_trigger_workflow_with_static_group(tmp_path: Path) -> None:
    """Single workflow with `on: [push, pull_request]` and a STATIC
    concurrency group — the PR-event run shares the group with the
    in-progress push-event run and cancels it.

    Templates that scope by event (github.ref, github.run_id, etc.)
    are filtered by same_file_safe — see
    test_xf_gh_002_does_not_fire_when_group_scopes_by_event.
    """
    wf = _write_workflow(
        tmp_path,
        "ci.yml",
        "on: [push, pull_request]\n"
        "concurrency:\n"
        "  group: production-ci\n"
        "  cancel-in-progress: true\n"
        "jobs: {}\n",
    )
    findings = _xf_findings(tmp_path, "XF-GH-002")
    assert len(findings) == 1
    assert findings[0].file == str(wf)
    assert "this workflow's own fork-trigger run" in findings[0].snippet


def test_xf_gh_002_does_not_fire_when_group_scopes_by_event(tmp_path: Path) -> None:
    """Group templates containing scope-by-event tokens (github.ref,
    github.head_ref, github.run_id, github.event_name,
    github.event.pull_request.number, github.sha) resolve to
    different runtime values for PR-event vs push-event runs.  The
    dual-trigger collision the rule looks for doesn't actually happen
    — the author has scoped by event by design.

    Verified against pytorch's `${{ github.workflow }}-${{
    github.event.pull_request.number || github.sha }}` and react's
    `${{ github.workflow }}-${{ github.head_ref || github.run_id }}`
    in the wild scan.  Earlier draft fired on these and produced 57
    FPs; this guard reduced the cross-workflow concurrency rule to
    only the static-group cases.
    """
    for token in ("github.ref", "github.head_ref", "github.run_id", "github.event_name"):
        wf = tmp_path / ".github" / "workflows"
        if wf.exists():
            for f in wf.iterdir():
                f.unlink()
        _write_workflow(
            tmp_path,
            "ci.yml",
            f"on: [push, pull_request]\n"
            f"concurrency:\n"
            f"  group: ci-${{{{ {token} }}}}\n"
            f"  cancel-in-progress: true\n"
            f"jobs: {{}}\n",
        )
        assert _xf_findings(tmp_path, "XF-GH-002") == [], f"FP guard missed token {token!r}"


def test_xf_gh_002_does_not_fire_without_cancel_in_progress(tmp_path: Path) -> None:
    # Group collision exists but neither side has cancel-in-progress
    # set — the worst case is queueing, not cancellation.  Not a
    # security finding.
    _write_workflow(
        tmp_path,
        "pr.yml",
        "on: pull_request\nconcurrency:\n  group: shared\njobs: {}\n",
    )
    _write_workflow(
        tmp_path,
        "release.yml",
        "on: push\nconcurrency:\n  group: shared\njobs: {}\n",
    )
    assert _xf_findings(tmp_path, "XF-GH-002") == []


def test_xf_gh_002_does_not_fire_when_groups_disjoint(tmp_path: Path) -> None:
    _write_workflow(
        tmp_path,
        "pr.yml",
        "on: pull_request\n"
        "concurrency:\n  group: pr-${{ github.ref }}\n  cancel-in-progress: true\n"
        "jobs: {}\n",
    )
    _write_workflow(
        tmp_path,
        "release.yml",
        "on: push\n"
        "concurrency:\n  group: release-${{ github.ref }}\n  cancel-in-progress: true\n"
        "jobs: {}\n",
    )
    assert _xf_findings(tmp_path, "XF-GH-002") == []


def test_xf_gh_002_does_not_fire_for_two_privileged_workflows(tmp_path: Path) -> None:
    # Both workflows are privileged (push + release) — no fork side,
    # no security primitive.  Cancellation between two maintainer-
    # triggered runs is normal release-pipeline behaviour.
    _write_workflow(
        tmp_path,
        "release.yml",
        "on: push\nconcurrency:\n  group: deploy\n  cancel-in-progress: true\njobs: {}\n",
    )
    _write_workflow(
        tmp_path,
        "release-tag.yml",
        "on: release\nconcurrency:\n  group: deploy\n  cancel-in-progress: true\njobs: {}\n",
    )
    assert _xf_findings(tmp_path, "XF-GH-002") == []


def test_xf_gh_002_only_one_side_has_cancel_in_progress(tmp_path: Path) -> None:
    """Only the FORK side has cancel-in-progress — the privileged
    side won't auto-cancel itself, but a NEW fork run with that flag
    cancels the in-flight privileged run that lives in the same
    group lock.  Still a TP.
    """
    _write_workflow(
        tmp_path,
        "pr.yml",
        "on: pull_request\nconcurrency:\n  group: deploy\n  cancel-in-progress: true\njobs: {}\n",
    )
    privileged = _write_workflow(
        tmp_path,
        "release.yml",
        "on: push\nconcurrency:\n  group: deploy\njobs: {}\n",
    )
    findings = _xf_findings(tmp_path, "XF-GH-002")
    assert len(findings) == 1
    assert findings[0].file == str(privileged)
    assert "peer ref carries cancel-in-progress" in findings[0].snippet


def test_xf_gh_002_handles_job_level_concurrency(tmp_path: Path) -> None:
    # Concurrency can also be declared per-job; the corpus indexes
    # both scopes.  The rule must fire on either.
    _write_workflow(
        tmp_path,
        "pr.yml",
        "on: pull_request\n"
        "jobs:\n  build:\n    concurrency:\n      group: deploy-${{ github.ref }}\n"
        "      cancel-in-progress: true\n    steps: []\n",
    )
    _write_workflow(
        tmp_path,
        "release.yml",
        "on: push\n"
        "jobs:\n  release:\n    concurrency:\n      group: deploy-${{ github.ref }}\n"
        "      cancel-in-progress: true\n    steps: []\n",
    )
    findings = _xf_findings(tmp_path, "XF-GH-002")
    assert len(findings) == 1


# ---------------------------------------------------------------------------
# XF-GH-003 — Reusable-fanout hub
# ---------------------------------------------------------------------------


def test_xf_gh_003_fires_on_three_inherit_callers(tmp_path: Path) -> None:
    """Three caller workflows pass `secrets: inherit` to the same
    reusable target — the hub holds the union of all three callers'
    secret scopes.  Fires on the local reusable file.
    """
    hub = _write_workflow(
        tmp_path,
        "build.yml",
        "on:\n  workflow_call:\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps: []\n",
    )
    for caller_name in ("a.yml", "b.yml", "c.yml"):
        _write_workflow(
            tmp_path,
            caller_name,
            "on: push\njobs:\n  call:\n"
            "    uses: ./.github/workflows/build.yml\n"
            "    secrets: inherit\n",
        )
    findings = _xf_findings(tmp_path, "XF-GH-003")
    assert len(findings) == 1
    assert findings[0].file == str(hub)
    assert "fanout hub" in findings[0].snippet
    assert "3 callers" in findings[0].snippet


def test_xf_gh_003_fires_on_fork_reachable_inherit_caller(tmp_path: Path) -> None:
    """A SINGLE fork-reachable caller passing `secrets: inherit`
    is enough to fire — the reusable runs with full secret scope
    on PR events.
    """
    hub = _write_workflow(
        tmp_path,
        "deploy.yml",
        "on:\n  workflow_call:\njobs:\n  d:\n    runs-on: ubuntu-latest\n    steps: []\n",
    )
    _write_workflow(
        tmp_path,
        "pr.yml",
        "on: pull_request_target\njobs:\n  call:\n"
        "    uses: ./.github/workflows/deploy.yml\n"
        "    secrets: inherit\n",
    )
    findings = _xf_findings(tmp_path, "XF-GH-003")
    assert len(findings) == 1
    assert findings[0].file == str(hub)
    assert "FORK-REACHABLE" in findings[0].snippet


def test_xf_gh_003_does_not_fire_on_two_inherit_callers(tmp_path: Path) -> None:
    """Two callers is below the fanout threshold and not yet a
    meaningful blast-radius increase (a release + a preview deploy
    sharing one reusable build job is the common pattern)."""
    _write_workflow(
        tmp_path,
        "build.yml",
        "on:\n  workflow_call:\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps: []\n",
    )
    for caller in ("a.yml", "b.yml"):
        _write_workflow(
            tmp_path,
            caller,
            "on: push\njobs:\n  call:\n"
            "    uses: ./.github/workflows/build.yml\n"
            "    secrets: inherit\n",
        )
    assert _xf_findings(tmp_path, "XF-GH-003") == []


def test_xf_gh_003_does_not_fire_when_callers_use_explicit_secrets(tmp_path: Path) -> None:
    # Three callers but each pins specific secrets — no fanout-hub
    # risk; the reusable workflow only sees the explicitly-passed
    # secrets per caller.
    _write_workflow(
        tmp_path,
        "build.yml",
        "on:\n  workflow_call:\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps: []\n",
    )
    for caller in ("a.yml", "b.yml", "c.yml"):
        _write_workflow(
            tmp_path,
            caller,
            "on: push\njobs:\n  call:\n"
            "    uses: ./.github/workflows/build.yml\n"
            "    secrets:\n      DEPLOY_KEY: ${{ secrets.DEPLOY_KEY }}\n",
        )
    assert _xf_findings(tmp_path, "XF-GH-003") == []


def test_xf_gh_003_fires_on_cross_repo_reusable_with_inherit(tmp_path: Path) -> None:
    """Cross-repo reusable refs (org/repo/.github/workflows/X.yml@ref)
    can't be introspected, but the threshold rule still applies —
    fire on the first caller as the citation point.
    """
    for caller in ("a.yml", "b.yml", "c.yml"):
        _write_workflow(
            tmp_path,
            caller,
            "on: push\njobs:\n  call:\n"
            "    uses: octo-org/shared-actions/.github/workflows/build.yml@v2\n"
            "    secrets: inherit\n",
        )
    findings = _xf_findings(tmp_path, "XF-GH-003")
    assert len(findings) == 1
    # Cross-repo target — citation is the first caller (a.yml).
    assert findings[0].file.endswith("a.yml")
    assert "octo-org/shared-actions" in findings[0].snippet


def test_xf_gh_003_does_not_fire_on_no_callers(tmp_path: Path) -> None:
    # A reusable workflow alone in the corpus, no callers — nothing
    # to fan out from.
    _write_workflow(
        tmp_path,
        "build.yml",
        "on:\n  workflow_call:\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps: []\n",
    )
    assert _xf_findings(tmp_path, "XF-GH-003") == []


# ---------------------------------------------------------------------------
# XF-GH-004 — PWN-request shape
# ---------------------------------------------------------------------------


def test_xf_gh_004_fires_on_pull_request_target_with_inherit(tmp_path: Path) -> None:
    """Caller uses `pull_request_target` and passes `secrets: inherit`
    to a reusable workflow — the canonical pwn-request shape.
    """
    _write_workflow(
        tmp_path,
        "reusable.yml",
        "on:\n  workflow_call:\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps: []\n",
    )
    caller = _write_workflow(
        tmp_path,
        "pr-target.yml",
        "on: pull_request_target\n"
        "jobs:\n  call:\n"
        "    uses: ./.github/workflows/reusable.yml\n"
        "    secrets: inherit\n",
    )
    findings = _xf_findings(tmp_path, "XF-GH-004")
    assert len(findings) == 1
    # Citation lands on the CALLER (the attacker handle).
    assert findings[0].file == str(caller)
    assert "pull_request_target" in findings[0].snippet
    assert findings[0].review_needed is False


def test_xf_gh_004_fires_on_reusable_with_write_permissions(tmp_path: Path) -> None:
    """Caller uses `pull_request_target` and the LOCAL reusable file
    declares write permissions.  Even without `secrets: inherit`, the
    write-context inheritance is the privilege primitive.
    """
    _write_workflow(
        tmp_path,
        "reusable.yml",
        "on:\n  workflow_call:\n"
        "permissions:\n  contents: write\n  pull-requests: write\n"
        "jobs:\n  b:\n    runs-on: ubuntu-latest\n    steps: []\n",
    )
    caller = _write_workflow(
        tmp_path,
        "pr-target.yml",
        "on: pull_request_target\njobs:\n  call:\n    uses: ./.github/workflows/reusable.yml\n",
    )
    findings = _xf_findings(tmp_path, "XF-GH-004")
    assert len(findings) == 1
    assert findings[0].file == str(caller)
    assert "write permissions" in findings[0].snippet


def test_xf_gh_004_fires_on_issue_comment_caller(tmp_path: Path) -> None:
    """`issue_comment` is in the pwn-request event class — same risk
    profile as `pull_request_target`.
    """
    _write_workflow(
        tmp_path,
        "reusable.yml",
        "on:\n  workflow_call:\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps: []\n",
    )
    caller = _write_workflow(
        tmp_path,
        "comment.yml",
        "on: issue_comment\n"
        "jobs:\n  call:\n"
        "    uses: ./.github/workflows/reusable.yml\n"
        "    secrets: inherit\n",
    )
    findings = _xf_findings(tmp_path, "XF-GH-004")
    assert len(findings) == 1
    assert findings[0].file == str(caller)
    assert "issue_comment" in findings[0].snippet


def test_xf_gh_004_does_not_fire_on_plain_pull_request(tmp_path: Path) -> None:
    """`pull_request` (without `_target`) runs on the fork's commit
    with read-only GITHUB_TOKEN — NOT a pwn-request shape.
    """
    _write_workflow(
        tmp_path,
        "reusable.yml",
        "on:\n  workflow_call:\n"
        "permissions:\n  contents: write\n"
        "jobs:\n  b:\n    runs-on: ubuntu-latest\n    steps: []\n",
    )
    _write_workflow(
        tmp_path,
        "pr.yml",
        "on: pull_request\n"
        "jobs:\n  call:\n    uses: ./.github/workflows/reusable.yml\n    secrets: inherit\n",
    )
    assert _xf_findings(tmp_path, "XF-GH-004") == []


def test_xf_gh_004_does_not_fire_when_reusable_has_no_write(tmp_path: Path) -> None:
    """Caller is `pull_request_target` but the reusable file has only
    read permissions and no `secrets: inherit` — no privilege primitive
    in the call chain.
    """
    _write_workflow(
        tmp_path,
        "reusable.yml",
        "on:\n  workflow_call:\n"
        "permissions:\n  contents: read\n"
        "jobs:\n  b:\n    runs-on: ubuntu-latest\n    steps: []\n",
    )
    _write_workflow(
        tmp_path,
        "pr-target.yml",
        "on: pull_request_target\njobs:\n  call:\n    uses: ./.github/workflows/reusable.yml\n",
    )
    assert _xf_findings(tmp_path, "XF-GH-004") == []


def test_xf_gh_004_fires_on_cross_repo_reusable_with_inherit(tmp_path: Path) -> None:
    """Cross-repo reusable target — we can't introspect its
    permissions block, but `secrets: inherit` from a pwn-request
    caller is enough signal on its own.
    """
    caller = _write_workflow(
        tmp_path,
        "pr-target.yml",
        "on: pull_request_target\n"
        "jobs:\n  call:\n"
        "    uses: octo-org/shared/.github/workflows/build.yml@v1\n"
        "    secrets: inherit\n",
    )
    findings = _xf_findings(tmp_path, "XF-GH-004")
    assert len(findings) == 1
    assert findings[0].file == str(caller)


def test_xf_gh_004_does_not_fire_on_workflow_dispatch(tmp_path: Path) -> None:
    """Maintainer-triggered events (`workflow_dispatch` /
    `repository_dispatch`) are not in the pwn-request class — only
    pre-authorised actors fire them.
    """
    _write_workflow(
        tmp_path,
        "reusable.yml",
        "on:\n  workflow_call:\n"
        "permissions: write-all\n"
        "jobs:\n  b:\n    runs-on: ubuntu-latest\n    steps: []\n",
    )
    _write_workflow(
        tmp_path,
        "release.yml",
        "on: workflow_dispatch\n"
        "jobs:\n  call:\n"
        "    uses: ./.github/workflows/reusable.yml\n    secrets: inherit\n",
    )
    assert _xf_findings(tmp_path, "XF-GH-004") == []


def test_xf_gh_004_dedup_per_uses_line(tmp_path: Path) -> None:
    """Multiple jobs in the caller invoking the same reusable should
    surface ONE finding per `uses:` line (not per job).
    """
    _write_workflow(
        tmp_path,
        "reusable.yml",
        "on:\n  workflow_call:\n"
        "permissions:\n  contents: write\n"
        "jobs:\n  b:\n    runs-on: ubuntu-latest\n    steps: []\n",
    )
    _write_workflow(
        tmp_path,
        "pr-target.yml",
        "on: pull_request_target\n"
        "jobs:\n"
        "  a:\n    uses: ./.github/workflows/reusable.yml\n    secrets: inherit\n"
        "  b:\n    uses: ./.github/workflows/reusable.yml\n    secrets: inherit\n",
    )
    findings = _xf_findings(tmp_path, "XF-GH-004")
    # Two distinct `uses:` lines → two findings (one per attacker handle).
    # Same line repeated from many runs would dedup.
    assert len(findings) == 2


# ---------------------------------------------------------------------------
# Windows path-separator regression tests
# ---------------------------------------------------------------------------


def test_xf_gh_003_local_reusable_match_handles_windows_separators():
    """Regression: ``_xf_gh_003_callback`` matches a local reusable
    target file against ``WorkflowSummary.filepath`` via ``endswith``.
    On Windows, ``os.path.join`` produces ``\\``-separated paths but
    the YAML-derived target always uses ``/``, so the naïve
    ``endswith`` returned False even when the paths matched.

    Construct a synthetic corpus with a ``\\``-style filepath (which
    is what the loader produces on Windows) and confirm the rule
    fires regardless of host OS.
    """
    from taintly.rules.github.cross_workflow import _xf_gh_003_callback
    from taintly.workflow_corpus import (
        ReusableRef,
        TriggerFamily,
        WorkflowCorpus,
        WorkflowSummary,
    )

    caller = WorkflowSummary(
        filepath=r"C:\repo\.github\workflows\caller.yml",
        content="",
        lines=[""],
        triggers=frozenset({TriggerFamily.FORK_REACHABLE}),
        reusable_uses=(
            ReusableRef(
                target="./.github/workflows/build.yml",
                is_local=True,
                repo_path="",
                workflow_path=".github/workflows/build.yml",
                ref="",
                secrets_inherit=True,
                line=5,
            ),
        ),
    )
    # Multiple inherit-callers would normally be needed for the
    # fanout-threshold path, so add two more inherit callers and the
    # reusable target itself.
    extra_callers = [
        WorkflowSummary(
            filepath=rf"C:\repo\.github\workflows\extra-{i}.yml",
            content="",
            lines=[""],
            triggers=frozenset({TriggerFamily.PRIVILEGED}),
            reusable_uses=(
                ReusableRef(
                    target="./.github/workflows/build.yml",
                    is_local=True,
                    repo_path="",
                    workflow_path=".github/workflows/build.yml",
                    ref="",
                    secrets_inherit=True,
                    line=5,
                ),
            ),
        )
        for i in range(2)
    ]
    target = WorkflowSummary(
        filepath=r"C:\repo\.github\workflows\build.yml",
        content="",
        lines=[""],
    )

    corpus = WorkflowCorpus(
        repo_path=r"C:\repo",
        workflows={
            caller.filepath: caller,
            target.filepath: target,
            **{w.filepath: w for w in extra_callers},
        },
    )

    findings = _xf_gh_003_callback(corpus)
    # Local-reusable citation should land on the hub file (the target),
    # not the caller, despite the Windows-style filepath separators.
    assert any(f[0] == target.filepath for f in findings), (
        "_xf_gh_003_callback failed to match Windows-style filepath against "
        "forward-slash workflow_path; the endswith check is OS-specific."
    )


def test_xf_gh_004_local_reusable_match_handles_windows_separators():
    """Same regression as the XF-GH-003 test, but for the
    ``_xf_gh_004_callback`` PWN-request rule.  The rule looks up the
    local reusable target to inspect its ``workflow_permissions``;
    failing the endswith match silently turned a real PWN-request TP
    into an FN on Windows.
    """
    from taintly.rules.github.cross_workflow import _xf_gh_004_callback
    from taintly.workflow_corpus import (
        PermissionBlock,
        ReusableRef,
        TriggerFamily,
        WorkflowCorpus,
        WorkflowSummary,
    )

    caller = WorkflowSummary(
        filepath=r"C:\repo\.github\workflows\caller.yml",
        content="",
        lines=[""],
        triggers=frozenset({TriggerFamily.FORK_REACHABLE}),
        raw_event_names=frozenset({"pull_request_target"}),
        reusable_uses=(
            ReusableRef(
                target="./.github/workflows/build.yml",
                is_local=True,
                repo_path="",
                workflow_path=".github/workflows/build.yml",
                ref="",
                secrets_inherit=False,
                line=4,
            ),
        ),
    )
    # The reusable target carries a write-permission block, which is
    # the privileged-context signal the rule looks for.  Without the
    # endswith fix, the lookup fails on Windows and the rule misses
    # this finding.
    target = WorkflowSummary(
        filepath=r"C:\repo\.github\workflows\build.yml",
        content="",
        lines=[""],
        workflow_permissions=PermissionBlock(
            scope_what="workflow",
            is_write_all=False,
            is_read_all=False,
            grants={"contents": "write"},
            line=2,
        ),
    )

    corpus = WorkflowCorpus(
        repo_path=r"C:\repo",
        workflows={
            caller.filepath: caller,
            target.filepath: target,
        },
    )

    findings = _xf_gh_004_callback(corpus)
    assert findings, (
        "_xf_gh_004_callback failed to match Windows-style filepath against "
        "forward-slash workflow_path; the endswith check is OS-specific."
    )
    assert findings[0][0] == caller.filepath
    assert "write permissions" in findings[0][2]
