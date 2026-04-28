"""Tests for taintly.workflow_corpus — Phase B2 cross-file resolver.

The corpus is the data layer that cross-file rules consume.  Each
extractor is tested in isolation so a regression caused by an
adversarial workflow shape is attributed to a single extractor, not
to the whole corpus build.

Test groups:
  * trigger family — `_extract_raw_events` + `_classify_triggers`
  * cache refs — `_extract_cache_refs` + `_cache_key_prefix`
  * (concurrency / environment / reusable / permissions — added as
    each extractor lands)
  * loader — `build_corpus` walks `.github/workflows/`
"""

from __future__ import annotations

from pathlib import Path

from taintly.workflow_corpus import (
    CorpusPattern,
    TriggerFamily,
    _cache_key_prefix,
    _classify_triggers,
    _extract_cache_refs,
    _extract_concurrency_refs,
    _extract_environment_refs,
    _extract_job_permissions,
    _extract_raw_events,
    _extract_reusable_refs,
    _extract_workflow_permissions,
    _parse_yaml_bool,
    build_corpus,
)

# ---------------------------------------------------------------------------
# _extract_raw_events / _classify_triggers
# ---------------------------------------------------------------------------


def test_extract_raw_events_single_string():
    assert _extract_raw_events("on: pull_request\njobs: {}\n") == {"pull_request"}


def test_extract_raw_events_flow_list():
    assert _extract_raw_events("on: [push, pull_request]\njobs: {}\n") == {
        "push",
        "pull_request",
    }


def test_extract_raw_events_block_mapping_skips_event_options():
    """``branches:``, ``types:``, list items under ``schedule:`` must
    NOT be classified as event names — only first-level keys under
    ``on:`` are events.
    """
    content = (
        "on:\n"
        "  push:\n"
        "    branches: [main]\n"
        "  pull_request:\n"
        "    types: [opened, synchronize]\n"
        "  schedule:\n"
        "    - cron: '0 0 * * *'\n"
        "  workflow_dispatch:\n"
        "jobs: {}\n"
    )
    events = _extract_raw_events(content)
    assert events == {"push", "pull_request", "schedule", "workflow_dispatch"}


def test_extract_raw_events_returns_empty_when_absent():
    assert _extract_raw_events("name: foo\njobs: {}\n") == set()


def test_extract_raw_events_does_not_match_run_block_with_on_text():
    # A `run:` step that contains the literal text "on:" must not
    # false-match the workflow trigger anchor.
    content = "name: x\njobs:\n  x:\n    steps:\n      - run: echo on:\n"
    assert _extract_raw_events(content) == set()


def test_classify_triggers_pull_request_is_fork_reachable():
    out = _classify_triggers({"pull_request"})
    assert TriggerFamily.FORK_REACHABLE in out
    assert TriggerFamily.PRIVILEGED not in out


def test_classify_triggers_push_is_privileged():
    out = _classify_triggers({"push"})
    assert TriggerFamily.PRIVILEGED in out
    assert TriggerFamily.FORK_REACHABLE not in out


def test_classify_triggers_schedule_is_scheduled():
    assert _classify_triggers({"schedule"}) == frozenset({TriggerFamily.SCHEDULED})


def test_classify_triggers_workflow_dispatch_is_dispatch():
    assert _classify_triggers({"workflow_dispatch"}) == frozenset({TriggerFamily.DISPATCH})


def test_classify_triggers_handles_multiple_simultaneously():
    # A workflow can carry multiple trigger families at once.
    out = _classify_triggers({"pull_request", "push", "schedule"})
    assert {
        TriggerFamily.FORK_REACHABLE,
        TriggerFamily.PRIVILEGED,
        TriggerFamily.SCHEDULED,
    } <= out


def test_classify_triggers_workflow_run_is_fork_reachable():
    # workflow_run inherits its trigger reach from the parent —
    # classified as fork-reachable here so the corpus is conservative.
    assert TriggerFamily.FORK_REACHABLE in _classify_triggers({"workflow_run"})


# ---------------------------------------------------------------------------
# _cache_key_prefix
# ---------------------------------------------------------------------------


def test_cache_prefix_static_key():
    assert _cache_key_prefix("plain-static-key") == "plain-static-key"


def test_cache_prefix_with_template_in_middle():
    assert _cache_key_prefix("Linux-build-${{ hashFiles('go.sum') }}") == "Linux-build-"


def test_cache_prefix_template_at_start_yields_empty_prefix():
    assert _cache_key_prefix("${{ runner.os }}-build") == ""


def test_cache_prefix_multiple_templates():
    # First template terminates the prefix.
    assert _cache_key_prefix("v2-deps-${{ hashFiles('go.sum') }}-${{ runner.os }}") == "v2-deps-"


def test_cache_prefix_empty_string():
    assert _cache_key_prefix("") == ""


# ---------------------------------------------------------------------------
# _extract_cache_refs
# ---------------------------------------------------------------------------


def test_cache_refs_bare_actions_cache_is_both_role():
    # Bare actions/cache@* reads on miss AND writes on success — role
    # "both" so cross-file rules can include it on either side of the
    # write/read join.
    content = (
        "jobs:\n  build:\n    steps:\n"
        "      - uses: actions/cache@v3\n"
        "        with:\n"
        "          key: my-key\n"
        "          path: ~/.cache\n"
    )
    refs = _extract_cache_refs(content.splitlines())
    assert len(refs) == 1
    assert refs[0].key == "my-key"
    assert refs[0].role == "both"
    assert refs[0].prefix == "my-key"


def test_cache_refs_save_action_is_write_role():
    content = (
        "jobs:\n  b:\n    steps:\n"
        "      - uses: actions/cache/save@v3\n"
        "        with:\n          key: k\n"
    )
    assert _extract_cache_refs(content.splitlines())[0].role == "write"


def test_cache_refs_restore_action_is_read_role():
    content = (
        "jobs:\n  b:\n    steps:\n"
        "      - uses: actions/cache/restore@v4\n"
        "        with:\n          key: k\n"
    )
    assert _extract_cache_refs(content.splitlines())[0].role == "read"


def test_cache_refs_extracts_restore_keys_block_scalar():
    content = (
        "jobs:\n  b:\n    steps:\n"
        "      - uses: actions/cache@v3\n"
        "        with:\n"
        "          key: linux-build-${{ hashFiles('go.sum') }}\n"
        "          restore-keys: |\n"
        "            linux-build-\n"
        "            linux-\n"
    )
    refs = _extract_cache_refs(content.splitlines())
    assert refs[0].restore_keys == ("linux-build-", "linux-")
    assert refs[0].prefix == "linux-build-"


def test_cache_refs_extracts_step_with_name_first():
    # `- name: ...` followed by `uses: actions/cache/save@v3` is the
    # canonical "named step" shape.  The extractor must traverse past
    # the same-indent `with:` sibling without truncating at step_indent.
    content = (
        "jobs:\n  b:\n    steps:\n"
        "      - name: Save build cache\n"
        "        uses: actions/cache/save@v3\n"
        "        with:\n          key: my-prefix-${{ github.sha }}\n"
    )
    refs = _extract_cache_refs(content.splitlines())
    assert len(refs) == 1
    assert refs[0].key == "my-prefix-${{ github.sha }}"
    assert refs[0].prefix == "my-prefix-"


def test_cache_refs_multiple_steps_in_one_job():
    content = (
        "jobs:\n  b:\n    steps:\n"
        "      - uses: actions/cache@v3\n"
        "        with:\n          key: a\n"
        "      - uses: actions/cache/restore@v4\n"
        "        with:\n          key: b\n"
    )
    refs = _extract_cache_refs(content.splitlines())
    assert len(refs) == 2
    assert refs[0].key == "a"
    assert refs[0].role == "both"  # bare actions/cache@* = both
    assert refs[1].key == "b"
    assert refs[1].role == "read"


def test_cache_refs_skips_unrelated_uses():
    content = (
        "jobs:\n  b:\n    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "      - uses: actions/setup-node@v3\n"
    )
    assert _extract_cache_refs(content.splitlines()) == []


def test_cache_refs_no_with_block_yields_empty_key():
    # An action used without a with: block still produces a CacheRef
    # so cross-file rules can see the action exists; key/prefix are
    # empty so they won't false-match a literal prefix.
    content = "jobs:\n  b:\n    steps:\n      - uses: actions/cache@v3\n"
    refs = _extract_cache_refs(content.splitlines())
    assert len(refs) == 1
    assert refs[0].key == ""
    assert refs[0].prefix == ""


# ---------------------------------------------------------------------------
# _parse_yaml_bool
# ---------------------------------------------------------------------------


def test_parse_yaml_bool_true_synonyms():
    for v in ("true", "True", "TRUE", "yes", "YES", "on", "ON", "1", "'true'", '"yes"'):
        assert _parse_yaml_bool(v), f"{v!r} should parse as truthy"


def test_parse_yaml_bool_false_synonyms():
    for v in ("false", "no", "off", "0", "FALSE", "garbage", ""):
        assert not _parse_yaml_bool(v), f"{v!r} should parse as falsy"


# ---------------------------------------------------------------------------
# _extract_concurrency_refs
# ---------------------------------------------------------------------------


def test_concurrency_shorthand_workflow_level():
    refs = _extract_concurrency_refs(
        "on: push\nconcurrency: build-${{ github.ref }}\njobs: {}\n".splitlines()
    )
    assert len(refs) == 1
    assert refs[0].group == "build-${{ github.ref }}"
    assert refs[0].scope == "workflow"
    assert refs[0].cancel_in_progress is False


def test_concurrency_block_workflow_level_with_cancel_true():
    content = (
        "on: push\nconcurrency:\n"
        "  group: build-${{ github.ref }}\n"
        "  cancel-in-progress: true\n"
        "jobs: {}\n"
    )
    refs = _extract_concurrency_refs(content.splitlines())
    assert len(refs) == 1
    assert refs[0].group == "build-${{ github.ref }}"
    assert refs[0].cancel_in_progress is True
    assert refs[0].scope == "workflow"


def test_concurrency_job_level():
    content = (
        "on: push\njobs:\n"
        "  deploy:\n"
        "    concurrency:\n"
        "      group: prod-${{ github.ref }}\n"
        "      cancel-in-progress: false\n"
        "    steps: []\n"
    )
    refs = _extract_concurrency_refs(content.splitlines())
    assert len(refs) == 1
    assert refs[0].scope == "job"
    assert refs[0].cancel_in_progress is False


def test_concurrency_absent_yields_empty():
    assert _extract_concurrency_refs("on: push\njobs: {}\n".splitlines()) == []


def test_concurrency_multiple_blocks_workflow_and_job():
    content = (
        "on: push\nconcurrency: workflow-group\n"
        "jobs:\n"
        "  a:\n"
        "    concurrency:\n"
        "      group: job-a-group\n"
        "      cancel-in-progress: true\n"
        "    steps: []\n"
    )
    refs = _extract_concurrency_refs(content.splitlines())
    assert len(refs) == 2
    scopes = {r.scope for r in refs}
    assert scopes == {"workflow", "job"}


def test_concurrency_quoted_group_string_unquoted_in_extraction():
    # A YAML quoted scalar must have its surrounding quotes stripped
    # for cross-file string equality to work.
    content = "on: push\nconcurrency: 'release-${{ github.ref }}'\njobs: {}\n"
    refs = _extract_concurrency_refs(content.splitlines())
    assert refs[0].group == "release-${{ github.ref }}"


# ---------------------------------------------------------------------------
# _extract_environment_refs
# ---------------------------------------------------------------------------


def test_environment_inline_shorthand():
    content = "on: push\njobs:\n  deploy:\n    environment: production\n    steps: []\n"
    refs = _extract_environment_refs(content.splitlines())
    assert len(refs) == 1
    assert refs[0].name == "production"
    assert refs[0].name_normalized == "production"


def test_environment_block_mapping_with_name():
    content = (
        "on: push\njobs:\n  deploy:\n"
        "    environment:\n"
        "      name: Production\n"
        "      url: https://prod.example.com\n"
        "    steps: []\n"
    )
    refs = _extract_environment_refs(content.splitlines())
    assert len(refs) == 1
    assert refs[0].name == "Production"
    # Case-normalised — this is the join key for the aliasing rule.
    assert refs[0].name_normalized == "production"


def test_environment_case_aliasing_normalizes():
    """``Production`` vs ``production`` is the canonical aliasing
    shape. The corpus exposes the case-folded form so cross-file
    rules can match without re-implementing case-insensitive
    equality at every callsite.
    """
    content = (
        "jobs:\n"
        "  a:\n    environment: Production\n"
        "  b:\n    environment: production\n"
        "  c:\n    environment: PRODUCTION\n"
    )
    refs = _extract_environment_refs(content.splitlines())
    assert len(refs) == 3
    assert {r.name_normalized for r in refs} == {"production"}


def test_environment_multiple_jobs_emits_one_ref_each():
    content = (
        "jobs:\n"
        "  staging:\n    environment: staging\n"
        "  prod:\n    environment:\n      name: production\n"
    )
    refs = _extract_environment_refs(content.splitlines())
    assert {r.name for r in refs} == {"staging", "production"}


def test_environment_quoted_name_unquoted():
    content = "jobs:\n  d:\n    environment: 'Production'\n"
    refs = _extract_environment_refs(content.splitlines())
    assert refs[0].name == "Production"


def test_environment_absent_returns_empty():
    assert _extract_environment_refs("on: push\njobs:\n  b:\n    steps: []\n".splitlines()) == []


# ---------------------------------------------------------------------------
# _extract_reusable_refs
# ---------------------------------------------------------------------------


def test_reusable_local_ref():
    content = "on: push\njobs:\n  call:\n    uses: ./.github/workflows/reusable.yml\n"
    refs = _extract_reusable_refs(content.splitlines())
    assert len(refs) == 1
    assert refs[0].is_local is True
    assert refs[0].repo_path == ""
    assert refs[0].workflow_path == ".github/workflows/reusable.yml"
    assert refs[0].ref == ""


def test_reusable_cross_repo_ref_with_sha():
    content = (
        "on: push\njobs:\n  call:\n"
        "    uses: octo-org/octo-repo/.github/workflows/build.yml@deadbeef\n"
    )
    refs = _extract_reusable_refs(content.splitlines())
    assert len(refs) == 1
    assert refs[0].is_local is False
    assert refs[0].repo_path == "octo-org/octo-repo"
    assert refs[0].workflow_path == ".github/workflows/build.yml"
    assert refs[0].ref == "deadbeef"


def test_reusable_secrets_inherit_detected():
    content = (
        "on: push\njobs:\n  call:\n"
        "    uses: octo-org/octo/.github/workflows/x.yml@v1\n"
        "    secrets: inherit\n"
    )
    refs = _extract_reusable_refs(content.splitlines())
    assert len(refs) == 1
    assert refs[0].secrets_inherit is True


def test_reusable_secrets_inherit_absent_when_not_set():
    content = (
        "on: push\njobs:\n  call:\n"
        "    uses: octo-org/octo/.github/workflows/x.yml@v1\n"
        "    with:\n      foo: bar\n"
    )
    refs = _extract_reusable_refs(content.splitlines())
    assert refs[0].secrets_inherit is False


def test_reusable_does_not_match_step_level_action_uses():
    """``uses: actions/checkout@v4`` is an ACTION call, not a reusable
    workflow.  The .yml suffix requirement of the regex filters it out;
    additionally the in-steps-block detector belt-and-braces guards
    against any future regex shape that would accidentally accept it.
    """
    content = (
        "on: push\njobs:\n  build:\n    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "      - uses: my-org/my-action@v1\n"
    )
    assert _extract_reusable_refs(content.splitlines()) == []


def test_reusable_skips_step_level_yml_uses():
    """Even an action ref that happened to point at a .yml file under
    a steps: block must not be classified as a reusable workflow —
    the parent context determines the meaning.
    """
    content = (
        "on: push\njobs:\n  build:\n    steps:\n"
        "      - uses: ./.github/workflows/local-action.yml\n"
    )
    # If a future change loosens the regex to allow YAML-suffix step
    # uses, the in-steps detector still catches it.
    assert _extract_reusable_refs(content.splitlines()) == []


def test_reusable_mixed_action_and_reusable_one_workflow():
    content = (
        "on: push\njobs:\n"
        "  build:\n    steps:\n      - uses: actions/checkout@v4\n"
        "  call:\n    uses: ./.github/workflows/x.yml\n    secrets: inherit\n"
    )
    refs = _extract_reusable_refs(content.splitlines())
    assert len(refs) == 1
    assert refs[0].is_local is True
    assert refs[0].secrets_inherit is True


# ---------------------------------------------------------------------------
# _extract_workflow_permissions / _extract_job_permissions
# ---------------------------------------------------------------------------


def test_workflow_permissions_write_all_shorthand():
    block = _extract_workflow_permissions(
        "on: push\npermissions: write-all\njobs: {}\n".splitlines()
    )
    assert block is not None
    assert block.is_write_all is True
    assert block.is_read_all is False
    assert block.grants == {}


def test_workflow_permissions_read_all_shorthand():
    block = _extract_workflow_permissions(
        "on: push\npermissions: read-all\njobs: {}\n".splitlines()
    )
    assert block is not None
    assert block.is_read_all is True


def test_workflow_permissions_block_mapping():
    content = (
        "on: push\npermissions:\n"
        "  contents: write\n"
        "  id-token: write\n"
        "  pull-requests: read\n"
        "jobs: {}\n"
    )
    block = _extract_workflow_permissions(content.splitlines())
    assert block is not None
    assert block.grants == {
        "contents": "write",
        "id-token": "write",
        "pull-requests": "read",
    }


def test_workflow_permissions_empty_mapping_means_deny_default():
    block = _extract_workflow_permissions("on: push\npermissions: {}\njobs: {}\n".splitlines())
    # The empty form is "deny everything" per GitHub Actions semantics —
    # represented by no flags and no grants.  Cross-file rules can
    # distinguish this from "absent" via the None vs PermissionBlock
    # return shape.
    assert block is not None
    assert block.is_write_all is False
    assert block.is_read_all is False
    assert block.grants == {}


def test_workflow_permissions_absent_returns_none():
    assert _extract_workflow_permissions("on: push\njobs: {}\n".splitlines()) is None


def test_job_permissions_per_job_block():
    content = (
        "on: push\njobs:\n"
        "  build:\n"
        "    permissions:\n"
        "      contents: write\n"
        "      packages: write\n"
        "    steps: []\n"
        "  deploy:\n"
        "    permissions: read-all\n"
        "    steps: []\n"
    )
    blocks = _extract_job_permissions(content.splitlines())
    by_scope = {b.scope_what: b for b in blocks}
    assert by_scope["build"].grants == {"contents": "write", "packages": "write"}
    assert by_scope["deploy"].is_read_all is True


def test_job_permissions_does_not_pick_up_workflow_level():
    content = "on: push\npermissions:\n  contents: read\njobs:\n  build:\n    steps: []\n"
    # The workflow-level permissions block must NOT appear in the
    # job-level extractor's output.
    assert _extract_job_permissions(content.splitlines()) == []


# ---------------------------------------------------------------------------
# build_corpus loader
# ---------------------------------------------------------------------------


def test_build_corpus_walks_workflows_dir(tmp_path: Path) -> None:
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "ci.yml").write_text("on: push\njobs: {}\n")
    (wf_dir / "release.yaml").write_text("on: release\njobs: {}\n")
    (wf_dir / "README.md").write_text("not a workflow\n")  # ignored

    corpus = build_corpus(str(tmp_path))
    assert len(corpus.workflows) == 2
    assert all(p.endswith((".yml", ".yaml")) for p in corpus.workflows)


def test_build_corpus_no_workflows_dir_returns_empty(tmp_path: Path) -> None:
    corpus = build_corpus(str(tmp_path))
    assert corpus.workflows == {}
    assert corpus.repo_path == str(tmp_path)


def test_build_corpus_indexes_triggers_per_workflow(tmp_path: Path) -> None:
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "fork.yml").write_text("on: pull_request\njobs: {}\n")
    (wf_dir / "main.yml").write_text("on: push\njobs: {}\n")

    corpus = build_corpus(str(tmp_path))
    fork_only = corpus.by_trigger(TriggerFamily.FORK_REACHABLE)
    privileged_only = corpus.by_trigger(TriggerFamily.PRIVILEGED)
    assert {Path(w.filepath).name for w in fork_only} == {"fork.yml"}
    assert {Path(w.filepath).name for w in privileged_only} == {"main.yml"}


def test_build_corpus_indexes_cache_refs_per_workflow(tmp_path: Path) -> None:
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "x.yml").write_text(
        "on: push\n"
        "jobs:\n  b:\n    steps:\n"
        "      - uses: actions/cache@v3\n"
        "        with:\n          key: shared-${{ github.sha }}\n"
    )

    corpus = build_corpus(str(tmp_path))
    summary = next(iter(corpus.workflows.values()))
    assert len(summary.cache_keys) == 1
    assert summary.cache_keys[0].prefix == "shared-"


def test_build_corpus_handles_unreadable_file_silently(tmp_path: Path) -> None:
    # A file the loader can't read should not raise; the per-file
    # scan path will already have emitted ENGINE-ERR for the same
    # file in the same run.
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    bad = wf_dir / "bad.yml"
    bad.write_text("on: push\njobs: {}\n")
    bad.chmod(0o000)
    try:
        corpus = build_corpus(str(tmp_path))
    finally:
        bad.chmod(0o644)
    # Either present (root could read) or absent (perm denied) is fine —
    # what matters is no exception bubbled.
    assert corpus.repo_path == str(tmp_path)


# ---------------------------------------------------------------------------
# CorpusPattern + engine integration
# ---------------------------------------------------------------------------


def test_corpus_pattern_check_returns_empty_for_per_file_path():
    """The per-file scan path must skip CorpusPattern rules cleanly —
    `check()` returns an empty list so existing scan_file machinery
    is a no-op for these rules.
    """
    pat = CorpusPattern(callback=lambda _corpus: [])
    assert pat.check("anything", ["anything"]) == []


def test_corpus_pattern_check_corpus_invokes_callback():
    seen: list[object] = []

    def cb(corpus):
        seen.append(corpus)
        return [("/x.yml", 1, "snippet")]

    pat = CorpusPattern(callback=cb)
    corpus = build_corpus("/nonexistent")
    assert pat.check_corpus(corpus) == [("/x.yml", 1, "snippet")]
    assert seen == [corpus]


def test_engine_scan_repo_invokes_corpus_rules(tmp_path: Path) -> None:
    """A registered CorpusPattern rule must produce findings via
    scan_repo's cross-file pass.  This is the engine integration
    contract that subsequent B3 rules will rely on.
    """
    from taintly.engine import scan_repo
    from taintly.models import Platform, Rule, Severity

    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "fork.yml").write_text("on: pull_request\njobs: {}\n")
    (wf_dir / "main.yml").write_text("on: push\njobs: {}\n")

    # Toy rule: fire once per workflow file in the corpus.
    def fire_per_workflow(corpus):
        return [(w.filepath, 1, "test snippet") for w in corpus.all()]

    rule = Rule(
        id="XF-GH-TEST",
        title="Test corpus rule",
        severity=Severity.MEDIUM,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-1",
        description="Test rule for corpus integration.",
        pattern=CorpusPattern(callback=fire_per_workflow),
        remediation="N/A",
        reference="",
    )

    reports = scan_repo(str(tmp_path), [rule], Platform.GITHUB)
    findings = [f for r in reports for f in r.findings if f.rule_id == "XF-GH-TEST"]
    assert len(findings) == 2
    files = {f.file for f in findings}
    assert files == {str(wf_dir / "fork.yml"), str(wf_dir / "main.yml")}
    # Cross-file findings carry the "cross-workflow" origin so reporters
    # can distinguish them from per-file matches.
    assert all(f.origin == "cross-workflow" for f in findings)


def test_engine_scan_repo_skips_corpus_build_when_no_corpus_rules(tmp_path: Path) -> None:
    """When no CorpusPattern rule is loaded, scan_repo must not
    invoke build_corpus — costs nothing on repos that don't exercise
    cross-file rules.
    """
    from taintly.engine import _run_corpus_rules
    from taintly.models import Platform, RegexPattern, Rule, Severity

    rule = Rule(
        id="X",
        title="x",
        severity=Severity.LOW,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-1",
        description="x",
        pattern=RegexPattern(match="x"),
        remediation="x",
        reference="",
    )
    # No CorpusPattern in the rule set → returns [] without touching disk.
    assert _run_corpus_rules(str(tmp_path), [rule]) == []


def test_engine_scan_repo_handles_corpus_rule_exception(tmp_path: Path) -> None:
    """If a corpus rule's callback raises, the engine must produce an
    ENGINE-ERR rather than crashing the whole scan.
    """
    from taintly.engine import scan_repo
    from taintly.models import Platform, Rule, Severity

    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "x.yml").write_text("on: push\njobs: {}\n")

    def boom(_corpus):
        raise RuntimeError("simulated callback failure")

    rule = Rule(
        id="XF-GH-BROKEN",
        title="broken corpus rule",
        severity=Severity.HIGH,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-1",
        description="x",
        pattern=CorpusPattern(callback=boom),
        remediation="x",
        reference="",
    )

    reports = scan_repo(str(tmp_path), [rule], Platform.GITHUB)
    errs = [f for r in reports for f in r.findings if f.rule_id == "ENGINE-ERR"]
    assert any("XF-GH-BROKEN" in (f.title or "") for f in errs)
