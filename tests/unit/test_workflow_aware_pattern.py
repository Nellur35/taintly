"""WorkflowAwarePattern test pack — context API and rule contract.

Phase 8 iteration 2: validates the ``PredicateContext`` helpers
(siblings / descendants / step_uses / steps_after / is_reusable_workflow)
and the ``WorkflowAwarePattern.check`` contract that surrounds them.

The three concrete tunes that drove this infrastructure
(SEC6-GH-010 safe-consumer allowlist, TAINT-GH-006 sink-kind
discrimination, SEC4-GH-005 downstream-use precision) are tested
indirectly via their rule packs.  The tests below cover the
generic mechanism so a regression there surfaces independently of
any individual rule.
"""

from __future__ import annotations

from taintly.workflow_aware_pattern import PredicateContext, WorkflowAwarePattern

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _calls(content: str, path: str | list[str]):
    """Run a recording predicate over ``content`` and return the
    list of ``(value, value_kind, path, ctx)`` tuples it observed.
    """
    seen: list[tuple[str, str, tuple[object, ...], PredicateContext]] = []

    def _record(value, value_kind, full_path, ctx):
        seen.append((value, value_kind, full_path, ctx))
        return False

    pattern = WorkflowAwarePattern(path=path, predicate=_record)
    pattern.check(content, content.splitlines())
    return seen


# ---------------------------------------------------------------------------
# Predicate dispatch
# ---------------------------------------------------------------------------


def test_predicate_runs_on_each_query_matched_leaf():
    src = (
        "jobs:\n"
        "  build:\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "      - uses: aquasecurity/trivy-action@v0.33.0\n"
    )
    calls = _calls(src, "jobs.*.steps[*].uses")
    values = [v for v, _, _, _ in calls]
    assert "actions/checkout@v4" in values
    assert "aquasecurity/trivy-action@v0.33.0" in values


def test_predicate_truthy_emits_at_leaf_line():
    src = (
        "jobs:\n"
        "  build:\n"
        "    steps:\n"
        "      - uses: third-party/x@v1\n"
        "      - uses: actions/checkout@v4\n"
    )

    def _fires_on_third_party(value, _kind, _path, _ctx):
        return value.startswith("third-party/")

    pattern = WorkflowAwarePattern(
        path="jobs.*.steps[*].uses",
        predicate=_fires_on_third_party,
    )
    findings = pattern.check(src, src.splitlines())
    assert len(findings) == 1
    line_num, snippet = findings[0]
    assert "third-party/x@v1" in snippet
    # Snippet contract: must be a substring of the source line.
    assert snippet in src.splitlines()[line_num - 1]


def test_multiple_path_globs_dedup_emissions():
    """A leaf matching more than one glob still emits a single finding."""
    src = "jobs:\n  build:\n    steps:\n      - run: echo hi\n"
    findings = WorkflowAwarePattern(
        path=["jobs.*.steps[*].run", "**.run"],
        predicate=lambda _v, _k, _p, _c: True,
    ).check(src, src.splitlines())
    assert len(findings) == 1


# ---------------------------------------------------------------------------
# Context: get_value, siblings, descendants
# ---------------------------------------------------------------------------


def test_ctx_get_value_returns_leaf_at_path():
    src = (
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
    )
    calls = _calls(src, "jobs.*.steps[*].uses")
    assert len(calls) == 1
    _, _, _, ctx = calls[0]
    assert ctx.get_value(("jobs", "build", "runs-on")) == "ubuntu-latest"
    assert ctx.get_value(("jobs", "build", "does-not-exist")) is None


def test_ctx_siblings_excludes_self_and_returns_peer_keys():
    src = (
        "jobs:\n"
        "  build:\n"
        "    steps:\n"
        "      - uses: third-party/x@v1\n"
        "        with:\n"
        "          token: aaa\n"
        "          name: bbb\n"
    )
    calls = _calls(src, "jobs.*.steps[*].with.token")
    assert len(calls) == 1
    _, _, path, ctx = calls[0]
    sibling_paths = {ev.path for ev in ctx.siblings(path)}
    # ``with.name`` is a sibling of ``with.token`` under the same
    # ``with`` parent map; ``uses`` is NOT (different parent).
    assert ("jobs", "build", "steps", 0, "with", "name") in sibling_paths
    assert ("jobs", "build", "steps", 0, "uses") not in sibling_paths


def test_ctx_descendants_yields_strict_subtree():
    src = (
        "jobs:\n"
        "  build:\n"
        "    steps:\n"
        "      - uses: third-party/x@v1\n"
        "        with:\n"
        "          token: aaa\n"
        "          name: bbb\n"
    )
    calls = _calls(src, "jobs.*.steps[*].uses")
    assert len(calls) == 1
    _, _, path, ctx = calls[0]
    step_prefix = path[:-1]  # ('jobs', 'build', 'steps', 0)
    descendant_paths = {ev.path for ev in ctx.descendants(step_prefix)}
    # All children of the step are descendants — uses, with.token,
    # with.name.  The step prefix itself is NOT a descendant.
    assert ("jobs", "build", "steps", 0, "uses") in descendant_paths
    assert ("jobs", "build", "steps", 0, "with", "token") in descendant_paths
    assert ("jobs", "build", "steps", 0, "with", "name") in descendant_paths
    assert step_prefix not in descendant_paths


# ---------------------------------------------------------------------------
# Context: step helpers
# ---------------------------------------------------------------------------


def test_ctx_step_index_recognises_step_paths_only():
    src = (
        "name: ci\n"
        "on: push\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
    )
    calls = _calls(src, "**")
    by_path = {p: ctx for _, _, p, ctx in calls}

    ctx = next(iter(by_path.values()))

    # Step path → (job_id, step_idx)
    assert ctx.step_index(("jobs", "build", "steps", 0, "uses")) == ("build", 0)
    # Job-level (not step) — None
    assert ctx.step_index(("jobs", "build", "runs-on")) is None
    # Top-level — None
    assert ctx.step_index(("name",)) is None


def test_ctx_step_uses_returns_step_uses_value():
    src = (
        "jobs:\n"
        "  build:\n"
        "    steps:\n"
        "      - uses: third-party/upload@v3\n"
        "        with:\n"
        "          api-key: ${{ secrets.K }}\n"
    )
    calls = _calls(src, "jobs.*.steps[*].with.api-key")
    assert len(calls) == 1
    _, _, path, ctx = calls[0]
    assert ctx.step_uses(path) == "third-party/upload@v3"


def test_ctx_steps_after_yields_subsequent_step_leaves():
    src = (
        "jobs:\n"
        "  build:\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "      - run: git push origin main\n"
        "      - run: echo done\n"
    )
    calls = _calls(src, "jobs.*.steps[*].uses")
    # First step's uses leaf — there's only one ``uses:`` in the
    # workflow, so the single call observes step 0.
    assert len(calls) == 1
    _, _, path, ctx = calls[0]
    assert ctx.step_index(path) == ("build", 0)
    after_values = [ev.value for ev in ctx.steps_after(path)]
    assert "git push origin main" in after_values
    assert "echo done" in after_values


# ---------------------------------------------------------------------------
# Context: file-shape detection
# ---------------------------------------------------------------------------


def test_ctx_is_reusable_workflow_bare_string():
    src = "on: workflow_call\njobs: {}\n"
    calls = _calls(src, "**")
    assert calls
    ctx = calls[0][3]
    assert ctx.is_reusable_workflow() is True


def test_ctx_is_reusable_workflow_block_form():
    src = "on:\n  workflow_call:\n    inputs:\n      tag:\n        type: string\njobs: {}\n"
    calls = _calls(src, "**")
    assert calls
    ctx = calls[0][3]
    assert ctx.is_reusable_workflow() is True


def test_ctx_is_reusable_workflow_list_form():
    src = "on: [workflow_call, push]\njobs: {}\n"
    calls = _calls(src, "**")
    assert calls
    ctx = calls[0][3]
    assert ctx.is_reusable_workflow() is True


def test_ctx_is_reusable_workflow_negative_for_push_only():
    src = "on: push\njobs: {}\n"
    calls = _calls(src, "**")
    assert calls
    ctx = calls[0][3]
    assert ctx.is_reusable_workflow() is False


# ---------------------------------------------------------------------------
# Snippet contract
# ---------------------------------------------------------------------------


def test_snippet_format_overrides_default():
    src = "jobs:\n  build:\n    steps:\n      - run: echo ${{ inputs.x }}\n"
    pattern = WorkflowAwarePattern(
        path="jobs.*.steps[*].run",
        predicate=lambda _v, _k, _p, _c: True,
        snippet_format="path={path}",
    )
    findings = pattern.check(src, src.splitlines())
    assert len(findings) == 1
    _, snippet = findings[0]
    assert snippet.startswith("path=")
    assert "steps" in snippet


def test_predicate_exception_swallowed_no_emission():
    src = "jobs:\n  build:\n    steps:\n      - run: hi\n"

    def _boom(value, _kind, _path, _ctx):
        raise ValueError("kaboom")

    pattern = WorkflowAwarePattern(path="**.run", predicate=_boom)
    findings = pattern.check(src, src.splitlines())
    assert findings == []


# ---------------------------------------------------------------------------
# Block-scalar (run: |) handling
# ---------------------------------------------------------------------------


def test_block_scalar_predicate_runs_per_body_line():
    src = (
        "jobs:\n"
        "  build:\n"
        "    steps:\n"
        "      - run: |\n"
        "          echo first\n"
        "          echo ${{ github.head_ref }}\n"
        "          echo last\n"
    )
    seen_lines: list[str] = []

    def _records(value, _kind, _path, _ctx):
        seen_lines.append(value)
        return "head_ref" in value

    pattern = WorkflowAwarePattern(path="jobs.*.steps[*].run", predicate=_records)
    findings = pattern.check(src, src.splitlines())
    assert len(findings) == 1
    line_num, snippet = findings[0]
    assert "head_ref" in snippet
    # Predicate observed all body lines, not just the matched one.
    assert any("first" in s for s in seen_lines)
    assert any("last" in s for s in seen_lines)
