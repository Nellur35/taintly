"""Whole-job guard alternatives for secret-bearing cache outputs."""

import pytest

from taintly.models import IncompletePatternMatches
from taintly.rules.github.secret_cache import SecretCachePattern

RULE = SecretCachePattern()
MAIN = "github.ref == 'refs/heads/main'"
DEV = "github.ref == 'refs/heads/dev'"
UNKNOWN = "contains(github.ref, 'main')"


def guard(text: str | None) -> str:
    return f"      - if: ${{{{ {text} }}}}\n" if text is not None else "      - "


def producer(*, condition: str | None = None, command: str = "env > target/env.txt") -> str:
    return (
        guard(condition)
        + f"        run: {command}\n"
        + "        env:\n"
        + "          TOKEN: ${{ secrets.TOKEN }}\n"
    )


def cache(*, condition: str | None = None, action: str = "actions/cache@v4") -> str:
    return (
        guard(condition)
        + f"        uses: {action}\n"
        + "        with:\n"
        + "          path: target/\n"
        + "          key: authored-v1\n"
    )


def workflow(steps: str, *, header: str = "on: push\n") -> str:
    return (
        header
        + "permissions: {contents: read}\n"
        + "jobs:\n  build:\n"
        + "    runs-on: ubuntu-latest\n    steps:\n"
        + steps
    )


def hits(content: str):
    return RULE.check(content, content.splitlines())


def test_event_name_comparison_is_case_insensitive():
    content = workflow(producer(condition="github.event_name == 'PUSH'") + cache())
    assert hits(content)


def test_different_ref_guards_do_not_join_producer_and_cache():
    content = workflow(producer(condition=MAIN) + cache(condition=DEV))
    assert hits(content) == []


def test_same_ref_guards_join_producer_and_cache():
    content = workflow(producer(condition=MAIN) + cache(condition=MAIN))
    assert hits(content)


def test_cleanup_in_mutually_exclusive_ref_does_not_erase_output():
    content = workflow(
        producer(condition=MAIN)
        + guard(DEV)
        + "        run: rm -f target/env.txt\n"
        + cache(condition=MAIN)
    )
    assert hits(content)


def test_same_ref_cleanup_erases_output_before_post_cache():
    content = workflow(
        producer(condition=MAIN)
        + guard(MAIN)
        + "        run: rm -f target/env.txt\n"
        + cache(condition=MAIN)
    )
    assert hits(content) == []


def test_mutually_exclusive_truncating_overwrite_does_not_erase_output():
    content = workflow(
        producer(condition=MAIN)
        + guard(DEV)
        + "        run: printf public > target/env.txt\n"
        + cache(condition=MAIN)
    )
    assert hits(content)


def test_conditional_github_env_write_does_not_persist_across_disjoint_refs():
    writer = guard(MAIN) + '        run: echo "TOKEN=${{ secrets.TOKEN }}" >> "$GITHUB_ENV"\n'
    consumer = guard(DEV) + "        run: env > target/env.txt\n"
    content = workflow(writer + consumer + cache(condition=DEV))
    assert hits(content) == []


def test_conditional_github_env_write_persists_on_compatible_ref():
    writer = guard(MAIN) + '        run: echo "TOKEN=${{ secrets.TOKEN }}" >> "$GITHUB_ENV"\n'
    consumer = guard(MAIN) + "        run: env > target/env.txt\n"
    content = workflow(writer + consumer + cache(condition=MAIN))
    assert hits(content)


def test_unknown_guard_branches_without_erasing_skip_state():
    content = workflow(
        producer(condition=MAIN)
        + guard(UNKNOWN)
        + "        run: rm -f target/env.txt\n"
        + cache(condition=MAIN)
    )
    assert hits(content)


def test_or_and_negation_keep_ref_alternatives_correlated():
    producer_or = "github.ref == 'refs/heads/main' || github.ref == 'refs/heads/dev'"
    assert hits(workflow(producer(condition=producer_or) + cache(condition=MAIN)))
    producer_not_dev = "github.ref != 'refs/heads/dev'"
    assert hits(workflow(producer(condition=producer_not_dev) + cache(condition=DEV))) == []


def test_malformed_guard_is_not_used_as_a_negative_proof():
    malformed = "github.ref =="
    content = workflow(producer(condition=malformed) + cache(condition=MAIN))
    assert hits(content)


def test_duplicate_guard_keys_are_not_used_as_negative_proofs():
    content = workflow(
        "      - if: github.ref == 'refs/heads/dev'\n"
        "        if: github.ref == 'refs/heads/main'\n"
        "        run: env > target/env.txt\n"
        "        env: {TOKEN: '${{ secrets.TOKEN }}'}\n" + cache(condition=MAIN)
    )
    assert hits(content)


def test_duplicate_ancestor_job_keys_are_not_used_as_negative_proofs():
    content = (
        "on: push\n"
        "permissions: {contents: read}\n"
        "jobs:\n"
        "  build:\n"
        "    if: false\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: echo first\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n" + producer() + cache()
    )
    assert hits(content)


def test_duplicate_ancestor_with_keys_are_not_used_as_negative_proofs():
    content = workflow(
        producer(command="cargo build")
        + "      - uses: Swatinem/rust-cache@v2\n"
        + "        with: {save-if: false}\n"
        + "        with: {cache-targets: true}\n"
    )
    assert hits(content)


def test_aliased_guard_is_not_used_as_a_negative_proof():
    content = workflow(
        "      - run: echo setup\n"
        "      - if: *main_guard\n"
        "        run: env > target/env.txt\n"
        "        env: {TOKEN: '${{ secrets.TOKEN }}'}\n" + cache(condition=DEV),
        header="on: push\nmain_guard: &main_guard github.ref == 'refs/heads/main'\n",
    )
    assert hits(content)


def test_recovered_structure_does_not_supply_missing_guard_proof():
    content = workflow(producer(condition=MAIN) + cache(condition=DEV)) + (
        "recursive: &node\n  child: *node\n"
    )
    assert hits(content)


def test_rust_cache_save_if_ref_is_part_of_cache_domain():
    rust_cache = (
        guard(MAIN)
        + "        uses: Swatinem/rust-cache@v2\n"
        + "        with: {save-if: github.ref == 'refs/heads/dev', workspaces: '. -> target'}\n"
    )
    assert hits(workflow(producer(condition=MAIN, command="cargo build") + rust_cache)) == []
    same_ref = rust_cache.replace("refs/heads/dev", "refs/heads/main")
    assert hits(workflow(producer(condition=MAIN, command="cargo build") + same_ref))


def test_rust_cache_false_save_if_disables_only_rust_cache_registration():
    rust_cache = (
        "      - uses: Swatinem/rust-cache@v2\n"
        "        with: {save-if: false, workspaces: '. -> target'}\n"
    )
    assert hits(workflow(producer(command="cargo build") + rust_cache)) == []


@pytest.mark.parametrize(
    "with_value",
    [
        "{save-if: false,, cache-targets: true}",
        "{save-if: false, stray}",
    ],
)
def test_malformed_flow_with_map_does_not_certify_rust_save_if(with_value: str):
    rust_cache = f"      - uses: Swatinem/rust-cache@v2\n        with: {with_value}\n"
    assert hits(workflow(producer(command="cargo build") + rust_cache))


@pytest.mark.parametrize(
    "suffix",
    [" stray\n", "\n          child: true\n"],
)
def test_flow_with_value_suffix_does_not_certify_rust_save_if(suffix: str):
    rust_cache = "      - uses: Swatinem/rust-cache@v2\n        with: {save-if: false}" + suffix
    assert hits(workflow(producer(command="cargo build") + rust_cache))


def test_actions_cache_ignores_rust_cache_save_if_input():
    standard = (
        "      - uses: actions/cache@v4\n"
        "        with: {path: target/, key: authored-v1, save-if: false}\n"
    )
    explicit = (
        "      - uses: actions/cache/save@v4\n"
        "        with: {path: target/, key: authored-v1, save-if: false}\n"
    )
    assert hits(workflow(producer() + standard))
    assert hits(workflow(producer() + explicit))


def test_explicit_save_uses_current_guard_domain_and_order():
    explicit = cache(action="actions/cache/save@v4")
    assert hits(workflow(producer(condition=MAIN) + explicit))
    assert (
        hits(
            workflow(
                producer(condition=MAIN) + cache(condition=DEV, action="actions/cache/save@v4")
            )
        )
        == []
    )


def test_equivalent_unknown_alternatives_are_deduplicated():
    no_op = guard(UNKNOWN) + "        run: echo harmless\n"
    content = workflow(producer(condition=MAIN) + no_op * 80 + cache(condition=MAIN))
    result = hits(content)
    assert not isinstance(result, IncompletePatternMatches)
    assert result


def test_state_cutoff_preserves_prior_matches_and_marks_result_incomplete():
    steps = producer(condition=MAIN) + cache(action="actions/cache/save@v4")
    for index in range(7):
        steps += producer(condition=UNKNOWN, command=f"env > target/branch-{index}.txt")
    result = hits(workflow(steps))
    assert isinstance(result, IncompletePatternMatches)
    assert result.reason
    assert result


def test_transition_cutoff_is_reported_instead_of_silently_truncating():
    steps = ""
    for index in range(6):
        steps += producer(condition=UNKNOWN, command=f"env > target/branch-{index}.txt")
    for _ in range(70):
        steps += guard(UNKNOWN) + "        run: echo harmless\n"
    result = hits(workflow(steps + cache()))
    assert isinstance(result, IncompletePatternMatches)
    assert "transition limit" in result.reason


def test_cutoff_in_one_job_keeps_matches_from_a_later_job():
    first_job_steps = ""
    for index in range(7):
        first_job_steps += producer(condition=UNKNOWN, command=f"env > target/{index}.txt")
    second_job = "  second:\n    runs-on: ubuntu-latest\n    steps:\n" + producer() + cache()
    content = workflow(first_job_steps) + second_job
    result = hits(content)
    assert isinstance(result, IncompletePatternMatches)
    assert result.reason
    assert result
