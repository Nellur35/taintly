"""PR-only ref context is shared safely by secret-cache guard analysis."""

from taintly.rules.github.secret_cache import SecretCachePattern

RULE = SecretCachePattern()


def _guard(condition: str) -> str:
    return f"      - if: ${{{{ {condition} }}}}\n"


def _workflow(steps: str, *, event: str = "pull_request_target") -> str:
    return (
        f"on: {event}\n"
        "cache-mode: write\n"
        "permissions: {contents: read}\n"
        "jobs:\n  build:\n"
        "    runs-on: ubuntu-latest\n    steps:\n" + steps
    )


def _producer(condition: str) -> str:
    return (
        _guard(condition)
        + "        run: env > target/env.txt\n"
        + "        env: {TOKEN: '${{ secrets.TOKEN }}'}\n"
    )


def _cache(condition: str) -> str:
    return (
        _guard(condition)
        + "        uses: actions/cache@v4\n"
        + "        with: {path: target/, key: pr-cache-v1}\n"
    )


def _hits(content: str):
    return RULE.check(content, content.splitlines())


def test_disjoint_pr_head_ref_producer_and_cache_do_not_join():
    content = _workflow(
        _producer("github.head_ref == 'source-a'") + _cache("github.head_ref == 'source-b'")
    )
    assert _hits(content) == []


def test_compatible_pr_head_ref_producer_and_cache_join():
    content = _workflow(
        _producer("github.head_ref == 'source-a'") + _cache("github.head_ref == 'SOURCE-A'")
    )
    assert _hits(content)


def test_disjoint_cleanup_does_not_erase_compatible_secret_output():
    content = _workflow(
        _producer("github.head_ref == 'source-a'")
        + _guard("github.head_ref == 'cleanup-branch'")
        + "        run: rm -f target/env.txt\n"
        + _cache("github.head_ref == 'source-a'")
    )
    assert _hits(content)


def test_same_head_ref_cleanup_erases_output_on_the_cache_path():
    content = _workflow(
        _producer("github.head_ref == 'source-a'")
        + _guard("github.head_ref == 'source-a'")
        + "        run: rm -f target/env.txt\n"
        + _cache("github.head_ref == 'source-a'")
    )
    assert _hits(content) == []


def test_non_pr_event_keeps_unavailable_base_ref_guards_conservative():
    content = _workflow(
        _producer("github.base_ref == 'target-a'") + _cache("github.base_ref == 'target-b'"),
        event="issues",
    )
    assert _hits(content)
