"""Secret -> process output -> saved cache usage, including safe controls."""

from pathlib import Path

import pytest

from taintly.engine import scan_repo
from taintly.models import Platform
from taintly.rules.registry import load_rules_for_platform

RULE_ID = "SEC6-GH-015"


def workflow(steps: str, *, env: str = "", header: str = "on: push\n") -> str:
    return (
        header
        + env
        + "permissions: {contents: read}\njobs:\n  build:\n"
        + "    runs-on: ubuntu-latest\n    steps:\n"
        + steps
    )


CACHE = """      - uses: actions/cache@v4
        with:
          path: target/
          key: rust-target-v1
"""
MIRI = """      - run: cargo +nightly-2026-09-20 miri test
        env:
          SERVICE_TOKEN: ${{ secrets.SERVICE_TOKEN }}
"""


def findings(tmp_path: Path, content: str):
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True, exist_ok=True)
    (workflows / "build.yml").write_text(content, encoding="utf-8")
    (workflows / "pr.yml").write_text(
        workflow(
            CACHE.replace("actions/cache@", "actions/cache/restore@"), header="on: pull_request\n"
        ),
        encoding="utf-8",
    )
    return [
        finding
        for report in scan_repo(str(tmp_path), load_rules_for_platform(Platform.GITHUB))
        for finding in report.findings
        if finding.rule_id == RULE_ID
    ]


def test_miri_usage_detected_end_to_end(tmp_path):
    result = findings(tmp_path, workflow(CACHE + MIRI))
    assert len(result) == 1
    assert result[0].review_needed
    assert result[0].confidence == "medium"
    assert "miri test" in result[0].snippet


def test_generic_environment_dump_detected_end_to_end(tmp_path):
    steps = CACHE + MIRI.replace(
        "cargo +nightly-2026-09-20 miri test", "env > target/environment.txt"
    )
    assert len(findings(tmp_path, workflow(steps))) == 1


@pytest.mark.parametrize(
    "steps",
    [
        CACHE + MIRI.replace("${{ secrets.SERVICE_TOKEN }}", "public-value"),
        CACHE.replace("path: target/", "path: ~/.cargo/registry/") + MIRI,
        CACHE.replace("actions/cache@", "actions/cache/restore@") + MIRI,
        CACHE
        + "      - run: cargo miri test\n      - run: ./publish.sh\n"
        + "        env: {TOKEN: '${{ secrets.TOKEN }}'}\n",
    ],
)
def test_safe_controls(tmp_path, steps):
    assert findings(tmp_path, workflow(steps)) == []


def hits(content):
    rule = next(rule for rule in load_rules_for_platform(Platform.GITHUB) if rule.id == RULE_ID)
    return rule.pattern.check(content, content.splitlines())


SECRET_ENV = "env: {TOKEN: '${{ secrets.TOKEN }}'}\n"
PLAIN_BUILD = "      - run: cargo build\n"
RUST_CACHE = "      - uses: Swatinem/rust-cache@v2\n"


@pytest.mark.parametrize(
    "steps,env,header",
    [
        (CACHE + PLAIN_BUILD, SECRET_ENV, "on: push\n"),
        (CACHE + MIRI, "", "on: [push, pull_request]\n"),
        (MIRI + CACHE, "", "on: push\n"),
        (MIRI + CACHE.replace("actions/cache@", "actions/cache/save@"), "", "on: push\n"),
        (RUST_CACHE + MIRI, "", "on: push\n"),
        (RUST_CACHE + MIRI.replace("2026-09-20", "2026-09-22"), "", "on: push\n"),
        (CACHE + MIRI, "", "on: pull_request_target\ncache-mode: write\n"),
        (CACHE + MIRI, "", "on: push\ncache-mode: write-only\n"),
        (
            CACHE
            + MIRI.replace(
                "cargo +nightly-2026-09-20 miri test", "printenv SERVICE_TOKEN > target/env.txt"
            ),
            "",
            "on: push\n",
        ),
        (
            CACHE + MIRI.replace("cargo +nightly-2026-09-20 miri test", "env | tee target/env.txt"),
            "",
            "on: push\n",
        ),
        (
            CACHE
            + MIRI.replace(
                "cargo +nightly-2026-09-20 miri test", 'echo "$SERVICE_TOKEN" > target/token'
            ),
            "",
            "on: push\n",
        ),
        (
            CACHE
            + MIRI.replace(
                "cargo +nightly-2026-09-20 miri test",
                "echo '${{ toJSON(secrets) }}' > target/secrets.json",
            ),
            "",
            "on: push\n",
        ),
        (CACHE + "      - run: TOKEN=${{ secrets.TOKEN }} cargo test\n", "", "on: push\n"),
        (
            CACHE
            + '      - run: |\n          echo "TOKEN=${{ secrets.TOKEN }}" >> $GITHUB_ENV\n'
            + PLAIN_BUILD,
            "",
            "on: push\n",
        ),
        (
            CACHE
            + "      - run: |\n          export TOKEN=${{ secrets.TOKEN }}\n          cargo build\n",
            "",
            "on: push\n",
        ),
        (CACHE + "      - run: env -u OTHER cargo build\n", SECRET_ENV, "on: push\n"),
        (CACHE + "      - run: env -u OTHER > target/env.txt\n", SECRET_ENV, "on: push\n"),
        (
            CACHE.replace("target/", "build/")
            + MIRI.replace("miri test", "miri test --target-dir build"),
            "",
            "on: push\n",
        ),
        (
            CACHE.replace("target/", "build/")
            + MIRI.replace("SERVICE_TOKEN:", "CARGO_TARGET_DIR: build\n          SERVICE_TOKEN:"),
            "",
            "on: push\n",
        ),
        (
            CACHE.replace("target/", "sub/target/")
            + MIRI.replace("      - run:", "      - working-directory: sub\n        run:"),
            "",
            "on: push\n",
        ),
        (
            CACHE.replace("target/", "sub/target/") + "      - run: cd sub && cargo build\n",
            SECRET_ENV,
            "on: push\n",
        ),
        (CACHE.replace("target/", "${{ github.workspace }}/target/") + MIRI, "", "on: push\n"),
        (
            CACHE.replace(
                "path: target/", "path: |\n            target/**\n            !target/tmp"
            )
            + MIRI,
            "",
            "on: push\n",
        ),
        (
            RUST_CACHE + "        with: {cache-targets: false, cache-directories: target}\n" + MIRI,
            "",
            "on: push\n",
        ),
        (
            RUST_CACHE
            + "        with: {workspaces: 'sub -> target'}\n"
            + MIRI.replace("      - run:", "      - working-directory: sub\n        run:"),
            "",
            "on: push\n",
        ),
    ],
)
def test_positive_usage_routes(steps, env, header):
    assert hits(workflow(steps, env=env, header=header))


@pytest.mark.parametrize(
    "steps,env,header",
    [
        (CACHE + MIRI, "", "on: pull_request\n"),
        (CACHE + MIRI, "", "on: pull_request_target\n"),
        (CACHE + MIRI, "", "on: push\ncache-mode: read\n"),
        (CACHE + MIRI, "", "on: push\ncache-mode: none\n"),
        (CACHE.replace("actions/cache@", "actions/cache/save@") + MIRI, "", "on: push\n"),
        (RUST_CACHE + "        with: {save-if: false}\n" + MIRI, "", "on: push\n"),
        (RUST_CACHE + "        with: {save-if: '${{ false }}'}\n" + MIRI, "", "on: push\n"),
        (RUST_CACHE + "        with: {cache-targets: false}\n" + MIRI, "", "on: push\n"),
        (RUST_CACHE + "        with: {cache-provider: warpbuild}\n" + MIRI, "", "on: push\n"),
        (CACHE + PLAIN_BUILD + "        env: {TOKEN: public}\n", SECRET_ENV, "on: push\n"),
        (CACHE + "      - run: env -u TOKEN cargo build\n", SECRET_ENV, "on: push\n"),
        (CACHE + "      - run: env -i cargo build\n", SECRET_ENV, "on: push\n"),
        (
            CACHE + "      - run: |\n          unset TOKEN\n          cargo build\n",
            SECRET_ENV,
            "on: push\n",
        ),
        (
            CACHE + "      - run: |\n          TOKEN=public\n          cargo build\n",
            SECRET_ENV,
            "on: push\n",
        ),
        (
            CACHE + "      - run: |\n          TOKEN=${{ secrets.TOKEN }}\n          cargo build\n",
            "",
            "on: push\n",
        ),
        (CACHE + "      - run: echo 'cargo miri test'\n", SECRET_ENV, "on: push\n"),
        (
            CACHE + "      - run: |\n          # cargo miri test\n          echo ok\n",
            SECRET_ENV,
            "on: push\n",
        ),
        (
            CACHE
            + "      - run: |\n          cat <<'EOF'\n          cargo miri test\n          EOF\n",
            SECRET_ENV,
            "on: push\n",
        ),
        (CACHE + "      - run: echo '$TOKEN' > target/token\n", SECRET_ENV, "on: push\n"),
        (CACHE + "      - run: printenv PUBLIC > target/env.txt\n", SECRET_ENV, "on: push\n"),
        (CACHE + MIRI + "      - run: rm -rf target\n", "", "on: push\n"),
        (CACHE.replace("target/", "elsewhere/") + MIRI, "", "on: push\n"),
        (CACHE + MIRI.replace("miri test", "miri test --target-dir elsewhere"), "", "on: push\n"),
        (CACHE + PLAIN_BUILD, "env: {TOKEN: \"${{ secrets.TOKEN != '' }}\"}\n", "on: push\n"),
        (CACHE + MIRI.replace("      - run:", "      - if: false\n        run:"), "", "on: push\n"),
        (
            CACHE.replace("      - uses:", "      - if: false\n        uses:") + MIRI,
            "",
            "on: push\n",
        ),
    ],
)
def test_safe_usage_routes(steps, env, header):
    assert hits(workflow(steps, env=env, header=header)) == []


def test_job_scope_and_defaults():
    unsafe = workflow(CACHE + PLAIN_BUILD).replace(
        "    runs-on:",
        "    env: {TOKEN: '${{ secrets.TOKEN }}'}\n    runs-on:",
    )
    assert hits(unsafe)
    assert not hits(unsafe.replace("    runs-on:", "    cache-mode: read\n    runs-on:"))
    split = workflow(CACHE) + "  publish:\n    runs-on: ubuntu-latest\n    steps:\n" + MIRI
    assert not hits(split)
    assert hits(
        unsafe.replace("path: target/", "path: sub/target/").replace(
            "    runs-on:",
            "    defaults: {run: {working-directory: sub}}\n    runs-on:",
        )
    )


def test_flow_style_and_same_indent_steps():
    assert hits("""on: push
env: {TOKEN: '${{ secrets.TOKEN }}'}
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
    - {uses: actions/cache@v4, with: {path: target, key: build}}
    - {run: cargo test}
""")


def test_github_env_only_affects_later_steps():
    assert not hits(
        workflow(
            CACHE
            + """      - run: |
          echo "TOKEN=${{ secrets.TOKEN }}" >> "$GITHUB_ENV"
          cargo build
"""
        )
    )
    unsafe = workflow(
        CACHE
        + """      - run: echo "TOKEN=${{ secrets.TOKEN }}" >> "$GITHUB_ENV"
      - run: cargo build
"""
    )
    assert hits(unsafe)
    assert not hits(
        unsafe.replace(
            "      - run: cargo build", "      - env: {TOKEN: public}\n        run: cargo build"
        )
    )


def test_partial_exclusion_does_not_hide_other_files():
    assert hits(
        workflow(
            CACHE.replace(
                "path: target/", "path: |\n            target/**\n            !target/tmp"
            )
            + MIRI
        )
    )
    assert not hits(
        workflow(
            CACHE.replace("path: target/", "path: |\n            target/**\n            !target/**")
            + MIRI
        )
    )


@pytest.mark.parametrize(
    "script,expected",
    [
        ("env 1> target/env", True),
        ("env 2> error.txt > target/env", True),
        ("env 2> target/env", False),
        ("env > target/env > elsewhere", False),
        ("echo 2 > target/env", False),
        ("echo 2 $TOKEN > target/env", True),
        ("env | tee target/env >/dev/null", True),
        ('printf "%s\\n" "$TOKEN" > target/env', True),
        ('printf "safe" "$TOKEN" > target/env', False),
        ('printf "%%s" "$TOKEN" > target/env', False),
        ("env > target/env; echo public > target/env", False),
        ("env > target/env; echo public >> target/env", True),
        ("env > target/env; rm target/env", False),
        ("cargo build; rm target || true", True),
        ("cargo build; false && rm -rf target", True),
        ("cargo build; maybe && rm -rf target", True),
        ("cargo build; rm -rf target", False),
        ("false && cargo build", False),
        ("true || cargo build", False),
        ("false || cargo build", True),
        ("cargo build --help", False),
        ("cargo build -h", False),
        ("cargo --verbose build", True),
        ("cargo test -- --help", True),
        ("cargo build; false && unset TOKEN; cargo build", True),
        ("echo 'text\ncargo build\ntext'", False),
    ],
)
def test_review_shell_reproductions(script, expected):
    steps = (
        CACHE
        + "      - run: |\n"
        + "".join("          " + line + "\n" for line in script.splitlines())
    )
    assert bool(hits(workflow(steps, env=SECRET_ENV))) is expected


@pytest.mark.parametrize(
    "first,expected",
    [
        ('echo "TOKEN=${{ secrets.TOKEN }}" >> $GITHUB_ENV', True),
        ('printf "TOKEN=%s\\n" "${{ secrets.TOKEN }}" >> $GITHUB_ENV', True),
        (
            'echo "TOKEN=${{ secrets.TOKEN }}" >> $GITHUB_ENV; echo PUBLIC=public > $GITHUB_ENV',
            False,
        ),
        ("env >> $GITHUB_ENV", True),
        ("printenv TOKEN >> $GITHUB_ENV", False),
    ],
)
def test_review_environment_file(first, expected):
    steps = (
        CACHE
        + "      - run: "
        + first
        + "\n        env: {TOKEN: '${{ secrets.TOKEN }}'}\n"
        + PLAIN_BUILD
    )
    assert bool(hits(workflow(steps))) is expected


def test_windows_default_shell_and_explicit_bash():
    content = workflow(CACHE + MIRI).replace("ubuntu-latest", "windows-latest")
    assert not hits(content)
    assert hits(content.replace("      - run:", "      - shell: bash\n        run:"))


@pytest.mark.parametrize("where", ["job", "cache", "producer", "persist"])
def test_pr_only_guard_cannot_borrow_push_cache_scope(where):
    guard = "github.event_name == 'pull_request'"
    content = workflow(CACHE + MIRI, header="on: [push, pull_request]\n")
    if where == "job":
        content = content.replace("    runs-on:", f"    if: {guard}\n    runs-on:")
    elif where == "cache":
        content = content.replace("      - uses:", f"      - if: {guard}\n        uses:")
    elif where == "producer":
        content = content.replace("      - run:", f"      - if: {guard}\n        run:")
    else:
        content = workflow(
            CACHE
            + f"      - if: {guard}\n        run: echo TOKEN=${{{{ secrets.TOKEN }}}} >> $GITHUB_ENV\n"
            + PLAIN_BUILD,
            header="on: [push, pull_request]\n",
        )
    assert not hits(content)


def test_usage_profile_paths():
    assert not hits(
        workflow(
            CACHE.replace("target/", "$HOME/target")
            + MIRI.replace("miri test", "miri test --target-dir ~/target")
        )
    )
    assert hits(
        workflow(
            RUST_CACHE
            + "        with: {workspaces: sub}\n"
            + MIRI.replace("      - run:", "      - working-directory: sub\n        run:")
        )
    )
    assert hits(
        workflow(
            RUST_CACHE
            + "        with: {cache-targets: false, cache-directories: 'other target'}\n"
            + MIRI
        )
    )
    dump = "      - run: env > custom-cargo/bin/env\n        env: {TOKEN: '${{ secrets.TOKEN }}'}\n"
    content = workflow(RUST_CACHE + dump, env="env: {CARGO_HOME: custom-cargo}\n")
    assert hits(content)
    assert not hits(content.replace(RUST_CACHE, RUST_CACHE + "        with: {cache-bin: false}\n"))
    # The wrapper cleans root target files before saving: don't claim survival.
    assert not hits(
        workflow(
            RUST_CACHE
            + MIRI.replace("cargo +nightly-2026-09-20 miri test", "env > target/environment.txt")
        )
    )


def test_real_secret_bytes_unnecessary_for_static_analysis(tmp_path):
    """The scanner never executes the tool or reads actual secret values."""
    content = workflow(CACHE + MIRI)
    result = findings(tmp_path, content)
    assert len(result) == 1
    assert "cache save at line" in result[0].snippet
    assert "does not prove secret" in result[0].description


@pytest.mark.parametrize(
    "script,expected",
    [
        ("true || false && cargo build", True),
        ("false && true || cargo build", True),
        ("cargo build; false && true || rm -rf target", False),
        ("cargo build; maybe || true && rm -rf target", False),
    ],
)
def test_left_associative_shell_condition_lists(script, expected):
    content = workflow(CACHE + "      - run: " + script + "\n", env=SECRET_ENV)
    assert bool(hits(content)) is expected
