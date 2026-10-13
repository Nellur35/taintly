"""Focused command semantics for YAML folded run scalars."""

from __future__ import annotations

from taintly.parsers.structural.walker import walk
from taintly.rules.github.secret_cache import SecretCachePattern, _commands


def _workflow(run: str) -> str:
    return (
        "on: push\n"
        "env: {TOKEN: '${{ secrets.TOKEN }}'}\n"
        "permissions: {contents: read}\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/cache@v4\n"
        "        with:\n"
        "          path: target/\n"
        "          key: rust-v1\n" + run
    )


def _run_event(content: str):
    return next(event for event in walk(content) if event.path and event.path[-1] == "run")


def _findings(content: str) -> list[tuple[int, str]]:
    return SecretCachePattern().check(content, content.splitlines())


def test_folded_echo_and_cargo_words_do_not_create_cargo_cache_producer():
    folded = _workflow("      - run: >-\n          echo safe\n          cargo build\n")
    decoded_control = _workflow("      - run: echo safe cargo build\n")

    assert _run_event(folded).value == "echo safe cargo build"
    assert not _findings(folded)
    assert not _findings(decoded_control)


def test_folded_cargo_command_split_across_source_lines_is_detected_at_scalar_header():
    content = _workflow("      - run: >-\n          cargo\n          build\n")
    header_line = next(
        line_number
        for line_number, line in enumerate(content.splitlines(), 1)
        if line.strip() == "- run: >-"
    )

    findings = _findings(content)

    assert len(findings) == 1
    assert findings[0][0] == header_line
    assert "decoded folded run body" in findings[0][1]
    assert "line is the YAML scalar header" in findings[0][1]


def test_folded_explicit_cache_save_qualifies_the_scalar_header():
    content = (
        "on: push\n"
        "env: {TOKEN: '${{ secrets.TOKEN }}'}\n"
        "permissions: {contents: read}\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: >-\n"
        "          cargo\n"
        "          build\n"
        "      - uses: actions/cache/save@v4\n"
        "        with:\n"
        "          path: target/\n"
        "          key: rust-v1\n"
    )
    lines = content.splitlines()
    header_line = next(
        line_number for line_number, line in enumerate(lines, 1) if line.strip() == "- run: >-"
    )
    cache_line = next(
        line_number
        for line_number, line in enumerate(lines, 1)
        if "uses: actions/cache/save@v4" in line
    )

    findings = _findings(content)

    assert findings == [
        (
            header_line,
            f"{lines[header_line - 1].strip()} "
            "[decoded folded run body; line is the YAML scalar header] "
            f"[cache save at line {cache_line}; output ./target]",
        )
    ]


def test_folded_paragraphs_keep_shell_commands_but_use_scalar_origin_line():
    content = _workflow(
        "      - run: >-\n          export TOKEN=${{ secrets.TOKEN }}\n\n          cargo build\n"
    )
    event = _run_event(content)

    commands = list(_commands(event, {}))

    assert [command[1][0] for command in commands] == ["export", "cargo"]
    assert {command[0] for command in commands} == {event.line}


def test_folded_heredoc_body_is_not_reclassified_as_a_cargo_command():
    content = _workflow(
        "      - run: >-\n          cat <<'EOF'\n\n          cargo build\n\n          EOF\n"
    )

    event = _run_event(content)
    commands = list(_commands(event, {}))

    assert event.value == "cat <<'EOF'\ncargo build\nEOF"
    assert commands
    assert all(command[1][0] != "cargo" for command in commands)
    assert not _findings(content)


def test_folded_retained_newline_with_escaped_lf_declines_without_partial_commands():
    content = _workflow("      - run: >-\n          echo safe\\\n\n          cargo build\n")
    event = _run_event(content)

    assert "\\\n" in event.value
    assert list(_commands(event, {})) == []
    assert not _findings(content)


def test_literal_run_commands_keep_physical_line_locations():
    content = _workflow("      - run: |-\n          unset TOKEN\n          cargo build\n")
    event = _run_event(content)

    commands = list(_commands(event, {}))

    expected_lines = [
        line_number
        for line_number, line in enumerate(content.splitlines(), 1)
        if line.strip() in {"unset TOKEN", "cargo build"}
    ]
    assert [command[0] for command in commands] == expected_lines
    assert [command[1][0] for command in commands] == ["unset", "cargo"]
