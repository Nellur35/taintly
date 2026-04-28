"""Tests for the shared BUILD_TOOL_ANCHOR regex.

BUILD_TOOL_ANCHOR is prefix-grouped for speed (see the comment in
taintly/rules/_build_tools.py). We keep the fragment list around
as the human-editable source of truth and use this test to prove
the grouped anchor matches exactly the same set of lines.
"""

from __future__ import annotations

import re

from taintly.rules._build_tools import BUILD_TOOL_ANCHOR, BUILD_TOOL_FRAGMENTS

# Lines that at least one fragment must match. Any line in this list
# that fails against the grouped anchor is a false-negative regression.
_KNOWN_POSITIVES = [
    "    - run: npm install",
    "    - run: npm ci",
    "    - run: npm run build",
    "    - run: yarn",
    "    - run: yarn build",
    "    - run: pnpm i",
    "    - run: pip install -r requirements.txt",
    "    - run: pip install .",
    "    - run: pip install -e .",
    "    - run: pip install --editable .",
    # pip3 / pip3.11 — Debian, Ubuntu, pyenv ship versioned binaries.
    # A plain `\bpip` anchor wouldn't match these (the `3` sits at the
    # word boundary and consumes `\s+`'s input).
    "    - run: pip3 install .",
    "    - run: pip3 install -r requirements.txt",
    "    - run: pip3.11 install -e .",
    # pipx install . — pipx is pip-with-isolation; local-path installs
    # still run setup.py / pyproject.toml build-backend hooks.
    "    - run: pipx install .",
    "    - run: pipx install -e .",
    # Poetry runs the build backend during install / add / update /
    # lock / sync, executing arbitrary code from a PR's pyproject.toml.
    "    - run: poetry install",
    "    - run: poetry add some-pkg",
    "    - run: poetry lock --no-update",
    "    - run: poetry sync",
    "    - run: python setup.py build",
    "    - run: python -m build",
    "    - run: make build",
    "    - run: make",
    "    - run: cmake --build .",
    "    - run: cargo build --release",
    "    - run: go build ./...",
    "    - run: gradle build",
    "    - run: ./gradlew assemble",
    "    - run: mvn package",
    "    - run: ./mvnw verify",
    "    - run: composer install",
    "    - run: bundle install",
    "    - run: docker build -t app .",
]

# Lines that no fragment should match. Comment-line filtering is the
# caller's job (rules exclude `^\s*#`); this set only contains lines
# whose content itself shouldn't match any build-tool fragment.
_KNOWN_NEGATIVES = [
    "    - run: echo hello",
    "    - name: Install tools",
    "    - uses: actions/checkout",
    "    - run: /usr/bin/make-release",  # \w/ before make — lookbehind fails
    "    - run: remake",  # `e` before make — lookbehind fails
    "    - run: pip list",  # pip list isn't in the install-family fragment
    "    - run: pip freeze",
    # pip / pipx with a named PyPI package — installs from the registry,
    # doesn't read attacker manifests. Match would be a false positive
    # in the LOTP context where the threat model is "manifest in the PR".
    "    - run: pip install PyGithub",
    "    - run: pip install --upgrade pip",
    "    - run: pip3 install requests",
    "    - run: pipx install cowsay",
    # Poetry read-only / version commands don't run the build backend.
    "    - run: poetry --version",
    "    - run: poetry run pytest",
    "    - run: poetry show",
]


def _any_fragment_matches(line: str) -> bool:
    """Reference: does at least one fragment match the line?"""
    for frag in BUILD_TOOL_FRAGMENTS:
        if re.search(frag, line):
            return True
    return False


def test_build_tool_anchor_matches_fragments():
    """Grouped anchor must match exactly when any fragment matches."""
    anchor_re = re.compile(BUILD_TOOL_ANCHOR)
    mismatches: list[tuple[str, bool, bool]] = []
    for line in _KNOWN_POSITIVES + _KNOWN_NEGATIVES:
        frag_match = _any_fragment_matches(line)
        anchor_match = bool(anchor_re.search(line))
        if frag_match != anchor_match:
            mismatches.append((line, frag_match, anchor_match))
    assert not mismatches, (
        f"BUILD_TOOL_ANCHOR diverged from BUILD_TOOL_FRAGMENTS on:\n"
        + "\n".join(f"  {line!r}: frag={f} anchor={a}" for line, f, a in mismatches)
    )


def test_build_tool_anchor_positives_fire():
    anchor_re = re.compile(BUILD_TOOL_ANCHOR)
    for line in _KNOWN_POSITIVES:
        assert anchor_re.search(line), f"anchor missed known positive: {line!r}"


def test_build_tool_anchor_negatives_do_not_fire():
    anchor_re = re.compile(BUILD_TOOL_ANCHOR)
    for line in _KNOWN_NEGATIVES:
        assert not anchor_re.search(line), f"anchor false-positive: {line!r}"
