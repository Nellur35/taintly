"""Shared build-tool regex used by LOTP rules across all three platforms.

This module lives at ``rules/`` root (not inside a platform sub-directory)
so LOTP rules on GitHub, GitLab, and Jenkins can all import it. The leading
underscore keeps the per-platform rule registries from picking it up as a
rule source.

Every entry is a regex fragment that matches a build-tool invocation on a
shell line. Fragments use word boundaries rather than start/end anchors so
the match survives when the command is preceded or followed by flags,
pipes, quotes, or environment-variable prefixes — important for Jenkins
where commands live inside ``sh 'npm install'`` / ``sh "npm install"``
Groovy strings, and for GitLab where they appear as ``script:`` YAML list
entries.

Updates to the tool list belong here; all LOTP rules import
:data:`BUILD_TOOL_ANCHOR`.
"""

from __future__ import annotations

# Build tools and package managers that execute lifecycle scripts, build
# hooks, or code-generator directives from checked-out source.
BUILD_TOOL_FRAGMENTS: list[str] = [
    # JavaScript / TypeScript
    # - install/ci/update/pack run pre/install/postinstall scripts
    # - publish runs prepublishOnly/prepublish/publish/postpublish
    # - run/build/test execute user scripts defined in package.json, which
    #   the attacker can redefine via a PR to package.json
    r"\bnpm\s+(?:install|ci|i|update|pack|publish|run|build|test)\b",
    # yarn with a subcommand OR bare (defaults to install)
    r"\byarn(?:\s+(?:install|run|build|test))?\b",
    r"\bpnpm\s+(?:install|i|run|build|test)\b",
    # Python
    # - pip install . / -e . / --editable . / -r <file> reads attacker manifests
    # - pip install PackageName (installs from PyPI) is NOT in this anchor;
    #   SEC4-GH-011 further excludes the bare-package form to avoid false
    #   positives on routine dependency installs.
    # - `pip\d*(?:\.\d+)?` catches `pip`, `pip3`, `pip3.11` — Debian /
    #   Ubuntu / pyenv commonly ship versioned binaries and a bare `\bpip`
    #   wouldn't match `pip3 install .` (the `3` sits at the word boundary).
    r"\bpip\d*(?:\.\d+)?\s+install\s+(?:\.|-e\s+\.|--editable\s+\.|-r\s+\S+)",
    # pipx install . — pipx is pip-with-isolation; installing from a local
    # path still runs setup.py / pyproject.toml build-backend hooks.  pipx
    # install <PackageName> is from PyPI and NOT matched (same exclusion
    # reasoning as the plain pip arm).
    r"\bpipx\s+install\s+(?:\.|-e\s+\.|--editable\s+\.)",
    # Poetry — reads pyproject.toml and invokes the build-backend at
    # install / update / lock / sync time, running arbitrary attacker
    # code from a PR's pyproject.toml.
    r"\bpoetry\s+(?:install|add|update|lock|sync)\b",
    r"\bpython\s+setup\.py\b",
    r"\bpython\s+-m\s+build\b",
    # C / C++ — Makefile and CMakeLists.txt are arbitrary shell
    # Negative lookbehind keeps \bmake\b from matching `/usr/bin/make` paths
    # or identifiers like `make_release` where a word char precedes.
    r"(?<![\w/])make(?:\s+\w+)*",
    r"\bcmake(?:\s+--build)?\b",
    # Rust — build.rs executes Rust at build time.
    # `cargo install <name>` downloads <name> from crates.io and runs
    # ITS build.rs — that's a registry install, not a build of the
    # checked-out source. Restrict the install arm to `--path` so only
    # local-code installs match (analog of pip's `.`/`-e .` requirement
    # above). `cargo build`/`run`/`test` build the local crate by
    # default and stay unconditional.
    r"\bcargo\s+(?:build|run|test)\b",
    r"\bcargo\s+install\s+--path\b",
    # Go — //go:generate runs arbitrary commands
    r"\bgo\s+(?:build|generate|install|run)\b",
    # JVM
    r"(?:\bgradle\b|\./gradlew\b)",
    r"(?:\bmvn\b|\./mvnw\b)",
    # PHP — composer runs post-install / post-update scripts by default
    r"\bcomposer\s+(?:install|update)\b",
    # Ruby — native-extension compilation during bundle install
    r"\bbundle\s+(?:install|exec)\b",
    # Container builds — RUN directives execute at build time
    r"\bdocker\s+build\b",
]

# Prefix-grouped form of BUILD_TOOL_FRAGMENTS — semantically equivalent
# to a naive alternation of the fragments, but ~37% faster per-line on
# whitespace-heavy adversarial YAML because the regex engine can
# discriminate on the leading letter before trying each alternative's
# body. Equivalence with the fragment list is enforced by a test
# (tests/unit/test_build_tools.py::test_build_tool_anchor_matches_fragments).
BUILD_TOOL_ANCHOR: str = (
    r"(?:"
    r"\bn(?:pm\s+(?:install|ci|i|update|pack|publish|run|build|test)\b)"
    r"|\by(?:arn(?:\s+(?:install|run|build|test))?\b)"
    r"|\bp(?:"
    r"npm\s+(?:install|i|run|build|test)\b"
    # pip / pip3 / pip3.11 install . / -e . / --editable . / -r <file>
    r"|ip\d*(?:\.\d+)?\s+install\s+(?:\.|-e\s+\.|--editable\s+\.|-r\s+\S+)"
    # pipx install . / -e . / --editable .  (local-path form only)
    r"|ipx\s+install\s+(?:\.|-e\s+\.|--editable\s+\.)"
    # poetry install / add / update / lock / sync — runs build-backend
    r"|oetry\s+(?:install|add|update|lock|sync)\b"
    r"|ython\s+(?:setup\.py|-m\s+build)\b"
    r")"
    r"|\bc(?:"
    r"make(?:\s+--build)?\b"
    # `cargo install` requires --path to count as a local-code build —
    # see BUILD_TOOL_FRAGMENTS for the rationale.
    r"|argo\s+(?:build|run|test)\b"
    r"|argo\s+install\s+--path\b"
    r"|omposer\s+(?:install|update)\b"
    r")"
    r"|\bg(?:o\s+(?:build|generate|install|run)\b|radle\b)"
    r"|\bmvn\b"
    r"|\bd(?:ocker\s+build\b)"
    r"|\bb(?:undle\s+(?:install|exec)\b)"
    r"|(?<![\w/])make(?:\s+\w+)*"
    r"|\./(?:gradlew|mvnw)\b"
    r")"
)
