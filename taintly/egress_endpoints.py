"""Egress-policy emitter primitives (feature A).

Turns a workflow's *required* egress into a candidate
``step-security/harden-runner`` ``allowed-endpoints`` list. This module is the
pure, side-effect-free extraction half: a curated action -> endpoint map, a
``run:``-step host extractor, and ``compute_egress`` which unions them. The
file-rewriting *scaffold* (and the ``--fix-egress-allowlist-scaffold`` CLI flag)
is wired separately, on top of these primitives, and is always
review-before-enforcing — taintly drafts an allow-list, it never enforces one.

Conservative + fail-loud by design: a host we cannot classify is NOT silently
allowed; it is reported (``unknown_actions``) so a reviewer sees it, and at
runtime harden-runner's ``audit`` mode logs it. That is why the curated map can
be incomplete without being dangerous.
"""

from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass

# Curated, DATED action -> endpoint map. Last reviewed 2026-06-09. Keyed by
# ``owner/repo`` (version-agnostic). Values are the hosts the action's happy
# path legitimately contacts. Grow conservatively; an UNKNOWN action is
# reported, never guessed. (Lesson: GitHub moved release downloads to
# ``release-assets.githubusercontent.com`` — keep this list maintained.)
ACTION_ENDPOINTS: dict[str, frozenset[str]] = {
    "actions/checkout": frozenset(
        {"github.com", "codeload.github.com", "objects.githubusercontent.com", "api.github.com"}
    ),
    "actions/setup-node": frozenset(
        {
            "github.com",
            "objects.githubusercontent.com",
            "release-assets.githubusercontent.com",
            "nodejs.org",
        }
    ),
    "actions/setup-python": frozenset(
        {
            "github.com",
            "objects.githubusercontent.com",
            "release-assets.githubusercontent.com",
        }
    ),
    "actions/setup-go": frozenset(
        {
            "github.com",
            "objects.githubusercontent.com",
            "release-assets.githubusercontent.com",
            "go.dev",
            "dl.google.com",
            "storage.googleapis.com",
        }
    ),
    "actions/setup-java": frozenset(
        {"github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com"}
    ),
    "actions/upload-artifact": frozenset({"api.github.com", "*.blob.core.windows.net"}),
    "actions/download-artifact": frozenset({"api.github.com", "*.blob.core.windows.net"}),
    "actions/cache": frozenset(
        {"api.github.com", "*.blob.core.windows.net", "*.actions.githubusercontent.com"}
    ),
    "step-security/harden-runner": frozenset({"api.github.com"}),
    "docker/login-action": frozenset({"ghcr.io", "registry-1.docker.io", "auth.docker.io"}),
    "docker/build-push-action": frozenset(
        {
            "ghcr.io",
            "registry-1.docker.io",
            "auth.docker.io",
            "production.cloudflarestorage.com",
        }
    ),
    "docker/setup-buildx-action": frozenset(
        {"github.com", "registry-1.docker.io", "auth.docker.io"}
    ),
}

# Always needed by any GitHub-hosted runner job (the workflow/runner plumbing).
BASE_ENDPOINTS: frozenset[str] = frozenset(
    {"github.com", "api.github.com", "*.actions.githubusercontent.com"}
)

# A package/fetch manager detected on a ``run:`` line -> the hosts it contacts.
_PKG_HOSTS: list[tuple[re.Pattern[str], frozenset[str]]] = [
    (re.compile(r"\bpip(?:3)?\s+install\b"), frozenset({"pypi.org", "files.pythonhosted.org"})),
    (re.compile(r"\b(?:npm|pnpm)\s+(?:ci|install|i|add)\b"), frozenset({"registry.npmjs.org"})),
    (re.compile(r"\byarn\s+(?:install|add)\b"), frozenset({"registry.yarnpkg.com"})),
    (
        re.compile(r"\bgo\s+(?:get|install|mod\s+download)\b"),
        frozenset({"proxy.golang.org", "sum.golang.org"}),
    ),
    (
        re.compile(r"\bcargo\s+(?:build|install|fetch|update)\b"),
        frozenset({"static.crates.io", "index.crates.io"}),
    ),
    (
        re.compile(r"\bapt(?:-get)?\s+(?:install|update)\b"),
        frozenset({"archive.ubuntu.com", "security.ubuntu.com", "azure.archive.ubuntu.com"}),
    ),
]

# A URL fetched via curl / wget / git clone -> parse its host.
_URL_RE = re.compile(r"""\b(?:curl|wget|git\s+clone)\b[^\n]*?(https?://[^\s'"|;&)]+)""")

# ``uses: owner/repo[/subpath]@ref`` on a step. Local (``./``) and ``docker://``
# refs have no ``@``-pinned ``owner/repo`` and are skipped by the consumer.
_USES_RE = re.compile(r"""^\s*(?:-\s*)?uses:\s*['"]?([^@'"\n]+)@""", re.MULTILINE)


def hosts_from_run_block(body: str) -> set[str]:
    """Best-effort hosts a shell body contacts (package managers + fetched URLs).

    Conservative: only well-known managers and explicit ``http(s)://`` URLs are
    classified; anything else is left for harden-runner ``audit`` mode to surface.
    """
    hosts: set[str] = set()
    for pat, host_set in _PKG_HOSTS:
        if pat.search(body):
            hosts |= host_set
    for m in _URL_RE.finditer(body):
        netloc = urllib.parse.urlsplit(m.group(1)).netloc
        if netloc:
            host = netloc.split("@")[-1].split(":")[0]  # strip any creds + port
            if host:
                hosts.add(host)
    return hosts


@dataclass(frozen=True)
class EgressPlan:
    """The computed egress for one workflow file.

    :attr allowed: sorted hosts the workflow legitimately needs (base + mapped
        actions + run-derived).
    :attr unknown_actions: ``(line, owner/repo)`` for ``uses:`` actions with no
        map entry — reported for review, never auto-allowed.
    :attr run_hosts: sorted hosts derived from ``run:`` steps (provenance).
    """

    allowed: tuple[str, ...]
    unknown_actions: tuple[tuple[int, str], ...]
    run_hosts: tuple[str, ...]


def _action_key(ref: str) -> str:
    """``owner/repo`` from a ``uses:`` ref (drops any ``/subpath``)."""
    return "/".join(ref.strip().split("/")[:2])


def compute_egress(content: str) -> EgressPlan:
    """Compute the candidate egress allow-list for a workflow's content."""
    allowed: set[str] = set(BASE_ENDPOINTS)
    unknown: list[tuple[int, str]] = []
    for m in _USES_RE.finditer(content):
        ref = m.group(1).strip()
        if ref.startswith(("./", ".\\", "docker://")):
            continue
        key = _action_key(ref)
        endpoints = ACTION_ENDPOINTS.get(key)
        if endpoints is None:
            line = content[: m.start()].count("\n") + 1
            unknown.append((line, key))
        else:
            allowed |= endpoints
    run_hosts = hosts_from_run_block(content)
    allowed |= run_hosts
    return EgressPlan(
        allowed=tuple(sorted(allowed)),
        unknown_actions=tuple(unknown),
        run_hosts=tuple(sorted(run_hosts)),
    )
