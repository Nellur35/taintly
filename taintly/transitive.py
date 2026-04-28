"""Transitive action dependency analysis for GitHub Actions.

Detects supply-chain risk hidden inside composite actions: a workflow step may
pin an action to a full SHA (trusted, immutable outer call), but that action's
own action.yml may call sub-actions using mutable branch/tag refs.

The outer SHA pin only guarantees the action.yml file itself — it does NOT
protect you from unpinned sub-actions called within a composite action's steps.
If the sub-action's repo is compromised or force-pushed, the malicious code
executes inside YOUR job with access to all secrets and build artefacts.

Usage:
    python -m taintly . --transitive

Requires GITHUB_TOKEN in the environment. Makes one GitHub API call per
unique pinned action found in the scanned workflow files.

Findings are tagged with rule_id "SEC3-GH-T01".
"""

from __future__ import annotations

import base64
import json
import os
import re
import time
import urllib.error
import urllib.request
from typing import Any

from .families import classify_rule, default_confidence
from .models import Finding, Severity

# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------

# Matches pinned uses: (full 40-char SHA)
_PINNED_USES_RE = re.compile(
    r"^\s+uses:\s+([a-zA-Z0-9_-][a-zA-Z0-9_.-]*/[a-zA-Z0-9_.-]+)"
    r"@([a-f0-9]{40})\b"
)

# Matches any uses: in action.yml steps (for sub-action detection)
_SUB_USES_RE = re.compile(r"^\s+uses:\s+(\S+)")

# Detects a full 40-char SHA ref in a uses: value
_SHA_RE = re.compile(r"@[a-f0-9]{40}\b")

# Local action refs are safe (relative path, not external)
_LOCAL_ACTION_RE = re.compile(r"^\./")

# Docker action refs (docker://image) — not relevant for sub-action chaining
_DOCKER_RE = re.compile(r"^docker://")

# GitHub API rate-limit headers
_RATE_REMAINING = "x-ratelimit-remaining"
_RATE_RESET = "x-ratelimit-reset"


# ---------------------------------------------------------------------------
# GitHub API helpers
# ---------------------------------------------------------------------------


def _api_get(url: str, token: str) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    """GET a GitHub API URL. Returns (parsed_json_or_None, response_headers)."""
    req = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "taintly/transitive",
        },
    )
    try:
        # URL is built from a fixed `https://api.github.com/...`
        # template with rule-registry-sourced components, never user
        # input — the B310 scheme-audit finding does not apply here.
        with urllib.request.urlopen(req, timeout=15) as resp:  # nosec B310
            headers = dict(resp.headers)
            body = json.loads(resp.read().decode("utf-8", errors="replace"))
            return body, headers
    except urllib.error.HTTPError as e:
        headers = dict(e.headers) if e.headers else {}
        return None, headers
    except Exception:
        return None, {}


def _fetch_action_yml(owner: str, repo: str, sha: str, token: str) -> str | None:
    """Fetch action.yml (or action.yaml) content from GitHub at a specific SHA."""
    for filename in ("action.yml", "action.yaml"):
        url = f"https://api.github.com/repos/{owner}/{repo}/contents/{filename}?ref={sha}"
        data, headers = _api_get(url, token)
        if data and data.get("encoding") == "base64":
            try:
                return base64.b64decode(data["content"]).decode("utf-8", errors="replace")
            except Exception:
                return None

        # Check rate limit
        remaining = headers.get(_RATE_REMAINING, "999")
        try:
            if int(remaining) < 5:
                reset = int(headers.get(_RATE_RESET, str(int(time.time()) + 60)))
                wait = max(1, reset - int(time.time()))
                raise RateLimitError(f"GitHub API rate limit reached. Resets in {wait}s.")
        except (ValueError, TypeError):
            pass

    return None


class RateLimitError(Exception):
    pass


# ---------------------------------------------------------------------------
# Collection: find pinned uses: in workflow files
# ---------------------------------------------------------------------------


def collect_pinned_refs(files: list[str]) -> dict[str, list[tuple[str, int]]]:
    """Scan workflow files and collect all SHA-pinned action references.

    Returns a mapping:
        {"owner/repo@sha40": [(filepath, line_number), ...]}

    Only full 40-char SHA pins are collected — mutable refs are already caught
    by SEC3-GH-001 and are out of scope for transitive analysis.
    """
    refs: dict[str, list[tuple[str, int]]] = {}

    for fpath in files:
        try:
            with open(fpath, encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
        except OSError:
            continue

        for lineno, line in enumerate(lines, start=1):
            m = _PINNED_USES_RE.match(line)
            if m:
                action_repo = m.group(1)
                sha = m.group(2)
                key = f"{action_repo}@{sha}"
                refs.setdefault(key, []).append((fpath, lineno))

    return refs


# ---------------------------------------------------------------------------
# Parsing: find unpinned sub-actions in a composite action.yml
# ---------------------------------------------------------------------------


def find_unpinned_sub_uses(content: str) -> list[str]:
    """Parse action.yml content and return unpinned uses: refs in composite steps.

    Only composite actions (`runs.using: composite`) have YAML-level sub-action
    calls. JavaScript and Docker actions execute compiled artefacts, not YAML steps.

    Returns a list of unpinned ref strings like ["org/action@main", "org/other@v2"].
    """
    lines = content.splitlines()

    # Quick check — skip non-composite actions
    if not any(re.search(r"using\s*:\s*['\"]?composite['\"]?", line) for line in lines):
        return []

    unpinned: list[str] = []
    in_runs = False
    in_steps = False

    for line in lines:
        stripped = line.lstrip()
        indent = len(line) - len(stripped)

        # Detect `runs:` top-level key
        if re.match(r"^runs\s*:", line):
            in_runs = True
            in_steps = False
            continue

        if in_runs:
            # `steps:` inside runs
            if re.match(r"\s+steps\s*:", line):
                in_steps = True
                continue
            # Left the runs block (back to indent 0, new top-level key)
            if indent == 0 and stripped and not stripped.startswith("#"):
                in_runs = False
                in_steps = False
                continue

        if in_steps:
            m = _SUB_USES_RE.match(line)
            if m:
                ref = m.group(1).strip("'\"")
                # Skip local (./action), docker://, and already-pinned refs
                if (
                    not _LOCAL_ACTION_RE.match(ref)
                    and not _DOCKER_RE.match(ref)
                    and not _SHA_RE.search(ref)
                ):
                    unpinned.append(ref)

    return unpinned


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def run_transitive_analysis(
    files: list[str],
    token: str,
    repo_path: str,
) -> list[Finding]:
    """Run transitive action dependency analysis on a set of workflow files.

    For each SHA-pinned action found, fetches its action.yml and checks whether
    the composite action calls any sub-actions without SHA pinning.

    Args:
        files: List of workflow file paths to scan.
        token: GitHub API token (GITHUB_TOKEN).
        repo_path: Repo root for relative path display.

    Returns:
        List of Finding objects for transitive supply chain risks found.
    """
    pinned_refs = collect_pinned_refs(files)
    if not pinned_refs:
        return []

    findings: list[Finding] = []
    checked: dict[str, list[str]] = {}  # cache: ref -> unpinned sub-uses

    for ref_key, call_sites in pinned_refs.items():
        # Parse owner/repo@sha
        at = ref_key.rfind("@")
        if at < 0:
            continue
        action_repo = ref_key[:at]
        sha = ref_key[at + 1 :]

        slash = action_repo.find("/")
        if slash < 0:
            continue
        owner = action_repo[:slash]
        repo = action_repo[slash + 1 :]

        if ref_key in checked:
            unpinned_subs = checked[ref_key]
        else:
            try:
                content = _fetch_action_yml(owner, repo, sha, token)
            except RateLimitError as e:
                # Emit a single INFO finding describing the rate limit hit
                findings.append(
                    Finding(
                        rule_id="SEC3-GH-T01",
                        severity=Severity.INFO,
                        title="Transitive analysis incomplete — GitHub API rate limit reached",
                        description=str(e),
                        file="(transitive-analysis)",
                        remediation="Wait for the rate limit to reset and re-run with --transitive.",
                        reference="https://docs.github.com/en/rest/overview/rate-limits-for-the-rest-api",
                        owasp_cicd="CICD-SEC-3",
                        finding_family=classify_rule("SEC3-GH-T01", "CICD-SEC-3"),
                        confidence=default_confidence("SEC3-GH-T01"),
                    )
                )
                break

            if content is None:
                checked[ref_key] = []
                continue

            unpinned_subs = find_unpinned_sub_uses(content)
            checked[ref_key] = unpinned_subs

        if not unpinned_subs:
            continue

        for fpath, lineno in call_sites:
            # Display the path relative to the scanned repo when
            # possible — keeps the reporter output short and paths
            # portable across machines. Fall back to the absolute path
            # if the file lives outside repo_path (e.g. symlinked).
            try:
                display_path = os.path.relpath(fpath, repo_path)
            except ValueError:
                display_path = fpath

            sub_list = ", ".join(unpinned_subs[:3])
            if len(unpinned_subs) > 3:
                sub_list += f" (+{len(unpinned_subs) - 3} more)"

            findings.append(
                Finding(
                    rule_id="SEC3-GH-T01",
                    severity=Severity.HIGH,
                    title="Pinned composite action calls sub-actions without SHA pinning",
                    description=(
                        f"Action '{action_repo}' is pinned to SHA {sha[:12]}... "
                        f"but its action.yml calls the following sub-actions without "
                        f"full SHA pinning: {sub_list}. "
                        f"The outer SHA pin only locks the action.yml content — "
                        f"sub-actions are resolved at runtime and can be tampered with "
                        f"by anyone who can push to their repositories."
                    ),
                    file=display_path,
                    line=lineno,
                    snippet=f"uses: {action_repo}@{sha[:12]}...",
                    remediation=(
                        f"Pin each sub-action call inside {action_repo}/action.yml to a "
                        f"full 40-character SHA:\n"
                        f"  uses: org/sub-action@<40-char-sha>  # was @main or @v1\n\n"
                        f"If you do not control this action, consider forking it to a "
                        f"trusted repository and pinning your fork."
                    ),
                    reference="https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-third-party-actions",
                    owasp_cicd="CICD-SEC-3",
                    finding_family=classify_rule("SEC3-GH-T01", "CICD-SEC-3"),
                    confidence=default_confidence("SEC3-GH-T01"),
                )
            )

    return findings
