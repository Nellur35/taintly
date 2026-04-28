"""GitHub Action security advisories.

Bundled curated list of known-compromised GitHub Actions plus a
version-range matcher.  Sourced from the GitHub Advisory Database
(``GET /advisories?ecosystem=actions``) at release time.

Refreshing the list:

  1. ``gh api "/advisories?ecosystem=actions" --paginate``
  2. For each entry of interest, copy ``ghsa_id``, ``cve_id``,
     ``severity``, ``summary``, and the ``package.name`` /
     ``vulnerable_version_range`` / ``first_patched_version`` fields
     from ``vulnerabilities[]``.
  3. Append to ``data/compromised_actions.json``.
  4. Optionally use ``--advisory-check`` at scan time for live lookups.

The matcher only recognises semver-shaped refs (``v1``, ``v1.2``,
``v1.2.3``, ``1.2.3``).  Branch refs (``main``, ``master``) and SHA
pins are skipped — branch refs may or may not include the fix
depending on the timing of the user's checkout, and a SHA pin needs
git history walking that we don't do here.  Both cases are surfaced
by ``SEC3-GH-001`` (unpinned tag) / SHA-pin advice in the README.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from dataclasses import dataclass
from importlib import resources

# Cache the parsed dataset at module load.
_CACHE: list[Advisory] | None = None


@dataclass(frozen=True)
class Advisory:
    """One advisory record matching one (package, version-range) pair."""

    ghsa: str
    cve: str | None
    package: str  # e.g., "tj-actions/changed-files"
    severity: str  # "critical" / "high" / "medium" / "low"
    summary: str
    affected: str  # version range expression (see _matches_range)
    fixed: str | None
    discovered: str | None

    def affects(self, ref: str) -> bool:
        """Return True if a ``uses: <package>@<ref>`` line is in the affected range."""
        return _matches_range(ref, self.affected)


# ---------------------------------------------------------------------------
# Version parsing
# ---------------------------------------------------------------------------

# v1, v1.2, v1.2.3, 1, 1.2, 1.2.3 — possibly with a non-numeric suffix
# (-beta, -rc1) which we treat as <= the same numeric prefix for
# ordering purposes.  Branch refs and SHAs return None.
_SEMVER_RE = re.compile(r"^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:[-+.][\w.-]*)?$")


def _parse_ref(ref: str) -> tuple[int, int, int] | None:
    """Parse a git ref into a (major, minor, patch) tuple, or None.

    None means "we cannot decide" — most commonly a branch or a SHA.
    Callers should treat None as "no advisory match" so the rule does
    not fire on unparseable refs.
    """
    if not ref:
        return None
    # Reject 40-char hex (full SHA) and 7-12 char hex (short SHA).
    if re.fullmatch(r"[0-9a-f]{7,40}", ref):
        return None
    m = _SEMVER_RE.match(ref)
    if not m:
        return None
    major = int(m.group(1))
    minor = int(m.group(2) or 0)
    patch = int(m.group(3) or 0)
    return (major, minor, patch)


# ---------------------------------------------------------------------------
# Range matching
# ---------------------------------------------------------------------------

# Recognised range expressions (all GHSA's actual output forms):
#   "<= 45.0.7"          inclusive upper bound
#   "< 41"               exclusive upper bound
#   ">= 0.31.0, < 0.34.0"   compound range (AND)
#   "== 1"               exact match (used for "v1" tag = compromised release)
_RANGE_TOKEN_RE = re.compile(r"\s*(<=|>=|<|>|==)\s*(\S+?)\s*(?:,|$)")


def _matches_range(ref: str, range_expr: str) -> bool:
    parsed = _parse_ref(ref)
    if parsed is None:
        # Unparseable ref (branch / SHA) — be conservative, don't fire.
        return False

    constraints = list(_RANGE_TOKEN_RE.finditer(range_expr))
    if not constraints:
        return False

    for token in constraints:
        op, bound_str = token.group(1), token.group(2)
        bound = _parse_ref(bound_str)
        if bound is None:
            # Bound itself unparseable — the advisory data is suspect; skip.
            return False
        if (op == "<=" and not (parsed <= bound)) or (op == "<" and not (parsed < bound)):
            return False
        if (
            (op == ">=" and not (parsed >= bound))
            or (op == ">" and not (parsed > bound))
            or (op == "==" and parsed != bound)
        ):
            return False
    return True


# ---------------------------------------------------------------------------
# Bundled data loader
# ---------------------------------------------------------------------------


def load_bundled_advisories() -> list[Advisory]:
    """Return all bundled advisories.  Cached after first call."""
    global _CACHE
    if _CACHE is not None:
        return _CACHE

    raw = (
        resources.files(__package__)
        .joinpath("data/compromised_actions.json")
        .read_text(encoding="utf-8")
    )
    payload = json.loads(raw)
    advisories: list[Advisory] = []
    for entry in payload.get("advisories", []):
        advisories.append(
            Advisory(
                ghsa=entry["ghsa"],
                cve=entry.get("cve"),
                package=entry["package"],
                severity=entry.get("severity", "high"),
                summary=entry.get("summary", ""),
                affected=entry["affected"],
                fixed=entry.get("fixed"),
                discovered=entry.get("discovered"),
            )
        )
    _CACHE = advisories
    return advisories


def find_advisories_for(package: str, ref: str) -> list[Advisory]:
    """Return all bundled advisories that affect a given package@ref."""
    return [a for a in load_bundled_advisories() if a.package == package and a.affects(ref)]


# ---------------------------------------------------------------------------
# Live lookup against the GitHub Advisory Database (--advisory-check).
#
# Augments the bundled list (does not replace it).  Offline runs still
# use the curated baseline coverage; live runs add anything published
# since the last taintly release.  Errors are silent so a flaky network
# never breaks the scan.
# ---------------------------------------------------------------------------


_GHSA_API_BASE = "https://api.github.com/advisories"
_GHSA_TIMEOUT = 15
_GHSA_USER_AGENT = "taintly-advisory-check/1.0"


def _ghsa_query_one(package: str, token: str | None) -> list[Advisory]:
    """Query GHSA for advisories affecting a single package.  Empty list on any error."""
    import json as _json
    import urllib.error
    import urllib.request

    url = f"{_GHSA_API_BASE}?ecosystem=actions&affects={package}"
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": _GHSA_USER_AGENT,
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(  # nosec B310 — URL is the documented GitHub Advisories endpoint
            req, timeout=_GHSA_TIMEOUT
        ) as resp:
            body = _json.loads(resp.read())
    except (urllib.error.URLError, urllib.error.HTTPError, OSError, ValueError):
        return []
    if not isinstance(body, list):
        return []

    out: list[Advisory] = []
    for entry in body:
        ghsa = entry.get("ghsa_id")
        if not ghsa:
            continue
        for vuln in entry.get("vulnerabilities") or []:
            pkg = (vuln.get("package") or {}).get("name") or ""
            if pkg != package:
                continue
            affected = vuln.get("vulnerable_version_range") or ""
            if not affected:
                continue
            out.append(
                Advisory(
                    ghsa=ghsa,
                    cve=entry.get("cve_id"),
                    package=pkg,
                    severity=entry.get("severity", "high"),
                    summary=(entry.get("summary") or "")[:300],
                    affected=affected,
                    fixed=vuln.get("first_patched_version"),
                    discovered=entry.get("published_at"),
                )
            )
    return out


def fetch_live_advisories(packages: Iterable[str], token: str | None = None) -> list[Advisory]:
    """Query GHSA for live advisories on each unique package."""
    out: list[Advisory] = []
    for pkg in sorted(set(packages)):
        out.extend(_ghsa_query_one(pkg, token))
    return out


def augment_cache_with_live(packages: Iterable[str], token: str | None = None) -> int:
    """Fetch live advisories and merge them into the in-memory cache.

    Idempotent: bundled advisories stay; live additions are unioned in.
    De-dupes by ``(ghsa, package, affected)``.  Returns the count of
    NEW (live-only) advisories added.
    """
    global _CACHE
    bundled = load_bundled_advisories()
    live = fetch_live_advisories(packages, token)
    seen = {(a.ghsa, a.package, a.affected) for a in bundled}
    new_entries = [a for a in live if (a.ghsa, a.package, a.affected) not in seen]
    _CACHE = bundled + new_entries
    return len(new_entries)


# ---------------------------------------------------------------------------
# Test-helper: lets unit tests inject custom advisories without
# round-tripping through the JSON file.
# ---------------------------------------------------------------------------


def _override_for_tests(advisories: Iterable[Advisory]) -> None:
    """Replace the cache with a hand-built list (tests only)."""
    global _CACHE
    _CACHE = list(advisories)


def _reset_cache() -> None:
    """Drop the cache so the next call re-reads the JSON file."""
    global _CACHE
    _CACHE = None
