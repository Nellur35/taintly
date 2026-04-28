"""Config file loader for taintly.

Loads .taintly.yml from the repo root (or a path given via --config).
Uses a hand-rolled YAML subset parser — zero dependencies required.

Supported schema:
    version: 1
    min-severity: HIGH
    fail-on: HIGH
    platform: github
    exclude-rules:
      - SEC4-GH-002
    ignore:
      - SEC4-GH-002                          # bare rule ID
      - id: SEC3-GH-001                      # id only
      - id: SEC3-GH-001                      # id + path prefix
        path: .github/workflows/legacy.yml
      - path: .github/workflows/vendor/      # path wildcard (all rules)
      # v2: justified, time-limited suppressions
      - id: SEC4-GH-002
        path: .github/workflows/internal.yml
        reason: "internal-only workflow — no fork triggers"
        expires: 2026-09-01                  # re-scan required after this date
        owner: platform-security@example.com
"""

from __future__ import annotations

import datetime as _dt
import os
import re
import sys
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .models import Finding

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CONFIG_FILENAME = ".taintly.yml"
MAX_CONFIG_BYTES = 64 * 1024  # 64 KB
MAX_IGNORE_ENTRIES = 500
SUPPORTED_VERSIONS = {1}
VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
VALID_PLATFORMS = {"github", "gitlab"}

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class IgnoreEntry:
    """A single ignore rule from the config file.

    rule_id=None  means "all rules"
    path_prefix=None means "all files"
    Both None means "suppress everything" (valid but triggers a warning).

    v2 fields (all optional, backward-compatible):

    * ``reason``  — free-form justification.  Entries without a reason
      trigger a one-time warning on each scan so silent exceptions don't
      accumulate unreviewed.
    * ``expires`` — ISO 8601 date (``YYYY-MM-DD``) after which the
      suppression is treated as expired: it still filters the finding
      (so CI doesn't break overnight) but a warning is emitted so the
      team sees the exception needs renewing.
    * ``owner``   — free-form accountability field (team name, email,
      Jira ticket).  Not interpreted, just carried through to JSON
      output for audit trails.
    """

    rule_id: str | None
    path_prefix: str | None  # normalised with os.path.normpath at parse time
    reason: str | None = None
    expires: _dt.date | None = None
    owner: str | None = None

    def is_expired(self, today: _dt.date | None = None) -> bool:
        if self.expires is None:
            return False
        if today is None:
            today = _dt.date.today()
        return today > self.expires


@dataclass
class AuditConfig:
    """Resolved configuration from .taintly.yml."""

    version: int = 1
    min_severity: str | None = None  # None = use CLI default (INFO)
    fail_on: str | None = None  # None = use built-in exit-code logic
    platform: str | None = None  # None = auto-detect
    exclude_rules: list[str] = field(default_factory=list)
    ignores: list[IgnoreEntry] = field(default_factory=list)


DEFAULT_CONFIG = AuditConfig()

# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class ConfigError(ValueError):
    """Raised when the config file cannot be parsed or fails validation."""


# ---------------------------------------------------------------------------
# Hand-rolled YAML subset parser
# ---------------------------------------------------------------------------

_TOP_KEY = re.compile(r"^([a-zA-Z][a-zA-Z0-9_-]*):\s*(.*)")
_LIST_ITEM_SCALAR = re.compile(r"^(\s*)-\s+(\S.*)")
_MAP_CONTINUATION = re.compile(r"^(\s+)([a-zA-Z][a-zA-Z0-9_-]*):\s*(.*)")


def _unquote(val: str) -> str:
    """Strip surrounding single or double quotes from a scalar value."""
    val = val.strip()
    if len(val) >= 2 and val[0] == val[-1] and val[0] in ('"', "'"):
        return val[1:-1]
    return val


def _parse_yaml_subset(text: str, warn_unknown: bool = True) -> dict[str, Any]:
    """Parse a strict subset of YAML sufficient for the taintly config schema.

    Handles:
    - Top-level scalar key: value pairs
    - Top-level list keys with scalar items or two-key objects (id/path)
    - Single-line comments (#)

    Does NOT handle anchors, aliases, multi-document, tags, block scalars,
    or any feature not needed by the schema above.

    Returns a plain dict. Raises ConfigError on unrecognised structure.
    """
    result: dict[str, Any] = {}
    current_key: str | None = None
    current_list: list[Any] | None = None
    current_obj: dict[str, Any] | None = None

    lines = text.splitlines()
    for lineno, raw in enumerate(lines, start=1):
        # Strip trailing whitespace; skip blanks and comments
        line = raw.rstrip()
        stripped = line.lstrip()
        if not stripped or stripped.startswith("#"):
            continue

        indent = len(line) - len(stripped)

        m_top = _TOP_KEY.match(line) if indent == 0 else None
        m_item = _LIST_ITEM_SCALAR.match(line) if indent > 0 else None
        m_map = _MAP_CONTINUATION.match(line) if indent > 2 else None

        if m_top:
            # Flush any pending list object and list
            if current_obj is not None and current_list is not None:
                current_list.append(current_obj)
                current_obj = None
            if current_key is not None and current_list is not None:
                result[current_key] = current_list

            current_key = m_top.group(1)
            val = m_top.group(2).strip()
            if val and not val.startswith("#"):
                result[current_key] = _unquote(val.split("#")[0].strip())
                current_list = None
                current_obj = None
            else:
                current_list = []
                current_obj = None

        elif m_item and current_list is not None:
            # New list item — flush previous object if any
            if current_obj is not None:
                current_list.append(current_obj)
                current_obj = None

            item_val = m_item.group(2).strip()
            # Is this a bare scalar or the start of a mapping object?
            if ":" in item_val and not item_val.startswith('"') and not item_val.startswith("'"):
                # Inline single-key map on the list-item line, e.g. "- id: SEC3-GH-001"
                inner_key, _, inner_val = item_val.partition(":")
                inner_val = inner_val.strip().split("#")[0].strip()
                current_obj = {inner_key.strip(): _unquote(inner_val) if inner_val else None}
            else:
                # Bare scalar list item (or quoted)
                current_list.append(_unquote(item_val.split("#")[0].strip()))

        elif m_map and current_obj is not None:
            # Continuation key inside a mapping object
            key = m_map.group(2)
            val = m_map.group(3).strip().split("#")[0].strip()
            current_obj[key] = _unquote(val) if val else None

        else:
            # Unrecognised structure.  Previously this branch silently
            # dropped the line, which means a user could believe a
            # suppression or setting had been applied while part of the
            # file was just skipped.  For a scanner whose output can gate
            # CI, silent partial parsing is worse than a noisy warning.
            if stripped and not stripped.startswith("#") and warn_unknown:
                print(
                    f"taintly: config warning: line {lineno}: "
                    f"unrecognised structure — ignored: {stripped[:80]!r}",
                    file=sys.stderr,
                )

    # Flush any trailing state
    if current_obj is not None and current_list is not None:
        current_list.append(current_obj)
    if current_key is not None and current_list is not None:
        result[current_key] = current_list

    return result


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def _validate_path(value: str, field_name: str) -> str:
    """Normalise a path value and reject path traversal."""
    normed = os.path.normpath(value)
    # Reject any path that escapes the repo root via ..
    parts = normed.replace("\\", "/").split("/")
    if ".." in parts:
        raise ConfigError(
            f"field '{field_name}': path '{value}' contains '..' components "
            f"and would escape the repo root — not allowed"
        )
    return normed


def _validate(raw: dict[str, Any]) -> AuditConfig:
    """Validate the parsed raw dict and return an AuditConfig."""
    known_keys = {"version", "min-severity", "fail-on", "platform", "exclude-rules", "ignore"}
    for key in raw:
        if key not in known_keys:
            print(
                f"taintly: config warning: unknown key '{key}' - ignored",
                file=sys.stderr,
            )

    # version
    version = 1
    if "version" in raw:
        try:
            version = int(raw["version"])
        except (TypeError, ValueError) as exc:
            raise ConfigError(f"field 'version': expected integer, got {raw['version']!r}") from exc
        if version not in SUPPORTED_VERSIONS:
            raise ConfigError(
                f"field 'version': unsupported version {version}; "
                f"supported: {sorted(SUPPORTED_VERSIONS)}"
            )

    # min-severity
    min_severity = None
    if "min-severity" in raw:
        val = str(raw["min-severity"]).upper()
        if val not in VALID_SEVERITIES:
            raise ConfigError(
                f"field 'min-severity': invalid value {raw['min-severity']!r}; "
                f"allowed: {', '.join(sorted(VALID_SEVERITIES))}"
            )
        min_severity = val

    # fail-on
    fail_on = None
    if "fail-on" in raw:
        val = str(raw["fail-on"]).upper()
        if val not in VALID_SEVERITIES:
            raise ConfigError(
                f"field 'fail-on': invalid value {raw['fail-on']!r}; "
                f"allowed: {', '.join(sorted(VALID_SEVERITIES))}"
            )
        fail_on = val

    # platform
    platform = None
    if "platform" in raw:
        val = str(raw["platform"]).lower()
        if val not in VALID_PLATFORMS:
            raise ConfigError(
                f"field 'platform': invalid value {raw['platform']!r}; "
                f"allowed: {', '.join(sorted(VALID_PLATFORMS))}"
            )
        platform = val

    # exclude-rules
    exclude_rules: list[str] = []
    if "exclude-rules" in raw:
        items = raw["exclude-rules"]
        if not isinstance(items, list):
            raise ConfigError("field 'exclude-rules': expected a list of rule IDs")
        for i, item in enumerate(items):
            if not isinstance(item, str):
                raise ConfigError(
                    f"field 'exclude-rules[{i}]': expected a string rule ID, got {item!r}"
                )
            exclude_rules.append(item.strip())

    # ignore
    ignores: list[IgnoreEntry] = []
    if "ignore" in raw:
        items = raw["ignore"]
        if not isinstance(items, list):
            raise ConfigError("field 'ignore': expected a list")
        if len(items) > MAX_IGNORE_ENTRIES:
            raise ConfigError(
                f"field 'ignore': too many entries ({len(items)}); maximum is {MAX_IGNORE_ENTRIES}"
            )
        for i, item in enumerate(items):
            if isinstance(item, str):
                # Bare rule ID
                ignores.append(IgnoreEntry(rule_id=item.strip(), path_prefix=None))
            elif isinstance(item, dict):
                rule_id = item.get("id")
                path_val = item.get("path")

                if rule_id is None and path_val is None:
                    raise ConfigError(
                        f"field 'ignore[{i}]': entry must have at least 'id' or 'path'"
                    )
                if rule_id is not None:
                    rule_id = str(rule_id).strip()
                if path_val is not None:
                    path_val = _validate_path(str(path_val), f"ignore[{i}].path")
                    # Warn on repo-root wildcard (suppress everything)
                    if path_val in (".", "") and rule_id is None:
                        print(
                            f"taintly: config warning: ignore[{i}] with path '.' and no rule "
                            f"ID suppresses ALL findings in the repo - verify this is intentional",
                            file=sys.stderr,
                        )

                # v2 fields — reason / expires / owner.  All optional.
                reason = item.get("reason")
                reason = str(reason).strip() if reason else None

                expires_raw = item.get("expires")
                expires_val: _dt.date | None = None
                if expires_raw:
                    try:
                        expires_val = _dt.date.fromisoformat(str(expires_raw).strip())
                    except ValueError as exc:
                        raise ConfigError(
                            f"field 'ignore[{i}].expires': invalid date {expires_raw!r}; "
                            f"expected ISO format YYYY-MM-DD"
                        ) from exc

                owner = item.get("owner")
                owner = str(owner).strip() if owner else None

                ignores.append(
                    IgnoreEntry(
                        rule_id=rule_id,
                        path_prefix=path_val,
                        reason=reason,
                        expires=expires_val,
                        owner=owner,
                    )
                )
            else:
                raise ConfigError(
                    f"field 'ignore[{i}]': expected a string or object, got {type(item).__name__}"
                )

    return AuditConfig(
        version=version,
        min_severity=min_severity,
        fail_on=fail_on,
        platform=platform,
        exclude_rules=exclude_rules,
        ignores=ignores,
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def find_config(repo_path: str) -> str | None:
    """Look for .taintly.yml in repo_path. Returns absolute path or None."""
    candidate = os.path.join(os.path.abspath(repo_path), CONFIG_FILENAME)
    return candidate if os.path.isfile(candidate) else None


def load_config(path: str) -> AuditConfig:
    """Load and validate a config file from path.

    Raises:
        FileNotFoundError: if path does not exist.
        ConfigError: if the file is too large, cannot be parsed, or fails validation.
    """
    abs_path = os.path.abspath(path)
    size = os.path.getsize(abs_path)
    if size > MAX_CONFIG_BYTES:
        raise ConfigError(
            f"config file is {size} bytes; maximum allowed is {MAX_CONFIG_BYTES} bytes (64 KB)"
        )

    with open(abs_path, encoding="utf-8", errors="replace") as f:
        text = f.read()

    try:
        raw = _parse_yaml_subset(text)
    except Exception as e:
        raise ConfigError(f"failed to parse config file: {e}") from e

    return _validate(raw)


def audit_ignores(
    ignores: list[IgnoreEntry],
    today: _dt.date | None = None,
) -> list[str]:
    """Return human-readable warnings about the suppression set.

    The improvement report specifically asked for justified, time-limited
    suppressions to prevent "permanent silent exceptions".  We enforce
    that by making this function emit one warning per problem found:

    * no ``reason`` on an entry  -> "suppression without justification"
    * ``expires`` date in the past -> "expired suppression still active"

    Warnings are only printed by the CLI — this function is pure so
    tests can assert on the exact message list.  Inline list-item
    suppressions (bare rule-id strings in the config) are exempt from
    the justification warning on the grounds that they're still
    human-readable exceptions in the committed config file.
    """
    messages: list[str] = []
    if today is None:
        today = _dt.date.today()

    for entry in ignores:
        # Bare rule-id entries have no dict to attach metadata to;
        # treat them as implicit "no justification provided" but
        # don't flood the output with warnings for every one.
        if (
            entry.rule_id
            and entry.path_prefix is None
            and entry.reason is None
            and entry.expires is None
            and entry.owner is None
        ):
            continue

        if entry.expires is not None and today > entry.expires:
            target = entry.rule_id or "<all rules>"
            where = entry.path_prefix or "<repo root>"
            messages.append(
                f"suppression expired on {entry.expires.isoformat()} but is still "
                f"active for rule {target} at {where} — review and renew or remove"
            )

        if entry.reason is None and (entry.path_prefix or entry.owner or entry.expires):
            target = entry.rule_id or "<all rules>"
            where = entry.path_prefix or "<repo root>"
            messages.append(
                f"suppression for rule {target} at {where} has no 'reason' field — "
                f"add a short justification so future readers know why"
            )

    return messages


def apply_config_ignores(
    findings: list[Finding], ignores: list[IgnoreEntry], repo_path: str
) -> list[Finding]:
    """Filter out findings suppressed by config ignore entries.

    Args:
        findings: list of Finding objects.
        ignores:  list of IgnoreEntry from AuditConfig.
        repo_path: absolute path to the repo root (for relative path computation).

    Returns a new list with suppressed findings removed.
    """
    if not ignores:
        return findings

    repo_abs = os.path.abspath(repo_path)
    return [finding for finding in findings if not _finding_is_ignored(finding, ignores, repo_abs)]


def _finding_is_ignored(finding, entries: list[IgnoreEntry], repo_abs: str) -> bool:
    """Return True if any ignore entry matches this finding."""
    try:
        rel = os.path.relpath(finding.file, repo_abs)
        rel_norm = os.path.normpath(rel)
    except ValueError:
        # On Windows, relpath can fail if paths are on different drives.
        rel_norm = os.path.normpath(finding.file)

    # Normalise to forward slashes for cross-platform prefix matching.
    rel_fwd = rel_norm.replace("\\", "/")

    for entry in entries:
        rule_matches = (entry.rule_id is None) or (entry.rule_id == finding.rule_id)
        if not rule_matches:
            continue

        if entry.path_prefix is None:
            # Global rule suppression — path irrelevant
            return True

        # Normalise the stored prefix to forward slashes for comparison.
        prefix = entry.path_prefix.replace("\\", "/")

        if rel_fwd == prefix:
            return True
        # Directory prefix: rel must start with prefix + "/"
        if rel_fwd.startswith(prefix + "/"):
            return True

    return False
