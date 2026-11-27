"""Advisory rules selected only by the local GitHub strict posture option."""

import re
from collections import Counter
from dataclasses import dataclass, replace

from taintly.actions_lock import ActionsLockAwarePattern
from taintly.models import IncompletePatternMatches, Platform, Rule, Severity
from taintly.parsers.structural import EventKind, walk_workflow
from taintly.rules.github.sec3_sec4_supply_chain_ppe import (
    _BRANCH_REF_NAMES,
    _CHECKOUT_USES_RE,
    _FULL_SHA_RE,
    _TRUSTED_FIRST_PARTY_OWNERS,
    _action_reference_at_uses,
    _is_github_uses_field,
)

_CHECKOUT_POSTURE_ID = "SEC4-GH-005C"
_MORE_SPECIFIC_CHECKOUT_IDS = {"SEC4-GH-005", "SEC4-GH-005B"}
_NAMED_REF = re.compile(r"[A-Za-z0-9_./-]+\Z")
_TRUE_INPUTS = {"true", "True", "TRUE"}
_FALSE_INPUTS = {"false", "False", "FALSE"}


@dataclass(frozen=True)
class _PosturePattern:
    checkout: bool

    def check(self, content: str, _lines: list[str]) -> list[tuple[int, str]]:
        events = tuple(
            walk_workflow(
                "workflow.yml", content=content, include_keys=True, include_merge_origins=True
            )
        )
        if any(event.kind in {EventKind.ERROR, EventKind.CUTOFF} for event in events):
            return IncompletePatternMatches([], reason="Could not resolve owning YAML fields.")
        keys = Counter(event.path for event in events if event.kind is EventKind.MAP_KEY)
        leaves = [
            event
            for event in events
            if event.kind is EventKind.LEAF_SCALAR
            and not any(base + (key,) in keys for base, key in event.merge_origins)
        ]
        values = Counter(event.path for event in leaves)
        conflict = {
            path for counts in (keys, values) for path, count in counts.items() if count > 1
        }
        options = {
            event.path: event
            for event in leaves
            if event.path[-2:] == ("with", "persist-credentials")
        }
        mappings = {path[:-1] for path in keys if isinstance(path[-1], str)}
        nested_options = {
            event.path[:6] for event in leaves if event.path[4:6] == ("with", "persist-credentials")
        }
        candidates = [
            event for event in leaves if _is_github_uses_field(event.path, composite=True)
        ]
        occurrences = Counter(event.line for event in candidates)

        matches = []
        unknown = []
        for event in candidates:
            value = event.value or ""
            path = event.path
            if self.checkout:
                if len(path) != 5 or not value.lower().startswith("actions/checkout@"):
                    continue
                option = path[:-1] + ("with", "persist-credentials")
                setting = options.get(option)
                if (
                    occurrences[event.line] != 1
                    or _ambiguous(path, conflict)
                    or _ambiguous(option, conflict)
                    or (setting is None and (option in keys or option in nested_options))
                    or (option[:-1] in keys and option[:-1] not in mappings)
                    or option[:-1] in values
                    or not _CHECKOUT_USES_RE.fullmatch(value)
                    or "${{" in value
                ):
                    unknown.append(event.line)
                    continue
                if setting is not None:
                    if setting.value in _FALSE_INPUTS:
                        continue
                    if setting.value not in _TRUE_INPUTS:
                        unknown.append(event.line)
                        continue
            else:
                action, at, ref = value.partition("@")
                if (
                    not at
                    or action.split("/", 1)[0].lower() not in _TRUSTED_FIRST_PARTY_OWNERS
                    or "/.github/workflows/" in action
                    or ref in _BRANCH_REF_NAMES
                    or _FULL_SHA_RE.fullmatch(ref.lower())
                ):
                    continue
                if (
                    _ambiguous(path, conflict)
                    or not _action_reference_at_uses(value, path)
                    or not _NAMED_REF.fullmatch(ref)
                ):
                    unknown.append(event.line)
                    continue
            matches.append((event.line, f"uses: {value}"))
        if unknown:
            return IncompletePatternMatches(
                matches,
                reason=f"Could not resolve the owning configuration at line {min(unknown)}.",
            )
        return matches


def _ambiguous(path: tuple[object, ...], conflicts: set[tuple[object, ...]]) -> bool:
    return any(path[:size] in conflicts for size in range(1, len(path) + 1))


def with_github_strict_posture(rules: list[Rule]) -> list[Rule]:
    """Extend one invocation's rule pack without mutating the shared registry."""
    return [
        replace(rule, supersedes=[*rule.supersedes, _CHECKOUT_POSTURE_ID])
        if rule.id in _MORE_SPECIFIC_CHECKOUT_IDS
        else rule
        for rule in rules
    ] + [
        Rule(
            id="SEC3-GH-001B",
            title="Action from a recognized publisher uses a mutable reference",
            severity=Severity.INFO,
            platform=Platform.GITHUB,
            owasp_cicd="CICD-SEC-3",
            description=(
                "The owning uses field selects a named reference instead of a commit. "
                "A change to that reference can change which code runs without a workflow edit."
            ),
            pattern=ActionsLockAwarePattern(_PosturePattern(checkout=False)),
            remediation="Pin this action to a reviewed full commit SHA.",
            reference="https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions",
            confidence="high",
            review_needed=True,
        ),
        Rule(
            id=_CHECKOUT_POSTURE_ID,
            title="Checkout leaves credential persistence enabled or unspecified",
            severity=Severity.INFO,
            platform=Platform.GITHUB,
            owasp_cicd="CICD-SEC-4",
            description=(
                "This checkout enables persist-credentials or leaves it unset. Supported "
                "checkout releases retain authentication by default. Check the exact checkout "
                "version, effective permissions, and whether later steps need that access."
            ),
            pattern=_PosturePattern(checkout=True),
            remediation=(
                "Check whether later steps need checkout authentication. Set "
                "persist-credentials: false if they do not, or supply deliberately scoped authentication."
            ),
            reference="https://github.com/actions/checkout#usage",
            confidence="high",
            review_needed=True,
        ),
    ]
