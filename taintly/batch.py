"""Sequential core scans with rule loading reused within one batch.

This API has scan_repo semantics; it does not apply CLI configuration, score or
render reports. Repository discoveries, contexts and findings remain per-scan.
"""

from __future__ import annotations

import os
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

from .engine import scan_repo
from .models import AuditReport, Platform, Rule
from .rules import registry


@dataclass
class RepositoryScanResult:
    """One ordered input's reports or explicit failure; never empty success on error."""

    repo_path: str
    reports: list[AuditReport] = field(default_factory=list)
    error: str | None = None


def scan_repositories(
    repo_paths: Iterable[str | os.PathLike[str]],
    platform: Platform | None = None,
    *,
    max_scan_seconds: float | None = None,
) -> list[RepositoryScanResult]:
    """Scan directory roots in order, including duplicates, loading packs once.

    With no explicit platform, load each supported pack once and let scan_repo
    discover platforms independently for each root. An import failure makes the
    whole batch unavailable. A per-root exception is an explicit error result
    and does not hide later roots. ENGINE-ERR findings remain in normal reports;
    callers must check those and files_scanned before treating a scan as clean.
    No cross-repository configuration or explicit GitHub identity is inherited.
    """
    paths = [os.fspath(path) for path in repo_paths]
    if not paths:
        return []
    rules: list[Rule] = []
    failures: list[str] = []
    try:
        for selected in (platform,) if platform is not None else tuple(Platform):
            rules.extend(registry.load_rules_for_platform(selected))
            failures.extend(registry._IMPORT_FAILURES)
    except Exception as exc:
        return [
            RepositoryScanResult(path, error=f"Rule loading failed: {type(exc).__name__}: {exc}")
            for path in paths
        ]
    if failures:
        return [
            RepositoryScanResult(path, error="Rule imports failed: " + ", ".join(failures))
            for path in paths
        ]
    results: list[RepositoryScanResult] = []
    for path in paths:
        try:
            if not Path(path).is_dir():
                results.append(RepositoryScanResult(path, error=f"NotADirectoryError: {path}"))
                continue
            reports = scan_repo(path, rules, platform, max_scan_seconds=max_scan_seconds)
            results.append(RepositoryScanResult(path, reports=reports))
        except Exception as exc:
            results.append(RepositoryScanResult(path, error=f"{type(exc).__name__}: {exc}"))
    return results
