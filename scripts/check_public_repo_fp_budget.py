#!/usr/bin/env python3
"""Source-locked public-repository precision budget.

This gate scans a small set of representative public repositories at exact
commits.  It keeps confirmed and review-needed findings in separate budgets so
new advisory evidence cannot be mistaken for a confirmed regression, while
still making growth in either class visible.

The scanner and checkout code use only the Python standard library.  Git is the
only external executable required to materialize the frozen source inputs.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any

_DEFAULT_CACHE = Path(os.environ.get("TAINTLY_SCAN_CACHE", "/tmp/taintly_scan_cache"))
_SHA_RE = re.compile(r"[0-9a-f]{40}")
_REPORT_EXIT_CODES = {0, 1, 2, 11}


@dataclass(frozen=True)
class Target:
    label: str
    repo_url: str
    revision: str
    cache_name: str
    scan_target: str
    platform: str
    max_confirmed: int
    max_review_needed: int

    @property
    def cache_key(self) -> str:
        return f"{self.cache_name}-{self.revision[:12]}"


# The revisions are evidence inputs, not update channels.  Change one only in a
# dedicated source-refresh review that records the before/after finding delta.
_TARGETS: tuple[Target, ...] = (
    Target(
        label="ripgrep",
        repo_url="https://github.com/BurntSushi/ripgrep.git",
        revision="4519153e5e461527f4bca45b042fff45c4ec6fb9",
        cache_name="gh_ripgrep",
        scan_target=".github/workflows",
        platform="github",
        max_confirmed=17,
        max_review_needed=5,
    ),
    Target(
        label="flask",
        repo_url="https://github.com/pallets/flask.git",
        revision="7374c85ddefc3f4b177a698ab9f0cbb6a5c0b392",
        cache_name="gh_flask",
        scan_target=".github/workflows",
        platform="github",
        max_confirmed=10,
        max_review_needed=2,
    ),
    Target(
        label="maven_jenkinsfile",
        repo_url="https://github.com/apache/maven.git",
        revision="5cd1b60264101080c712accd605180a4bd9222e0",
        cache_name="jk_maven",
        scan_target="Jenkinsfile",
        platform="jenkins",
        max_confirmed=2,
        max_review_needed=0,
    ),
)


@dataclass(frozen=True)
class ScanResult:
    confirmed: int
    review_needed: int
    engine_errors: int
    findings: tuple[dict[str, Any], ...]
    rule_counts: dict[str, int]
    severity_counts: dict[str, int]


@dataclass(frozen=True)
class SourceIdentity:
    revision: str
    repo_url: str
    worktree_dirty: bool


def _validate_target(target: Target) -> None:
    if not target.label or not target.cache_name:
        raise ValueError("target label and cache_name must be non-empty")
    if _SHA_RE.fullmatch(target.revision) is None:
        raise ValueError(f"{target.label}: revision must be a full lowercase SHA")
    path = PurePosixPath(target.scan_target.replace("\\", "/"))
    if path.is_absolute() or ".." in path.parts or not path.parts:
        raise ValueError(f"{target.label}: scan_target must stay inside the checkout")
    if "/" in target.cache_name or "\\" in target.cache_name or target.cache_name in {".", ".."}:
        raise ValueError(f"{target.label}: unsafe cache_name")
    if target.max_confirmed < 0 or target.max_review_needed < 0:
        raise ValueError(f"{target.label}: budgets must be non-negative")


def _run_git(args: list[str], cwd: Path, timeout: int = 180) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def _head_sha(checkout: Path) -> str | None:
    proc = _run_git(["rev-parse", "HEAD"], checkout, timeout=30)
    if proc.returncode != 0:
        return None
    value = proc.stdout.strip().lower()
    return value if _SHA_RE.fullmatch(value) else None


def _source_identity(checkout: Path) -> tuple[SourceIdentity | None, str | None]:
    """Read the three source properties that make a cached checkout evidence."""
    revision = _head_sha(checkout)
    if revision is None:
        return None, "checkout has no valid HEAD"
    origin = _run_git(["remote", "get-url", "origin"], checkout, timeout=30)
    repo_url = origin.stdout.strip() if origin.returncode == 0 else ""
    if not repo_url:
        return None, "checkout has no readable origin URL"
    status = _run_git(
        ["status", "--porcelain", "--untracked-files=all", "--ignored"],
        checkout,
        timeout=30,
    )
    if status.returncode != 0:
        return None, "checkout worktree status could not be read"
    return (
        SourceIdentity(
            revision=revision,
            repo_url=repo_url,
            worktree_dirty=bool(status.stdout.strip()),
        ),
        None,
    )


def _validate_source_identity(
    checkout: Path, target: Target
) -> tuple[SourceIdentity | None, str | None]:
    identity, error = _source_identity(checkout)
    if identity is None:
        return None, error
    if identity.revision != target.revision:
        return None, (f"cached checkout has {identity.revision}, expected {target.revision}")
    if identity.repo_url != target.repo_url:
        return None, (
            "cached checkout origin URL mismatch: "
            f"expected {target.repo_url!r}, got {identity.repo_url!r}"
        )
    if identity.worktree_dirty:
        return None, "cached checkout has modified, untracked, or ignored files"
    return identity, None


def _remove_partial(path: Path, cache: Path) -> None:
    """Remove only a failed materialization directory below ``cache``."""
    try:
        path.resolve().relative_to(cache.resolve())
    except (OSError, ValueError):
        return
    if path.exists() and not path.is_symlink():
        shutil.rmtree(path, ignore_errors=True)


def _materialize(target: Target, cache: Path) -> tuple[Path | None, str | None]:
    """Materialize only ``scan_target`` at ``revision``.

    The revision is part of the cache key.  An existing checkout with a
    different HEAD is treated as corrupted evidence and is never updated in
    place.  Sparse checkout avoids Windows long-path failures in repositories
    such as Maven when only one Jenkinsfile is needed.
    """
    _validate_target(target)
    cache.mkdir(parents=True, exist_ok=True)
    checkout = cache / target.cache_key
    wanted = checkout / Path(target.scan_target)
    if checkout.exists():
        _identity, identity_error = _validate_source_identity(checkout, target)
        if identity_error:
            return None, identity_error
        if not wanted.exists():
            return None, f"pinned target is missing: {target.scan_target}"
        return checkout, None

    partial = cache / f".{target.cache_key}.partial"
    if partial.exists():
        return None, f"stale partial checkout exists: {partial.name}"
    partial.mkdir(parents=False)
    commands = (
        ["init", "-q"],
        ["remote", "add", "origin", target.repo_url],
        ["sparse-checkout", "init", "--no-cone"],
        ["sparse-checkout", "set", "--no-cone", target.scan_target],
        ["fetch", "-q", "--depth", "1", "--filter=blob:none", "origin", target.revision],
        ["checkout", "-q", "--detach", "FETCH_HEAD"],
    )
    try:
        for args in commands:
            proc = _run_git(args, partial)
            if proc.returncode != 0:
                detail = (proc.stderr or proc.stdout).strip().splitlines()
                reason = detail[-1] if detail else f"git {' '.join(args)} failed"
                _remove_partial(partial, cache)
                return None, reason
        _identity, identity_error = _validate_source_identity(partial, target)
        if identity_error:
            _remove_partial(partial, cache)
            return None, identity_error
        if not (partial / Path(target.scan_target)).exists():
            _remove_partial(partial, cache)
            return None, f"pinned target is missing: {target.scan_target}"
        partial.replace(checkout)
        return checkout, None
    except (OSError, subprocess.TimeoutExpired) as exc:
        _remove_partial(partial, cache)
        return None, f"{type(exc).__name__}: {exc}"


def _relative_file(raw: object, checkout: Path) -> str:
    value = str(raw or "")
    if not value:
        return ""
    path = Path(value)
    try:
        return path.resolve().relative_to(checkout.resolve()).as_posix()
    except (OSError, ValueError):
        # Reports should never disclose a machine-specific absolute path.
        return path.name


def _normalise_finding(raw: dict[str, Any], checkout: Path) -> dict[str, Any]:
    evidence = {
        "rule_id": str(raw.get("rule_id", "")),
        "severity": str(raw.get("severity", "")),
        "file": _relative_file(raw.get("file"), checkout),
        "line": int(raw.get("line") or 0),
        "title": str(raw.get("title", "")),
        "finding_family": str(raw.get("finding_family", "")),
        "exploitability": str(raw.get("exploitability", "")),
        "review_needed": bool(raw.get("review_needed", False)),
    }
    fingerprint_input = dict(evidence)
    fingerprint_input["snippet"] = str(raw.get("snippet", ""))
    encoded = json.dumps(
        fingerprint_input, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    evidence["fingerprint"] = hashlib.sha256(encoded).hexdigest()
    return evidence


def _scan(checkout: Path, target: Target) -> tuple[ScanResult | None, str | None]:
    scan_path = checkout / Path(target.scan_target)
    cmd = [
        sys.executable,
        "-m",
        "taintly",
        str(scan_path),
        "--platform",
        target.platform,
        "--format",
        "json",
        "--min-severity",
        "LOW",
        "--no-color",
        "--no-config",
    ]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return None, "scan timed out"
    try:
        report = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        return None, f"scan produced no parseable JSON: {exc}"
    if proc.returncode not in _REPORT_EXIT_CODES:
        return None, f"scan exited with code {proc.returncode}"
    if not isinstance(report, dict):
        return None, "scan JSON root is not an object"
    raw_findings = report.get("findings")
    if not isinstance(raw_findings, list):
        return None, "scan JSON has no findings list"
    if any(not isinstance(item, dict) for item in raw_findings):
        return None, "scan JSON contains a malformed finding"
    raw_errors = report.get("errors", [])
    if not isinstance(raw_errors, list):
        return None, "scan JSON errors field is not a list"
    try:
        findings = tuple(_normalise_finding(item, checkout) for item in raw_findings)
    except (TypeError, ValueError) as exc:
        return None, f"scan JSON contains invalid finding fields: {exc}"
    rule_counts = dict(sorted(Counter(f["rule_id"] for f in findings).items()))
    severity_counts = dict(sorted(Counter(f["severity"] for f in findings).items()))
    finding_engine_errors = sum(f["rule_id"] == "ENGINE-ERR" for f in findings)
    return (
        ScanResult(
            confirmed=sum(not f["review_needed"] for f in findings),
            review_needed=sum(f["review_needed"] for f in findings),
            # JSON reporters mirror ENGINE-ERR findings into the top-level
            # errors list. max() avoids double-counting while remaining
            # conservative if either representation is incomplete.
            engine_errors=max(finding_engine_errors, len(raw_errors)),
            findings=findings,
            rule_counts=rule_counts,
            severity_counts=severity_counts,
        ),
        None,
    )


def _budget_failures(target: Target, result: ScanResult) -> list[str]:
    failures: list[str] = []
    if result.confirmed > target.max_confirmed:
        failures.append(f"confirmed {result.confirmed} exceeds {target.max_confirmed}")
    if result.review_needed > target.max_review_needed:
        failures.append(f"review-needed {result.review_needed} exceeds {target.max_review_needed}")
    if result.engine_errors:
        failures.append(f"{result.engine_errors} ENGINE-ERR coverage finding(s)")
    return failures


def _annotate(level: str, message: str) -> None:
    if os.environ.get("GITHUB_ACTIONS") == "true":
        print(f"::{level}::{message}")


def _write_summary(lines: list[str]) -> None:
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_path:
        return
    try:
        with open(summary_path, "a", encoding="utf-8") as handle:
            handle.write("\n".join(lines) + "\n")
    except OSError:
        pass


def _scanner_identity() -> dict[str, Any]:
    """Return the scanner commit and whether tracked files differ from it."""
    root = Path(__file__).resolve().parents[1]
    revision = _head_sha(root) or "unknown"
    workflow_revision_raw = os.environ.get("GITHUB_SHA", "").strip().lower()
    workflow_revision: str | None = (
        workflow_revision_raw if _SHA_RE.fullmatch(workflow_revision_raw) is not None else None
    )
    status = _run_git(["status", "--porcelain", "--untracked-files=no"], root, timeout=30)
    dirty: bool | None = None
    if status.returncode == 0:
        dirty = bool(status.stdout.strip())
    return {
        "revision": revision,
        "workflow_revision": workflow_revision,
        "workflow_revision_matches": (
            workflow_revision == revision if workflow_revision is not None else None
        ),
        "tracked_files_dirty": dirty,
    }


def _scanner_identity_error(identity: dict[str, Any]) -> str | None:
    if identity.get("revision") == "unknown":
        return "scanner: current revision could not be read"
    if identity.get("tracked_files_dirty") is not False:
        return "scanner: tracked files are dirty or could not be verified clean"
    if identity.get("workflow_revision_matches") is False:
        return "scanner: GITHUB_SHA does not match the checked-out revision"
    return None


def _target_receipt(target: Target, result: ScanResult, identity: SourceIdentity) -> dict[str, Any]:
    return {
        "label": target.label,
        "source": {
            "repo_url": target.repo_url,
            "revision": target.revision,
            "scan_target": target.scan_target,
            "platform": target.platform,
            "observed": asdict(identity),
        },
        "budgets": {
            "confirmed": target.max_confirmed,
            "review_needed": target.max_review_needed,
        },
        "result": asdict(result),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run the source-locked public-repository precision budget"
    )
    parser.add_argument("--strict-skips", action="store_true")
    parser.add_argument("--cache", type=Path, default=_DEFAULT_CACHE)
    parser.add_argument("--receipt", type=Path)
    parser.add_argument(
        "--target",
        action="append",
        choices=[target.label for target in _TARGETS],
        help="run only this target; repeat to select more than one",
    )
    args = parser.parse_args(argv)

    if shutil.which("git") is None:
        message = "git not available; no frozen source could be materialized"
        print(message, file=sys.stderr)
        return 2 if args.strict_skips else 0

    selected = set(args.target or ())
    targets = [t for t in _TARGETS if not selected or t.label in selected]
    failures: list[str] = []
    skipped: list[str] = []
    receipts: list[dict[str, Any]] = []
    summary = ["## Source-locked public-repo precision budget", ""]
    scanner_identity = _scanner_identity()
    scanner_error = _scanner_identity_error(scanner_identity)
    if scanner_error:
        skipped.append(scanner_error)

    for target in targets:
        checkout, checkout_error = _materialize(target, args.cache)
        if checkout is None:
            skipped.append(f"{target.label}: {checkout_error}")
            continue
        result, scan_error = _scan(checkout, target)
        if result is None:
            skipped.append(f"{target.label}: {scan_error}")
            continue
        identity, identity_error = _validate_source_identity(checkout, target)
        if identity is None:
            skipped.append(f"{target.label}: source identity changed during scan: {identity_error}")
            continue
        target_failures = _budget_failures(target, result)
        marker = "FAIL" if target_failures else "OK  "
        line = (
            f"{marker} {target.label:22s} confirmed {result.confirmed:3d}/"
            f"{target.max_confirmed:<3d} review {result.review_needed:3d}/"
            f"{target.max_review_needed:<3d} source {target.revision[:12]}"
        )
        print(line)
        summary.append(f"- `{line}`")
        receipts.append(_target_receipt(target, result, identity))
        for detail in target_failures:
            message = f"{target.label}: {detail}"
            failures.append(message)
            _annotate("error", message)

    if skipped:
        summary.extend(["", "### Not measured"])
        for message in skipped:
            print(f"SKIP {message}", file=sys.stderr)
            summary.append(f"- {message}")
            _annotate("warning", message)
    _write_summary(summary)

    if args.receipt:
        receipt = {
            "schema_version": 1,
            "status": ("failed" if failures else "incomplete" if skipped else "complete"),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "scanner": scanner_identity,
            "selection": {
                "requested_targets": len(targets),
                "completed_targets": len(receipts),
            },
            "targets": receipts,
            "failures": failures,
            "skipped": skipped,
        }
        args.receipt.parent.mkdir(parents=True, exist_ok=True)
        args.receipt.write_text(
            json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

    if failures:
        print("\nPrecision budget exceeded:", file=sys.stderr)
        for message in failures:
            print(f"  - {message}", file=sys.stderr)
        return 1
    if skipped and args.strict_skips:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
