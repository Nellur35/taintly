"""Repository-bounded discovery and GitLab local-include resolution."""

from __future__ import annotations

import fnmatch
import os
from collections.abc import Iterator


def is_within_repo(repo_root: str, candidate: str) -> bool:
    root = os.path.normcase(os.path.realpath(repo_root))
    resolved = os.path.normcase(os.path.realpath(candidate))
    try:
        return os.path.commonpath((root, resolved)) == root
    except ValueError:
        # Different Windows drives have no common path.
        return False


def iter_files_within_repo(repo_path: str, relative_root: str) -> Iterator[str]:
    """Yield logical file paths without following directories outside the repo."""
    search_root = os.path.join(repo_path, relative_root)
    if not os.path.isdir(search_root) or not is_within_repo(repo_path, search_root):
        return
    for root, dirs, files in os.walk(search_root, followlinks=False):
        dirs[:] = [name for name in dirs if is_within_repo(repo_path, os.path.join(root, name))]
        for name in files:
            candidate = os.path.join(root, name)
            if os.path.isfile(candidate) and is_within_repo(repo_path, candidate):
                yield os.path.normpath(candidate)


def _matches_glob(path: str, pattern: str) -> bool:
    """Match path parts using GitLab's documented local-include semantics."""
    path_parts = path.split("/")
    pattern_parts = pattern.split("/")

    def match(path_index: int, pattern_index: int) -> bool:
        if pattern_index == len(pattern_parts):
            return path_index == len(path_parts)
        part = pattern_parts[pattern_index]
        if part == "**":
            # GitLab's ``dir/**/*.yml`` form requires a subdirectory;
            # unlike common glob implementations, ``**`` is not empty here.
            return path_index < len(path_parts) and (
                match(path_index + 1, pattern_index) or match(path_index + 1, pattern_index + 1)
            )
        if "**" in part:
            # ``dir/**.yml`` matches both direct and nested YAML files.
            leaf_pattern = part.replace("**", "*")
            return path_index < len(path_parts) and (
                (
                    fnmatch.fnmatchcase(path_parts[path_index], leaf_pattern)
                    and match(path_index + 1, pattern_index + 1)
                )
                or match(path_index + 1, pattern_index)
            )
        return (
            path_index < len(path_parts)
            and fnmatch.fnmatchcase(path_parts[path_index], part)
            and match(path_index + 1, pattern_index + 1)
        )

    return match(0, 0)


def _expand_glob(repo_path: str, rel: str) -> list[str]:
    parts = rel.split("/")
    first_glob = next(
        (index for index, part in enumerate(parts) if any(char in part for char in "*?[")),
        len(parts),
    )
    search_root = os.path.join(repo_path, *parts[:first_glob])
    if not os.path.isdir(search_root) or not is_within_repo(repo_path, search_root):
        return []

    return [
        candidate
        for candidate in iter_files_within_repo(repo_path, os.path.relpath(search_root, repo_path))
        if _matches_glob(os.path.relpath(candidate, repo_path).replace(os.sep, "/"), rel)
    ]


def resolve_local_include(repo_path: str, ref: str, *, expand_globs: bool = False) -> list[str]:
    """Resolve one GitLab local include without leaving repo_path."""
    ref = ref.strip().strip("'\"")
    if not ref or "://" in ref:
        return []
    # GitLab local paths use POSIX separators. Treating a backslash or drive
    # prefix as host syntax would let a hostile repo escape on Windows.
    if "\\" in ref:
        return []
    rel = ref.lstrip("/")
    if os.path.splitdrive(rel)[0]:
        return []
    if any(part == ".." for part in rel.split("/")):
        return []

    base = os.path.join(repo_path, *rel.split("/"))
    has_glob = any(character in rel for character in "*?[")
    if has_glob and not expand_globs:
        return []
    if has_glob:
        return _expand_glob(repo_path, rel)
    candidates = [base]
    return [
        os.path.normpath(candidate)
        for candidate in candidates
        if os.path.isfile(candidate) and is_within_repo(repo_path, candidate)
    ]
