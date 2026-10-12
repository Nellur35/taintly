from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError
from threading import Lock

import pytest

import taintly.models as models
from taintly.models import scan_session
from taintly.parsers.segmentation import JobSegment, for_each_job

_WORKFLOW = (
    "name: jobs\r\n"
    "# preamble comment\r\n"
    "jobs:\r\n"
    "  build:\r\n"
    "    runs-on: ubuntu-latest\r\n"
    "\r\n"
    "  test: # sibling\r\n"
    "    runs-on: ubuntu-latest\r\n"
    "    steps: []"
)


def _equal_new_string(value: str) -> str:
    result = (value + "\0")[:-1]
    assert result == value
    assert result is not value
    return result


def test_for_each_job_reuses_identical_content_inside_scan_session(monkeypatch) -> None:
    calls = 0
    original = models._compute_job_segments

    def counted(lines: list[str]):
        nonlocal calls
        calls += 1
        return original(lines)

    monkeypatch.setattr(models, "_compute_job_segments", counted)
    with scan_session():
        first = for_each_job(_WORKFLOW)
        second = for_each_job(_equal_new_string(_WORKFLOW))

    assert calls == 1
    assert second == first
    assert second is not first


def test_cached_job_results_keep_exact_lines_and_fresh_mutable_lists() -> None:
    expected = [
        JobSegment("", 1, 3, ("name: jobs", "# preamble comment", "jobs:")),
        JobSegment(
            "build",
            4,
            6,
            ("  build:", "    runs-on: ubuntu-latest", ""),
        ),
        JobSegment(
            "test",
            7,
            9,
            ("  test: # sibling", "    runs-on: ubuntu-latest", "    steps: []"),
        ),
    ]
    with scan_session():
        first = for_each_job(_WORKFLOW)
        first.clear()
        second = for_each_job(_WORKFLOW)

    assert second == expected
    assert second is not first
    with pytest.raises(FrozenInstanceError):
        second[1].name = "changed"  # type: ignore[misc]


def test_for_each_job_remains_uncached_outside_scan_session(monkeypatch) -> None:
    calls = 0
    original = models._compute_job_segments

    def counted(lines: list[str]):
        nonlocal calls
        calls += 1
        return original(lines)

    monkeypatch.setattr(models, "_compute_job_segments", counted)
    assert for_each_job(_WORKFLOW) == for_each_job(_WORKFLOW)
    assert calls == 2


def test_content_cache_is_bounded_to_two_entries() -> None:
    contents = [f"jobs:\n  job{i}:\n    runs-on: ubuntu-latest" for i in range(3)]
    with scan_session():
        for content in contents:
            for_each_job(content)
            assert len(models._JOB_SEGMENT_CONTENT_CACHE.get() or {}) <= 2


def test_content_cache_is_nested_exception_and_thread_local(monkeypatch) -> None:
    with scan_session():
        outer = for_each_job(_WORKFLOW)
        outer_cache = models._JOB_SEGMENT_CACHE.get()
        outer_content_cache = models._JOB_SEGMENT_CONTENT_CACHE.get()
        assert outer_cache is not None
        assert outer_content_cache is not None

        with scan_session():
            nested = for_each_job(_WORKFLOW)
            assert for_each_job(_WORKFLOW) is not nested
        assert models._JOB_SEGMENT_CACHE.get() is outer_cache
        assert models._JOB_SEGMENT_CONTENT_CACHE.get() is outer_content_cache
        assert for_each_job(_WORKFLOW) == outer

        def abort_nested_session():
            with scan_session():
                for_each_job("jobs:\n  temporary:\n    runs-on: linux")
                raise RuntimeError("abort")

        with pytest.raises(RuntimeError, match="abort"):
            abort_nested_session()
        assert models._JOB_SEGMENT_CACHE.get() is outer_cache
        assert models._JOB_SEGMENT_CONTENT_CACHE.get() is outer_content_cache
        assert for_each_job(_WORKFLOW) == outer

    calls = 0
    original = models._compute_job_segments
    calls_lock = Lock()

    def counted(lines: list[str]):
        nonlocal calls
        with calls_lock:
            calls += 1
        return original(lines)

    monkeypatch.setattr(models, "_compute_job_segments", counted)

    def separate_thread():
        with scan_session():
            first = for_each_job(_WORKFLOW)
            second = for_each_job(_WORKFLOW)
            return first, second

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _: separate_thread(), range(2)))
    assert all(first == second and first is not second for first, second in results)
    assert results[0][0] is not results[1][0]
    assert calls == 2
