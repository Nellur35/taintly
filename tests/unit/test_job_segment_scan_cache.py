from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

import pytest

from taintly.models import _JOB_SEGMENT_CACHE, _split_into_job_segments, scan_session


def _workflow_lines() -> list[str]:
    return [
        "on: push",
        "jobs:",
        "  build:",
        "    runs-on: ubuntu-latest",
        "  deploy:",
        "    runs-on: ubuntu-latest",
    ]


def test_job_segments_are_reused_only_inside_scan_session() -> None:
    lines = _workflow_lines()
    with scan_session():
        first = _split_into_job_segments(lines)
        second = _split_into_job_segments(lines)
        assert first is second
        assert len(first) == 3

    assert _JOB_SEGMENT_CACHE.get() is None
    after_session = _split_into_job_segments(lines)
    assert after_session == first
    assert after_session is not first


def test_job_segment_cache_keys_line_list_identity() -> None:
    lines = _workflow_lines()
    equal_lines = list(lines)
    assert equal_lines == lines
    assert equal_lines is not lines

    with scan_session():
        first = _split_into_job_segments(lines)
        second = _split_into_job_segments(equal_lines)
        assert second == first
        assert second is not first
        assert len(_JOB_SEGMENT_CACHE.get() or {}) == 2


def test_nested_scan_session_restores_outer_cache() -> None:
    outer_lines = _workflow_lines()
    inner_lines = ["job:", "  script: echo nested"]

    with scan_session():
        outer_segments = _split_into_job_segments(outer_lines)
        outer_cache = _JOB_SEGMENT_CACHE.get()
        assert outer_cache is not None

        with scan_session():
            inner_segments = _split_into_job_segments(inner_lines)
            assert _split_into_job_segments(inner_lines) is inner_segments

        assert _JOB_SEGMENT_CACHE.get() is outer_cache
        assert _split_into_job_segments(outer_lines) is outer_segments


def test_job_segment_cache_is_bounded_and_clears_on_exception() -> None:
    lists = [_workflow_lines() for _ in range(4)]

    def scan_then_abort() -> None:
        with scan_session():
            for lines in lists:
                _split_into_job_segments(lines)
                assert len(_JOB_SEGMENT_CACHE.get() or {}) <= 2
            raise RuntimeError("scan abort")

    with pytest.raises(RuntimeError, match="scan abort"):
        scan_then_abort()

    assert _JOB_SEGMENT_CACHE.get() is None


def test_job_segment_cache_is_context_local_between_threads() -> None:
    lines = _workflow_lines()

    def scan_once() -> tuple[object, object]:
        with scan_session():
            first = _split_into_job_segments(lines)
            second = _split_into_job_segments(lines)
            return first, second

    with ThreadPoolExecutor(max_workers=2) as executor:
        first_scan, second_scan = list(executor.map(lambda _: scan_once(), range(2)))

    assert first_scan[0] is first_scan[1]
    assert second_scan[0] is second_scan[1]
    assert first_scan[0] is not second_scan[0]
    assert first_scan[0] == second_scan[0]
