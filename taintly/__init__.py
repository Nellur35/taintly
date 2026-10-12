"""taintly - zero-dependency CI/CD pipeline security auditor."""

from __future__ import annotations

from threading import RLock

_VERSION_LOCK = RLock()
# Reloading the package should refresh the same public version attribute.
globals().pop("__version__", None)


def _resolve_version() -> str:
    """Return the package version, with a dev-checkout fallback.

    Three strategies, tried in order:

    1. ``importlib.metadata.version("taintly")`` — works for any
       install (wheel, ``pip install -e .``, sdist).
    2. ``setuptools_scm.get_version()`` — works in a git checkout
       even before ``pip install``.  setuptools-scm is the build
       backend, so a contributor capable of building taintly already
       has it; we import lazily to keep the runtime zero-dep.
    3. ``"0.0.0+unknown"`` — last-resort sentinel for source trees
       with no git history (e.g. a Docker COPY of just the package).
    """
    from importlib.metadata import PackageNotFoundError
    from importlib.metadata import version as _pkg_version

    try:
        return _pkg_version("taintly")
    except PackageNotFoundError:
        pass
    try:
        from pathlib import Path

        from setuptools_scm import get_version

        # ``setuptools_scm.get_version`` is untyped (returns Any); coerce
        # for mypy without changing behaviour at runtime.
        return str(get_version(root=str(Path(__file__).resolve().parent.parent)))
    except Exception:
        return "0.0.0+unknown"


def __getattr__(name: str) -> str:
    """Resolve the public version only when a caller actually requests it."""
    if name != "__version__":
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    with _VERSION_LOCK:
        if name not in globals():
            globals()[name] = _resolve_version()
        version: str = globals()[name]
        return version


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(__all__))


__all__ = ["__version__"]
