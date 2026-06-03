"""In-house facts/closure model for the taint subsystem.

This package holds the *platform-agnostic* core:

* :mod:`taintly.taint_facts.relations` — the ``Fact`` protocol and the
  ``Database`` (relation store with key-only-hash dedup).
* :mod:`taintly.taint_facts.closure` — the naive fixed-point evaluator.

Platform extraction, the rule sets, and the projection back into
``TaintPath`` live in :mod:`taintly.taint` (GitHub Actions) and
:mod:`taintly.gitlab_taint` (GitLab CI) — Phase A keeps them in place
so the public surface of those modules does not move; Phase B splits
the extractors out (see the decision record).
"""

from .closure import solve
from .relations import Database, Fact

__all__ = ["Database", "Fact", "solve"]
