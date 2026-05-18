"""Structural Jenkinsfile reader (optional, ``[jenkins-structural]`` extra).

Mirrors the structural CI YAML reader at
:mod:`taintly.parsers.structural` but for Jenkinsfile (Groovy DSL).
Backed by tree-sitter-groovy when the optional extra is installed.
The tree-sitter import is deferred to first call of
:func:`walk_jenkinsfile`, so importing this module always succeeds
even when the ``[jenkins-structural]`` extra is not installed — the
``ImportError`` (with an install hint) surfaces from the first call
to :func:`walk_jenkinsfile`, not at module import.

Rules that depend on structural Jenkinsfile parsing must guard
their call to ``walk_jenkinsfile`` (or an early probe of it) with
a ``try/except ImportError`` and fall back to regex-based detection
(or skip) so the zero-runtime-dependency promise of the default
install holds.

See ``docs/JENKINSFILE_READER_SCOPE.md`` for the supported-feature
contract.

Usage::

    from taintly.parsers.jenkinsfile import walk_jenkinsfile, EventKind

    for event in walk_jenkinsfile(content):
        if event.kind == EventKind.LEAF:
            ...   # event.value is the scalar; event.path is the
                  # nested-block path
        elif event.kind == EventKind.CUTOFF:
            # Parse error or unsupported construct hit.
            break
"""

from __future__ import annotations

from .api import walk_jenkinsfile
from .events import Event, EventKind

__all__ = ["Event", "EventKind", "walk_jenkinsfile"]
