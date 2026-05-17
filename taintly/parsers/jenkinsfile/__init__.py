"""Structural Jenkinsfile reader (optional, ``[jenkins-structural]`` extra).

Mirrors the structural CI YAML reader at
:mod:`taintly.parsers.structural` but for Jenkinsfile (Groovy DSL).
Backed by tree-sitter-groovy when the optional extra is installed;
when it's not, importing this module raises ``ImportError`` with a
clear install hint.

Rules that depend on structural Jenkinsfile parsing must guard
their import with a ``try/except ImportError`` and fall back to
regex-based detection (or skip) so the zero-runtime-dependency
promise of the default install holds.

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

from .events import Event, EventKind
from .api import walk_jenkinsfile

__all__ = ["Event", "EventKind", "walk_jenkinsfile"]
