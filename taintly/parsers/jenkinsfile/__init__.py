"""Structural Jenkinsfile reader (zero-dependency).

Mirrors the structural CI YAML reader at
:mod:`taintly.parsers.structural` but for Jenkinsfile (Groovy DSL).
Backed by a pure-Python island-grammar Groovy reader: a tolerant
tokenizer + scope-stack walker that never raises on unmodelled
Groovy (it skips to the next recognisable island rather than cutting
off), so it works on every install with no optional extra and no
native parser.

Usage::

    from taintly.parsers.jenkinsfile import walk_jenkinsfile, EventKind

    for event in walk_jenkinsfile(content):
        if event.kind == EventKind.LEAF:
            ...   # event.value is the scalar; event.path is the
                  # nested-block path
"""

from __future__ import annotations

from .api import walk_jenkinsfile
from .events import Event, EventKind

__all__ = ["Event", "EventKind", "walk_jenkinsfile"]
