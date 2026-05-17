"""Public walk_jenkinsfile entry point.

Wraps the tree-sitter-groovy parse and the walker that translates
the parse tree into structural Events.  The import of tree-sitter
is deferred to first call so module import doesn't fail when the
optional ``[jenkins-structural]`` extra isn't installed — the
ImportError only surfaces when a caller actually tries to walk a
Jenkinsfile.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from .events import Event, EventKind

_TS_PARSER: Any = None  # cached after first init
_TS_INIT_ERROR: Exception | None = None


def _install_hint() -> str:
    return (
        "tree-sitter and tree-sitter-groovy are required for the "
        "structural Jenkinsfile reader. Install with:\n"
        "    pip install 'taintly[jenkins-structural]'\n"
        "or, equivalently:\n"
        "    pip install tree-sitter tree-sitter-groovy"
    )


def _get_parser() -> Any:
    """Lazily build the cached tree-sitter parser for Groovy.

    Raises ImportError with an install hint when the optional extra
    isn't available.  Caches the parser globally so repeated calls
    don't re-instantiate.
    """
    global _TS_PARSER, _TS_INIT_ERROR
    if _TS_PARSER is not None:
        return _TS_PARSER
    if _TS_INIT_ERROR is not None:
        raise _TS_INIT_ERROR
    try:
        import tree_sitter_groovy as _tsg
        from tree_sitter import Language, Parser
    except ImportError as exc:
        err = ImportError(f"{exc.msg}\n\n{_install_hint()}")
        _TS_INIT_ERROR = err
        raise err from exc
    try:
        lang = Language(_tsg.language())
        _TS_PARSER = Parser(lang)
    except Exception as exc:  # pragma: no cover - tree-sitter init failure
        err = ImportError(f"failed to initialise tree-sitter-groovy ({exc!r})\n\n{_install_hint()}")
        _TS_INIT_ERROR = err
        raise err from exc
    return _TS_PARSER


def walk_jenkinsfile(content: str, *, recover: bool = True) -> Iterator[Event]:
    """Walk a Jenkinsfile, yielding :class:`Event` instances.

    Args:
        content: Jenkinsfile source as a string.
        recover: when True (default), parse errors are surfaced as a
            single ``CUTOFF`` event and walking stops cleanly.  When
            False, the underlying tree-sitter exception is raised.

    Yields:
        :class:`Event` instances.  See :class:`EventKind` for the
        documented stream contract.

    Raises:
        ImportError: when the optional ``[jenkins-structural]`` extra
            isn't installed.
    """
    parser = _get_parser()
    src = content.encode("utf-8", errors="replace")
    tree = parser.parse(src)
    root = tree.root_node

    # CUTOFF on top-level parse failure.  tree-sitter's parser is
    # error-recovering, so ``root.has_error`` flags partial-parse
    # state — we still walk the recovered subtree but cap the
    # downstream contract: any unresolved query becomes
    # could-not-evaluate (mirrors the YAML walker's CUTOFF contract).
    cutoff_emitted = False

    from .walker import iter_leaves

    yield from iter_leaves(root, src)

    if root.has_error:
        if recover and not cutoff_emitted:
            yield Event(
                kind=EventKind.CUTOFF,
                line=_first_error_line(root) or 1,
                detail="tree-sitter-groovy reported parse errors",
            )


def _first_error_line(node: Any) -> int | None:
    """Find the 1-based line number of the first ERROR node under
    ``node``, or None if none."""
    if node.type == "ERROR" or getattr(node, "is_missing", False):
        return node.start_point[0] + 1
    for child in node.children:
        line = _first_error_line(child)
        if line is not None:
            return line
    return None
