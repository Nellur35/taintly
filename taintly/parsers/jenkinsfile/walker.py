"""Walk a tree-sitter-groovy parse tree, emit structural Events.

Scope (declarative pipeline first; scripted pipeline is best-effort):

    pipeline {
        agent <directive>
        environment { KEY = 'value'; ... }
        tools { <type> '<name>' }
        options { <name>(...) }
        triggers { <name>(...) }
        parameters { <type>(name: '<id>', ...) }
        stages {
            stage('<name>') {
                agent ...
                when { <conditions> }
                environment { ... }
                steps {
                    sh '<command>'
                    bat '<command>'
                    powershell '<command>'
                    tool '<name>'
                    withCredentials([...]) { ... }
                    <pipelineStep>(<args>)
                }
                post { ... }
            }
        }
    }

LEAF events fire for:
  - sh / bat / powershell string arguments (value_kind="shell")
  - tool string arguments (value_kind="string")
  - environment block ``KEY = 'value'`` rhs (value_kind="string")
  - stage('<name>') name argument (value_kind="string")
  - agent <identifier> directive (value_kind="identifier")
  - credentialsId / variable / passwordVariable / etc. in
    withCredentials list (value_kind="string")
  - generic stringly-typed args to top-level / step calls
    (best-effort, may broaden over time)

The walker is intentionally lossy: we only emit what rules will
actually query.  Adding new shapes is a one-line addition to
``_SHELL_CALLS`` / ``_INTERESTING_CALLS`` and an entry in the
dispatch loop.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from .events import Event, EventKind

# Names of pipeline step calls whose first string argument is a
# shell body (the primary sink for the JK rule pack).
_SHELL_CALLS = frozenset({"sh", "bat", "powershell"})

# Names of pipeline step calls whose first string argument is a
# plain string (not a shell body) we still want to surface.
_STRING_FIRST_ARG_CALLS = frozenset({"tool", "stage", "echo"})


def iter_leaves(root: Any, src: bytes) -> Iterator[Event]:
    """Yield LEAF events for every interesting scalar in the tree.

    Path components reflect the nesting at the point of emission:
    ``("pipeline", "stages", "stage:Build", "steps", "sh")`` for a
    ``sh '...'`` call inside ``stage('Build') { steps { sh '...' } }``.
    """
    yield from _walk(root, src, path=())


def _walk(node: Any, src: bytes, path: tuple[object, ...]) -> Iterator[Event]:
    """Recursive walker.  Looks at every node; emits LEAFs for
    recognised shapes and recurses into children otherwise.

    Real tree-sitter-groovy node types (observed):
      - ``program`` — top-level.
      - ``expression_statement`` — wraps statements.
      - ``method_invocation`` — ``name(args)`` form, with optional
        trailing ``closure``.
      - ``juxt_function_call`` — Groovy command-style ``name arg`` form
        (no parens), used for ``sh '...'`` inside steps blocks.
      - ``argument_list`` — call args, including parens.
      - ``character_literal`` — what tree-sitter-groovy calls string
        literals (single, double, triple-quoted, GString).
      - ``closure`` — ``{ ... }`` block.
      - ``identifier`` — bareword.
      - ``local_variable_declaration`` — ``agent any`` parses here:
        Groovy's grammar treats ``agent any`` as a typed declaration
        where ``agent`` is the type and ``any`` is the variable.
      - ``assignment_expression`` — ``KEY = 'value'`` inside
        environment blocks.
    """
    nt = node.type

    if nt == "method_invocation":
        yield from _handle_call(node, src, path)
        return

    if nt == "juxt_function_call":
        yield from _handle_call(node, src, path)
        return

    if nt == "assignment_expression":
        yield from _handle_binary(node, src, path)
        return

    if nt == "local_variable_declaration":
        # ``agent any`` / ``agent none`` — Groovy parser treats
        # the first token as a type, the rest as variable names.
        yield from _handle_typed_decl(node, src, path)
        return

    # Default: descend into children with the same path.
    for child in node.children:
        yield from _walk(child, src, path)


def _handle_call(node: Any, src: bytes, path: tuple[object, ...]) -> Iterator[Event]:
    """A function call.  Groovy method-call shape:
    ``<identifier> <args>`` or ``<identifier> ( <args> )``.

    Recognised forms:
      - ``sh 'cmd'`` / ``bat 'cmd'`` / ``powershell 'cmd'``
        → LEAF with value_kind="shell"
      - ``tool 'jdk-11'`` → LEAF with value_kind="string"
      - ``stage('Build') { ... }`` → push ``stage:Build`` onto
        path, recurse into the closure
      - ``pipeline { ... }`` / ``stages { ... }`` /
        ``steps { ... }`` / ``environment { ... }`` / etc.
        → push the call name onto path, recurse into the closure
      - Other calls → recurse with unchanged path.
    """
    name = _call_name(node, src)
    args = _call_arguments(node)
    closure = _call_closure(node)
    first_string = _first_string_arg(args, src) if args else None

    # Shell-body sink — emit LEAF and skip closure (sh has no body).
    if name in _SHELL_CALLS and first_string is not None:
        value, line = first_string
        yield Event(
            kind=EventKind.LEAF,
            path=path + (name,),
            value=value,
            value_kind="shell",
            line=line,
        )
        return

    # stage('Name') { steps {...} } — pushed as `stage:Name`.
    if name == "stage" and first_string is not None and closure is not None:
        stage_name, line = first_string
        # Emit a LEAF for the stage name itself so rules can query it.
        yield Event(
            kind=EventKind.LEAF,
            path=path + ("stage",),
            value=stage_name,
            value_kind="string",
            line=line,
        )
        yield from _walk(closure, src, path + (f"stage:{stage_name}",))
        return

    # Other recognised-first-string calls (tool, echo).
    if name in _STRING_FIRST_ARG_CALLS and first_string is not None:
        value, line = first_string
        yield Event(
            kind=EventKind.LEAF,
            path=path + (name,),
            value=value,
            value_kind="string",
            line=line,
        )
        # Also recurse into closure if present (rare for these).
        if closure is not None:
            yield from _walk(closure, src, path + (name,))
        return

    # Block-only calls (no leading string arg, just a closure body):
    # pipeline { ... }, stages { ... }, steps { ... }, environment
    # { ... }, agent { ... }, etc.  Push the call name onto path
    # and recurse.
    if name and closure is not None:
        yield from _walk(closure, src, path + (name,))
        # Some block-style calls (notably ``agent``) also accept a
        # leading identifier: ``agent any`` / ``agent none``.
        # When there's no closure but the call has identifier args,
        # surface them as LEAFs.
        return

    # ``agent any`` / ``agent none`` — identifier argument, no closure.
    if name == "agent" and args is not None:
        for ident_value, ident_line in _identifier_args(args, src):
            yield Event(
                kind=EventKind.LEAF,
                path=path + ("agent",),
                value=ident_value,
                value_kind="identifier",
                line=ident_line,
            )
        return

    # Generic fallthrough: recurse into children.
    for child in node.children:
        yield from _walk(child, src, path)


def _handle_typed_decl(
    node: Any, src: bytes, path: tuple[object, ...]
) -> Iterator[Event]:
    """``agent any`` / ``agent none`` / ``tool jdk`` shapes.

    Groovy parses these as typed declarations: first child is a
    ``type_identifier`` (the directive name), second is one or more
    ``variable_declarator``s each carrying an identifier (the
    argument).  We surface the argument identifier as a LEAF under
    a path whose last component is the directive name.
    """
    type_id = None
    for child in node.children:
        if child.type == "type_identifier":
            type_id = src[child.start_byte : child.end_byte].decode(
                "utf-8", errors="replace"
            )
            break
    if type_id is None:
        # Not the shape we expected; descend so any inner leaves
        # still surface.
        for child in node.children:
            yield from _walk(child, src, path)
        return
    for child in node.children:
        if child.type != "variable_declarator":
            continue
        for sub in child.children:
            if sub.type == "identifier":
                arg = src[sub.start_byte : sub.end_byte].decode(
                    "utf-8", errors="replace"
                )
                yield Event(
                    kind=EventKind.LEAF,
                    path=path + (type_id,),
                    value=arg,
                    value_kind="identifier",
                    line=sub.start_point[0] + 1,
                )


def _handle_binary(
    node: Any, src: bytes, path: tuple[object, ...]
) -> Iterator[Event]:
    """``KEY = 'value'`` inside an ``environment { }`` block (or
    elsewhere).  Treat the lhs identifier as a path step and the rhs
    string as the LEAF.  Recurse on anything else.
    """
    # binary_expression children typically are: [lhs, op, rhs].
    if len(node.children) < 3:
        for child in node.children:
            yield from _walk(child, src, path)
        return
    lhs, op, rhs = node.children[0], node.children[1], node.children[2]
    if op.type != "=":
        for child in node.children:
            yield from _walk(child, src, path)
        return
    if lhs.type != "identifier":
        for child in node.children:
            yield from _walk(child, src, path)
        return
    key = src[lhs.start_byte : lhs.end_byte].decode("utf-8", errors="replace")
    value_pair = _string_node_value(rhs, src)
    if value_pair is None:
        # Non-string rhs (e.g. a method call).  Recurse so any nested
        # leaves still surface.
        yield from _walk(rhs, src, path + (key,))
        return
    value, line = value_pair
    yield Event(
        kind=EventKind.LEAF,
        path=path + (key,),
        value=value,
        value_kind="string",
        line=line,
    )


# ---------------------------------------------------------------------------
# Helpers — tree-sitter-groovy AST shape adapters.
# ---------------------------------------------------------------------------


def _call_name(node: Any, src: bytes) -> str:
    """Name of the called method (first identifier child)."""
    for child in node.children:
        if child.type == "identifier":
            return src[child.start_byte : child.end_byte].decode(
                "utf-8", errors="replace"
            )
    return ""


def _call_arguments(node: Any) -> Any:
    """The argument_list node of a call, or None."""
    for child in node.children:
        if child.type == "argument_list" or child.type == "arguments":
            return child
    return None


def _call_closure(node: Any) -> Any:
    """The trailing closure node of a call, or None."""
    for child in node.children:
        if child.type == "closure":
            return child
    return None


def _first_string_arg(args: Any, src: bytes) -> tuple[str, int] | None:
    """Return ``(value, line)`` of the first string-literal argument,
    or None if the first non-trivial arg isn't a string."""
    for child in args.children:
        if child.type in ("(", ")", ",", "argument"):
            # Unwrap arguments-as-named-children, otherwise skip syntactic.
            if child.type == "argument":
                for sub in child.children:
                    pair = _string_node_value(sub, src)
                    if pair is not None:
                        return pair
                return None
            continue
        pair = _string_node_value(child, src)
        if pair is not None:
            return pair
        # First non-string non-syntactic arg → no shell-style match.
        return None
    return None


def _string_node_value(node: Any, src: bytes) -> tuple[str, int] | None:
    """Decode a string-literal node to ``(unquoted_value, line)``.
    Returns None if ``node`` isn't a string.

    tree-sitter-groovy uses ``character_literal`` as the catch-all
    name for any quoted string (single, double, triple, GString).
    """
    if node.type not in (
        "character_literal",
        "string_literal",
        "string",
        "gstring",
    ):
        return None
    raw = src[node.start_byte : node.end_byte].decode("utf-8", errors="replace")
    # Strip leading/trailing quote (single, double, triple).
    if raw.startswith(("'''", '"""')) and raw.endswith(raw[:3]):
        body = raw[3:-3]
    elif raw and raw[0] in "'\"" and raw[-1] == raw[0]:
        body = raw[1:-1]
    else:
        body = raw
    return body, node.start_point[0] + 1


def _identifier_args(args: Any, src: bytes) -> Iterator[tuple[str, int]]:
    """Yield ``(name, line)`` for each bareword identifier argument."""
    for child in args.children:
        if child.type == "identifier":
            yield (
                src[child.start_byte : child.end_byte].decode("utf-8", errors="replace"),
                child.start_point[0] + 1,
            )
        elif child.type == "argument":
            for sub in child.children:
                if sub.type == "identifier":
                    yield (
                        src[sub.start_byte : sub.end_byte].decode(
                            "utf-8", errors="replace"
                        ),
                        sub.start_point[0] + 1,
                    )
