"""Source-owned publication review for the native GitLab MR scenario."""

from __future__ import annotations

import re
import shlex
import unicodedata
from collections import Counter, defaultdict
from collections.abc import Callable

from taintly.gitlab_workflow_corpus import GitLabCorpusMatches, GitLabWorkflowCorpus
from taintly.gitlabguard import _RESERVED_TOP_LEVEL
from taintly.parsers.structural import Event, EventKind, walk_workflow
from taintly.parsers.yaml_command_scalar import decode_single_line_command_scalar

_MR = "merge_request_event"
_EXPLICIT_MR = re.compile(
    r"\$CI_PIPELINE_SOURCE\s*==\s*(?:'merge_request_event'|\"merge_request_event\")"
)
_RULE_REFERENCE = re.compile(r"!reference[ \t]+\[([.][A-Za-z0-9_.-]+),[ \t]*rules\]")
_PUBLICATION = frozenset(
    {
        ("docker", "push"),
        ("kubectl", "apply"),
        ("helm", "upgrade"),
        ("npm", "publish"),
        ("pip", "upload"),
        ("twine", "upload"),
        ("cargo", "publish"),
        ("gem", "push"),
        ("mvn", "deploy"),
    }
)
_NOOP = {"--help", "--version", "-h"}
_REGISTRY_LOGIN = 'echo "$CI_REGISTRY_PASSWORD" | docker login -u "$CI_REGISTRY_USER" --password-stdin "$CI_REGISTRY"'
_PATH = r"[A-Za-z0-9_-][A-Za-z0-9_.-]*(?:/[A-Za-z0-9_-][A-Za-z0-9_.-]*)*"
_TAG_ASSIGN = re.compile(r"TAG=\$\(sha256sum (" + _PATH + r") \| cut -c1-[1-9][0-9]?\)")
_IMAGE_ASSIGN = re.compile(r'IMAGE="\$\{CI_REGISTRY_IMAGE\}/[a-z0-9][a-z0-9_.-]*"')
_BUILD = re.compile(
    r'docker build -t "\$\{IMAGE\}:\$\{TAG\}" -f (' + _PATH + r") (?:\.|" + _PATH + r")"
)
_PUSH = 'docker push "${IMAGE}:${TAG}"'
_MANIFEST_CHECK = 'if docker manifest inspect "${IMAGE}:${TAG}" >/dev/null 2>&1; then'
_MANIFEST_EXISTS = 'echo "${IMAGE}:${TAG} already exists"'
_REGISTRY_BINDINGS = {
    "CI_REGISTRY",
    "CI_REGISTRY_USER",
    "CI_REGISTRY_PASSWORD",
    "CI_REGISTRY_IMAGE",
    "GIT_STRATEGY",
    "GIT_CHECKOUT",
    "GIT_CLONE_PATH",
    "BASH_ENV",
    "ENV",
    "PATH",
}


NullConstraints = frozenset[tuple[str, bool]]
_NULL_COMPARE_RE = re.compile(r"\$([A-Za-z_][A-Za-z0-9_]*)\s*(==|!=)\s*null")


def null_constraints(expression: str) -> NullConstraints | None:
    """Parse a bounded conjunction; None is unsupported, never false."""
    terms = expression.split("&&")
    if len(expression) > 2048 or len(terms) > 16:
        return None
    out: set[tuple[str, bool]] = set()
    for term in terms:
        match = _NULL_COMPARE_RE.fullmatch(term.strip())
        if match is None:
            return None
        out.add((match[1], match[2] == "!="))
    return frozenset(out)


_NAME = r"[A-Za-z_][A-Za-z0-9_]*"

_LITERAL_NAME = re.compile(_NAME + r"\Z")

_BARE = re.compile(r"\$(" + _NAME + r")\Z")

_COMPARE = re.compile(
    r"\$(" + _NAME + r")\s*(==|!=)\s*(?:'([^']*)'|\"([^\"]*)\"|\$(" + _NAME + r"))\Z"
)

_REGEX = re.compile(r"\$" + _NAME + r"\s*(?:=~|!~)\s*/(?:\\.|[^/\\\r\n])+/[im]*\Z")

_NATIVE = frozenset(
    {"CI_PIPELINE_SOURCE", "CI_MERGE_REQUEST_IID", "CI_COMMIT_BRANCH", "CI_DEFAULT_BRANCH"}
)

_WHEN = frozenset({"never", "always", "on_success", "on_failure", "manual", "delayed"})


def _condition(expression: str, source: str) -> str:
    """Finite syntax/definedness only; unknown values and regexes stay possible."""
    expression = expression.strip()
    if not expression or len(expression) > 2048:
        return "unsupported"
    defined = {"CI_PIPELINE_SOURCE": True}
    if source == "merge_request_event":
        defined.update(CI_MERGE_REQUEST_IID=True, CI_COMMIT_BRANCH=False, CI_DEFAULT_BRANCH=True)
    constraints = null_constraints(expression)
    if constraints is not None:
        if any(name in defined and defined[name] != present for name, present in constraints):
            return "false"
        return "true" if all(name in defined for name, _ in constraints) else "maybe"
    bare = _BARE.fullmatch(expression)
    if bare:
        return ("true" if defined[bare[1]] else "false") if bare[1] in defined else "maybe"
    comparison = _COMPARE.fullmatch(expression)
    if comparison:
        left, operator, single, double, right_name = comparison.groups()
        literal = single if single is not None else double
        equal: bool | None = None
        if right_name == left:
            equal = True
        elif left == "CI_PIPELINE_SOURCE" and literal is not None:
            equal = source == literal
        elif source == "merge_request_event" and left == "CI_COMMIT_BRANCH":
            if (literal is not None and literal != "") or defined.get(right_name or "") is True:
                equal = False
        if equal is None:
            return "maybe"
        return "true" if equal == (operator == "==") else "false"
    if _REGEX.fullmatch(expression):
        return "maybe"  # Do not execute or interpret a GitLab/RE2 expression.
    if "&&" in expression:
        terms = expression.split("&&")
        if len(terms) > 16:
            return "unsupported"
        outcomes = [_condition(term, source) for term in terms]
        if "unsupported" in outcomes:
            return "unsupported"
        if "false" in outcomes:
            return "false"
        return "true" if all(value == "true" for value in outcomes) else "maybe"
    return "unsupported"


def _variable_scope(path: tuple[object, ...]) -> bool:
    return (
        path == ("variables",)
        or (len(path) == 2 and path[1] == "variables")
        or (
            len(path) == 4
            and path[1] == "rules"
            and isinstance(path[2], int)
            and path[3] == "variables"
        )
    )


def _opaque_native_name(name: object) -> bool:
    return not isinstance(name, str) or name in _NATIVE or _LITERAL_NAME.fullmatch(name) is None


def _outcome(
    record: dict[str, object],
    fallback: str,
    source: str,
    *,
    condition: Callable[[str, str], str] = _condition,
) -> str:
    rules = record.get("rules")
    if not isinstance(rules, list) or not rules or len(rules) > 64:
        return "unknown"
    for rule in rules:
        if not isinstance(rule, dict) or set(rule) - {"if", "when", "changes", "exists"}:
            return "unknown"
        when = rule.get("when", fallback)
        if not isinstance(when, str) or when not in _WHEN:
            return "unknown"
        expression = rule.get("if")
        if "if" in rule and not isinstance(expression, str):
            return "unknown"
        verdict = condition(expression, source) if isinstance(expression, str) else "true"
        if verdict == "unsupported":
            return "unknown"
        if verdict == "false":
            continue
        if when != "never":
            return "possible"  # Conditional configured outcome, not observed execution.
        if verdict == "true" and not (set(rule) & {"changes", "exists"}):
            return "excluded"
        # A possible denial does not establish admission or block later denials.
    return "excluded"


def _owned_rule_record(
    branch: list[Event],
    keys: Counter[tuple[object, ...]],
    lines: list[str],
    name: str,
    *,
    inactive_rule_items: frozenset[int] = frozenset(),
) -> dict[str, object]:
    """Materialize existing rule fields; callers establish owner/context policy.

    No activation, inheritance or container-kind conclusion is made here.
    Inactive items are skipped only when the caller has established they cannot
    match its scenario. An empty record does not establish a sequence schema.
    """
    root = (name, "rules")
    rule_events = [e for e in branch if e.path[:2] == root]
    if not keys[root]:
        return {}
    if any(
        len(e.path) < 3 or not isinstance(e.path[2], int)
        for e in rule_events
        if e.kind is not EventKind.MAP_KEY or e.path != root
    ):
        return {"rules": None}
    items: dict[int, list[Event]] = defaultdict(list)
    for event in rule_events:
        if len(event.path) >= 3 and isinstance(event.path[2], int):
            items[event.path[2]].append(event)
    indexes = sorted(items)
    rules: list[object] = []
    for expected, index in enumerate(indexes):
        if expected != index:
            rules.append(None)
            break
        if index in inactive_rule_items:
            continue
        item = root + (index,)
        item_events = items[index]
        fields = {str(e.path[3]) for e in item_events if len(e.path) >= 4 and e.path[:3] == item}
        if not fields or any(
            e.kind is EventKind.LEAF_SCALAR and e.path == item for e in item_events
        ):
            rules.append(None)
            break
        record: dict[str, object] = {}
        for field in fields:
            path = item + (field,)
            values = [e for e in item_events if e.kind is EventKind.LEAF_SCALAR and e.path == path]
            if field not in {"if", "when"}:
                record[field] = None  # Present, with unresolved matching/modifier semantics.
                continue
            if keys[path] != 1 or len(values) != 1:
                record["if"] = None
                break
            value = values[0]
            text = value.value if value.value_kind == "plain" else None
            if value.value_kind == "quoted" and 0 < value.line <= len(lines):
                text = decode_single_line_command_scalar(lines[value.line - 1], value)
            if text is None or not text.strip() or text.strip() in {"null", "~"}:
                record["if"] = None
                break
            record[field] = text
        rules.append(record)
    return {"rules": rules}


def command_text(event: Event, lines: list[str]) -> str | None:
    """Decode one owned single-line scalar; alias replay is not use-site text."""
    if not 0 < event.line <= len(lines) or event.column < 1 or event.block_lines is not None:
        return None
    if event.value_kind == "quoted":
        return decode_single_line_command_scalar(lines[event.line - 1], event)
    if event.value_kind != "plain":
        return None
    value = event.value or ""
    if any(
        (char.isspace() and char not in " \t")
        or (unicodedata.category(char).startswith("C") and char != "\t")
        or (unicodedata.category(char) == "Zs" and char != " ")
        for char in value
    ):
        return None
    raw = lines[event.line - 1][event.column - 1 :]
    if not raw.startswith(value):
        return None
    tail = raw[len(value) :].lstrip(" \t")
    return value if not tail or tail.startswith(("#", ",", "]", "}")) else None


def _script_items(branch: list[Event], job: str) -> list[Event]:
    prefix = (job, "script")
    fields = [event for event in branch if event.path[:2] == prefix]
    if not any(event.kind is EventKind.MAP_KEY and event.path == prefix for event in fields):
        return []
    leaves = [event for event in fields if event.kind is EventKind.LEAF_SCALAR]
    if len(leaves) == 1 and leaves[0].path == prefix:
        return leaves
    if any(event.path != (*prefix, index) for index, event in enumerate(leaves)):
        return []
    return leaves


def _comparison_terms(expression: str, separator: str) -> list[str]:
    if len(expression) > 2048:
        return []
    if _COMPARE.fullmatch(expression):
        return [expression]
    terms = [term.strip() for term in expression.split(separator)]
    return terms if 1 < len(terms) <= 16 and all(_COMPARE.fullmatch(term) for term in terms) else []


def _publication_condition(expression: str, source: str) -> str:
    result = _condition(expression, source)
    if result != "unsupported" or "||" not in expression:
        return result
    terms = _comparison_terms(expression, "||")
    if not terms:
        return "unsupported"
    outcomes = [_condition(term, source) for term in terms]
    if "true" in outcomes:
        return "true"
    return "false" if all(value == "false" for value in outcomes) else "maybe"


def _explicit_mr(expression: str) -> bool:
    separator = "||" if "||" in expression else "&&"
    return any(
        _EXPLICIT_MR.fullmatch(term) for term in _comparison_terms(expression.strip(), separator)
    )


def _binding_names(branch: list[Event]) -> set[object]:
    return {
        event.path[-1]
        for event in branch
        if event.kind is EventKind.MAP_KEY and _variable_scope(event.path[:-1])
    }


def _unique_branch(events: list[Event], keys: Counter[tuple[object, ...]]) -> bool:
    return not any(
        event.kind is EventKind.ERROR
        or (
            event.kind is EventKind.MAP_KEY
            and (keys[event.path] != 1 or "\\" in (event.value or ""))
        )
        for event in events
    )


def _local_rules(
    name: str, branches: dict[str, list[Event]], keys: Counter[tuple[object, ...]], lines: list[str]
) -> dict[str, object]:
    """Read ordered rules; skip a single-level local reference only if every row is false."""
    branch = branches[name]
    omitted: set[int] = set()
    for event in branch:
        path = event.path
        if len(path) < 3 or path[1] != "rules" or not isinstance(path[2], int):
            continue
        if path[2] >= 64:
            return {"rules": None}
        if len(path) != 3 or event.kind is not EventKind.LEAF_SCALAR or event.value_kind != "plain":
            continue
        ref = _RULE_REFERENCE.fullmatch(command_text(event, lines) or "")
        if not ref:
            continue
        target = branches.get(ref[1], [])
        if not target or not _unique_branch(target, keys) or keys[(ref[1], "extends")]:
            continue
        rows = _owned_rule_record(target, keys, lines, ref[1]).get("rules")
        if (
            isinstance(rows, list)
            and rows
            and all(
                isinstance(row, dict)
                and isinstance(test := row.get("if"), str)
                and _condition(test, _MR) == "false"
                for row in rows
            )
        ):
            omitted.add(path[2])
    return _owned_rule_record(branch, keys, lines, name, inactive_rule_items=frozenset(omitted))


_SIMPLE_EXPANSION = re.compile(r"\$(?:[A-Za-z_][A-Za-z_0-9]*|\{[A-Za-z_][A-Za-z_0-9]*\})")


def _direct_publish(commands: list[Event], lines: list[str]) -> int | None:
    for event in commands:
        text = command_text(event, lines)
        if (
            not text
            or any(char in text for char in "`\\")
            or "$" in _SIMPLE_EXPANSION.sub("", text)
        ):
            continue
        lexer = shlex.shlex(text, posix=True, punctuation_chars=True)
        lexer.whitespace_split = True
        try:
            argv = list(lexer)
        except ValueError:
            continue
        if (
            tuple(argv[:2]) in _PUBLICATION
            and not any(set(word) & set("();|&<>") for word in argv)
            and not _NOOP.intersection(argv)
            and not any(arg.split("=", 1)[0] in _NOOP | {"--dry-run"} for arg in argv[2:])
        ):
            return event.line
    return None


def _registry_path(
    commands: list[Event], lines: list[str]
) -> tuple[int, int, int, str, bool] | None:
    """Own login, tag, local build and push in one bounded shell sequence."""
    if len(commands) not in {4, 5}:
        return None
    login, tag, image, *tail = commands
    if command_text(login, lines) != _REGISTRY_LOGIN:
        return None
    tag_match = _TAG_ASSIGN.fullmatch(command_text(tag, lines) or "")
    if not tag_match or not _IMAGE_ASSIGN.fullmatch(command_text(image, lines) or ""):
        return None
    if len(tail) == 1:
        block = tail[0]
        if not block.block_lines or not re.fullmatch(
            r"[ \t]*-[ \t]+\|[+-]?[ \t]*(?:#.*)?", lines[block.line - 1]
        ):
            return None
        body = [(line, value.strip()) for line, value in block.block_lines if value.strip()]
        if len(body) != 6 or [body[i][1] for i in (0, 1, 2, 5)] != [
            _MANIFEST_CHECK,
            _MANIFEST_EXISTS,
            "else",
            "fi",
        ]:
            return None
        (build_line, build), (push_line, push) = body[3:5]
    else:
        build_line, push_line = (event.line for event in tail)
        build, push = (command_text(event, lines) or "" for event in tail)
    build_match = _BUILD.fullmatch(build)
    if push == _PUSH and build_match and build_match[1] == tag_match[1]:
        return login.line, build_line, push_line, build_match[1], len(tail) == 1
    return None


def _declared_tokens(branch: list[Event], job: str, lines: list[str]) -> list[str]:
    return [
        f"{event.path[2]} (audience at line {event.line})"
        for event in branch
        if event.kind is EventKind.LEAF_SCALAR
        and len(event.path) == 4
        and event.path[:2] == (job, "id_tokens")
        and event.path[3] == "aud"
        and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", str(event.path[2]))
        and command_text(event, lines)
    ]


def _mr_lines(branch: list[Event], lines: list[str]) -> list[int]:
    return [
        event.line
        for event in branch
        if event.kind is EventKind.LEAF_SCALAR
        and len(event.path) == 4
        and event.path[1] == "rules"
        and event.path[-1] == "if"
        and _explicit_mr(command_text(event, lines) or "")
    ]


def compose_mr_publication(corpus: GitLabWorkflowCorpus) -> GitLabCorpusMatches:
    matches: list[tuple[str, int, str]] = []
    notes: dict[tuple[str, int, str], tuple[str, ...]] = {}
    # Effective cross-file merge, inherited jobs and remote policy are outside this review.
    workflow = corpus.by_filepath(corpus.entry_filepath) if corpus.entry_filepath else None
    if workflow is None or not any(
        word in workflow.content for word in ("id_tokens", "CI_REGISTRY_PASSWORD")
    ):
        return GitLabCorpusMatches(matches, notes=notes)
    events = tuple(
        walk_workflow(workflow.filepath, content=workflow.content, include_keys=True, recover=True)
    )
    keys = Counter(event.path for event in events if event.kind is EventKind.MAP_KEY)
    branches: dict[str, list[Event]] = defaultdict(list)
    for event in events:
        if event.kind is EventKind.CUTOFF or (event.kind is EventKind.ERROR and not event.path):
            return GitLabCorpusMatches(matches, notes=notes)
        if event.path and isinstance(event.path[0], str):
            branches[event.path[0]].append(event)
    if not _unique_branch(branches.get("workflow", []), keys):
        return GitLabCorpusMatches(matches, notes=notes)
    common_bindings = _binding_names(branches.get("variables", [])) | _binding_names(
        branches.get("workflow", [])
    )
    if any(_opaque_native_name(name) for name in common_bindings):
        return GitLabCorpusMatches(matches, notes=notes)
    root = _owned_rule_record(branches.get("workflow", []), keys, workflow.lines, "workflow")
    root_state = _outcome(root, "on_success", _MR, condition=_publication_condition)
    if root_state == "excluded":
        return GitLabCorpusMatches(matches, notes=notes)
    root_mr_lines = _mr_lines(branches.get("workflow", []), workflow.lines)
    for job, branch in branches.items():
        if job.startswith(".") or job in _RESERVED_TOP_LEVEL or not keys[(job, "rules")]:
            continue
        if keys[(job, "extends")] or not _unique_branch(branch, keys):
            continue
        job_bindings = _binding_names(branch)
        if any(_opaque_native_name(name) for name in job_bindings) or keys[(job, "parallel")]:
            continue
        local = _local_rules(job, branches, keys, workflow.lines)
        if (
            keys[(job, "when")]
            or _outcome(local, "on_success", _MR, condition=_publication_condition) != "possible"
        ):
            continue
        mr_lines = _mr_lines(branch, workflow.lines)
        if not mr_lines and root_state == "possible":
            mr_lines = root_mr_lines
        if not mr_lines:
            continue
        commands = _script_items(branch, job)
        if not commands:
            continue
        registry = None
        if not _REGISTRY_BINDINGS.intersection(common_bindings | job_bindings) and not any(
            keys[prefix]
            for prefix in ((job, "before_script"), ("default", "before_script"), ("before_script",))
        ):
            registry = _registry_path(commands, workflow.lines)
        tokens = _declared_tokens(branch, job, workflow.lines)
        evidence = [
            f"Job '{job}' has a possible selection under its source-local rules in a native merge request (event rule at line {mr_lines[0]})."
        ]
        if registry:
            login, build, publish, dockerfile, conditional = registry
            evidence.append(
                f"Line {login}: GitLab registry login using CI_REGISTRY_PASSWORD. Line {build}: build from the "
                f"pipeline workspace Dockerfile {dockerfile}. Line {publish}: push the same configured image tag."
            )
            evidence.append(
                "This source path assumes standard checkout and native GitLab registry variables."
            )
            if conditional:
                evidence.append(
                    "The build and push are configured only when the manifest check returns nonzero."
                )
        elif tokens and (direct := _direct_publish(commands, workflow.lines)) is not None:
            publish = direct
        else:
            continue
        if tokens:
            evidence.append(
                "Job-local OIDC declarations: "
                + ", ".join(tokens)
                + ". Token use and relying-party write grants are unverified."
            )
        if keys[("include",)] or (keys[("workflow", "rules")] and root_state == "unknown"):
            evidence.append("Effective workflow and include configuration remain unresolved.")
        evidence.append(
            "A normal fork run uses fork resources. Parent-project execution requires an authorized trigger and applicable settings. "
            "Actual checkout, granted access, command execution and publication are unverified."
        )
        key = (
            workflow.filepath,
            publish,
            f"Job '{job}' configures a publication command on a possible merge-request path.",
        )
        matches.append(key)
        notes[key] = tuple(evidence)
    return GitLabCorpusMatches(matches, notes=notes)
