"""Join execution findings to configured authority without guessing defaults.

This first profile covers direct GitHub checkout/build paths. It does not
resolve external secrets, action refs, runner images or cloud trust policies.
Unknown links remain review-needed; an execution observation is never removed.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from hashlib import sha256

from .eventguard import event_guard_verdict
from .models import CheckoutBuildWitness, Finding, Severity
from .parsers.gha_expr import (
    Binary,
    ExprSyntaxError,
    Lit,
    canonical_path,
    context_paths,
    iter_expression_bodies,
    parse,
)
from .parsers.structural import Event, EventKind, triggers, walk_workflow

_RULES = frozenset({"LOTP-GH-001", "LOTP-GH-003"})
_MAX_PROFILE_EVENTS = 20_000
_MAX_PROFILE_STEPS = 256
_SCOPES = frozenset(
    {
        "actions",
        "attestations",
        "checks",
        "code-quality",
        "contents",
        "deployments",
        "discussions",
        "id-token",
        "issues",
        "packages",
        "pages",
        "pull-requests",
        "security-events",
        "statuses",
        "artifact-metadata",
        "vulnerability-alerts",
    }
)
_HOSTED = re.compile(
    r"(?:ubuntu-(?:latest|20\.04|22\.04|24\.04)|"
    r"windows-(?:latest|2019|2022|2025)|macos-(?:latest|13|14|15|26))\Z"
)
_CHECKOUT = re.compile(r"actions/checkout@v([2-7])\Z", re.I)
_TOKEN_PATHS = frozenset({"github.token", "secrets.github_token"})
_PR_REPOSITORY = "github.event.pull_request.head.repo.full_name"
_PR_REFS = frozenset({"github.event.pull_request.head.sha", "github.event.pull_request.head.ref"})
# Deliberately literal commands whose ordinary contract consumes the checkout's
# build definitions/hooks. Flags, alternate paths, shell wrappers and expansion
# need richer evidence; the underlying LOTP observation remains visible.
_DIRECT_LOCAL_BUILD = re.compile(
    r"(?:npm (?:ci|install|run [A-Za-z0-9_][A-Za-z0-9_:.-]*)|"
    r"make(?: [A-Za-z0-9_][A-Za-z0-9_.:-]*)?|cargo (?:build|test))\Z"
)


def _expression_path(value: str) -> str | None:
    source = value.strip()
    if not (source.startswith("${{") and source.endswith("}}")):
        return None
    try:
        return canonical_path(parse(source[3:-2].strip()))
    except (ExprSyntaxError, RecursionError):
        return None


def _paths(value: str) -> set[str]:
    paths: set[str] = set()
    for body in iter_expression_bodies(value):
        try:
            paths.update(context_paths(body))
        except (ExprSyntaxError, RecursionError):
            paths.add("unknown")
    if "${{" in value and not paths:
        paths.add("unknown")
    return paths


@dataclass(frozen=True)
class _Grants:
    known: bool = False
    writes: tuple[str, ...] = ()
    line: int = 0
    write_lines: tuple[int, ...] = ()
    levels: tuple[tuple[str, str], ...] = ()


class _Index:
    def __init__(self, content: str, *, events: Iterable[Event] | None = None) -> None:
        self.content = content
        self.lines = content.splitlines()
        self.keys: dict[tuple[object, ...], Event] = {}
        self.leaves: dict[tuple[object, ...], Event] = {}
        self.children: dict[tuple[object, ...], list[tuple[object, ...]]] = {}
        self.environments: dict[tuple[object, ...], dict[str, Event]] = {}
        self.steps: dict[str, set[tuple[object, ...]]] = {}
        self.ambiguous = False
        source = (
            events
            if events is not None
            else walk_workflow(
                "workflow.yml", content=content, include_keys=True, include_merge_origins=True
            )
        )
        for count, event in enumerate(source):
            if count >= _MAX_PROFILE_EVENTS:
                self.ambiguous = True
                break
            if event.kind in {EventKind.ERROR, EventKind.CUTOFF} or event.merge_origins:
                self.ambiguous = True
            target = self.keys if event.kind is EventKind.MAP_KEY else self.leaves
            if event.kind not in {EventKind.MAP_KEY, EventKind.LEAF_SCALAR}:
                continue
            if event.path in target:
                self.ambiguous = True
            target[event.path] = event
            if event.kind is EventKind.MAP_KEY:
                self.children.setdefault(event.path[:-1], []).append(event.path)
            elif (
                len(event.path) >= 2 and event.path[-2] == "env" and isinstance(event.path[-1], str)
            ):
                self.environments.setdefault(event.path[:-1], {})[event.path[-1]] = event
            path = event.path
            if (
                len(path) >= 5
                and path[0] == "jobs"
                and path[2] == "steps"
                and isinstance(path[3], int)
            ):
                self.steps.setdefault(str(path[1]), set()).add(path[:4])

    def value(self, path: tuple[object, ...], default: str = "") -> str:
        event = self.leaves.get(path)
        return (event.value or "") if event else default

    def has(self, path: tuple[object, ...]) -> bool:
        return path in self.keys or path in self.leaves

    def mapping_complete(self, path: tuple[object, ...]) -> bool:
        if not self.has(path):
            return True
        key = self.keys.get(path)
        if key is None or path in self.leaves:
            return False
        children = self.children.get(path, [])
        if children:
            return all(
                len(p) == len(path) + 1 and isinstance(p[-1], str) and p in self.leaves
                for p in children
            )
        tail = self.lines[key.line - 1][key.column - 1 :].split(":", 1)[-1]
        return re.fullmatch(r"\s*\{\s*\}\s*(?:#.*)?", tail) is not None

    def environment(self, step: tuple[object, ...]) -> dict[str, Event]:
        env: dict[str, Event] = {}
        for scope in (("env",), step[:2] + ("env",), step + ("env",)):
            env.update(self.environments.get(scope, {}))
        return env

    def grants(self, job: str) -> _Grants:
        path: tuple[object, ...] = ("jobs", job, "permissions")
        if not self.has(path):
            path = ("permissions",)
        key = self.keys.get(path)
        if key is None:
            return _Grants()
        value = self.value(path)
        if path in self.leaves:
            if value == "read-all":
                return _Grants(
                    True,
                    (),
                    key.line,
                    (),
                    tuple((s, "none" if s == "id-token" else "read") for s in sorted(_SCOPES)),
                )
            if value == "write-all":
                return _Grants(
                    True,
                    ("write-all",),
                    key.line,
                    (key.line,),
                    tuple(
                        (s, "read" if s == "vulnerability-alerts" else "write")
                        for s in sorted(_SCOPES)
                    ),
                )
            return _Grants()
        children = self.children.get(path, [])
        if not children:
            # A null/unsupported scalar is not an explicit empty permission map.
            tail = self.lines[key.line - 1][key.column - 1 :].split(":", 1)[-1]
            if re.fullmatch(r"\s*\{\s*\}\s*(?:#.*)?", tail):
                return _Grants(True, (), key.line, (), tuple((s, "none") for s in sorted(_SCOPES)))
            return _Grants()
        writes = []
        write_lines = []
        levels = dict.fromkeys(_SCOPES, "none")
        for child in children:
            scope = str(child[-1])
            grant = self.value(child)
            if (
                len(child) != len(path) + 1
                or scope not in _SCOPES
                or grant not in {"read", "write", "none"}
                or (scope == "id-token" and grant == "read")
                or (scope == "vulnerability-alerts" and grant == "write")
            ):
                return _Grants()
            if grant == "write":
                writes.append(scope)
                write_lines.append(self.leaves[child].line)
            levels[scope] = grant
        return _Grants(
            True, tuple(writes), key.line, tuple(write_lines), tuple(sorted(levels.items()))
        )

    def sink(self, line: int) -> tuple[object, ...] | None:
        owners = []
        for path, event in self.leaves.items():
            if len(path) != 5 or path[0] != "jobs" or path[2] != "steps" or path[4] != "run":
                continue
            if event.line == line or any(n == line for n, _ in event.block_lines or ()):
                owners.append(path[:4])
        return owners[0] if len(owners) == 1 else None


def _fork_guard_true(value: str | None, event: str) -> bool:
    verdict = event_guard_verdict(value, event)
    if verdict is not None:
        return verdict
    # A fork-only guard is satisfiable by the attacker supplying this source.
    source = (value or "").strip()
    if source.startswith("${{") and source.endswith("}}"):
        source = source[3:-2].strip()
    try:
        node = parse(source)
    except (ExprSyntaxError, RecursionError):
        return False
    if isinstance(node, Binary) and node.op in {"==", "!="}:
        for subject, literal in ((node.left, node.right), (node.right, node.left)):
            if (
                canonical_path(subject) == "github.event.pull_request.head.repo.fork"
                and isinstance(literal, Lit)
                and literal.kind == "bool"
            ):
                return bool(literal.value) if node.op == "==" else not bool(literal.value)
    return False


def _guard(index: _Index, path: tuple[object, ...]) -> str | None:
    return index.value(path) if index.has(path) else None


def _classify(index: _Index, finding: Finding) -> tuple[str, list[str]]:
    unresolved = "unresolved"
    sink = index.sink(finding.line)
    notes = [f"Build observation at line {finding.line}; authority is evaluated separately."]
    if index.ambiguous or sink is None or not isinstance(sink[3], int):
        return unresolved, notes + ["Structural ownership is incomplete or ambiguous."]
    job = str(sink[1])
    base: tuple[object, ...] = ("jobs", job)
    steps = index.steps.get(job, set())
    if len(steps) > _MAX_PROFILE_STEPS:
        return unresolved, notes + [
            "Authority profile step budget exceeded; no limiting or elevated-authority conclusion."
        ]
    grant = index.grants(job)
    if not grant.known:
        return unresolved, notes + ["Effective token permissions are unknown or unsupported."]
    notes.append(
        f"Effective permissions at line {grant.line}: "
        + (
            ", ".join(
                f"{scope}:write (line {line})"
                for scope, line in zip(grant.writes, grant.write_lines, strict=True)
            )
            if grant.writes
            else "read/none only"
        )
        + "."
    )
    checkouts = [
        (p[:4], e)
        for p, e in index.leaves.items()
        if len(p) == 5
        and p[:2] == base
        and p[2] == "steps"
        and p[4] == "uses"
        and isinstance(p[3], int)
        and isinstance(sink[3], int)
        and p[3] < sink[3]
        and (e.value or "").lower().startswith("actions/checkout@")
    ]
    if len(checkouts) != 1:
        return unresolved, notes + [
            "A unique direct checkout credential/source path is not established."
        ]
    checkout, uses = checkouts[0]
    ref = checkout + ("with", "ref")
    repo = checkout + ("with", "repository")
    if (
        checkout[3] != sink[3] - 1
        or _expression_path(index.value(ref)) not in _PR_REFS
        or _expression_path(index.value(repo)) != _PR_REPOSITORY
    ):
        return unresolved, notes + [
            "Indirect source, workspace changes or intervening steps need review."
        ]
    notes.append(
        f"PR-head source at lines {index.leaves[repo].line}/{index.leaves[ref].line}; checkout at line {uses.line} precedes this build."
    )
    version = _CHECKOUT.fullmatch(uses.value or "")
    if version is None:
        return unresolved, notes + ["Checkout ref/version contract has not been resolved."]
    if index.has(base + ("container",)):
        return unresolved, notes + [
            "Container credential and process boundaries have not been resolved."
        ]
    if any(
        index.has(p) and index.value(p) not in {"", ".", "./"}
        for p in (
            checkout + ("with", "path"),
            ("defaults", "run", "working-directory"),
            base + ("defaults", "run", "working-directory"),
            sink + ("working-directory",),
        )
    ):
        return unresolved, notes + [
            "The build workspace needs an explicit source-to-directory proof."
        ]
    if any(
        index.has(p) and index.value(p) not in {"bash", "sh", "pwsh", "powershell", "cmd"}
        for p in (
            ("defaults", "run", "shell"),
            base + ("defaults", "run", "shell"),
            sink + ("shell",),
        )
    ):
        return unresolved, notes + ["Custom shell execution or isolation needs review."]
    run = index.leaves[sink + ("run",)]
    before = [
        text
        for n, text in run.block_lines or ()
        if n < finding.line and text.strip() and not text.lstrip().startswith("#")
    ]
    command = index.lines[finding.line - 1].strip()
    if before or any(marker in command for marker in ("${", "$", "`", ";", "&&", "||")):
        return unresolved, notes + [
            "Script statements or dynamic command state before the build need review."
        ]
    token = index.value(checkout + ("with", "token"))
    ssh = index.value(checkout + ("with", "ssh-key"))
    if ssh or (token and _expression_path(token) not in _TOKEN_PATHS):
        return unresolved, notes + [
            "Custom checkout credentials have authority independent of GITHUB_TOKEN permissions."
        ]
    persistence = index.value(checkout + ("with", "persist-credentials"), "true").lower()
    if persistence not in {"true", "false"}:
        return unresolved, notes + ["Checkout credential persistence is dynamic or unsupported."]
    events = {
        event
        for event in triggers(index.content)
        if all(
            event_guard_verdict(_guard(index, p), event) is not False
            for p in (base + ("if",), checkout + ("if",), sink + ("if",))
        )
    }
    if (
        version[1] == "7"
        and events.intersection({"pull_request_target", "workflow_run"})
        and index.value(checkout + ("with", "allow-unsafe-pr-checkout")).lower() != "true"
    ):
        return unresolved, notes + [
            "Checkout v7 blocks privileged fork checkout by default; execution requires separate verification."
        ]
    if any(
        not index.mapping_complete(p)
        for p in (("env",), base + ("env",), *(step + ("env",) for step in steps))
    ):
        return unresolved, notes + ["Environment mapping or precedence is incomplete."]
    # Evaluate env precedence for every step: earlier/later bindings may persist,
    # but a workflow binding overridden throughout this job is not inherited.
    env = index.environment(sink)
    modeled_env_scopes = (base + ("env",), *(step + ("env",) for step in steps))
    scoped_events = [
        (path, ev)
        for path, ev in index.leaves.items()
        if path[:2] == base and not any(path[: len(scope)] == scope for scope in modeled_env_scopes)
    ]
    scoped_events.extend(
        (("env", name), ev) for step in steps for name, ev in index.environment(step).items()
    )
    sink_token = next(
        (ev for ev in env.values() if _expression_path(ev.value or "") in _TOKEN_PATHS), None
    )
    secret_lines = [
        ev.line
        for _, ev in scoped_events
        if any(p == "secrets" or p.startswith("secrets.") for p in _paths(ev.value or ""))
        and _expression_path(ev.value or "") not in _TOKEN_PATHS
    ]
    if secret_lines:
        notes.append(
            "Configured secret references at lines "
            + ", ".join(map(str, sorted(set(secret_lines))))
            + "; existence, release and persistence are not proven."
        )
    reachable_target = "pull_request_target" in events and all(
        _fork_guard_true(_guard(index, p), "pull_request_target")
        for p in (base + ("if",), checkout + ("if",), sink + ("if",))
    )
    token_writes = tuple(scope for scope in grant.writes if scope != "id-token")
    access_event = (
        index.leaves.get(checkout + ("with", "persist-credentials")) or uses
        if persistence == "true"
        else sink_token
    )
    if reachable_target and token_writes and access_event is not None:
        access_line = access_event.line
        notes.append(
            f"On the pull_request_target path, configured GITHUB_TOKEN write authority is accessible at line {access_line} through "
            + (
                "checkout credential persistence (same runner user; removed after the job)."
                if persistence == "true"
                else "the effective build environment."
            )
            + " Provider permission policy still applies; no cloud role or external secret value is inferred."
        )
        return "evidenced", notes
    opaque = any(
        p == "unknown" or p.startswith(("steps.", "needs.", "inputs.", "vars.", "env.", "matrix."))
        for path, ev in scoped_events
        if "env" in path or ("with" in path and path[-1] in {"token", "ssh-key"})
        for p in _paths(ev.value or "")
    )
    runner = [ev.value or "" for p, ev in index.leaves.items() if p[:3] == base + ("runs-on",)]
    if (
        events == {"pull_request"}
        and not grant.writes
        and persistence == "false"
        and not secret_lines
        and not opaque
        and runner
        and all(_HOSTED.fullmatch(v) for v in runner)
    ):
        notes.append(
            "Ordinary PR, explicit read/none grants, known hosted runner and disabled checkout persistence bound this profile. Untrusted execution remains present; external credential state is not certified."
        )
        return "limited", notes
    return unresolved, notes + [
        "Accessible elevated authority is not established by this supported profile; review defaults, event policy, credentials, runner and subsequent steps."
    ]


def _configured_build_path(index: _Index, finding: Finding) -> CheckoutBuildWitness | None:
    """Refine an evidenced authority profile into a bounded persisted path.

    Called only after _classify validates source/ref, compatible guards,
    credentials, directory, shell and explicit grants. Environment-only token
    access is not a persisted-checkout witness. A build observation alone is
    not enough: require a literal local command without alternate-path options.
    """
    sink = index.sink(finding.line)
    if sink is None or not isinstance(sink[3], int):
        return None
    base = ("jobs", sink[1])
    checkout = base + ("steps", sink[3] - 1)
    uses = index.leaves.get(checkout + ("uses",))
    if uses is None:
        return None
    run = index.leaves[sink + ("run",)]
    statements = [
        text.strip()
        for text in (run.value or "").splitlines()
        if text.strip() and not text.lstrip().startswith("#")
    ]
    if len(statements) != 1:
        return None
    command = statements[0]
    if _DIRECT_LOCAL_BUILD.fullmatch(command) is None:
        return None
    shell = next(
        (
            index.value(p)
            for p in (
                sink + ("shell",),
                base + ("defaults", "run", "shell"),
                ("defaults", "run", "shell"),
            )
            if index.has(p)
        ),
        "",
    )
    if shell not in {"bash", "sh"} and not (
        not shell
        and re.fullmatch(
            r"ubuntu-(?:latest|20\.04|22\.04|24\.04)", index.value(base + ("runs-on",))
        )
    ):
        return None
    if index.value(checkout + ("with", "persist-credentials"), "true").lower() != "true":
        return None
    # Explicit configuration can disable npm lifecycle hooks. Unknown values
    # and executable/search-path overrides also need separate investigation.
    environment = index.environment(sink)
    if any(
        name.upper()
        in {
            "PATH",
            "BASH_ENV",
            "ENV",
            "NODE_OPTIONS",
            "MAKEFLAGS",
            "MFLAGS",
            "MAKEFILES",
            "CARGO_HOME",
            "CARGO_TARGET_DIR",
            "RUSTC",
            "RUSTC_WRAPPER",
        }
        or (command.startswith("npm ") and name.upper().startswith("NPM_CONFIG_"))
        for name in environment
    ):
        return None
    grant = index.grants(str(sink[1]))
    return CheckoutBuildWitness(
        source_sha256=sha256(index.content.encode("utf-8")).hexdigest(),
        file=finding.file,
        job=str(sink[1]),
        checkout_step=int(checkout[3]),
        build_step=sink[3],
        checkout_line=uses.line,
        repository_line=index.leaves[checkout + ("with", "repository")].line,
        ref_line=index.leaves[checkout + ("with", "ref")].line,
        build_line=finding.line,
        command=command,
        permission_line=grant.line,
        write_scopes=tuple(
            (scope, line)
            for scope, line in zip(grant.writes, grant.write_lines, strict=True)
            if scope != "id-token"
        ),
        persistence_line=(
            index.leaves.get(checkout + ("with", "persist-credentials")) or uses
        ).line,
    )


def calibrate_lotp_authority(findings: list[Finding], content: str) -> None:
    """Annotate only LOTP001/003; preserve matches, IDs, spans and rule confidence."""
    targets = [f for f in findings if f.rule_id in _RULES and f.origin == "file"]
    if not targets:
        return
    index = _Index(content)
    for finding in targets:
        # A reused Finding must not retain a witness from different source.
        finding._checkout_build = None
        state, notes = _classify(index, finding)
        if state == "evidenced":
            finding._checkout_build = _configured_build_path(index, finding)
        finding.context_tags.append("authority-" + state)
        finding.context_notes.extend(notes)
        if state == "limited":
            if finding.severity in {Severity.HIGH, Severity.CRITICAL}:
                finding.severity = Severity.MEDIUM
            finding.exploitability = "low"
            finding.review_needed = True
        elif state == "unresolved":
            if finding.exploitability == "high":
                finding.exploitability = "medium"
            finding.review_needed = True
        finding.calibration_reason = " ".join(
            filter(None, (finding.calibration_reason, f"Authority {state}: " + notes[-1]))
        )
