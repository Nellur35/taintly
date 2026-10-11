"""Immutable configured authority carried by local call graph invocations.

This joins declarations and exact credential bindings, not live permission
policy, secret values, runner state, credential persistence or cloud roles.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from .authority_context import _expression_path, _Index, _paths
from .parsers.gha_expr import iter_expression_bodies


@dataclass(frozen=True)
class AuthorityWitness:
    file: str
    line: int
    detail: str

    def label(self) -> str:
        return f"{self.file}:{self.line} ({self.detail})"


@dataclass(frozen=True)
class CredentialBinding:
    kind: str
    source: str
    witnesses: tuple[AuthorityWitness, ...]


@dataclass(frozen=True)
class PermissionCeiling:
    known: bool = False
    levels: tuple[tuple[str, str], ...] = ()
    witnesses: tuple[AuthorityWitness, ...] = ()


@dataclass(frozen=True)
class AuthorityInvocation:
    ceiling: PermissionCeiling = PermissionCeiling()
    root: bool = True
    secrets: tuple[tuple[str, CredentialBinding], ...] = ()
    secret_wildcard: bool = True
    secret_hops: tuple[AuthorityWitness, ...] = ()
    inputs: tuple[tuple[str, CredentialBinding], ...] = ()
    environment: tuple[tuple[str, CredentialBinding], ...] = ()
    notes: tuple[str, ...] = ()
    invalid: bool = False
    environment_unresolved: bool = False


@dataclass(frozen=True)
class CallAuthorityEvidence:
    state: str = "unresolved"
    token_permissions: tuple[tuple[str, str], ...] = ()
    permission_witnesses: tuple[AuthorityWitness, ...] = ()
    token_access: tuple[CredentialBinding, ...] = ()
    secret_access: tuple[CredentialBinding, ...] = ()
    notes: tuple[str, ...] = ()
    invocation_unresolved: bool = False

    def context_notes(self) -> tuple[str, ...]:
        grants = ", ".join(f"{s}: {v}" for s, v in self.token_permissions if v != "none") or "none"
        permission_note = (
            f"Configured token permissions under caller ceiling: {grants}."
            if self.token_permissions
            else "Token permissions under the caller ceiling are not established. Configured token permissions remain unresolved."
        )
        return (
            permission_note,
            *(f"Permission witness: {w.label()}." for w in self.permission_witnesses),
            *(
                f"Token access binding: {b.source}; "
                + " -> ".join(w.label() for w in b.witnesses)
                + "."
                for b in self.token_access
            ),
            *(
                f"Secret access binding: {b.source}; "
                + " -> ".join(w.label() for w in b.witnesses)
                + "."
                for b in self.secret_access
            ),
            *self.notes,
            "Configured references do not prove secret existence, value, release or external credential privileges. Provider policy applies; cloud authority and external runner/process state are not certified.",
        )


class CallAuthorityResolver:
    """Resolve facts on existing graph frames; never traverse another graph."""

    def __init__(self, index: Callable[[str], _Index]) -> None:
        self.index = index

    def _permissions(
        self, frame: AuthorityInvocation, file: str, kind: str, owner: tuple[object, ...]
    ) -> tuple[PermissionCeiling, tuple[str, ...], bool]:
        if kind == "action":
            return frame.ceiling, (), False
        index = self.index(file)
        job = str(owner[1])
        declared = index.has(("jobs", job, "permissions")) or index.has(("permissions",))
        grant = index.grants(job)
        if index.ambiguous:
            return PermissionCeiling(), (f"Permission ownership at {file} is unresolved.",), True
        if not declared:
            if frame.root:
                return (
                    PermissionCeiling(),
                    (f"Default token permission policy at {file} is unresolved.",),
                    False,
                )
            return frame.ceiling, (), False
        witness = AuthorityWitness(file, grant.line, "permission declaration")
        witnesses = frame.ceiling.witnesses + (witness,)
        if not grant.known:
            return (
                PermissionCeiling(False, (), witnesses),
                (f"Permission declaration at {file}:{grant.line} is unsupported.",),
                True,
            )
        if frame.root:
            return PermissionCeiling(True, grant.levels, witnesses), (), False
        if not frame.ceiling.known:
            # An explicit none map bounds this token even if the upstream default
            # is unknown. Other requested grants do not establish availability.
            if all(level == "none" for _, level in grant.levels):
                return PermissionCeiling(True, grant.levels, witnesses), (), False
            return (
                PermissionCeiling(False, (), witnesses),
                (
                    f"Requested callee permissions at {file}:{grant.line} have an unresolved caller ceiling.",
                ),
                False,
            )
        rank = {"none": 0, "read": 1, "write": 2}
        parent = dict(frame.ceiling.levels)
        elevated = [s for s, v in grant.levels if rank[v] > rank[parent.get(s, "none")]]
        if elevated:
            return (
                PermissionCeiling(False, (), witnesses),
                (
                    f"Incompatible callee permission request at {file}:{grant.line} exceeds the caller ceiling: "
                    + ", ".join(
                        f"{s} requested {dict(grant.levels)[s]}, caller {parent.get(s, 'none')}"
                        for s in elevated
                    )
                    + "; invocation validity is unresolved.",
                ),
                True,
            )
        return PermissionCeiling(True, grant.levels, witnesses), (), False

    def _binding(
        self,
        value: str,
        frame: AuthorityInvocation,
        witness: AuthorityWitness,
        *,
        allow_secrets: bool,
    ) -> tuple[CredentialBinding | None, tuple[str, ...]]:
        path = _expression_path(value)
        if path in {"github.token", "secrets.github_token"} and (
            allow_secrets or path == "github.token"
        ):
            return CredentialBinding("token", "GITHUB_TOKEN", (witness,)), ()
        if path and path.startswith("inputs."):
            binding = dict(frame.inputs).get(path[7:].lower())
            if binding:
                unknown = (
                    (
                        f"Configured credential input {path} at {witness.label()} has unresolved credential provenance.",
                    )
                    if binding.kind == "unresolved"
                    else ()
                )
                return CredentialBinding(
                    binding.kind, binding.source, binding.witnesses + (witness,)
                ), unknown
            return None, ()  # Ordinary tainted/literal inputs are not credential evidence.
        if path and path.startswith("secrets."):
            if not allow_secrets:
                return None, (
                    f"Composite secrets context at {witness.label()} is not an independent credential source.",
                )
            name = path[8:].lower()
            binding = dict(frame.secrets).get(name)
            if binding:
                unknown = (
                    (
                        f"Configured incoming secret {path} at {witness.label()} has unresolved credential provenance; a supplied key does not establish a stored secret value.",
                    )
                    if binding.kind == "unresolved"
                    else ()
                )
                return CredentialBinding(
                    binding.kind, binding.source, binding.witnesses + (witness,)
                ), unknown
            if frame.secret_wildcard:
                return CredentialBinding("secret", path, frame.secret_hops + (witness,)), ()
            return None, (
                f"Secret {path} at {witness.label()} has no configured incoming binding; forwarding stopped at a reusable boundary.",
            )
        if any(
            p in {"unknown", "secrets", "github.token"}
            or p.startswith(("secrets.", "inputs.", "env.", "steps.", "needs.", "matrix.", "vars."))
            for p in _paths(value)
        ):
            return None, (
                f"Credential expression at {witness.label()} is unresolved; exact binding is not established.",
            )
        return None, ()

    def _environment(
        self, frame: AuthorityInvocation, file: str, kind: str, owner: tuple[object, ...]
    ) -> tuple[tuple[tuple[str, CredentialBinding], ...], tuple[str, ...], bool]:
        index = self.index(file)
        scopes = (
            (("env",), owner[:2] + ("env",), owner + ("env",))
            if kind == "workflow"
            else (owner + ("env",),)
        )
        env = dict(frame.environment) if kind == "action" else {}
        notes: list[str] = []
        uncertain = False
        seen = set(env)
        for scope in scopes:
            if not index.mapping_complete(scope):
                notes.append(
                    f"Environment mapping at {file}:{index.keys[scope].line if scope in index.keys else 0} is unresolved."
                )
                env.clear()
                uncertain = True
                continue
            for name, event in index.environments.get(scope, {}).items():
                if name in seen:
                    notes.append(
                        f"Environment override at {file}:{event.line}: {name} replaces the earlier binding."
                    )
                seen.add(name)
        # Resolve after precedence, so an overridden secret expression cannot
        # donate either a binding or an environment-secret uncertainty.
        effective = (
            index.environment(owner)
            if kind == "workflow"
            else index.environments.get(owner + ("env",), {})
        )
        for name, event in effective.items():
            env.pop(name, None)
            binding, unknown = self._binding(
                event.value or "",
                frame,
                AuthorityWitness(file, event.line, f"env {name}"),
                allow_secrets=kind == "workflow",
            )
            notes.extend(unknown)
            uncertain |= bool(unknown)
            if binding:
                if (
                    kind == "workflow"
                    and index.has(owner[:2] + ("environment",))
                    and binding.kind == "secret"
                ):
                    notes.append(
                        f"Environment secret precedence/release at {file}:{event.line} is unresolved."
                    )
                    uncertain = True
                else:
                    env[name] = binding
        if index.ambiguous:
            env.clear()
            notes.append(f"Credential ownership at {file} is unresolved.")
            uncertain = True
        return tuple(sorted(env.items())), tuple(dict.fromkeys(notes)), uncertain

    def call(
        self,
        frame: AuthorityInvocation,
        file: str,
        kind: str,
        owner: tuple[object, ...],
        target: str,
        target_kind: str,
        line: int,
    ) -> AuthorityInvocation:
        index, callee = self.index(file), self.index(target)
        ceiling, permission_notes, invalid = self._permissions(frame, file, kind, owner)
        notes = list(frame.notes + permission_notes)
        env: tuple[tuple[str, CredentialBinding], ...] = ()
        if target_kind == "action":
            env, env_notes, env_unknown = self._environment(frame, file, kind, owner)
            notes.extend(env_notes)
        inputs: dict[str, CredentialBinding] = {}
        for path, event in index.leaves.items():
            if path[:-1] != owner + ("with",):
                continue
            binding, unknown = self._binding(
                event.value or "",
                frame,
                AuthorityWitness(file, event.line, f"input {path[-1]}"),
                allow_secrets=kind == "workflow",
            )
            notes.extend(unknown)
            declaration = (
                ("on", "workflow_call", "inputs", str(path[-1]))
                if target_kind == "workflow"
                else ("inputs", str(path[-1]))
            )
            if binding and not callee.has(declaration):
                notes.append(f"Credential input contract {path[-1]} at {target} is undeclared.")
                invalid = True
            elif (
                binding
                and target_kind == "workflow"
                and callee.value(declaration + ("type",)) != "string"
            ):
                notes.append(
                    f"Credential input {path[-1]} at {target} requires a declared string contract; invocation validity is unresolved."
                )
                invalid = True
            elif binding:
                inputs[str(path[-1]).lower()] = binding
        if target_kind == "action":
            return AuthorityInvocation(
                ceiling,
                False,
                frame.secrets,
                frame.secret_wildcard,
                frame.secret_hops,
                tuple(sorted(inputs.items())),
                env,
                tuple(dict.fromkeys(notes)),
                frame.invalid or invalid,
                frame.environment_unresolved or env_unknown,
            )
        # A reusable call creates a fresh job: env does not cross this boundary.
        secret_path = owner + ("secrets",)
        secrets: dict[str, CredentialBinding] = {}
        supplied: set[str] = set()
        wildcard = False
        hops: tuple[AuthorityWitness, ...] = ()
        if index.value(secret_path) == "inherit":
            secrets = dict(frame.secrets)
            wildcard = frame.secret_wildcard
            edge = AuthorityWitness(file, index.leaves[secret_path].line, "secrets inherit")
            secrets = {
                name: CredentialBinding(b.kind, b.source, b.witnesses + (edge,))
                for name, b in secrets.items()
            }
            hops = frame.secret_hops + (edge,)
        elif not index.mapping_complete(secret_path):
            notes.append(f"Secret forwarding at {file}:{line} is unresolved.")
            invalid = True
        else:
            for path, event in index.leaves.items():
                if path[:-1] != secret_path:
                    continue
                name = str(path[-1]).lower()
                supplied.add(name)
                binding, unknown = self._binding(
                    event.value or "",
                    frame,
                    AuthorityWitness(file, event.line, f"secret mapping {name}"),
                    allow_secrets=kind == "workflow",
                )
                notes.extend(unknown)
                if not callee.has(("on", "workflow_call", "secrets", str(path[-1]))):
                    notes.append(
                        f"Explicit secret contract {name} at {target} is undeclared; invocation validity is unresolved."
                    )
                    invalid = True
                elif binding:
                    secrets[name] = binding
                else:
                    secrets[name] = CredentialBinding(
                        "unresolved",
                        "configured value with unresolved credential provenance",
                        (AuthorityWitness(file, event.line, f"secret mapping {name}"),),
                    )
        for path, event in callee.leaves.items():
            if (
                len(path) == 5
                and path[:3] == ("on", "workflow_call", "secrets")
                and path[-1] == "required"
                and event.value == "true"
            ):
                name = str(path[3]).lower()
                if name not in supplied and name not in secrets and not wildcard:
                    notes.append(
                        f"Required secret {name} at {target}:{event.line} has no proven configured binding; invocation validity is unresolved."
                    )
                    invalid = True
        notes.append(
            f"Caller workflow env at {file}:{line} is not propagated across this reusable boundary."
        )
        return AuthorityInvocation(
            ceiling,
            False,
            tuple(sorted(secrets.items())),
            wildcard,
            hops,
            tuple(sorted(inputs.items())),
            (),
            tuple(dict.fromkeys(notes)),
            frame.invalid or invalid,
        )

    def sink(
        self,
        frame: AuthorityInvocation,
        file: str,
        kind: str,
        owner: tuple[object, ...],
        event: str,
    ) -> CallAuthorityEvidence:
        ceiling, grant_notes, invalid = self._permissions(frame, file, kind, owner)
        env, env_notes, env_unknown = self._environment(frame, file, kind, owner)
        if kind == "action" and frame.environment_unresolved:
            env_notes += ("Inherited composite environment is unresolved.",)
            env_unknown = True
        exposed = [binding for _, binding in env]
        source_notes: list[str] = []
        index = self.index(file)
        run = index.leaves.get(owner + ("run",))
        if run:
            physical = run.block_lines or ((run.line, run.value or ""),)
            source = "\n".join(text for _, text in physical)
            cursor = 0
            for body in iter_expression_bodies(source):
                opening = source.find("${{", cursor)
                expression_line = physical[source[:opening].count("\n")][0]
                cursor = opening + 3 + len(body) + 2
                binding, unknown = self._binding(
                    "${{ " + body + " }}",
                    frame,
                    AuthorityWitness(file, expression_line, "run template"),
                    allow_secrets=kind == "workflow",
                )
                source_notes.extend(unknown)
                if (
                    binding
                    and kind == "workflow"
                    and index.has(owner[:2] + ("environment",))
                    and binding.kind == "secret"
                ):
                    source_notes.append(
                        f"Environment secret precedence/release at {file}:{expression_line} is unresolved."
                    )
                elif binding:
                    exposed.append(binding)
        bindings = tuple(dict.fromkeys(exposed))
        tokens = tuple(b for b in bindings if b.kind == "token")
        secrets = tuple(b for b in bindings if b.kind == "secret")
        notes = list(frame.notes + grant_notes + env_notes + tuple(source_notes))
        invalid |= frame.invalid
        state = "unresolved"
        if ceiling.known and not invalid and not source_notes and not env_unknown:
            if not any(v == "write" for _, v in ceiling.levels) and not secrets:
                state = "limited"
                notes.append(
                    "Only the configured token/explicit binding profile is limited; untrusted execution and external credentials remain possible."
                )
            elif tokens or secrets:
                state = "configured"
        if event in {"pull_request", "?"}:
            state = "unresolved"
            notes.append(
                "Ordinary PR/fork origin and provider write-token/secret policy require review; YAML does not establish effective release."
            )
        if dict(ceiling.levels).get("id-token") == "write":
            notes.append(
                "id-token: write permits requesting an OIDC token, not assuming a cloud role; cloud trust policy is not established."
            )
        if not tokens:
            notes.append(
                "Exact GITHUB_TOKEN sink access is not established; ambient action context or persisted credentials require separate review."
            )
        return CallAuthorityEvidence(
            state,
            ceiling.levels if ceiling.known else (),
            ceiling.witnesses,
            tokens,
            secrets,
            tuple(dict.fromkeys(notes)),
            invalid,
        )
