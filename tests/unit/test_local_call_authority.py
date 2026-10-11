"""Source-labeled contracts for configured authority on local call flows.

Policy sources (official GitHub documentation):
- https://docs.github.com/en/actions/reference/workflows-and-actions/reusing-workflow-configurations
  Reusable workflow permissions can be maintained or reduced, not elevated; caller workflow env does not cross the call boundary.
- https://docs.github.com/en/actions/how-tos/reuse-automations/reuse-workflows
  Secrets must be passed to a direct reusable-workflow call; nested calls require another pass; inherit applies to the direct call.
- https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax
  A fork pull_request may have write permissions reduced to read-only by provider policy; org/repository settings affect token defaults.
- https://docs.github.com/en/actions/concepts/security/github_token
  GITHUB_TOKEN is repository-scoped; id-token: write alone does not establish a cloud role binding.
- https://docs.github.com/en/actions/reference/workflows-and-actions/contexts
  Step-level env overrides job/workflow env while the step executes.
- https://docs.github.com/en/actions/reference/workflows-and-actions/metadata-syntax
  Composite action run steps declare their own shell steps; configuration does not prove runtime execution.
- https://docs.github.com/en/actions/reference/security/oidc
  id-token: write permits requesting a JWT; cloud trust and role policy are separate.

These tests model static configuration only. They do not claim a run occurred or
that provider settings, runner state, secret values, checked-out bytes, or cloud
identity are known.
"""
from pathlib import Path

from taintly.engine import scan_repo
from taintly.models import Platform
from taintly.rules.registry import load_rules_for_platform


def _write(root: Path, files: dict[str, str]) -> Path:
    for rel, body in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
    return root


def _findings(root: Path, rule_id: str = "XF-GH-005"):
    rules = load_rules_for_platform(Platform.GITHUB)
    reports = scan_repo(str(root), rules, Platform.GITHUB)
    return [
        finding
        for report in reports
        for finding in report.findings
        if finding.rule_id == rule_id
    ]


def _one(root: Path, rule_id: str = "XF-GH-005"):
    found = _findings(root, rule_id)
    assert len(found) == 1, [(item.rule_id, item.title, item.file, item.line) for item in found]
    return found[0]


def _authority(finding) -> str:
    tags = set(finding.context_tags)
    states = tags & {
        "call-authority-configured",
        "call-authority-limited",
        "call-authority-unresolved",
    }
    assert len(states) == 1, tags
    return next(iter(states))


def _notes(finding) -> str:
    return "\n".join(finding.context_notes).replace("\\", "/")


def _caller(*, event="issues", permissions="contents: write", call_permissions="", secrets="", env=""):
    source = "github.event.pull_request.title" if event == "pull_request" else "github.event.issue.title"
    job_permissions = f"    permissions:\n{call_permissions}" if call_permissions else ""
    env_block = f"env:\n{env}" if env else ""
    secrets_block = f"    secrets:\n{secrets}" if secrets else ""
    return f"""on: {event}
{permissions}
{env_block}jobs:
  call:
    uses: ./.github/workflows/callee.yml
{job_permissions}    with:
      payload: ${{{{ {source} }}}}
{secrets_block}"""


def _callee(*, permissions="contents: read", secret_decl="", env="", step_env="", run_extra=""):
    secrets_decl = f"    secrets:\n{secret_decl}" if secret_decl else ""
    env_block = f"    env:\n{env}" if env else ""
    step_env_block = f"          {step_env}" if step_env else ""
    return f"""on:
  workflow_call:
    inputs:
      payload: {{type: string}}
{secrets_decl}jobs:
  consume:
    runs-on: ubuntu-latest
    permissions:
      {permissions}
{env_block}    steps:
      - env:
{step_env_block}          GH_TOKEN: ${{{{ github.token }}}}
        run: eval \"${{{{ inputs.payload }}}}\"; client --token \"$GH_TOKEN\" {run_extra}
"""


def test_caller_write_callee_read_is_bounded_to_read_and_has_witnesses(tmp_path):
    _write(tmp_path, {
        ".github/workflows/caller.yml": _caller(permissions="permissions:\n  contents: write"),
        ".github/workflows/callee.yml": _callee(permissions="contents: read"),
    })
    finding = _one(tmp_path)
    assert _authority(finding) == "call-authority-limited"
    notes = _notes(finding).lower()
    assert "configured token permissions" in notes
    assert "contents" in notes and "read" in notes
    assert ".github/workflows/caller.yml:" in notes
    assert ".github/workflows/callee.yml:" in notes
    assert "external runner" in notes or "provider" in notes


def test_callee_write_request_above_read_caller_is_unresolved_not_write(tmp_path):
    _write(tmp_path, {
        ".github/workflows/caller.yml": _caller(permissions="permissions:\n  contents: read"),
        ".github/workflows/callee.yml": _callee(permissions="contents: write"),
    })
    finding = _one(tmp_path)
    assert _authority(finding) == "call-authority-unresolved"
    notes = _notes(finding).lower()
    assert "contents" in notes and "write" in notes and "read" in notes
    assert "cannot" in notes or "not elevated" in notes or "unresolved" in notes
    assert "configured token permissions" in notes


def test_sibling_job_write_does_not_donate_to_read_call(tmp_path):
    caller = """on: issues
permissions:
  contents: read
jobs:
  writer:
    permissions:
      contents: write
    uses: ./.github/workflows/callee.yml
    with:
      payload: ${{ github.event.issue.title }}
  reader:
    permissions:
      contents: read
    uses: ./.github/workflows/callee.yml
    with:
      payload: ${{ github.event.issue.title }}
"""
    _write(tmp_path, {
        ".github/workflows/caller.yml": caller,
        ".github/workflows/callee.yml": _callee(permissions="contents: read"),
    })
    found = _findings(tmp_path)
    assert len(found) == 2
    assert {_authority(item) for item in found} == {"call-authority-limited"}
    witnesses = [_notes(item).lower() for item in found]
    assert all("contents" in note and "read" in note for note in witnesses)
    assert len({item.line for item in found}) == 2


def test_caller_workflow_env_does_not_cross_workflow_call(tmp_path):
    _write(tmp_path, {
        ".github/workflows/caller.yml": _caller(
            permissions="permissions:\n  contents: read",
            env="  DEPLOY_TOKEN: ${{ secrets.DEPLOY_TOKEN }}\n",
        ),
        ".github/workflows/callee.yml": _callee(
            permissions="contents: read",
            env="      DEPLOY_TOKEN: ${{ env.DEPLOY_TOKEN }}\n",
            run_extra="deploy --token \"$DEPLOY_TOKEN\"",
        ),
    })
    finding = _one(tmp_path)
    notes = _notes(finding).lower()
    assert "secret access binding" not in notes or "caller env" in notes
    assert "call-authority-unresolved" in finding.context_tags
    assert "caller workflow env" in notes or "not propagated" in notes


def test_named_secret_needs_pass_and_sink_binding(tmp_path):
    _write(tmp_path, {
        ".github/workflows/caller.yml": _caller(
            permissions="permissions:\n  contents: read",
            secrets="      deploy: ${{ secrets.DEPLOY_TOKEN }}\n",
        ),
        ".github/workflows/callee.yml": _callee(
            permissions="contents: read",
            secret_decl="      deploy: {required: true}\n",
            run_extra="deploy --token \"$DEPLOY_TOKEN\"",
        ).replace(
            "      - env:\n          GH_TOKEN:",
            "      - env:\n          DEPLOY_TOKEN: ${{ secrets.deploy }}\n          GH_TOKEN:",
        ),
    })
    finding = _one(tmp_path)
    notes = _notes(finding).lower()
    assert "secret access binding" in notes
    assert "deploy" in notes
    assert ".github/workflows/caller.yml:" in notes
    assert ".github/workflows/callee.yml:" in notes
    assert "secret value" in notes or "external runner" in notes


def test_unpassed_secret_is_not_claimed_as_sink_access(tmp_path):
    _write(tmp_path, {
        ".github/workflows/caller.yml": _caller(permissions="permissions:\n  contents: read"),
        ".github/workflows/callee.yml": _callee(
            permissions="contents: read",
            secret_decl="      deploy: {required: true}\n",
            run_extra="deploy --token \"$DEPLOY_TOKEN\"",
        ).replace(
            "      - env:\n          GH_TOKEN:",
            "      - env:\n          DEPLOY_TOKEN: ${{ secrets.deploy }}\n          GH_TOKEN:",
        ),
    })
    finding = _one(tmp_path)
    notes = _notes(finding).lower()
    assert "call-authority-unresolved" in finding.context_tags
    assert "secret access binding" not in notes
    assert "deploy" in notes and ("not passed" in notes or "unavailable" in notes or "unresolved" in notes)


def test_inherit_is_direct_only_and_does_not_auto_forward_to_grandchild(tmp_path):
    _write(tmp_path, {
        ".github/workflows/caller.yml": """on: issues
permissions:
  contents: read
jobs:
  call-middle:
    uses: ./.github/workflows/middle.yml
    secrets: inherit
    with:
      payload: ${{ github.event.issue.title }}
""",
        ".github/workflows/middle.yml": """on:
  workflow_call:
    inputs:
      payload: {type: string}
jobs:
  call-leaf:
    uses: ./.github/workflows/leaf.yml
    with:
      payload: ${{ inputs.payload }}
""",
        ".github/workflows/leaf.yml": """on:
  workflow_call:
    inputs:
      payload: {type: string}
jobs:
  leaf:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - run: eval \"${{ inputs.payload }}\"; deploy --token \"${{ secrets.deploy }}\"
""",
    })
    finding = _one(tmp_path)
    notes = _notes(finding).lower()
    assert "secret access binding" not in notes or "not forwarded" in notes
    assert "direct" in notes or "forward" in notes
    assert "leaf.yml:" in notes
    assert "call-authority-unresolved" in finding.context_tags


def test_step_env_override_replaces_job_secret_binding_at_sink(tmp_path):
    _write(tmp_path, {
        ".github/workflows/caller.yml": _caller(
            permissions="permissions:\n  contents: read",
            secrets="      deploy: ${{ secrets.DEPLOY_TOKEN }}\n",
        ),
        ".github/workflows/callee.yml": _callee(
            permissions="contents: read",
            secret_decl="      deploy: {required: true}\n",
            env="      DEPLOY_TOKEN: ${{ secrets.deploy }}\n",
            step_env="DEPLOY_TOKEN: ${{ github.sha }}\n",
            run_extra="deploy --token \"$DEPLOY_TOKEN\"",
        ),
    })
    finding = _one(tmp_path)
    notes = _notes(finding).lower()
    assert "call-authority-limited" in finding.context_tags
    assert "secret access binding" not in notes
    assert "deploy_token" in notes and ("override" in notes or "step env" in notes)


def test_pull_request_write_setting_is_unresolved_without_provider_policy(tmp_path):
    _write(tmp_path, {
        ".github/workflows/caller.yml": _caller(
            event="pull_request",
            permissions="permissions:\n  contents: write",
        ),
        ".github/workflows/callee.yml": _callee(permissions="contents: write"),
    })
    finding = _one(tmp_path)
    notes = _notes(finding).lower()
    assert _authority(finding) == "call-authority-unresolved"
    assert "pull_request" in notes
    assert "fork" in notes or "provider policy" in notes
    assert "contents: write" not in notes or "configured" in notes


def test_id_token_write_does_not_establish_cloud_role(tmp_path):
    _write(tmp_path, {
        ".github/workflows/caller.yml": _caller(
            permissions="permissions:\n  id-token: write\n  contents: read",
        ),
        ".github/workflows/callee.yml": _callee(
            permissions="id-token: write\n      contents: read",
            run_extra="curl -H \"Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN\" \"$ACTIONS_ID_TOKEN_REQUEST_URL\"",
        ),
    })
    finding = _one(tmp_path)
    notes = _notes(finding).lower()
    assert "id-token" in notes
    assert "role" in notes and ("not establish" in notes or "not proven" in notes or "unknown" in notes)


def test_composite_env_propagation_keeps_runtime_authority_unproven(tmp_path):
    caller = """on: issues
permissions:
  contents: read
jobs:
  call-action:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: ./.github/actions/deploy
        env:
          DEPLOY_TOKEN: ${{ secrets.DEPLOY_TOKEN }}
        with:
          payload: ${{ github.event.issue.title }}
"""
    # The invocation explicitly supplies the environment binding to a local
    # composite action. Configured inheritance still does not prove runtime
    # checkout bytes, actual secret value, or effective process authority.
    _write(tmp_path, {
        ".github/workflows/caller.yml": caller,
        ".github/actions/deploy/action.yml": """inputs:
  payload: {required: true}
runs:
  using: composite
  steps:
    - run: eval \"${{ inputs.payload }}\"; deploy --token \"$DEPLOY_TOKEN\"
      shell: bash
""",
    })
    finding = _one(tmp_path, "XF-GH-006")
    notes = _notes(finding).lower()
    assert "call-authority-configured" in finding.context_tags
    assert "secret access binding" in notes
    assert "runtime" in notes or "composite" in notes
    assert "token" in notes and ("not established" in notes or "unknown" in notes)
