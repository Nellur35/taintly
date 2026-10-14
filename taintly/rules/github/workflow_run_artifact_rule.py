from taintly.models import Platform, Rule, Severity
from taintly.rules.github.workflow_run_artifact_pattern import (
    WorkflowRunArtifactConsumerPattern,
)

_POSITIVE = """\
on: workflow_run
jobs:
  consume:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v5
        with:
          name: report
          run-id: ${{ github.event.workflow_run.id }}
          repository: ${{ github.repository }}
          github-token: ${{ github.token }}
          path: incoming
      - run: bash incoming/preview.sh
"""

_DATA_ONLY = """\
on: workflow_run
jobs:
  consume:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v5
        with:
          name: report
          run-id: ${{ github.event.workflow_run.id }}
          repository: ${{ github.repository }}
          github-token: ${{ github.token }}
          path: incoming
      - shell: bash
        run: jq -r '.status, .summary' incoming/report.json
"""

RULES = [
    Rule(
        id="SEC4-GH-023",
        title="Downloaded workflow-run artifact is selected for script execution",
        severity=Severity.MEDIUM,
        platform=Platform.GITHUB,
        owasp_cicd="CICD-SEC-4",
        description=(
            "A workflow_run consumer is configured to download the triggering run's "
            "artifact and invoke a literal file under that download destination in "
            "the same job. The candidate does not establish producer identity, "
            "artifact membership or bytes, successful transfer or execution, pull "
            "request origin, or effective credentials."
        ),
        pattern=WorkflowRunArtifactConsumerPattern(),
        remediation=(
            "Keep untrusted artifact contents as data, or execute them only in an "
            "isolated job without sensitive credentials. If execution is required, "
            "verify the intended producer, event/ref/revision, artifact member and "
            "digest. A successful workflow_run conclusion, artifact name, or "
            "actions:read permission alone does not establish trusted contents."
        ),
        reference="https://docs.github.com/en/actions/using-workflows/events-that-trigger-workflows#workflow_run",
        test_positive=[_POSITIVE],
        test_negative=[_DATA_ONLY],
        finding_family="untrusted_code_execution",
        confidence="medium",
        review_needed=True,
    )
]
