# Post-processing pipeline

## Status

Phase 7 introduces an explicit post-detection processor registry. The scanner
still detects first, then applies exploitability-aware suppression and
calibration, then reports.

## Pipeline order

```python
POST_PROCESSORS = (
    github_dead_path_suppression,
    gitlab_dead_job_suppression,
    jenkins_dead_stage_suppression,
    maintainer_gated_severity_downgrade,
)
```

Dead paths are removed before downgrade calibration. A finding that is
statically impossible to execute should not survive merely as a lower-severity
finding.

## Boundaries

- Rule pack behavior stays unchanged.
- Platform-specific condition logic remains in adapters:
  - `staticguard.py` for GitHub Actions
  - `gitlabguard.py` for GitLab CI
  - `jenkinsguard.py` for Jenkins Declarative Pipeline
- Reporters render final engine decisions; they do not recompute risk.
- Unknown platform semantics stay reportable.

## Reason metadata

When a finding survives with calibrated severity, the engine attaches
`calibration_reason` so text, JSON, CSV, SARIF, and HTML reporters can explain
the decision consistently.

Suppressed findings are absent from the report in this phase. If future product
work adds suppressed-finding audit trails, those records should use
`suppression_reason` rather than teaching reporters to infer why a finding is
missing.
