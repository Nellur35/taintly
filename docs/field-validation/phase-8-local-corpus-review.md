# Phase 8 field-validation evidence

Status: initial local corpus run. Human assessment fields remain unreviewed.

## Corpus summary

- Targets scanned: 6
- Files scanned: 37
- Findings emitted: 289

| Target | Platform | Files | Findings | Critical | High | Medium | Low | Review-needed | Context notes | Calibration | Engine errors |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| github-actions-goat | github | 24 | 214 | 7 | 74 | 65 | 26 | 44 | 0 | 0 | 0 |
| harden-runner | github | 9 | 64 | 0 | 15 | 15 | 14 | 20 | 0 | 1 | 0 |
| cicd-goat-awesome-app | gitlab | 1 | 2 | 0 | 1 | 1 | 0 | 0 | 0 | 0 | 0 |
| cicd-goat-nest-of-gold | gitlab | 1 | 4 | 0 | 1 | 3 | 0 | 0 | 0 | 0 | 0 |
| cicd-goat-caterpillar | jenkins | 1 | 3 | 0 | 0 | 2 | 1 | 0 | 0 | 0 | 0 |
| cicd-goat-white-rabbit | jenkins | 1 | 2 | 0 | 0 | 1 | 1 | 0 | 0 | 0 | 0 |

## Review method

For each sampled finding, fill `assessment` with one of:

- `valid`
- `false_positive`
- `false_negative_near_miss`
- `needs_context`
- `unclear`

Do not treat this document as a suppression source. It is evidence for future work.

## Top rule clusters

### github-actions-goat

- `SEC3-GH-001`: 72
- `SEC3-GH-006`: 42
- `SEC10-GH-001`: 26
- `SEC4-GH-005`: 25
- `SEC2-GH-002`: 20
- `SEC6-GH-010`: 13
- `SEC7-GH-001`: 7
- `SEC3-GH-003`: 3
- `SEC3-GH-004`: 3
- `SEC4-GH-002`: 2

### harden-runner

- `SEC3-GH-006`: 20
- `SEC10-GH-001`: 14
- `SEC4-GH-005`: 11
- `SEC3-GH-001`: 10
- `SEC3-GH-005`: 5
- `SEC5-GH-001`: 2
- `SEC1-GH-001`: 1
- `SEC4-GH-008`: 1

### cicd-goat-awesome-app

- `SEC10-GL-002`: 1
- `SEC3-GL-005`: 1

### cicd-goat-nest-of-gold

- `SEC1-GL-001`: 1
- `SEC10-GL-002`: 1
- `SEC3-GL-005`: 1
- `SEC5-GL-001`: 1

### cicd-goat-caterpillar

- `SEC1-JK-002`: 1
- `SEC5-JK-001`: 1
- `SEC7-JK-001`: 1

### cicd-goat-white-rabbit

- `SEC1-JK-002`: 1
- `SEC7-JK-001`: 1

## Sample review queue

### github-actions-goat

| Assessment | Rule | Severity | Family | File | Line | Snippet | Note |
| --- | --- | --- | --- | --- | ---: | --- | --- |
| unreviewed | `SEC10-GH-001` | LOW | resource_controls | PRTargetWorkflow.yml | 12 | `runs-on: ubuntu-latest` |  |
| unreviewed | `SEC2-GH-002` | MEDIUM | identity_access | PRTargetWorkflow.yml | 1 | `(pattern not found: ^\s*permissions:)` |  |
| unreviewed | `SEC3-GH-001` | HIGH | supply_chain_immutability | PRTargetWorkflow.yml | 16 | `uses: actions/checkout@v4` |  |
| unreviewed | `SEC4-GH-002` | HIGH | privileged_pr_trigger | PRTargetWorkflow.yml | 4 | `pull_request_target:` |  |
| unreviewed | `SEC4-GH-005` | MEDIUM | credential_persistence | PRTargetWorkflow.yml | 16 | `uses: actions/checkout@v4` |  |
| unreviewed | `SEC10-GH-001` | LOW | resource_controls | anomalous-outbound-calls.yaml | 7 | `runs-on: ubuntu-latest` |  |
| unreviewed | `SEC2-GH-002` | MEDIUM | identity_access | anomalous-outbound-calls.yaml | 1 | `(pattern not found: ^\s*permissions:)` |  |
| unreviewed | `SEC3-GH-001` | HIGH | supply_chain_immutability | anomalous-outbound-calls.yaml | 10 | `uses: step-security/harden-runner@v2` |  |
| unreviewed | `SEC3-GH-006` | INFO | Mutable dependency references | anomalous-outbound-calls.yaml | 10 | `uses: step-security/harden-runner@v2` |  |
| unreviewed | `SEC10-GH-001` | LOW | resource_controls | arc-codecov-simulation.yml | 7 | `runs-on: self-hosted` |  |

### harden-runner

| Assessment | Rule | Severity | Family | File | Line | Snippet | Note |
| --- | --- | --- | --- | --- | ---: | --- | --- |
| unreviewed | `SEC10-GH-001` | LOW | resource_controls | canary.yml | 21 | `runs-on: ubuntu-latest` |  |
| unreviewed | `SEC3-GH-006` | INFO | Mutable dependency references | canary.yml | 25 | `- uses: step-security/harden-runner@5c7944e73c4c2a096b17a9cb74d65b6c2bbafbde # v1` |  |
| unreviewed | `SEC3-GH-006` | INFO | Mutable dependency references | canary.yml | 34 | `uses: step-security/publish-action@b438f840875fdcb7d1de4fc3d1d30e86cf6acb5d` |  |
| unreviewed | `SEC3-GH-005` | HIGH | supply_chain_immutability | canary.yml | 40 | `uses: docker://ghcr.io/step-security/integration-test/int:latest` |  |
| unreviewed | `SEC3-GH-005` | HIGH | supply_chain_immutability | canary.yml | 46 | `uses: docker://ghcr.io/step-security/integration-test/int:latest` |  |
| unreviewed | `SEC4-GH-005` | MEDIUM | credential_persistence | canary.yml | 32 | `- uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # v2` |  |
| unreviewed | `SEC4-GH-008` | MEDIUM | script_injection | canary.yml | 20 | `name: Update the rc tag to ${{ github.event.inputs.COMMIT_SHA }} commit` |  |
| unreviewed | `SEC10-GH-001` | LOW | resource_controls | codeql-analysis.yml | 29 | `runs-on: ubuntu-latest` |  |
| unreviewed | `SEC3-GH-006` | INFO | Mutable dependency references | codeql-analysis.yml | 44 | `uses: step-security/harden-runner@5c7944e73c4c2a096b17a9cb74d65b6c2bbafbde` |  |
| unreviewed | `SEC4-GH-005` | MEDIUM | credential_persistence | codeql-analysis.yml | 49 | `uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11` |  |

### cicd-goat-awesome-app

| Assessment | Rule | Severity | Family | File | Line | Snippet | Note |
| --- | --- | --- | --- | --- | ---: | --- | --- |
| unreviewed | `SEC3-GL-005` | HIGH | supply_chain_immutability | .gitlab-ci.yml | 1 | `image: "python:3.9.15-alpine3.16"` |  |
| unreviewed | `SEC10-GL-002` | MEDIUM | logging_visibility | .gitlab-ci.yml | 1 | `(pattern not found: THIS_RULE_NEVER_MATCHES_INTENTIONALLY_DISABLED)` |  |

### cicd-goat-nest-of-gold

| Assessment | Rule | Severity | Family | File | Line | Snippet | Note |
| --- | --- | --- | --- | --- | ---: | --- | --- |
| unreviewed | `SEC1-GL-001` | MEDIUM | resource_controls | .gitlab-ci.yml | 19 | `environment: production` |  |
| unreviewed | `SEC5-GL-001` | MEDIUM | identity_access | .gitlab-ci.yml | 19 | `environment: production` |  |
| unreviewed | `SEC3-GL-005` | HIGH | supply_chain_immutability | .gitlab-ci.yml | 1 | `image: "python:3.9.15-alpine3.16"` |  |
| unreviewed | `SEC10-GL-002` | MEDIUM | logging_visibility | .gitlab-ci.yml | 1 | `(pattern not found: THIS_RULE_NEVER_MATCHES_INTENTIONALLY_DISABLED)` |  |

### cicd-goat-caterpillar

| Assessment | Rule | Severity | Family | File | Line | Snippet | Note |
| --- | --- | --- | --- | --- | ---: | --- | --- |
| unreviewed | `SEC7-JK-001` | MEDIUM | ungoverned_services | Jenkinsfile | 2 | `agent any` |  |
| unreviewed | `SEC5-JK-001` | MEDIUM | identity_access | Jenkinsfile | 29 | `stage('deploy') {` |  |
| unreviewed | `SEC1-JK-002` | LOW | resource_controls | Jenkinsfile | 1 | `pipeline {` |  |

### cicd-goat-white-rabbit

| Assessment | Rule | Severity | Family | File | Line | Snippet | Note |
| --- | --- | --- | --- | --- | ---: | --- | --- |
| unreviewed | `SEC7-JK-001` | MEDIUM | ungoverned_services | Jenkinsfile | 2 | `agent any` |  |
| unreviewed | `SEC1-JK-002` | LOW | resource_controls | Jenkinsfile | 1 | `pipeline {` |  |
