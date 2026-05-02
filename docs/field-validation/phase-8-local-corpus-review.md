# Phase 8 field-validation evidence

Status: sanitized local corpus example. Human assessment fields remain unreviewed.

Repository identities, local paths, filenames, and snippets are redacted from committed artifacts.

## Corpus summary

- Targets scanned: 6
- Files scanned: 37
- Findings emitted: 289

| Target | Platform | Files | Findings | Critical | High | Medium | Low | Review-needed | Context notes | Calibration | Engine errors |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| github-target-01 | github | 24 | 214 | 7 | 74 | 65 | 26 | 44 | 0 | 0 | 0 |
| github-target-02 | github | 9 | 64 | 0 | 15 | 15 | 14 | 20 | 0 | 1 | 0 |
| gitlab-target-01 | gitlab | 1 | 2 | 0 | 1 | 1 | 0 | 0 | 0 | 0 | 0 |
| gitlab-target-02 | gitlab | 1 | 4 | 0 | 1 | 3 | 0 | 0 | 0 | 0 | 0 |
| jenkins-target-01 | jenkins | 1 | 3 | 0 | 0 | 2 | 1 | 0 | 0 | 0 | 0 |
| jenkins-target-02 | jenkins | 1 | 2 | 0 | 0 | 1 | 1 | 0 | 0 | 0 | 0 |

## Review method

For each sampled finding, fill `assessment` with one of:

- `valid`
- `false_positive`
- `false_negative_near_miss`
- `needs_context`
- `unclear`

Do not treat this document as a suppression source. It is evidence for future work.

## Top rule clusters

### github-target-01

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

### github-target-02

- `SEC3-GH-006`: 20
- `SEC10-GH-001`: 14
- `SEC4-GH-005`: 11
- `SEC3-GH-001`: 10
- `SEC3-GH-005`: 5
- `SEC5-GH-001`: 2
- `SEC1-GH-001`: 1
- `SEC4-GH-008`: 1

### gitlab-target-01

- `SEC10-GL-002`: 1
- `SEC3-GL-005`: 1

### gitlab-target-02

- `SEC1-GL-001`: 1
- `SEC10-GL-002`: 1
- `SEC3-GL-005`: 1
- `SEC5-GL-001`: 1

### jenkins-target-01

- `SEC1-JK-002`: 1
- `SEC5-JK-001`: 1
- `SEC7-JK-001`: 1

### jenkins-target-02

- `SEC1-JK-002`: 1
- `SEC7-JK-001`: 1

## Sample review queue

### github-target-01

| Assessment | Rule | Severity | Family | File | Line | Snippet | Note |
| --- | --- | --- | --- | --- | ---: | --- | --- |
| unreviewed | `SEC10-GH-001` | LOW | resource_controls | file-001 | 12 | `<redacted>` |  |
| unreviewed | `SEC2-GH-002` | MEDIUM | identity_access | file-001 | 1 | `<redacted>` |  |
| unreviewed | `SEC3-GH-001` | HIGH | supply_chain_immutability | file-001 | 16 | `<redacted>` |  |
| unreviewed | `SEC4-GH-002` | HIGH | privileged_pr_trigger | file-001 | 4 | `<redacted>` |  |
| unreviewed | `SEC4-GH-005` | MEDIUM | credential_persistence | file-001 | 16 | `<redacted>` |  |
| unreviewed | `SEC10-GH-001` | LOW | resource_controls | file-002 | 7 | `<redacted>` |  |
| unreviewed | `SEC2-GH-002` | MEDIUM | identity_access | file-002 | 1 | `<redacted>` |  |
| unreviewed | `SEC3-GH-001` | HIGH | supply_chain_immutability | file-002 | 10 | `<redacted>` |  |
| unreviewed | `SEC3-GH-006` | INFO | Mutable dependency references | file-002 | 10 | `<redacted>` |  |
| unreviewed | `SEC10-GH-001` | LOW | resource_controls | file-003 | 7 | `<redacted>` |  |

### github-target-02

| Assessment | Rule | Severity | Family | File | Line | Snippet | Note |
| --- | --- | --- | --- | --- | ---: | --- | --- |
| unreviewed | `SEC10-GH-001` | LOW | resource_controls | file-001 | 21 | `<redacted>` |  |
| unreviewed | `SEC3-GH-006` | INFO | Mutable dependency references | file-001 | 25 | `<redacted>` |  |
| unreviewed | `SEC3-GH-006` | INFO | Mutable dependency references | file-001 | 34 | `<redacted>` |  |
| unreviewed | `SEC3-GH-005` | HIGH | supply_chain_immutability | file-001 | 40 | `<redacted>` |  |
| unreviewed | `SEC3-GH-005` | HIGH | supply_chain_immutability | file-001 | 46 | `<redacted>` |  |
| unreviewed | `SEC4-GH-005` | MEDIUM | credential_persistence | file-001 | 32 | `<redacted>` |  |
| unreviewed | `SEC4-GH-008` | MEDIUM | script_injection | file-001 | 20 | `<redacted>` |  |
| unreviewed | `SEC10-GH-001` | LOW | resource_controls | file-002 | 29 | `<redacted>` |  |
| unreviewed | `SEC3-GH-006` | INFO | Mutable dependency references | file-002 | 44 | `<redacted>` |  |
| unreviewed | `SEC4-GH-005` | MEDIUM | credential_persistence | file-002 | 49 | `<redacted>` |  |

### gitlab-target-01

| Assessment | Rule | Severity | Family | File | Line | Snippet | Note |
| --- | --- | --- | --- | --- | ---: | --- | --- |
| unreviewed | `SEC3-GL-005` | HIGH | supply_chain_immutability | file-001 | 1 | `<redacted>` |  |
| unreviewed | `SEC10-GL-002` | MEDIUM | logging_visibility | file-001 | 1 | `<redacted>` |  |

### gitlab-target-02

| Assessment | Rule | Severity | Family | File | Line | Snippet | Note |
| --- | --- | --- | --- | --- | ---: | --- | --- |
| unreviewed | `SEC1-GL-001` | MEDIUM | resource_controls | file-001 | 19 | `<redacted>` |  |
| unreviewed | `SEC5-GL-001` | MEDIUM | identity_access | file-001 | 19 | `<redacted>` |  |
| unreviewed | `SEC3-GL-005` | HIGH | supply_chain_immutability | file-001 | 1 | `<redacted>` |  |
| unreviewed | `SEC10-GL-002` | MEDIUM | logging_visibility | file-001 | 1 | `<redacted>` |  |

### jenkins-target-01

| Assessment | Rule | Severity | Family | File | Line | Snippet | Note |
| --- | --- | --- | --- | --- | ---: | --- | --- |
| unreviewed | `SEC7-JK-001` | MEDIUM | ungoverned_services | file-001 | 2 | `<redacted>` |  |
| unreviewed | `SEC5-JK-001` | MEDIUM | identity_access | file-001 | 29 | `<redacted>` |  |
| unreviewed | `SEC1-JK-002` | LOW | resource_controls | file-001 | 1 | `<redacted>` |  |

### jenkins-target-02

| Assessment | Rule | Severity | Family | File | Line | Snippet | Note |
| --- | --- | --- | --- | --- | ---: | --- | --- |
| unreviewed | `SEC7-JK-001` | MEDIUM | ungoverned_services | file-001 | 2 | `<redacted>` |  |
| unreviewed | `SEC1-JK-002` | LOW | resource_controls | file-001 | 1 | `<redacted>` |  |
