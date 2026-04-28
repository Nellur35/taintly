# Evasion Corpus

These YAML files are **semantically dangerous** but the tool **cannot detect them**.

They are NOT test failures. They are documented gaps — the tool's known false negative ceiling.
Each file is tested by `test_evasion.py` which asserts the rule does NOT fire (confirming
the bypass is real and has not been accidentally fixed).

When a bypass IS fixed in a rule, the corresponding evasion file should be moved to
`tests/fixtures/github/vulnerable/` and added to the detection tests.

## Categories

| File | Bypass technique | Rule bypassed | Why undetectable |
|------|-----------------|---------------|-----------------|
| `variable_indirection.yml` | `OUT=$GITHUB_ENV; echo >> $OUT` | SEC4-GH-006 | Single-line pattern, split across lines |
| `anchor_merge_inject.yml` | `<<: *checkout_opts` | SEC4-GH-005 | Anchor defined outside lookahead window |
| `cross_job_output_routing.yml` | secret → GITHUB_OUTPUT → needs.X.outputs | SEC6-GH-004/005 | Cross-job data flow invisible to single-file analysis |
| `base64_shell.yml` | `echo "BASE64" \| base64 -d \| bash` | SEC6-GH-007 | Encoded payload, not literal pipe-to-shell |
| `orphaned_sha.yml` | 40-char hex pointing to orphaned fork commit | SEC3-GH-001 | Static analysis cannot distinguish real from orphaned SHA |
| `shell_export_unsecure.yml` | `export ACTIONS_ALLOW_UNSECURE_COMMANDS=true` | SEC4-GH-009 | Rule checks YAML key, not shell export |

## The meta-lesson

These bypasses exist in two categories:

1. **Structural** (variable indirection, cross-job routing, shell export): The rule checks
   a single line or YAML key. The dangerous operation is split across multiple steps, jobs,
   or shell constructs. Fixing these requires multi-line or cross-job taint tracking.

2. **Semantic** (orphaned SHA, anchor merge, base64): The value *looks* safe to static
   analysis but is dangerous at runtime. Fixing these requires either API access (for SHA
   validation) or YAML evaluation (for anchor expansion).

Both categories are fundamental limitations of static single-file regex analysis.
