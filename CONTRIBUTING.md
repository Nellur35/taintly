# Contributing

## Dev setup

```bash
git clone https://github.com/Nellur35/taintly
cd taintly
pip install -e ".[dev]"
```

Zero runtime dependencies on purpose — don't add `requests`, `pyyaml`, etc. to the main `[project]` dependencies. `[project.optional-dependencies].dev` is fair game.

## Run the tests

```bash
pytest tests/ --cov=taintly --cov-branch
python -m taintly --self-test
python -m taintly --self-test --mutate
```

A fresh clone runs the full suite with zero failing tests when
`pip install -e ".[dev]"` has been run.  Reporter snapshot baselines
live under `tests/unit/_snapshots/reporters/` and are checked in;
intentional reporter-output changes get regenerated with
`pytest tests/unit/test_reporter_snapshots.py --snapshot-update`,
and the regenerated files ship alongside the reporter change.

## Code style

- `ruff check taintly/` and `ruff format taintly/`
- `mypy`
- `bandit -r taintly/ -c pyproject.toml -x taintly/testing/`

CI enforces all four on every PR.

## Pull requests

- One logical change per PR
- CI must be green
- Squash-merge is the default

## Conventions for new rules

When adding or modifying a rule, the PR review checks:

1. **`test_positive` covers the documented attack shape.**  Each
   sample exercises a distinct shape the rule is designed to catch;
   the rule's own `description` field is the source-of-truth list.
2. **`test_negative` covers the obvious safe pattern AND the
   most-common false-positive shape.**  Negative samples should
   demonstrate that the rule does NOT fire on legitimate code that
   superficially resembles the attack pattern.
3. **Severity changes require corpus or threat-model justification
   in the PR description** — cite the specific finding, mutation
   result, or attack shape that drove the change.
4. **Self-test must pass** (`python -m taintly --self-test`).  All
   `test_positive` samples must fire; all `test_negative` samples
   must not.  Self-test runs as part of CI but is also worth running
   locally before pushing.
5. **Cross-rule sync**: if the rule shares an attacker-context list
   with another rule (e.g. SEC4-GH-004 vs `_TAINTED_CONTEXTS` in
   `taint.py`), update both and add a sync-check unit test if one
   doesn't already exist (see
   `tests/unit/test_taint_dangerous_context_sync.py`).

## Filesystem policy

taintly does NOT follow symlinks during file discovery.  A
repository whose `.github/workflows/` directory is a symlink
pointing outside the repository will not have its symlinked
content scanned.  This is deliberate: a scanner that traverses
symlinks can be steered to read files outside the audited tree
by an attacker who controls the directory layout.

If you legitimately need taintly to scan content outside the
repository root, copy or check it in rather than symlink it.
