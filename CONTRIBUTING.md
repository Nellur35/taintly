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
