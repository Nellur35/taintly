# Scan multiple local repositories

The Python core API can reuse rule loading across sequential repository scans:

```python
from taintly.batch import scan_repositories
from taintly.models import Platform

results = scan_repositories(
    ["/work/service-a", "/work/service-b"],
    platform=Platform.GITHUB,
)
for result in results:
    if result.error:
        print(result.repo_path, "unavailable:", result.error)
        continue
    for report in result.reports:
        if report.engine_errors():
            print(result.repo_path, "incomplete:", report.engine_errors())
        elif report.files_scanned == 0:
            print(result.repo_path, "no supported CI files found")
        else:
            print(result.repo_path, report.files_scanned, len(report.findings))
```

Omit `platform` to discover supported platforms separately in each directory.
Each selected rule pack loads once per call. Input order and duplicates are
preserved, with fresh report objects. An invalid directory or scanner exception
produces an explicit error and later repositories still run. Rule import failure
makes all inputs unavailable. No project commands execute and no packages are
installed by this API.

This has the core `scan_repo` contract: configuration files, CLI exclusions,
deployment context files, scoring and rendering are not applied. Inspect
`error`, report engine errors and `files_scanned` before treating an input as
successfully evaluated. A zero-finding report with zero scanned files does not
establish a clean repository. Apply your severity policy and report formatting
explicitly after collection if your integration needs them.

Only rule loading is reused by this API; discovery, repository identity and
finding/context state are evaluated for each directory. Rules are cached within
the call, not in a new process-global registry. Calls are sequential and retain
all reports in memory; split very large input lists into bounded batches.
`max_scan_seconds` forwards the existing scanner time-budget option.

The main expected benefit is avoiding repeated process startup and rule loading
when an integration previously invoked one CLI process per repository. It is not
a claim that individual rules have become faster. Scans on large repositories
still depend on file size, rule complexity and filesystem speed.
