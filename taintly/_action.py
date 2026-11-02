"""GitHub composite-Action launcher; the installed CLI owns all analysis."""

from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
import sysconfig
from collections.abc import Mapping
from pathlib import Path


def _arguments(env: Mapping[str, str]) -> list[str]:
    args = [env.get("CICD_AUDIT_PATH", "."), "--no-color"]
    for key, flag, default in (
        ("FAIL_ON", "--fail-on", "HIGH"),
        ("MIN_SEVERITY", "--min-severity", "INFO"),
        ("PLATFORM", "--platform", ""),
        ("CONFIG", "--config", ""),
    ):
        value = env.get("CICD_AUDIT_" + key, default)
        if value:
            args.extend((flag, value))
    if env.get("CICD_AUDIT_BASELINE", "false") == "true":
        args.extend(("--diff", env.get("CICD_AUDIT_BASELINE_FILE", ".taintly-baseline.json")))
    for rule in env.get("CICD_AUDIT_EXCLUDE_RULES", "").replace(",", "\n").splitlines():
        if rule.strip():
            args.extend(("--exclude-rule", rule.strip()))
    args.extend(shlex.split(env.get("CICD_AUDIT_EXTRA_ARGS", "")))
    return args


def _error(message: str) -> None:
    # A source-derived path or parser message cannot inject a workflow command.
    escaped = message.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    print("::error::" + escaped, file=sys.stderr)


def _valid_sarif(path: Path) -> bool:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeError, ValueError):
        return False
    return (
        isinstance(document, dict)
        and document.get("version") == "2.1.0"
        and isinstance(document.get("runs"), list)
    )


def main() -> int:
    env = os.environ
    rc = 3
    try:
        args = _arguments(env)
        # Use this interpreter's installed entry point, not a workspace file
        # named taintly or a different Python installation's PATH entry.
        executable = Path(sysconfig.get_path("scripts")) / (
            "taintly.exe" if os.name == "nt" else "taintly"
        )
        console = subprocess.run(
            [str(executable), *args, "--format", env.get("CICD_AUDIT_FORMAT", "text")],
            check=False,
        ).returncode
        rc = console
        if env.get("CICD_AUDIT_UPLOAD_SARIF", "false") == "true":
            report = Path(env.get("CICD_AUDIT_SARIF_FILE", "taintly.sarif"))
            with report.open("w", encoding="utf-8") as output:
                sarif = subprocess.run(
                    [str(executable), *args, "--format", "sarif"],
                    stdout=output,
                    check=False,
                ).returncode
            if sarif in {0, 1, 2} and not _valid_sarif(report):
                _error("Requested report is not SARIF 2.1.0 JSON with a runs list.")
                sarif = 3
            elif sarif not in {0, 1, 2}:
                _error(f"SARIF generation failed or was incomplete (exit {sarif}).")
            if console in {0, 1, 2}:
                # Either scan can observe findings or incomplete analysis.
                rc = max(console, sarif) if sarif in {0, 1, 2} else sarif
    except (OSError, ValueError) as exc:
        _error(f"Could not run the Action or write its report: {exc}")
        if rc in {0, 1, 2}:
            rc = 3
    try:
        with Path(env["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as output:
            output.write(f"exit-code={rc}\n")
    except (OSError, KeyError) as exc:
        _error(f"Could not write the Action exit-code output: {exc}")
        return 3
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
