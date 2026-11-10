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

if __package__:
    from ._file_commit import staged_text
else:
    # action.yml executes this pinned launcher by filename. Load only its
    # adjacent stdlib helper, without importing a workspace-owned taintly package.
    import importlib.util

    helper_name = "_taintly_action_file_commit"
    helper_spec = importlib.util.spec_from_file_location(
        helper_name, Path(__file__).with_name("_file_commit.py")
    )
    if helper_spec is None or helper_spec.loader is None:
        raise ImportError("Action file-commit helper is unavailable")
    helper = importlib.util.module_from_spec(helper_spec)
    sys.modules[helper_name] = helper
    helper_spec.loader.exec_module(helper)
    staged_text = helper.staged_text


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


def _require_sarif(path: Path, status: int) -> None:
    if status not in {0, 1, 2, 11}:
        raise ValueError(f"SARIF generation failed (exit {status}).")
    if not _valid_sarif(path):
        raise ValueError("Requested report is not SARIF 2.1.0 JSON with a runs list.")


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
        # Absolute interpreter-owned executable; caller argv is data, no shell.
        console = subprocess.run(  # nosec B603
            [str(executable), *args, "--format", env.get("CICD_AUDIT_FORMAT", "text")],
            check=False,
        ).returncode
        rc = console
        if env.get("CICD_AUDIT_UPLOAD_SARIF", "false") == "true":
            report = Path(env.get("CICD_AUDIT_SARIF_FILE", "taintly.sarif"))
            with staged_text(report) as (output, temporary_report):
                # Same installed executable and argv-only boundary as above.
                sarif = subprocess.run(  # nosec B603
                    [str(executable), *args, "--format", "sarif"],
                    stdout=output,
                    check=False,
                ).returncode
                if console in {0, 1, 2}:
                    # Keep the scanner's failure or incomplete status even when
                    # it could not also produce a valid partial report.
                    rc = max(console, sarif) if sarif in {0, 1, 2} else sarif
                output.flush()
                _require_sarif(temporary_report, sarif)
            if sarif == 11:
                _error("SARIF generation was incomplete (exit 11).")
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
