"""Action invocation contracts; scanner accuracy is evaluated separately."""

import json
import os
from pathlib import Path
import re
import shutil
import subprocess
from types import SimpleNamespace

import pytest

from taintly import _action
from taintly.parsers.structural import EventKind, walk_workflow

ROOT = Path(__file__).resolve().parents[2]


def manifest():
    path = ROOT / "action.yml"
    return {
        e.path: e.value
        for e in walk_workflow(str(path), content=path.read_text(encoding="utf8"))
        if e.kind is EventKind.LEAF_SCALAR
    }


def test_manifest_pins_existing_ref_shapes_and_wires_data_separately():
    values = manifest()
    assert re.fullmatch(r"[a-f0-9]{40}", values[("inputs", "version", "default")])
    assert values[("runs", "steps", 0, "uses")] == (
        "actions/setup-python@0b93645e9fea7318ecaed2b359559ac225c90a2b"
    )
    assert values[("runs", "steps", 1, "env", "CICD_AUDIT_VERSION")] == "${{ inputs.version }}"
    assert "${{ inputs.version }}" not in values[("runs", "steps", 1, "run")]
    assert values[("runs", "steps", 2, "run")] == 'python "$GITHUB_ACTION_PATH/taintly/_action.py"'
    # Ref existence is checked against upstream in acceptance, not inferred
    # from a40-character shape. These checks protect the reviewed local wiring.


def test_extra_arguments_are_quoted_data_without_filesystem_globbing():
    result = _action._arguments({
        "CICD_AUDIT_PATH": "repo with spaces",
        "CICD_AUDIT_EXCLUDE_RULES": "SEC1-GH-001, SEC2-GH-001\nSEC3-GH-001\r\n\n",
        "CICD_AUDIT_EXTRA_ARGS": '--exclude "directory with spaces/**" --score',
        "CICD_AUDIT_CONFIG": "policy with spaces.yml",
        "CICD_AUDIT_BASELINE": "true",
        "CICD_AUDIT_BASELINE_FILE": "baseline with spaces.json",
    })
    assert result[0] == "repo with spaces"
    assert result.count("--exclude-rule") == 3
    assert [result[i + 1] for i, value in enumerate(result) if value == "--exclude-rule"] == [
        "SEC1-GH-001", "SEC2-GH-001", "SEC3-GH-001"
    ]
    assert result[-3:] == ["--exclude", "directory with spaces/**", "--score"]
    assert result[result.index("--diff") + 1] == "baseline with spaces.json"
    assert result[result.index("--config") + 1] == "policy with spaces.yml"


def configure(monkeypatch, tmp_path, *, sarif=False):
    for key in list(os.environ):
        if key.startswith("CICD_AUDIT_"):
            monkeypatch.delenv(key)
    output = tmp_path / "outputs.txt"
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))
    monkeypatch.setenv("CICD_AUDIT_PATH", "repo with spaces")
    monkeypatch.setenv("CICD_AUDIT_UPLOAD_SARIF", "true" if sarif else "false")
    monkeypatch.setenv("CICD_AUDIT_SARIF_FILE", str(tmp_path / "report with spaces.sarif"))
    return output


@pytest.mark.parametrize("console,sarif,expected", [
    (0, 0, 0), (1, 0, 1), (2, 0, 2), (0, 2, 2),
    (0, 11, 11), (2, 11, 11), (0, 3, 3), (11, 0, 11), (3, 2, 3),
])
def test_requested_report_and_console_failure_statuses_are_preserved(monkeypatch, tmp_path, console, sarif, expected):
    output = configure(monkeypatch, tmp_path, sarif=True)
    calls = []
    statuses = iter([console, sarif])

    def run(argv, **kwargs):
        calls.append(argv)
        if "stdout" in kwargs:
            json.dump({"version": "2.1.0", "runs": []}, kwargs["stdout"])
        return SimpleNamespace(returncode=next(statuses))

    monkeypatch.setattr(_action.subprocess, "run", run)
    assert _action.main() == expected
    assert output.read_text() == f"exit-code={expected}\n"
    assert calls[0][1] == "repo with spaces"
    assert Path(calls[0][0]).is_absolute()
    assert calls[0][-2:] == ["--format", "text"]
    assert calls[1][-2:] == ["--format", "sarif"]
    report = tmp_path / "report with spaces.sarif"
    if sarif == 3:
        assert not report.exists()
    else:
        assert json.loads(report.read_text())["version"] == "2.1.0"


@pytest.mark.parametrize("code", [0, 1, 2, 3, 11])
def test_plain_scan_keeps_actual_exit_code(monkeypatch, tmp_path, code):
    output = configure(monkeypatch, tmp_path)
    monkeypatch.setattr(_action.subprocess, "run", lambda *a, **k: SimpleNamespace(returncode=code))
    assert _action.main() == code
    assert output.read_text() == f"exit-code={code}\n"


def test_invalid_argument_quoting_fails_before_launch(monkeypatch, tmp_path):
    output = configure(monkeypatch, tmp_path)
    monkeypatch.setenv("CICD_AUDIT_EXTRA_ARGS", '--exclude "not closed')
    monkeypatch.setattr(_action.subprocess, "run", lambda *a, **k: pytest.fail("invalid arguments launched"))
    assert _action.main() == 3
    assert output.read_text() == "exit-code=3\n"


def test_report_io_failure_is_not_a_success(monkeypatch, tmp_path):
    output = configure(monkeypatch, tmp_path, sarif=True)
    monkeypatch.setenv("CICD_AUDIT_SARIF_FILE", str(tmp_path / "missing" / "report.sarif"))
    monkeypatch.setattr(_action.subprocess, "run", lambda *a, **k: SimpleNamespace(returncode=0))
    assert _action.main() == 3
    assert output.read_text() == "exit-code=3\n"


@pytest.mark.parametrize("payload", ["usage: taintly ...", "", "[]", '{"version":"1.0","runs":[]}', '{"version":"2.1.0","runs":{}}'])
def test_successful_process_without_requested_report_is_not_success(monkeypatch, tmp_path, payload):
    output = configure(monkeypatch, tmp_path, sarif=True)

    def run(*args, **kwargs):
        if "stdout" in kwargs:
            kwargs["stdout"].write(payload)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(_action.subprocess, "run", run)
    assert _action.main() == 3
    assert output.read_text() == "exit-code=3\n"


def test_report_io_error_does_not_erase_primary_incomplete_code(monkeypatch, tmp_path):
    output = configure(monkeypatch, tmp_path, sarif=True)
    monkeypatch.setenv("CICD_AUDIT_SARIF_FILE", str(tmp_path / "missing" / "report.sarif"))
    monkeypatch.setattr(_action.subprocess, "run", lambda *a, **k: SimpleNamespace(returncode=11))
    assert _action.main() == 11
    assert output.read_text() == "exit-code=11\n"


def test_missing_cli_and_output_file_fail_visibly(monkeypatch, tmp_path):
    configure(monkeypatch, tmp_path)
    monkeypatch.setattr(_action.subprocess, "run", lambda *a, **k: (_ for _ in ()).throw(FileNotFoundError("scanner")))
    assert _action.main() == 3
    monkeypatch.delenv("GITHUB_OUTPUT")
    assert _action.main() == 3


def test_workflow_error_labels_cannot_inject_new_commands(capsys):
    _action._error("path%\r\n::notice::forged")
    assert capsys.readouterr().err == "::error::path%25%0D%0A::notice::forged\n"


def test_actual_install_shell_treats_version_as_one_data_argument(tmp_path):
    candidates = [Path("C:/Program Files/Git/bin/bash.exe")]
    if found := shutil.which("bash"):
        candidates.append(Path(found))
    bash = next((str(p) for p in candidates if p.is_file()), None)
    if bash is None:
        pytest.skip("Bash is required by the composite Action")
    capture = tmp_path / "argv.bin"
    env = os.environ.copy()
    version = 'ref$(printf harmless); untouched'
    env.update(CICD_AUDIT_VERSION=version, CAPTURE_ARGS=str(capture))
    prelude = 'python() { printf "%s\\0" "$@" > "$CAPTURE_ARGS"; };\n'
    result = subprocess.run([bash, "-c", prelude + manifest()[("runs", "steps", 1, "run")]], env=env, capture_output=True)
    assert result.returncode == 0, result.stderr
    assert capture.read_bytes().decode().split("\0")[:-1] == [
        "-m", "pip", "install", "git+https://github.com/Nellur35/taintly@" + version
    ]


@pytest.mark.parametrize("failure", ["invalid-output", "subprocess-io", "fatal-exit", "replace"])
def test_failed_sarif_publication_preserves_existing_report(monkeypatch, tmp_path, failure):
    output = configure(monkeypatch, tmp_path, sarif=True)
    report = tmp_path / "report with spaces.sarif"
    original = b'{"version":"2.1.0","runs":[]}'
    report.write_bytes(original)

    def run(*args, **kwargs):
        if "stdout" not in kwargs:
            return SimpleNamespace(returncode=0)
        if failure == "invalid-output":
            kwargs["stdout"].write("{")
        elif failure == "subprocess-io":
            kwargs["stdout"].write("{")
            raise OSError("injected scanner I/O failure")
        else:
            kwargs["stdout"].write('{"version":"2.1.0","runs":[{}]}')
        return SimpleNamespace(returncode=3 if failure == "fatal-exit" else 0)

    if failure == "replace":
        def fail_replace(*args):
            raise OSError("injected replacement failure")
        monkeypatch.setattr(os, "replace", fail_replace)
    monkeypatch.setattr(_action.subprocess, "run", run)
    assert _action.main() == 3
    assert output.read_text() == "exit-code=3\n"
    assert report.read_bytes() == original
    assert not list(tmp_path.glob(".taintly-*.tmp"))
