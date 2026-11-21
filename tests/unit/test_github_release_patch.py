"""Authored acceptance and contradiction checks for saved Release PATCH comparisons."""

import hashlib
import json

import pytest

from taintly.ingestion.github_release_request import release_request_observation

_YAML = r"""
name: Review release update
on:
  push:
    branches:
      - diagnostics/compare
permissions:
  contents: write
jobs:
  compare:
    runs-on: ubuntu-latest
    env:
      GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
      REPO: ${{ github.repository }}
      PUBLISHED_ID: '42'
      PUBLISHED_TAG: checked
      PUBLISHED_SHA: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
    steps:
      - name: Compare requests
        run: |
          probe() {
            local label="$1"; shift
            local out status msg
            out=$(gh api -i "$@" 2>&1) || true
            status=$(printf '%s\n' "$out" | awk 'toupper($1) ~ /^HTTP\// {print $2; exit}')
            msg=$(printf '%s\n' "$out" | grep -o '"message":"[^"]*"' | head -1)
            printf '%-55s HTTP %s %s\n' "$label" "${status:-???}" "$msg"
          }
          NAME=$(gh api "repos/$REPO/releases/$PUBLISHED_ID" --jq .name)
          echo "== Published release ($PUBLISHED_TAG)"
          probe "1. GET release" "repos/$REPO/releases/$PUBLISHED_ID"
          probe "2. PATCH {} (no fields)" -X PATCH "repos/$REPO/releases/$PUBLISHED_ID" --input - <<< '{}'
          probe "3. PATCH name (unchanged)" -X PATCH "repos/$REPO/releases/$PUBLISHED_ID" -f name="$NAME"
          probe "4. PATCH tag_name (unchanged)" -X PATCH "repos/$REPO/releases/$PUBLISHED_ID" -f tag_name="$PUBLISHED_TAG"
          probe "5. PATCH target_commitish (unchanged)" -X PATCH "repos/$REPO/releases/$PUBLISHED_ID" -f target_commitish="$PUBLISHED_SHA"
""".lstrip()
REPO = "team/project"
PATH = ".github/workflows/release-check.yml"
RUN = f"https://github.com/{REPO}/actions/runs/10"
COMMIT = "a" * 40


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _time(seconds):
    return f"2026-11-21T10:00:{seconds:02d}Z"


@pytest.fixture
def capture(tmp_path):
    source = tmp_path / PATH
    source.parent.mkdir(parents=True)
    source.write_bytes(_YAML.encode())
    values = [
        "##[group]GITHUB_TOKEN Permissions",
        "Contents: write",
        "Metadata: read",
        "##[endgroup]",
        "2. PATCH {} (no fields) HTTP 200",
        "3. PATCH name (unchanged) HTTP 200",
        "4. PATCH tag_name (unchanged) HTTP 200",
        '5. PATCH target_commitish (unchanged) HTTP 403 "message":"Resource not accessible by integration"',
    ]
    rows = []
    for n, value in enumerate(values, 1):
        stamp = _time(n + (5 if n > 4 else 0))
        rows.append(
            {"line": n, "time": stamp, "value": value, "sha256": _sha(f"{stamp} {value}".encode())}
        )
    raw = "".join(f"{r['time']} {r['value']}\n" for r in rows).encode()
    log = tmp_path / "release-patch.log"
    log.write_bytes(raw)
    cap = {
        "schema": "github-release-patch-comparison-v1",
        "repository": REPO,
        "run": {
            "id": 10,
            "html_url": RUN,
            "path": PATH,
            "head_sha": COMMIT,
            "head_branch": "diagnostics/compare",
            "head_repository": REPO,
            "event": "push",
            "run_attempt": 1,
            "conclusion": "success",
            "created_at": _time(0),
            "referenced_workflows": [],
        },
        "job": {
            "id": 20,
            "run_id": 10,
            "run_attempt": 1,
            "head_sha": COMMIT,
            "name": "compare",
            "html_url": RUN + "/job/20",
            "started_at": _time(0),
            "completed_at": _time(20),
            "conclusion": "success",
            "steps": [
                {
                    "number": n,
                    "name": name,
                    "started_at": _time(a),
                    "completed_at": _time(b),
                    "conclusion": "success",
                }
                for n, name, a, b in [
                    (1, "Set up job", 0, 5),
                    (2, "Compare requests", 5, 15),
                    (3, "Complete job", 15, 18),
                ]
            ],
        },
        "source": {"path": PATH, "revision": COMMIT, "sha256": _sha(source.read_bytes())},
        "patch_log": {
            "url": f"https://api.github.com/repos/{REPO}/actions/jobs/20/logs",
            "sha256": _sha(raw),
            "last_source_line": len(_YAML.splitlines()),
            "permissions": rows[:4],
            "bindings": [],
            "responses": rows[4:],
        },
    }

    def evaluate():
        snapshot = tmp_path / "receipt.json"
        snapshot.write_text(json.dumps(cap), encoding="utf-8")
        return release_request_observation(snapshot, tmp_path, REPO, 10, 20)

    return cap, source, log, evaluate


def test_report_binds_denied_target_field_in_successful_job(capture):
    _, _, _, evaluate = capture
    result = evaluate()
    assert result["state"] == "release-patch-comparison-reported"
    assert result["job_conclusion"] == "success"
    assert result["operation"] == {
        "method": "PATCH",
        "url": f"https://api.github.com/repos/{REPO}/releases/42",
    }
    assert [row["field"] for row in result["requests"]] == [
        None,
        "name",
        "tag_name",
        "target_commitish",
    ]
    assert [row["status"] for row in result["requests"]] == [200, 200, 200, 403]
    assert result["requests"][-1]["target_commitish"] == "b" * 40
    assert "publication" not in result


@pytest.mark.parametrize(
    "contrast",
    [
        "job",
        "attempt",
        "step",
        "grant",
        "missing-log",
        "raw-log",
        "borrowed-response",
        "shell-prefix",
        "token-source",
        "mixed-profile",
    ],
)
def test_patch_comparison_rejects_contradictory_or_incomplete_evidence(capture, contrast):
    cap, source, log, evaluate = capture
    if contrast == "job":
        cap["patch_log"]["url"] = cap["patch_log"]["url"].replace("jobs/20", "jobs/21")
    elif contrast == "attempt":
        cap["job"]["run_attempt"] = 2
    elif contrast == "step":
        cap["job"]["steps"][1]["started_at"] = _time(11)
    elif contrast == "grant":
        cap["patch_log"]["permissions"][1]["value"] = "Contents: read"
    elif contrast == "missing-log":
        log.unlink()
    elif contrast == "raw-log":
        log.write_bytes(log.read_bytes() + b"unattributed response\n")
    elif contrast == "borrowed-response":
        row = cap["patch_log"]["responses"][-1]
        row["line"] -= 1
    elif contrast == "mixed-profile":
        cap["creation"] = {}
    else:
        old = "          NAME=" if contrast == "shell-prefix" else "secrets.GITHUB_TOKEN"
        new = (
            "          unset GH_TOKEN\n          NAME="
            if contrast == "shell-prefix"
            else "secrets.OTHER_TOKEN"
        )
        content = _YAML.replace(old, new, 1).encode()
        source.write_bytes(content)
        cap["source"]["sha256"] = _sha(content)
        cap["patch_log"]["last_source_line"] = len(content.splitlines())
    result = evaluate()
    assert result["state"] == "unresolved"
    assert "requests" not in result
