"""Canonical source strings for the bounded workflow_run artifact tests."""

from __future__ import annotations

import hashlib

CASE_EXEC = "workflow_run_pr_artifact_exec_secret"
CASE_DATA = "workflow_run_pr_json_parse_only"
CASE_UNKNOWN = "workflow_run_unknown_external_producer"
CASE_IDS = (CASE_EXEC, CASE_DATA, CASE_UNKNOWN)

CONSUMERS = {
    "workflow_run_pr_artifact_exec_secret": "name: Privileged Preview Consumer\non:\n  workflow_run:\n    workflows: [PR Preview]\n    types: [completed]\njobs:\n  consume:\n    if: github.event.workflow_run.event == 'pull_request' && github.event.workflow_run.conclusion == 'success'\n    runs-on: ubuntu-latest\n    permissions:\n      actions: read\n    steps:\n      - name: Download exact triggering run artifact\n        uses: actions/download-artifact@v5\n        with:\n          name: pr-preview\n          run-id: ${{ github.event.workflow_run.id }}\n          github-token: ${{ github.token }}\n          repository: ${{ github.repository }}\n          path: incoming\n      - name: Execute downloaded PR-owned script\n        env:\n          PREVIEW_SECRET: ${{ secrets.PREVIEW_SECRET }}\n        run: bash incoming/preview.sh\n",
    "workflow_run_pr_json_parse_only": "name: PR Metadata Reader\non:\n  workflow_run:\n    workflows: [PR Metadata Capture]\n    types: [completed]\njobs:\n  read-metadata:\n    if: github.event.workflow_run.event == 'pull_request' && github.event.workflow_run.conclusion == 'success'\n    runs-on: ubuntu-latest\n    permissions:\n      actions: read\n    steps:\n      - uses: actions/download-artifact@v5\n        with:\n          name: pr-metadata\n          run-id: ${{ github.event.workflow_run.id }}\n          github-token: ${{ github.token }}\n          repository: ${{ github.repository }}\n          path: incoming\n      - name: Parse fixed JSON fields as data\n        run: jq -r '.status, .summary' incoming/preview.json\n",
    "workflow_run_unknown_external_producer": "name: Partner Artifact Consumer\non:\n  workflow_run:\n    workflows: [Partner Build]\n    types: [completed]\njobs:\n  consume:\n    if: github.event.workflow_run.conclusion == 'success'\n    runs-on: ubuntu-latest\n    permissions:\n      actions: read\n    steps:\n      - name: Download prior artifact\n        uses: actions/download-artifact@v5\n        with:\n          name: partner-package\n          run-id: ${{ github.event.workflow_run.id }}\n          github-token: ${{ github.token }}\n          repository: ${{ github.repository }}\n          path: incoming\n      - name: Run prior artifact script\n        env:\n          REGISTRY_TOKEN: ${{ secrets.REGISTRY_TOKEN }}\n        run: bash incoming/package/verify.sh\n",
}
PRODUCER = "name: PR Preview\non:\n  pull_request:\n    types: [opened, synchronize, reopened]\npermissions:\n  contents: read\njobs:\n  capture:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v7\n      - name: Copy the PR-owned hook as data\n        run: |\n          mkdir -p bundle\n          cp .github/scripts/preview.sh bundle/preview.sh\n      - uses: actions/upload-artifact@v7\n        with:\n          name: pr-preview\n          path: bundle/preview.sh\n          if-no-files-found: error\n"

SOURCE_SHA256 = {
    "workflow_run_pr_artifact_exec_secret/consumer.yml": "c9a7687dc11984046028e878e9b2018d03c77448b285087b9ca5a9aed1e1f16c",
    "workflow_run_pr_json_parse_only/consumer.yml": "79bb82b0e51d82b90771f634db20214a018089337c8488ebb215f9d9bb296315",
    "workflow_run_unknown_external_producer/consumer.yml": "bebe3c2e5ee3b94cc20f2dc361417d95e92653c86021feaffb44dcb1165634e7",
    "workflow_run_pr_artifact_exec_secret/producer.yml": "536f80bfe27d791ee1f31e43a252d8774d2b160b3b9a8ea193cea1ecc18ae445",
}


def source_sha256(text: str) -> str:
    """Hash canonical UTF-8 bytes exactly as checked in the source packet."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()
