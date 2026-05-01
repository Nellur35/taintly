"""Tests for the pre-merge hygiene script."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent.parent
SCRIPT = ROOT / "scripts" / "check_premerge_hygiene.py"


def _load_hygiene_module():
    spec = importlib.util.spec_from_file_location("check_premerge_hygiene", SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_author_identity_clean_metadata_passes(monkeypatch):
    hygiene = _load_hygiene_module()

    monkeypatch.setattr(
        hygiene,
        "_commit_identities",
        lambda base: (
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\t"
            "Asaf Yashayev\tasaf@example.com\t"
            "Asaf Yashayev\tasaf@example.com\n"
        ),
    )

    assert hygiene._scan_author_identities("origin/main") == []


def test_author_identity_flags_ai_author(monkeypatch):
    hygiene = _load_hygiene_module()

    monkeypatch.setattr(
        hygiene,
        "_commit_identities",
        lambda base: (
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\t"
            "Claude Bot\tclaude@anthropic.com\t"
            "Asaf Yashayev\tasaf@example.com\n"
        ),
    )

    hits = hygiene._scan_author_identities("origin/main")

    assert len(hits) == 1
    assert hits[0].source == "commit bbbbbbbb author identity"
    assert hits[0].line == "Claude Bot <claude@anthropic.com>"


def test_author_identity_flags_ai_committer(monkeypatch):
    hygiene = _load_hygiene_module()

    monkeypatch.setattr(
        hygiene,
        "_commit_identities",
        lambda base: (
            "cccccccccccccccccccccccccccccccccccccccc\t"
            "Asaf Yashayev\tasaf@example.com\t"
            "Copilot\tbot@users.noreply.github.com\n"
        ),
    )

    hits = hygiene._scan_author_identities("origin/main")

    assert len(hits) == 1
    assert hits[0].source == "commit cccccccc committer identity"
    assert hits[0].line == "Copilot <bot@users.noreply.github.com>"


def test_path_allowlist_does_not_skip_author_identity(monkeypatch, capsys):
    hygiene = _load_hygiene_module()

    monkeypatch.setattr(sys, "argv", ["check_premerge_hygiene.py"])
    monkeypatch.setattr(hygiene, "_changed_files", lambda base: ["docs/AI_TRIAGE.md"])
    monkeypatch.setattr(hygiene, "_diff_for_file", lambda base, path: "")
    monkeypatch.setattr(hygiene, "_commit_messages", lambda base: "")
    monkeypatch.setattr(
        hygiene,
        "_commit_identities",
        lambda base: (
            "dddddddddddddddddddddddddddddddddddddddd\t"
            "Asaf Yashayev\tasaf@example.com\t"
            "OpenAI Committer\tcommitter@openai.com\n"
        ),
    )

    assert hygiene.main() == 1

    out = capsys.readouterr().out
    assert "commit dddddddd committer identity" in out
    assert "OpenAI Committer <committer@openai.com>" in out
