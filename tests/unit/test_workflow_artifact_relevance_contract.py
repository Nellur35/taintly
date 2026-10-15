from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
from taintly.rules.github._workflow_run_artifact import analyze_corpus
from taintly.workflow_corpus import build_corpus

FIXTURES = Path(__file__).parent / "fixtures" / "workflow_artifact_relevance"

CASES = (
    # filename, expected outcome, expected helper reason or source anchor
    ("safe-rerun-only.yml", "no-target", None),
    ("safe-multi-event-no-artifact.yml", "no-target", None),
    ("dangerous-download-consumer.yml", "candidate", "run: bash incoming/preview.sh"),
    ("dangerous-with-unrelated-sibling.yml", "candidate", "run: bash incoming/preview.sh"),
    ("unknown-download-consumer.yml", "unknown", "unsupported download-artifact action version"),
    (
        "unknown-case-variant-download-consumer.yml",
        "unknown",
        "unsupported download-artifact action version",
    ),
    ("unknown-multi-event-artifact.yml", "unknown", "unsupported event union"),
)

CANONICAL_LF_SHA256 = {
    "dangerous-download-consumer.yml": "6B84ED212368229784964B9C63A4AEC0724040EA0107B4C13024A9BD4A17F812",
    "dangerous-with-unrelated-sibling.yml": "99F7B1493AD8E083EF7A64BD40C4AA9ED1F1F5261A8F3664A028EE91A72E6057",
    "safe-multi-event-no-artifact.yml": "0B870BD7946E872BAB2199D270FFA602EA41A33DBA75956DE5DC48541B636E9D",
    "safe-rerun-only.yml": "C8F267FADC49951B13FEA7665DC1C26553D7A43CE8B60881AB0C08D7B3D0094E",
    "unknown-case-variant-download-consumer.yml": "72DBB57A6D7CB38A12A7A3649414815334E9BC992F7F386E3154B45D0E437A04",
    "unknown-download-consumer.yml": "47A459F15EE211CFAA93CBA70E8A05F7EE15F2DCCB96F2C66FFF7FBA6C4BB86C",
    "unknown-multi-event-artifact.yml": "E01D3A1491D07A89B0241563611AA7DE20BF53F8AE7D721EEE500E15E7409AA2",
}


def _canonicalize_checkout_newlines(source: bytes) -> bytes:
    """Normalize only CRLF pairs; preserve all other source bytes."""
    return source.replace(b"\r\n", b"\n")


@pytest.mark.parametrize(("filename", "outcome", "detail"), CASES)
def test_workflow_run_artifact_relevance_contract(
    tmp_path: Path, filename: str, outcome: str, detail: str | None
) -> None:
    source_bytes = (FIXTURES / filename).read_bytes()
    canonical = _canonicalize_checkout_newlines(source_bytes)
    expected_hash = CANONICAL_LF_SHA256[filename]
    assert hashlib.sha256(canonical).hexdigest().upper() == expected_hash

    # Git checkout EOL conversion is the only accepted byte difference.
    crlf = canonical.replace(b"\n", b"\r\n")
    assert _canonicalize_checkout_newlines(crlf) == canonical
    changed_source = canonical.replace(b"name:", b"Name:", 1)
    assert hashlib.sha256(changed_source).hexdigest().upper() != expected_hash

    source = canonical.decode("utf-8")
    workflow = tmp_path / ".github" / "workflows" / filename
    workflow.parent.mkdir(parents=True, exist_ok=True)
    workflow.write_bytes(canonical)

    result = analyze_corpus(build_corpus(str(tmp_path)))
    matches = [
        finding
        for finding in result.findings
        if finding.title == "Downloaded workflow-run artifact is selected for script execution"
    ]

    if outcome == "no-target":
        assert matches == []
        assert result.incomplete == ()
    elif outcome == "candidate":
        assert isinstance(detail, str)
        assert len(matches) == 1
        expected_line = next(
            number for number, line in enumerate(source.splitlines(), 1) if line.strip() == detail
        )
        assert matches[0].line == expected_line
        assert matches[0].snippet == detail
        assert result.incomplete == ()
    else:
        assert isinstance(detail, str)
        assert matches == []
        assert len(result.incomplete) == 1
        assert detail in result.incomplete[0].reason
