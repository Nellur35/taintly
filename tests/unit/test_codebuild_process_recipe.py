"""Keep the documented CodeBuild probe byte-identical to the admitted profile."""

from base64 import b64decode
from hashlib import sha256
from pathlib import Path
import re

from taintly.ingestion.codebuild_put import _OPERATOR_PLAN_SHA256


def test_reviewed_process_recipe_matches_scanner_and_readable_collector():
    examples = Path(__file__).resolve().parents[2] / "docs" / "examples" / "codebuild-process"
    plan = (examples / "probe.buildspec.yml").read_bytes()
    collector = (examples / "taintly_receipt.py").read_bytes()

    assert sha256(plan).hexdigest() == _OPERATOR_PLAN_SHA256
    payloads = re.findall(
        rb"^        printf '%s' '([A-Za-z0-9+/=]+)' \| /usr/bin/base64 -d > taintly_receipt\.py$",
        plan,
        re.M,
    )
    assert len(payloads) == 1
    embedded = b64decode(payloads[0], validate=True)
    assert embedded.replace(b"\r\n", b"\n") == collector
    assert sha256(embedded).hexdigest().encode("ascii") in plan
