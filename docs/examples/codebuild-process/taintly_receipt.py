"""Emit only the evidence required to correlate a CodeBuild marker request."""

from hashlib import file_digest
from pathlib import Path
import json
import os
import re


def collect(http_response, parsed, **_):
    try:
        request_id = parsed["ResponseMetadata"]["RequestId"]
        if not isinstance(request_id, str) or not re.fullmatch(r"[A-Za-z0-9-]{1,128}", request_id):
            return
        process_executable = Path("/proc/self/exe")
        executable = os.readlink(process_executable)
        cwd = Path.cwd().resolve(strict=True)
        if not executable.startswith("/") or executable.endswith(" (deleted)"):
            return
        if type(http_response.status_code) is not int or http_response.status_code not in (200, 403):
            return
        with process_executable.open("rb") as stream:
            fingerprint = file_digest(stream, "sha256").hexdigest()
            executable_stat = os.fstat(stream.fileno())
        directory_stat = cwd.stat()
        evidence = {
            "operation": "PutObject",
            "request_id": request_id,
            "http_status": http_response.status_code,
            "pid": os.getpid(),
            "executable_path": executable,
            "executable_sha256": fingerprint,
            "executable_identity": [executable_stat.st_dev, executable_stat.st_ino],
            "cwd": str(cwd),
            "cwd_identity": [directory_stat.st_dev, directory_stat.st_ino],
        }
        with Path(__file__).with_name("receipt.json").open("x", encoding="utf8") as record:
            json.dump(evidence, record, ensure_ascii=True, separators=(",", ":"))
            record.write("\n")
    except (OSError, KeyError, TypeError):
        # A missing observation must leave the original AWS response intact.
        return


def awscli_initialize(events):
    events.register("after-call.s3.PutObject", collect)
