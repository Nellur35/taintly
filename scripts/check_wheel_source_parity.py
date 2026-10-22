"""Reject a wheel whose shipped Taintly files differ from the current source.

Use after building a wheel, especially from a checkout with a preexisting
``build/lib`` directory. This check does not build, install, or clean files.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import zipfile
from email.parser import Parser
from pathlib import Path


def check_wheel(source_root: Path, wheel_path: Path) -> list[str]:
    errors: list[str] = []
    try:
        tracked = subprocess.check_output(
            ["git", "ls-files", "-z", "--", "taintly"], cwd=source_root
        ).decode("utf-8")
    except (OSError, subprocess.CalledProcessError, UnicodeDecodeError) as exc:
        return [f"Cannot list tracked Taintly source: {exc}"]

    source_names = set(filter(None, tracked.split("\0")))
    if not source_names:
        return ["No tracked Taintly source files found"]
    for name in sorted(source_names):
        if not (source_root / name).is_file():
            errors.append(f"Tracked source file is absent: {name}")

    try:
        with zipfile.ZipFile(wheel_path) as archive:
            member_names = [
                info.filename
                for info in archive.infolist()
                if info.filename.startswith("taintly/") and not info.is_dir()
            ]
            wheel_names = set(member_names)
            for name in sorted(wheel_names - source_names):
                errors.append(f"Wheel contains untracked Taintly file: {name}")
            for name in sorted(source_names - wheel_names):
                errors.append(f"Wheel omits tracked Taintly file: {name}")
            if len(wheel_names) != len(member_names):
                errors.append("Wheel contains duplicate Taintly member names")
            for name in sorted(wheel_names & source_names):
                source_file = source_root / name
                if source_file.is_file() and archive.read(name) != source_file.read_bytes():
                    errors.append(f"Wheel bytes differ from source: {name}")

            metadata_names = [
                name for name in archive.namelist() if name.endswith(".dist-info/METADATA")
            ]
            if len(metadata_names) != 1:
                errors.append("Wheel must contain exactly one package METADATA file")
            else:
                metadata = Parser().parsestr(archive.read(metadata_names[0]).decode("utf-8"))
                for requirement in metadata.get_all("Requires-Dist", []):
                    if "extra ==" not in requirement:
                        errors.append(f"Wheel declares a mandatory dependency: {requirement}")
    except (OSError, zipfile.BadZipFile, UnicodeDecodeError) as exc:
        errors.append(f"Cannot read wheel: {exc}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("wheel", type=Path)
    parser.add_argument("--source-root", type=Path, default=Path(__file__).resolve().parent.parent)
    args = parser.parse_args()
    errors = check_wheel(args.source_root.resolve(), args.wheel.resolve())
    for error in errors:
        print(error, file=sys.stderr)
    if errors:
        return 1
    print("Wheel matches tracked Taintly source bytes and has no mandatory dependencies")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
