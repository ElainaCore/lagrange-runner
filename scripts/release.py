"""Bump the runner version using SemVer patch carry rules."""

from __future__ import annotations

import argparse
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERSION_FILE = ROOT / "VERSION"
VERSION_RE = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")


def read_version() -> tuple[int, int, int]:
    value = VERSION_FILE.read_text(encoding="utf-8").strip()
    match = VERSION_RE.fullmatch(value)
    if not match:
        raise SystemExit(f"invalid VERSION: {value!r}")
    return tuple(int(part) for part in match.groups())  # type: ignore[return-value]


def bump_patch(version: tuple[int, int, int]) -> tuple[int, int, int]:
    major, minor, patch = version
    patch += 1
    if patch >= 10:
        patch = 0
        minor += 1
    if minor >= 10:
        minor = 0
        major += 1
    return major, minor, patch


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bump", action="store_true", help="increment VERSION and print it")
    args = parser.parse_args()
    version = bump_patch(read_version()) if args.bump else read_version()
    if args.bump:
        VERSION_FILE.write_text("%d.%d.%d\n" % version, encoding="utf-8")
    print("%d.%d.%d" % version)


if __name__ == "__main__":
    main()
