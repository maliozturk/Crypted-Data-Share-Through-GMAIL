"""Print the single-sourced application version.

The version lives in exactly one place, ``src/crypted_mail/__init__.py``.
setuptools reads it statically (see ``[tool.setuptools.dynamic]`` in
pyproject.toml), the Inno Setup script receives it via ``/DAppVersion``, and
the PyInstaller spec parses the same literal. Nothing else may hardcode it.

Deliberately dependency-free and it never imports ``crypted_mail`` - it has to
run before the package is installed, and importing it would drag in PySide6.
"""

from __future__ import annotations

import argparse
import pathlib
import re


INIT_FILE = pathlib.Path(__file__).resolve().parents[1] / "src" / "crypted_mail" / "__init__.py"
_VERSION_LITERAL = re.compile(r'^__version__\s*=\s*"([^"]+)"\s*$', re.M)

MAX_VERSION_PART = 65535


def read_version() -> str:
    match = _VERSION_LITERAL.search(INIT_FILE.read_text(encoding="utf-8"))
    if not match:
        raise SystemExit(f"__version__ string literal not found in {INIT_FILE}")
    return match.group(1)


def to_file_version(version: str) -> str:
    """Convert to the four-integer form a Windows VERSIONINFO resource requires."""
    core = re.split(r"[-+]", version, maxsplit=1)[0]
    parts = [part for part in core.split(".") if part.isdigit()][:3]
    while len(parts) < 3:
        parts.append("0")
    for part in parts:
        if int(part) > MAX_VERSION_PART:
            raise SystemExit(f"version component out of range for Windows: {version}")
    return ".".join(parts) + ".0"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--file-version",
        action="store_true",
        help="print the four-part Windows file version instead",
    )
    args = parser.parse_args()
    version = read_version()
    print(to_file_version(version) if args.file_version else version)


if __name__ == "__main__":
    main()
