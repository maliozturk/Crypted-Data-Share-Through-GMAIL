"""Archive type checks for attachment selection.

This is a **usability guardrail, not a security control**. The ``.cmenc`` format
encrypts arbitrary bytes regardless of what is in them; these checks exist so
users do not accidentally attach a 4 GB disk image and so the error message says
something useful.

Deliberately shallow: we read four magic bytes and parse nothing. No
``zipfile.is_zipfile`` (it seeks and parses attacker-controlled structure) and
certainly no ``tarfile.open`` on a ``.tar.gz`` (that decompresses, which is a
zip-bomb vector).
"""

from __future__ import annotations

from pathlib import Path

from crypted_mail.core.exceptions import (
    AttachmentTooLargeError,
    UnsupportedAttachmentTypeError,
)


ARCHIVE_FILTER = "Archives (*.zip *.tar.gz *.tgz);;All Files (*)"

GZIP_MAGIC = b"\x1f\x8b"
# PK\x07\x08 (spanned/split archives) is deliberately absent.
ZIP_MAGICS = (b"PK\x03\x04", b"PK\x05\x06")

KIND_ZIP = "zip"
KIND_GZIP = "gzip"


def expected_kind_from_name(path: Path) -> str:
    """Map a filename to the archive kind it claims to be.

    ``Path("report.tar.gz").suffix`` is ``".gz"``, not ``".tar.gz"``, so this
    tests the lowercased full name instead of the suffix.
    """
    name = Path(path).name.lower()
    if name.endswith(".tar.gz") or name.endswith(".tgz"):
        return KIND_GZIP
    if name.endswith(".zip"):
        return KIND_ZIP
    raise UnsupportedAttachmentTypeError(
        f"{Path(path).name} must be a .zip, .tar.gz, or .tgz file."
    )


def detect_archive_kind(path: Path) -> str:
    """Identify an archive by its leading bytes."""
    path = Path(path)
    try:
        with path.open("rb") as handle:
            head = handle.read(4)
    except OSError as exc:
        raise UnsupportedAttachmentTypeError(f"{path.name} could not be read.") from exc
    if head[:2] == GZIP_MAGIC:
        return KIND_GZIP
    if head[:4] in ZIP_MAGICS:
        return KIND_ZIP
    raise UnsupportedAttachmentTypeError(
        f"{path.name} is not a ZIP or GZIP archive. "
        "Only .zip and .tar.gz files can be attached."
    )


def validate_archive_file(path: Path, *, max_bytes: int) -> int:
    """Check that ``path`` is an attachable archive and return its size."""
    path = Path(path)
    if not path.is_file():
        raise UnsupportedAttachmentTypeError(f"{path.name} is not a file.")

    size = path.stat().st_size
    if size == 0:
        raise UnsupportedAttachmentTypeError(f"{path.name} is empty.")
    if size > max_bytes:
        raise AttachmentTooLargeError(
            f"{path.name} is {_human_size(size)}, which is larger than the "
            f"{_human_size(max_bytes)} limit for a single attachment."
        )

    expected = expected_kind_from_name(path)
    actual = detect_archive_kind(path)
    if expected != actual:
        raise UnsupportedAttachmentTypeError(
            f"{path.name} has a {expected.upper()} extension but its contents start "
            f"with a {actual.upper()} signature. Rename it or pick a different file."
        )
    return size


def _human_size(num_bytes: int) -> str:
    value = float(num_bytes)
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024 or unit == "GB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} GB"
