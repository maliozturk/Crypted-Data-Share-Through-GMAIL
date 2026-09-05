from __future__ import annotations

import pytest

from crypted_mail.core.archives import (
    KIND_GZIP,
    KIND_ZIP,
    detect_archive_kind,
    validate_archive_file,
)
from crypted_mail.core.exceptions import (
    AttachmentTooLargeError,
    UnsupportedAttachmentTypeError,
)


LIMIT = 18 * 1024 * 1024


def _write(tmp_path, name: str, payload: bytes):
    path = tmp_path / name
    path.write_bytes(payload)
    return path


def test_zip_magic_accepted(tmp_path):
    path = _write(tmp_path, "report.zip", b"PK\x03\x04" + b"\x00" * 100)
    assert detect_archive_kind(path) == KIND_ZIP
    assert validate_archive_file(path, max_bytes=LIMIT) == 104


def test_empty_zip_magic_accepted(tmp_path):
    path = _write(tmp_path, "empty.zip", b"PK\x05\x06" + b"\x00" * 18)
    assert validate_archive_file(path, max_bytes=LIMIT) == 22


def test_gzip_magic_accepted(tmp_path):
    path = _write(tmp_path, "photos.tar.gz", b"\x1f\x8b\x08\x00" + b"\x00" * 50)
    assert detect_archive_kind(path) == KIND_GZIP
    assert validate_archive_file(path, max_bytes=LIMIT) == 54


def test_tgz_extension_accepted(tmp_path):
    path = _write(tmp_path, "photos.tgz", b"\x1f\x8b\x08\x00" + b"\x00" * 10)
    assert validate_archive_file(path, max_bytes=LIMIT) == 14


def test_uppercase_extension_accepted(tmp_path):
    path = _write(tmp_path, "REPORT.ZIP", b"PK\x03\x04" + b"\x00" * 10)
    assert validate_archive_file(path, max_bytes=LIMIT) == 14


def test_pdf_content_rejected(tmp_path):
    path = _write(tmp_path, "notes.pdf", b"%PDF-1.7 and some content")
    with pytest.raises(UnsupportedAttachmentTypeError) as excinfo:
        validate_archive_file(path, max_bytes=LIMIT)
    assert ".zip" in str(excinfo.value)


def test_extension_content_mismatch_rejected(tmp_path):
    path = _write(tmp_path, "report.zip", b"\x1f\x8b\x08\x00" + b"\x00" * 10)
    with pytest.raises(UnsupportedAttachmentTypeError) as excinfo:
        validate_archive_file(path, max_bytes=LIMIT)
    message = str(excinfo.value)
    assert "ZIP extension" in message and "GZIP signature" in message


def test_bare_gz_extension_rejected(tmp_path):
    path = _write(tmp_path, "notes.gz", b"\x1f\x8b\x08\x00" + b"\x00" * 10)
    with pytest.raises(UnsupportedAttachmentTypeError):
        validate_archive_file(path, max_bytes=LIMIT)


def test_spanned_zip_rejected(tmp_path):
    path = _write(tmp_path, "split.zip", b"PK\x07\x08" + b"\x00" * 10)
    with pytest.raises(UnsupportedAttachmentTypeError):
        validate_archive_file(path, max_bytes=LIMIT)


def test_empty_file_rejected(tmp_path):
    path = _write(tmp_path, "report.zip", b"")
    with pytest.raises(UnsupportedAttachmentTypeError) as excinfo:
        validate_archive_file(path, max_bytes=LIMIT)
    assert "empty" in str(excinfo.value)


def test_oversized_file_rejected(tmp_path):
    path = _write(tmp_path, "report.zip", b"PK\x03\x04" + b"\x00" * 5000)
    with pytest.raises(AttachmentTooLargeError):
        validate_archive_file(path, max_bytes=1024)


def test_directory_rejected(tmp_path):
    folder = tmp_path / "archive.zip"
    folder.mkdir()
    with pytest.raises(UnsupportedAttachmentTypeError):
        validate_archive_file(folder, max_bytes=LIMIT)
