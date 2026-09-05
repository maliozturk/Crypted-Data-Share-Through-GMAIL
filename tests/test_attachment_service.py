from __future__ import annotations

import hashlib

import pytest

from crypted_mail.core.exceptions import AttachmentTooLargeError, UnsupportedAttachmentTypeError
from crypted_mail.services.attachment_service import AttachmentService


PASSPHRASE = "shared secret"


@pytest.fixture()
def service() -> AttachmentService:
    return AttachmentService()


def _zip(tmp_path, name: str, size: int = 2048):
    path = tmp_path / name
    path.write_bytes(b"PK\x03\x04" + b"\x5a" * (size - 4))
    return path


def test_prepare_writes_cmenc_files_and_cleans_up(service, tmp_path):
    source = _zip(tmp_path, "report.zip")
    workspace, prepared = service.prepare([source], PASSPHRASE, sender_hint="alice@example.com")

    assert len(prepared) == 1
    item = prepared[0]
    assert item.encrypted_name == "report.zip.cmenc"
    assert item.encrypted_path.exists()
    assert item.plaintext_size == 2048
    assert item.plaintext_sha256 == hashlib.sha256(source.read_bytes()).hexdigest()
    assert item.encrypted_path.parent == workspace

    service.discard(workspace)
    assert not workspace.exists()


def test_prepare_round_trips_through_recover(service, tmp_path):
    source = _zip(tmp_path, "photos.tar.gz")
    source.write_bytes(b"\x1f\x8b\x08\x00" + b"\x11" * 5000)

    workspace, prepared = service.prepare([source], PASSPHRASE)
    try:
        recovered = tmp_path / "out" / "photos.tar.gz"
        header = service.recover(prepared[0].encrypted_path, recovered, PASSPHRASE)
        assert recovered.read_bytes() == source.read_bytes()
        assert header.filename == "photos.tar.gz"
    finally:
        service.discard(workspace)


def test_prepare_enforces_total_size_limit(service, tmp_path, monkeypatch):
    monkeypatch.setattr(service, "max_total_bytes", 1024, raising=False)
    source = _zip(tmp_path, "report.zip", size=4096)
    with pytest.raises(AttachmentTooLargeError):
        service.prepare([source], PASSPHRASE)


def test_prepare_rejects_unsupported_type(service, tmp_path):
    bad = tmp_path / "notes.pdf"
    bad.write_bytes(b"%PDF-1.7 nope")
    with pytest.raises(UnsupportedAttachmentTypeError):
        service.prepare([bad], PASSPHRASE)


def test_prepare_removes_workspace_when_a_later_file_fails(service, tmp_path, monkeypatch):
    good = _zip(tmp_path, "one.zip")
    original = service.prepare

    def boom(*args, **kwargs):
        raise OSError("disk gone")

    monkeypatch.setattr(
        "crypted_mail.services.attachment_service.encrypt_file_with_passphrase", boom
    )
    with pytest.raises(OSError):
        original([good], PASSPHRASE)
    assert not list(tmp_path.glob("crypted-mail-*"))


def test_check_total_size_sums_sources(service, tmp_path):
    first = _zip(tmp_path, "a.zip", size=1000)
    second = _zip(tmp_path, "b.zip", size=2000)
    assert service.check_total_size([first, second]) == 3000


def test_describe_manifest_lists_names_and_hashes(service, tmp_path):
    source = _zip(tmp_path, "report.zip")
    workspace, prepared = service.prepare([source], PASSPHRASE)
    try:
        manifest = service.describe_manifest(prepared)
        assert "Crypted Mail attachments" in manifest
        assert "report.zip" in manifest
        assert prepared[0].plaintext_sha256 in manifest
    finally:
        service.discard(workspace)


def test_describe_manifest_is_empty_without_attachments(service):
    assert service.describe_manifest([]) == ""


def test_progress_reports_across_multiple_files(service, tmp_path):
    first = _zip(tmp_path, "a.zip", size=8192)
    second = _zip(tmp_path, "b.zip", size=8192)
    seen: list[tuple[int, int, str]] = []
    workspace, _ = service.prepare(
        [first, second], PASSPHRASE, on_progress=lambda d, t, n: seen.append((d, t, n))
    )
    try:
        assert seen
        assert all(total == 16384 for _, total, _ in seen)
        assert [done for done, _, _ in seen] == sorted(done for done, _, _ in seen)
        assert {name for _, _, name in seen} == {"a.zip", "b.zip"}
    finally:
        service.discard(workspace)
