from __future__ import annotations

import json
from pathlib import Path

from crypted_mail.core.envelope import build_email_body
from crypted_mail.services.mail_service import MailService


def test_recipient_import_export_round_trip(key_service):
    key_service.create_profile("Alice", "alice@example.com", "passphrase")
    exported = key_service.export_public_key()
    recipient = key_service.import_recipient(exported)

    assert recipient.email == "alice@example.com"
    assert recipient.key_id
    assert recipient.fingerprint


def test_token_cache_file_fallback(repository):
    token_json = json.dumps({"token": "abc", "refresh_token": "xyz"})
    repository.token_store.save("alice@example.com", token_json)
    loaded = repository.token_store.load("alice@example.com")
    assert loaded is not None


def test_remembered_passphrase_uses_secure_store(monkeypatch, repository):
    captured = {}

    monkeypatch.setattr(repository.secure_value_store, "save", lambda key, value: captured.update({key: value}))
    monkeypatch.setattr(repository.secure_value_store, "load", lambda key: captured.get(key))

    repository.save_default_passphrase("alice@example.com", "remember me")
    loaded = repository.load_default_passphrase("alice@example.com")

    assert loaded == "remember me"
    assert "default-passphrase::alice@example.com" in captured


def test_mail_send_path_uses_gmail_api(monkeypatch, repository):
    service = MailService(repository)
    repository.token_store.save(
        "alice@example.com",
        json.dumps(
            {
                "token": "tok",
                "refresh_token": "refresh",
                "token_uri": "https://oauth2.googleapis.com/token",
                "client_id": "client-id",
                "client_secret": "client-secret",
                "scopes": ["https://www.googleapis.com/auth/gmail.send"],
            }
        ),
    )

    class FakeCredentials:
        valid = True
        expired = False
        refresh_token = "refresh"

    class FakeSend:
        def execute(self):
            return {"id": "gmail-message-123"}

    class FakeMessages:
        def send(self, userId, body):
            assert userId == "me"
            assert "raw" in body
            return FakeSend()

    class FakeUsers:
        def messages(self):
            return FakeMessages()

    class FakeService:
        def users(self):
            return FakeUsers()

    monkeypatch.setattr("crypted_mail.services.mail_service.Credentials.from_authorized_user_info", lambda data, scopes: FakeCredentials())
    monkeypatch.setattr("crypted_mail.services.mail_service.build", lambda *args, **kwargs: FakeService())

    message_id = service.send_encrypted_email("alice@example.com", "bob@example.com", "Subject", build_email_body("payload"))
    assert message_id == "gmail-message-123"


def test_packaging_assets_exist():
    root = Path(__file__).resolve().parents[1]
    assert (root / "scripts" / "build_windows.ps1").exists()
    assert (root / "scripts" / "build_installer.ps1").exists()
    assert (root / "installer" / "crypted_mail.iss").exists()


def test_mail_send_with_attachment_uses_media_upload(monkeypatch, repository, mail_service, tmp_path):
    """Attachments must go through the resumable media path, not {"raw": ...}."""
    captured = {}

    class FakeSend:
        def execute(self):
            return {"id": "gmail-message-456"}

    class FakeMessages:
        def send(self, userId, body, media_body=None):
            captured["userId"] = userId
            captured["body"] = body
            captured["media_body"] = media_body
            return FakeSend()

    class FakeUsers:
        def messages(self):
            return FakeMessages()

    class FakeService:
        def users(self):
            return FakeUsers()

    class FakeCredentials:
        valid = True
        expired = False
        refresh_token = "refresh"

        def to_json(self):
            return "{}"

    repository.token_store.save("alice@example.com", '{"token": "abc"}')
    monkeypatch.setattr(
        "crypted_mail.services.mail_service.Credentials.from_authorized_user_info",
        lambda data, scopes: FakeCredentials(),
    )
    monkeypatch.setattr(
        "crypted_mail.services.mail_service.build", lambda *args, **kwargs: FakeService()
    )

    attachment = tmp_path / "report.zip.cmenc"
    attachment.write_bytes(b"encrypted-bytes")

    message_id = mail_service.send_encrypted_email(
        sender="alice@example.com",
        recipient_email="bob@example.com",
        subject="Secret",
        armored_payload="cm1:body",
        attachments=[attachment],
    )

    assert message_id == "gmail-message-456"
    assert captured["body"] == {}
    assert captured["media_body"] is not None


def test_oversized_message_is_rejected_before_upload(mail_service):
    from crypted_mail.core.exceptions import AttachmentTooLargeError
    import pytest as _pytest

    with _pytest.raises(AttachmentTooLargeError):
        mail_service._ensure_within_gmail_limit(26 * 1024 * 1024)


def test_packaging_assets_exist_including_version_script():
    root = Path(__file__).resolve().parents[1]
    assert (root / "scripts" / "build_windows.ps1").exists()
    assert (root / "scripts" / "build_installer.ps1").exists()
    assert (root / "scripts" / "get_version.py").exists()
    assert (root / "installer" / "crypted_mail.iss").exists()


def test_version_is_single_sourced():
    import re as _re

    root = Path(__file__).resolve().parents[1]
    pyproject = (root / "pyproject.toml").read_text(encoding="utf-8")
    assert 'dynamic = ["version"]' in pyproject
    assert 'version = {attr = "crypted_mail.__version__"}' in pyproject

    iss = (root / "installer" / "crypted_mail.iss").read_text(encoding="utf-8")
    assert "AppVersion={#AppVersion}" in iss
    assert "VersionInfoVersion={#AppFileVersion}" in iss
    assert "OutputBaseFilename=CryptedMail-Setup-{#AppVersion}" in iss
    # No hardcoded version anywhere in the installer script.
    assert not _re.search(r"^\s*AppVersion\s*=\s*\d", iss, _re.M)


def test_version_matches_file_version_rules():
    """A non X.Y.Z version would make parse_version reject every release,
    silently cutting every client off from updates forever."""
    import re as _re

    from crypted_mail import __version__
    from crypted_mail.services.update_service import parse_version

    assert _re.match(r"^\d+\.\d+\.\d+$", __version__)
    assert parse_version(__version__) is not None


def test_installer_has_update_safety_directives():
    root = Path(__file__).resolve().parents[1]
    iss = (root / "installer" / "crypted_mail.iss").read_text(encoding="utf-8")
    assert "PrivilegesRequired=lowest" in iss
    assert "CloseApplications=yes" in iss
    assert "SetupMutex=" in iss
    # AppMutex is deliberately absent: with /VERYSILENT /SUPPRESSMSGBOXES its
    # prompt is suppressed and the default answer aborts the install.
    assert "AppMutex=" not in iss
    assert "{param:relaunch|0}" in iss
    assert "AppId={{" in iss


def test_spec_declares_a_version_resource():
    root = Path(__file__).resolve().parents[1]
    spec = (root / "crypted_mail.spec").read_text(encoding="utf-8")
    assert "VSVersionInfo" in spec
    assert "version=version_info," in spec
