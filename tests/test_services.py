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
