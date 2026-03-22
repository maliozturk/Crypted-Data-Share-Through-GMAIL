from __future__ import annotations

import json

import pytest
from google.oauth2.credentials import Credentials

from crypted_mail import CryptedMailClient
from crypted_mail.core.exceptions import GmailConfigurationError
from crypted_mail.services.mail_service import MailService


def build_credentials() -> Credentials:
    return Credentials(
        token="tok",
        refresh_token="refresh",
        token_uri="https://oauth2.googleapis.com/token",
        client_id="client-id",
        client_secret="client-secret",
        scopes=MailService.scopes(),
    )


def test_mail_send_path_uses_gmail_api(monkeypatch):
    service = MailService()
    credentials = build_credentials()

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

    monkeypatch.setattr("crypted_mail.services.mail_service.build", lambda *args, **kwargs: FakeService())

    message_id = service.send_encrypted_email(
        sender="alice@example.com",
        recipient_email="bob@example.com",
        subject="Subject",
        armored_payload="cm1:payload",
        credentials=credentials,
    )
    assert message_id == "gmail-message-123"


def test_expired_credentials_refresh_before_send(monkeypatch):
    service = MailService()
    credentials = build_credentials()
    monkeypatch.setattr(type(credentials), "valid", property(lambda self: False))
    monkeypatch.setattr(type(credentials), "expired", property(lambda self: True))
    refreshed = {"called": False}

    def fake_refresh(request):
        refreshed["called"] = True

    class FakeSend:
        def execute(self):
            return {"id": "gmail-message-123"}

    class FakeMessages:
        def send(self, userId, body):
            return FakeSend()

    class FakeUsers:
        def messages(self):
            return FakeMessages()

    class FakeService:
        def users(self):
            return FakeUsers()

    monkeypatch.setattr(credentials, "refresh", fake_refresh)
    monkeypatch.setattr("crypted_mail.services.mail_service.build", lambda *args, **kwargs: FakeService())

    message_id = service.send_encrypted_email(
        sender="alice@example.com",
        recipient_email="bob@example.com",
        subject="Subject",
        armored_payload="cm1:payload",
        credentials=credentials,
    )

    assert refreshed["called"] is True
    assert message_id == "gmail-message-123"


def test_invalid_credentials_raise(monkeypatch):
    service = MailService()
    credentials = build_credentials()
    monkeypatch.setattr(type(credentials), "valid", property(lambda self: False))
    monkeypatch.setattr(type(credentials), "expired", property(lambda self: False))

    with pytest.raises(GmailConfigurationError):
        service.send_encrypted_email(
            sender="alice@example.com",
            recipient_email="bob@example.com",
            subject="Subject",
            armored_payload="cm1:payload",
            credentials=credentials,
        )


def test_client_serializes_and_deserializes_credentials():
    client = CryptedMailClient()
    credentials = build_credentials()

    serialized = client.serialize_credentials(credentials)
    restored = client.deserialize_credentials(serialized)

    assert json.loads(serialized)["client_id"] == "client-id"
    assert restored.client_id == "client-id"


def test_client_accepts_serialized_credentials(monkeypatch):
    client = CryptedMailClient()
    serialized = client.serialize_credentials(build_credentials())
    captured = {}

    def fake_send(*, sender, recipient_email, subject, armored_payload, credentials):
        captured["client_id"] = credentials.client_id
        return "gmail-message-123"

    monkeypatch.setattr(client._mail, "send_encrypted_email", fake_send)

    message_id = client.send_encrypted_email(
        sender="alice@example.com",
        recipient_email="bob@example.com",
        subject="Subject",
        armored_payload="cm1:payload",
        credentials_or_token=serialized,
    )

    assert message_id == "gmail-message-123"
    assert captured["client_id"] == "client-id"


def test_public_import_surface():
    client = CryptedMailClient()
    assert isinstance(client, CryptedMailClient)
