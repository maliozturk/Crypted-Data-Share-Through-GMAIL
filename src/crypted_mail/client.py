from __future__ import annotations

import json
from typing import Any

from google.oauth2.credentials import Credentials

from crypted_mail.core.crypto import CryptoService
from crypted_mail.services.mail_service import MailService


SerializedCredentials = str | dict[str, Any]


class CryptedMailClient:
    """High-level API for notebook and script usage."""

    def __init__(self) -> None:
        self._crypto = CryptoService()
        self._mail = MailService()

    def connect_gmail_oauth(
        self,
        client_secret_path: str,
        account_email: str | None = None,
    ) -> str:
        credentials = self._mail.connect_gmail_oauth(client_secret_path=client_secret_path, account_email=account_email)
        return self.serialize_credentials(credentials)

    def encrypt_with_passphrase(
        self,
        plaintext: str,
        passphrase: str,
        sender_hint: str | None = None,
        note: str | None = None,
    ) -> str:
        return self._crypto.encrypt_with_passphrase(
            plaintext=plaintext,
            passphrase=passphrase,
            sender_hint=sender_hint,
            note=note,
        )

    def decrypt_with_passphrase(self, armored_text: str, passphrase: str) -> str:
        return self._crypto.decrypt_with_passphrase(armored_text=armored_text, passphrase=passphrase)

    def send_encrypted_email(
        self,
        sender: str,
        recipient_email: str,
        subject: str,
        armored_payload: str,
        credentials_or_token: Credentials | SerializedCredentials,
    ) -> str:
        credentials = self.credentials_from_any(credentials_or_token)
        return self._mail.send_encrypted_email(
            sender=sender,
            recipient_email=recipient_email,
            subject=subject,
            armored_payload=armored_payload,
            credentials=credentials,
        )

    def encrypt_and_send_with_passphrase(
        self,
        sender: str,
        recipient_email: str,
        subject: str,
        plaintext: str,
        passphrase: str,
        credentials_or_token: Credentials | SerializedCredentials,
        sender_hint: str | None = None,
        note: str | None = None,
    ) -> str:
        armored_payload = self.encrypt_with_passphrase(
            plaintext=plaintext,
            passphrase=passphrase,
            sender_hint=sender_hint,
            note=note,
        )
        return self.send_encrypted_email(
            sender=sender,
            recipient_email=recipient_email,
            subject=subject,
            armored_payload=armored_payload,
            credentials_or_token=credentials_or_token,
        )

    @staticmethod
    def serialize_credentials(credentials: Credentials) -> str:
        return credentials.to_json()

    @staticmethod
    def credentials_to_dict(credentials: Credentials) -> dict[str, Any]:
        return json.loads(credentials.to_json())

    @staticmethod
    def deserialize_credentials(credentials_json: str) -> Credentials:
        return Credentials.from_authorized_user_info(json.loads(credentials_json), scopes=MailService.scopes())

    @classmethod
    def credentials_from_any(cls, credentials_or_token: Credentials | SerializedCredentials) -> Credentials:
        if isinstance(credentials_or_token, Credentials):
            return credentials_or_token
        if isinstance(credentials_or_token, str):
            return cls.deserialize_credentials(credentials_or_token)
        if isinstance(credentials_or_token, dict):
            return Credentials.from_authorized_user_info(credentials_or_token, scopes=MailService.scopes())
        raise TypeError("credentials_or_token must be a Credentials object, JSON string, or dict.")
