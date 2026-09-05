"""High-level API for notebook and script usage.

This is the surface ``pip install crypted-mail`` gives you. It needs no Qt and
no local state: you hold the Gmail credentials and pass them in.

    from crypted_mail import CryptedMailClient

    client = CryptedMailClient()
    token = client.connect_gmail_oauth("client_secret.json")
    client.encrypt_and_send_with_passphrase(
        sender="me@gmail.com",
        recipient_email="you@example.com",
        subject="Report",
        plaintext="the secret text",
        passphrase="a long shared passphrase",
        credentials_or_token=token,
    )

The desktop app (``pip install crypted-mail[desktop]``) is a separate entry
point and stores credentials for you instead.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Sequence

from google.oauth2.credentials import Credentials

from crypted_mail.core.attachments import (
    AttachmentHeader,
    decrypt_file_with_passphrase,
    encrypt_file_with_passphrase,
    encrypted_name_for,
)
from crypted_mail.core.crypto import CryptoService
from crypted_mail.core.envelope import build_email_body
from crypted_mail.services.mail_service import MailService


SerializedCredentials = str | dict[str, Any]


class CryptedMailClient:
    """High-level API for notebook and script usage."""

    def __init__(self) -> None:
        self._crypto = CryptoService()
        self._mail = MailService()

    # -- authentication ------------------------------------------------

    def connect_gmail_oauth(
        self,
        client_secret_path: str,
        account_email: str | None = None,
    ) -> str:
        """Run the OAuth flow and return serialized credentials to keep."""
        credentials = self._mail.connect_gmail_oauth(
            client_secret_path=client_secret_path, account_email=account_email
        )
        return self.serialize_credentials(credentials)

    # -- text ------------------------------------------------------------

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
        return self._crypto.decrypt_with_passphrase(
            armored_text=armored_text, passphrase=passphrase
        )

    # -- attachments -------------------------------------------------------

    def encrypt_file(
        self,
        source_path: str | Path,
        passphrase: str,
        destination_path: str | Path | None = None,
        *,
        sender_hint: str | None = None,
    ) -> Path:
        """Encrypt any file into a self-contained ``.cmenc`` and return its path."""
        source = Path(source_path)
        destination = (
            Path(destination_path)
            if destination_path is not None
            else source.with_name(encrypted_name_for(source))
        )
        encrypt_file_with_passphrase(
            source, destination, passphrase, sender_hint=sender_hint
        )
        return destination

    def decrypt_file(
        self,
        encrypted_path: str | Path,
        destination_path: str | Path,
        passphrase: str,
    ) -> AttachmentHeader:
        """Recover the original file, verifying its SHA-256."""
        return decrypt_file_with_passphrase(
            Path(encrypted_path), Path(destination_path), passphrase
        )

    # -- sending -----------------------------------------------------------

    def send_encrypted_email(
        self,
        sender: str,
        recipient_email: str,
        subject: str,
        armored_payload: str,
        credentials_or_token: Credentials | SerializedCredentials,
        attachments: Sequence[str | Path] | None = None,
    ) -> str:
        credentials = self.credentials_from_any(credentials_or_token)
        return self._mail.send_encrypted_email(
            sender=sender,
            recipient_email=recipient_email,
            subject=subject,
            armored_payload=armored_payload,
            attachments=[Path(item) for item in (attachments or ())] or None,
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
        attachments: Sequence[str | Path] | None = None,
    ) -> str:
        """Encrypt text (and optionally files) and send it in one call.

        Each attachment is encrypted into its own ``.cmenc`` file next to the
        source and attached separately; the recipient needs only the same
        passphrase to recover them.
        """
        encrypted_attachments = [
            self.encrypt_file(item, passphrase, sender_hint=sender_hint)
            for item in (attachments or ())
        ]
        armored_payload = self.encrypt_with_passphrase(
            plaintext=plaintext,
            passphrase=passphrase,
            sender_hint=sender_hint,
            note=note,
        )
        body = build_email_body(
            armored_payload,
            note=note,
            attachment_names=[path.name for path in encrypted_attachments] or None,
        )
        return self.send_encrypted_email(
            sender=sender,
            recipient_email=recipient_email,
            subject=subject,
            armored_payload=body,
            credentials_or_token=credentials_or_token,
            attachments=encrypted_attachments,
        )

    # -- credential helpers -------------------------------------------------

    @staticmethod
    def serialize_credentials(credentials: Credentials) -> str:
        return credentials.to_json()

    @staticmethod
    def credentials_to_dict(credentials: Credentials) -> dict[str, Any]:
        return json.loads(credentials.to_json())

    @staticmethod
    def deserialize_credentials(credentials_json: str) -> Credentials:
        return Credentials.from_authorized_user_info(
            json.loads(credentials_json), scopes=MailService.scopes()
        )

    @classmethod
    def credentials_from_any(
        cls, credentials_or_token: Credentials | SerializedCredentials
    ) -> Credentials:
        if isinstance(credentials_or_token, Credentials):
            return credentials_or_token
        if isinstance(credentials_or_token, str):
            return cls.deserialize_credentials(credentials_or_token)
        if isinstance(credentials_or_token, dict):
            return Credentials.from_authorized_user_info(
                credentials_or_token, scopes=MailService.scopes()
            )
        raise TypeError(
            "credentials_or_token must be a Credentials object, JSON string, or dict."
        )
