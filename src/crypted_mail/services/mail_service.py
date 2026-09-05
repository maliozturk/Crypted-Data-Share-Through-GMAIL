from __future__ import annotations

import base64
import io
import json
from email.message import EmailMessage
from pathlib import Path
from typing import Sequence

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseUpload

from crypted_mail.core.exceptions import AttachmentTooLargeError, GmailConfigurationError
from crypted_mail.core.models import AppState
from crypted_mail.services.storage import AppRepository


GMAIL_SEND_SCOPE = "https://www.googleapis.com/auth/gmail.send"

# Gmail rejects messages over 25 MB. The simple {'raw': ...} JSON endpoint
# caps far lower (~5 MB request), so attachments go through a media upload.
MAX_MESSAGE_BYTES = 25 * 1024 * 1024


class MailService:
    def __init__(self, repository: AppRepository | None = None):
        # The desktop app always passes a repository. Library callers may not:
        # they hold their own credentials and never touch the local token cache.
        self.repository = repository

    @staticmethod
    def scopes() -> list[str]:
        return [GMAIL_SEND_SCOPE]

    def _require_repository(self) -> AppRepository:
        if self.repository is None:
            raise GmailConfigurationError(
                "This MailService has no local storage. Pass credentials explicitly."
            )
        return self.repository

    def connect_gmail_oauth(
        self, client_secret_path: str, account_email: str | None = None
    ) -> Credentials:
        client_secret = Path(client_secret_path)
        if not client_secret.exists():
            raise GmailConfigurationError("Google OAuth client secret JSON file was not found.")

        flow = InstalledAppFlow.from_client_secrets_file(str(client_secret), scopes=self.scopes())
        credentials = flow.run_local_server(port=0)
        if account_email is None or self.repository is None:
            # Library mode: hand the credentials back and store nothing.
            return credentials
        self._save_credentials(account_email, credentials)
        state = self.repository.load_state()
        state.gmail_connected = True
        state.gmail_account_email = account_email
        state.oauth_secret_path = str(client_secret)
        self.repository.save_state(state)
        return credentials

    def send_encrypted_email(
        self,
        sender: str,
        recipient_email: str,
        subject: str,
        armored_payload: str,
        attachments: Sequence[Path] | None = None,
        credentials: Credentials | None = None,
    ) -> str:
        supplied = credentials is not None
        if credentials is None:
            credentials = self._load_credentials(sender)
        if not credentials.valid:
            if credentials.expired and credentials.refresh_token:
                credentials.refresh(Request())
                if not supplied:
                    self._save_credentials(sender, credentials)
            else:
                raise GmailConfigurationError("Gmail authorization is missing or expired. Reconnect the Gmail account.")

        message = EmailMessage()
        message["To"] = recipient_email
        message["From"] = sender
        message["Subject"] = subject
        message.set_content(armored_payload)

        attachment_paths = [Path(path) for path in (attachments or ())]
        for path in attachment_paths:
            # Reads the whole file into memory, as does as_bytes() below. That is
            # inherent to EmailMessage and acceptable only because Gmail caps the
            # message at 25 MB anyway; attachment *encryption* stays streaming.
            message.add_attachment(
                path.read_bytes(),
                maintype="application",
                subtype="octet-stream",
                filename=path.name,
            )

        service = build("gmail", "v1", credentials=credentials, cache_discovery=False)
        if not attachment_paths:
            raw = base64.urlsafe_b64encode(message.as_bytes()).decode("ascii")
            sent = service.users().messages().send(userId="me", body={"raw": raw}).execute()
        else:
            raw_bytes = message.as_bytes()
            self._ensure_within_gmail_limit(len(raw_bytes))
            media = MediaIoBaseUpload(
                io.BytesIO(raw_bytes), mimetype="message/rfc822", resumable=True
            )
            # With a resumable upload the message comes from the media stream,
            # so the request body itself stays empty.
            sent = (
                service.users()
                .messages()
                .send(userId="me", body={}, media_body=media)
                .execute()
            )
        return sent["id"]

    @staticmethod
    def _ensure_within_gmail_limit(size_bytes: int) -> None:
        if size_bytes > MAX_MESSAGE_BYTES:
            raise AttachmentTooLargeError(
                "Attachments are too large to send. Gmail allows about 25 MB per message, "
                f"and this one is {size_bytes / (1024 * 1024):.1f} MB once encrypted and "
                "encoded. Remove a file, or split the archive into smaller parts."
            )

    def _save_credentials(self, account_email: str, credentials: Credentials) -> None:
        self._require_repository().token_store.save(account_email, credentials.to_json())

    def _load_credentials(self, account_email: str) -> Credentials:
        token_json = self._require_repository().token_store.load(account_email)
        if not token_json:
            raise GmailConfigurationError("No Gmail OAuth token is cached for the configured sender.")
        data = json.loads(token_json)
        return Credentials.from_authorized_user_info(data, scopes=[GMAIL_SEND_SCOPE])

    def load_state(self) -> AppState:
        return self._require_repository().load_state()

    def disconnect_gmail(self, account_email: str) -> None:
        repository = self._require_repository()
        repository.token_store.clear(account_email)
        state = repository.load_state()
        state.gmail_connected = False
        state.gmail_account_email = None
        repository.save_state(state)
