from __future__ import annotations

import base64
from email.message import EmailMessage
from pathlib import Path

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

from crypted_mail.core.exceptions import GmailConfigurationError


GMAIL_SEND_SCOPE = "https://www.googleapis.com/auth/gmail.send"


class MailService:
    @staticmethod
    def scopes() -> list[str]:
        return [GMAIL_SEND_SCOPE]

    def connect_gmail_oauth(
        self,
        client_secret_path: str,
        account_email: str | None = None,
    ) -> Credentials:
        client_secret = Path(client_secret_path)
        if not client_secret.exists():
            raise GmailConfigurationError("Google OAuth client secret JSON file was not found.")

        flow = InstalledAppFlow.from_client_secrets_file(str(client_secret), scopes=self.scopes())
        credentials = flow.run_local_server(port=0)
        if account_email:
            credentials.account = account_email
        return credentials

    def send_encrypted_email(
        self,
        sender: str,
        recipient_email: str,
        subject: str,
        armored_payload: str,
        credentials: Credentials,
    ) -> str:
        active_credentials = self._ensure_valid_credentials(credentials)
        message = EmailMessage()
        message["To"] = recipient_email
        message["From"] = sender
        message["Subject"] = subject
        message.set_content(armored_payload)
        raw = base64.urlsafe_b64encode(message.as_bytes()).decode("ascii")
        service = build("gmail", "v1", credentials=active_credentials, cache_discovery=False)
        sent = service.users().messages().send(userId="me", body={"raw": raw}).execute()
        return sent["id"]

    def _ensure_valid_credentials(self, credentials: Credentials) -> Credentials:
        if credentials.valid:
            return credentials
        if credentials.expired and credentials.refresh_token:
            credentials.refresh(Request())
            return credentials
        raise GmailConfigurationError("Gmail authorization is missing or expired. Reconnect the Gmail account.")
