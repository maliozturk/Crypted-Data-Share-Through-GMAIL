from __future__ import annotations

import base64
import json
from email.message import EmailMessage
from pathlib import Path

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

from crypted_mail.core.exceptions import GmailConfigurationError
from crypted_mail.core.models import AppState
from crypted_mail.services.storage import AppRepository


GMAIL_SEND_SCOPE = "https://www.googleapis.com/auth/gmail.send"


class MailService:
    def __init__(self, repository: AppRepository):
        self.repository = repository

    def connect_gmail_oauth(self, client_secret_path: str, account_email: str) -> Credentials:
        client_secret = Path(client_secret_path)
        if not client_secret.exists():
            raise GmailConfigurationError("Google OAuth client secret JSON file was not found.")

        flow = InstalledAppFlow.from_client_secrets_file(str(client_secret), scopes=[GMAIL_SEND_SCOPE])
        credentials = flow.run_local_server(port=0)
        self._save_credentials(account_email, credentials)
        state = self.repository.load_state()
        state.gmail_connected = True
        state.gmail_account_email = account_email
        state.oauth_secret_path = str(client_secret)
        self.repository.save_state(state)
        return credentials

    def send_encrypted_email(self, sender: str, recipient_email: str, subject: str, armored_payload: str) -> str:
        credentials = self._load_credentials(sender)
        if not credentials.valid:
            if credentials.expired and credentials.refresh_token:
                credentials.refresh(Request())
                self._save_credentials(sender, credentials)
            else:
                raise GmailConfigurationError("Gmail authorization is missing or expired. Reconnect the Gmail account.")

        message = EmailMessage()
        message["To"] = recipient_email
        message["From"] = sender
        message["Subject"] = subject
        message.set_content(armored_payload)
        raw = base64.urlsafe_b64encode(message.as_bytes()).decode("ascii")
        service = build("gmail", "v1", credentials=credentials, cache_discovery=False)
        sent = service.users().messages().send(userId="me", body={"raw": raw}).execute()
        return sent["id"]

    def _save_credentials(self, account_email: str, credentials: Credentials) -> None:
        self.repository.token_store.save(account_email, credentials.to_json())

    def _load_credentials(self, account_email: str) -> Credentials:
        token_json = self.repository.token_store.load(account_email)
        if not token_json:
            raise GmailConfigurationError("No Gmail OAuth token is cached for the configured sender.")
        data = json.loads(token_json)
        return Credentials.from_authorized_user_info(data, scopes=[GMAIL_SEND_SCOPE])

    def load_state(self) -> AppState:
        return self.repository.load_state()

    def disconnect_gmail(self, account_email: str) -> None:
        self.repository.token_store.clear(account_email)
        state = self.repository.load_state()
        state.gmail_connected = False
        state.gmail_account_email = None
        self.repository.save_state(state)
