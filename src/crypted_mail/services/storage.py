from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import keyring
from keyring.errors import KeyringError

from crypted_mail.config import APP_NAME, AppPaths
from crypted_mail.core.models import AppState, LocalProfile, RecipientRecord


class JsonFileStore:
    def __init__(self, path: Path):
        self.path = path

    def ensure_parent(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def load(self, default: Any) -> Any:
        if not self.path.exists():
            return default
        return json.loads(self.path.read_text(encoding="utf-8"))

    def save(self, payload: Any) -> None:
        self.ensure_parent()
        self.path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


class TokenStore:
    def __init__(self, app_name: str, cache_file: Path):
        self.app_name = app_name
        self.cache_file = cache_file
        self.file_store = JsonFileStore(cache_file)

    def save(self, account: str, token_json: str) -> None:
        try:
            keyring.set_password(self.app_name, account, token_json)
            self.file_store.save({"account": account})
        except KeyringError:
            self.file_store.save({"account": account, "token_json": token_json})

    def load(self, account: str) -> str | None:
        try:
            token_json = keyring.get_password(self.app_name, account)
            if token_json:
                return token_json
        except KeyringError:
            pass
        data = self.file_store.load(default={})
        if data.get("account") == account:
            return data.get("token_json")
        return None

    def clear(self, account: str) -> None:
        try:
            keyring.delete_password(self.app_name, account)
        except Exception:
            pass
        if self.cache_file.exists():
            self.cache_file.unlink()


class SecureValueStore:
    def __init__(self, app_name: str):
        self.app_name = app_name

    def is_available(self) -> bool:
        try:
            keyring.set_password(self.app_name, "__availability_probe__", "ok")
            keyring.delete_password(self.app_name, "__availability_probe__")
            return True
        except Exception:
            return False

    def save(self, key: str, value: str) -> None:
        keyring.set_password(self.app_name, key, value)

    def load(self, key: str) -> str | None:
        return keyring.get_password(self.app_name, key)

    def clear(self, key: str) -> None:
        try:
            keyring.delete_password(self.app_name, key)
        except Exception:
            pass


class AppRepository:
    def __init__(self, paths: AppPaths | None = None):
        self.paths = paths or AppPaths.default()
        self.state_store = JsonFileStore(self.paths.state_file)
        self.profile_store = JsonFileStore(self.paths.profile_file)
        self.recipients_store = JsonFileStore(self.paths.recipients_file)
        self.token_store = TokenStore(APP_NAME, self.paths.token_cache_file)
        self.secure_value_store = SecureValueStore(APP_NAME)

    def load_state(self) -> AppState:
        return AppState.from_dict(self.state_store.load(default={}))

    def save_state(self, state: AppState) -> None:
        self.state_store.save(state.to_dict())

    def load_profile(self) -> LocalProfile | None:
        data = self.profile_store.load(default=None)
        return None if data is None else LocalProfile.from_dict(data)

    def save_profile(self, profile: LocalProfile) -> None:
        self.profile_store.save(profile.to_dict())

    def load_recipients(self) -> list[RecipientRecord]:
        items = self.recipients_store.load(default=[])
        return [RecipientRecord.from_dict(item) for item in items]

    def save_recipients(self, recipients: list[RecipientRecord]) -> None:
        self.recipients_store.save([item.to_dict() for item in recipients])

    def save_default_passphrase(self, sender_email: str, passphrase: str) -> None:
        self.secure_value_store.save(f"default-passphrase::{sender_email.lower()}", passphrase)

    def load_default_passphrase(self, sender_email: str) -> str | None:
        return self.secure_value_store.load(f"default-passphrase::{sender_email.lower()}")

    def clear_default_passphrase(self, sender_email: str) -> None:
        self.secure_value_store.clear(f"default-passphrase::{sender_email.lower()}")
