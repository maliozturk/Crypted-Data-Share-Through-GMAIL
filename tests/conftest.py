from __future__ import annotations

from pathlib import Path

import pytest

from crypted_mail.config import AppPaths
from crypted_mail.core.crypto import CryptoService
from crypted_mail.services.app_context import AppContext
from crypted_mail.services.key_service import KeyService
from crypted_mail.services.mail_service import MailService
from crypted_mail.services.storage import AppRepository


@pytest.fixture()
def app_paths(tmp_path: Path) -> AppPaths:
    return AppPaths(
        base_dir=tmp_path,
        state_file=tmp_path / "state.json",
        profile_file=tmp_path / "profile.json",
        recipients_file=tmp_path / "recipients.json",
        token_cache_file=tmp_path / "tokens.json",
    )


@pytest.fixture()
def repository(app_paths: AppPaths) -> AppRepository:
    return AppRepository(paths=app_paths)


@pytest.fixture()
def key_service(repository: AppRepository) -> KeyService:
    return KeyService(repository)


@pytest.fixture()
def mail_service(repository: AppRepository) -> MailService:
    return MailService(repository)


@pytest.fixture()
def app_context(repository: AppRepository) -> AppContext:
    return AppContext(
        repository=repository,
        key_service=KeyService(repository),
        crypto_service=CryptoService(),
        mail_service=MailService(repository),
    )
