from __future__ import annotations

from dataclasses import dataclass

from crypted_mail.core.crypto import CryptoService
from crypted_mail.services.key_service import KeyService
from crypted_mail.services.mail_service import MailService
from crypted_mail.services.storage import AppRepository


@dataclass(slots=True)
class AppContext:
    repository: AppRepository
    key_service: KeyService
    crypto_service: CryptoService
    mail_service: MailService

    @classmethod
    def create_default(cls) -> "AppContext":
        repository = AppRepository()
        return cls(
            repository=repository,
            key_service=KeyService(repository),
            crypto_service=CryptoService(),
            mail_service=MailService(repository),
        )
