from __future__ import annotations

from dataclasses import dataclass, field

from crypted_mail.core.crypto import CryptoService
from crypted_mail.services.attachment_service import AttachmentService
from crypted_mail.services.key_service import KeyService
from crypted_mail.services.mail_service import MailService
from crypted_mail.services.storage import AppRepository


@dataclass(slots=True)
class AppContext:
    repository: AppRepository
    key_service: KeyService
    crypto_service: CryptoService
    mail_service: MailService
    # Defaulted so existing callers constructing AppContext with four
    # keyword arguments keep working unchanged.
    attachment_service: AttachmentService = field(default_factory=AttachmentService)

    @classmethod
    def create_default(cls) -> "AppContext":
        repository = AppRepository()
        return cls(
            repository=repository,
            key_service=KeyService(repository),
            crypto_service=CryptoService(),
            mail_service=MailService(repository),
            attachment_service=AttachmentService(),
        )
