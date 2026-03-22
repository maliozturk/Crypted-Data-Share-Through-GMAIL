from __future__ import annotations

import base64
from datetime import datetime, timezone

from crypted_mail.core.exceptions import ProfileNotInitializedError, RecipientNotFoundError
from crypted_mail.core.keys import compute_key_id, export_public_key_block, generate_keypair, parse_public_key_block, protect_private_key
from crypted_mail.core.models import LocalProfile, RecipientRecord
from crypted_mail.services.storage import AppRepository


class KeyService:
    def __init__(self, repository: AppRepository):
        self.repository = repository

    def create_profile(self, display_name: str, email: str, passphrase: str) -> LocalProfile:
        private_key, public_key = generate_keypair()
        protected = protect_private_key(private_key, passphrase)
        profile = LocalProfile(
            email=email.strip(),
            display_name=display_name.strip(),
            public_key_b64=base64.b64encode(bytes(public_key)).decode("ascii"),
            key_id=compute_key_id(bytes(public_key)),
            protected_private_key=protected,
            created_at=datetime.now(timezone.utc).isoformat(),
        )
        self.repository.save_profile(profile)
        return profile

    def get_profile(self) -> LocalProfile:
        profile = self.repository.load_profile()
        if profile is None:
            raise ProfileNotInitializedError("No local profile is configured yet.")
        return profile

    def export_public_key(self) -> str:
        profile = self.get_profile()
        from crypted_mail.core.keys import public_key_from_b64

        return export_public_key_block(profile.display_name, profile.email, public_key_from_b64(profile.public_key_b64))

    def import_recipient(self, public_key_text: str) -> RecipientRecord:
        data = parse_public_key_block(public_key_text)
        recipients = self.repository.load_recipients()
        recipient = RecipientRecord(
            name=data["name"],
            email=data["email"],
            public_key_b64=data["public_key_b64"],
            key_id=data["key_id"],
            fingerprint=data["fingerprint"],
            created_at=data.get("created_at", datetime.now(timezone.utc).isoformat()),
        )
        updated = [item for item in recipients if item.email.lower() != recipient.email.lower()]
        updated.append(recipient)
        updated.sort(key=lambda item: item.email.lower())
        self.repository.save_recipients(updated)
        return recipient

    def list_recipients(self) -> list[RecipientRecord]:
        return self.repository.load_recipients()

    def get_recipient(self, email: str) -> RecipientRecord:
        for recipient in self.repository.load_recipients():
            if recipient.email.lower() == email.lower():
                return recipient
        raise RecipientNotFoundError(f"No recipient key found for {email}.")
