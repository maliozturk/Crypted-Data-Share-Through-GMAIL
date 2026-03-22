from __future__ import annotations

import base64
from datetime import datetime, timezone

from nacl import pwhash, secret, utils
from nacl.public import SealedBox

from crypted_mail.core.envelope import (
    ENVELOPE_VERSION,
    PUBLIC_KEY_ALGORITHM,
    PUBLIC_KEY_MODE,
    SHARED_PASSPHRASE_ALGORITHM,
    SHARED_PASSPHRASE_MODE,
    parse_armored_message,
    serialize_envelope,
)
from crypted_mail.core.exceptions import EnvelopeError
from crypted_mail.core.keys import public_key_from_b64, unlock_private_key
from crypted_mail.core.models import LocalProfile, MessageEnvelope, RecipientRecord


class CryptoService:
    def encrypt_with_passphrase(
        self,
        plaintext: str,
        passphrase: str,
        sender_hint: str | None = None,
        note: str | None = None,
    ) -> str:
        if not passphrase:
            raise EnvelopeError("A shared passphrase is required for Model A encryption.")
        salt = utils.random(pwhash.argon2id.SALTBYTES)
        nonce = utils.random(secret.SecretBox.NONCE_SIZE)
        key = pwhash.argon2id.kdf(
            secret.SecretBox.KEY_SIZE,
            passphrase.encode("utf-8"),
            salt,
            pwhash.argon2id.OPSLIMIT_MODERATE,
            pwhash.argon2id.MEMLIMIT_MODERATE,
        )
        box = secret.SecretBox(key)
        ciphertext = box.encrypt(plaintext.encode("utf-8"), nonce).ciphertext
        envelope = MessageEnvelope(
            version=ENVELOPE_VERSION,
            mode=SHARED_PASSPHRASE_MODE,
            algorithm=SHARED_PASSPHRASE_ALGORITHM,
            created_at=datetime.now(timezone.utc).isoformat(),
            ciphertext_b64=base64.b64encode(ciphertext).decode("ascii"),
            salt_b64=base64.b64encode(salt).decode("ascii"),
            nonce_b64=base64.b64encode(nonce).decode("ascii"),
            sender_hint=sender_hint,
            note=note,
        )
        return serialize_envelope(envelope)

    def decrypt_with_passphrase(self, armored_text: str, passphrase: str) -> str:
        envelope = parse_armored_message(armored_text)
        if envelope.mode != SHARED_PASSPHRASE_MODE:
            raise EnvelopeError("This message is not a shared-passphrase message.")
        if not passphrase:
            raise EnvelopeError("A shared passphrase is required to decrypt this message.")
        key = pwhash.argon2id.kdf(
            secret.SecretBox.KEY_SIZE,
            passphrase.encode("utf-8"),
            base64.b64decode(envelope.salt_b64.encode("ascii")),
            pwhash.argon2id.OPSLIMIT_MODERATE,
            pwhash.argon2id.MEMLIMIT_MODERATE,
        )
        box = secret.SecretBox(key)
        try:
            plaintext_bytes = box.decrypt(
                base64.b64decode(envelope.nonce_b64.encode("ascii")) + base64.b64decode(envelope.ciphertext_b64.encode("ascii"))
            )
        except Exception as exc:
            raise EnvelopeError("Unable to decrypt the shared-passphrase message. Check the passphrase and try again.") from exc
        return plaintext_bytes.decode("utf-8")

    def encrypt_for_recipient(
        self,
        plaintext: str,
        recipient: RecipientRecord,
        sender_hint: str | None = None,
        note: str | None = None,
    ) -> str:
        recipient_key = public_key_from_b64(recipient.public_key_b64)
        sealed_box = SealedBox(recipient_key)
        ciphertext = sealed_box.encrypt(plaintext.encode("utf-8"))
        envelope = MessageEnvelope(
            version=ENVELOPE_VERSION,
            mode=PUBLIC_KEY_MODE,
            algorithm=PUBLIC_KEY_ALGORITHM,
            created_at=datetime.now(timezone.utc).isoformat(),
            ciphertext_b64=base64.b64encode(ciphertext).decode("ascii"),
            recipient_key_id=recipient.key_id,
            sender_hint=sender_hint,
            note=note,
        )
        return serialize_envelope(envelope)

    def decrypt_message(self, armored_text: str, profile: LocalProfile, passphrase: str) -> str:
        envelope = parse_armored_message(armored_text)
        if envelope.mode != PUBLIC_KEY_MODE:
            raise EnvelopeError("This message is not a public-key encrypted message.")
        if envelope.recipient_key_id != profile.key_id:
            raise EnvelopeError("This encrypted message was not addressed to the current local profile.")

        private_key = unlock_private_key(profile.protected_private_key, passphrase)
        sealed_box = SealedBox(private_key)
        try:
            plaintext_bytes = sealed_box.decrypt(base64.b64decode(envelope.ciphertext_b64.encode("ascii")))
        except Exception as exc:
            raise EnvelopeError("Unable to decrypt message with the current private key.") from exc
        return plaintext_bytes.decode("utf-8")

    def parse_message(self, armored_text: str) -> MessageEnvelope:
        return parse_armored_message(armored_text)
