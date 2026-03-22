from __future__ import annotations

import base64
from datetime import datetime, timezone

from nacl import pwhash, secret, utils

from crypted_mail.core.envelope import (
    ENVELOPE_VERSION,
    SHARED_PASSPHRASE_ALGORITHM,
    SHARED_PASSPHRASE_MODE,
    parse_armored_message,
    serialize_envelope,
)
from crypted_mail.core.exceptions import EnvelopeError
from crypted_mail.core.models import MessageEnvelope


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

    def parse_message(self, armored_text: str) -> MessageEnvelope:
        return parse_armored_message(armored_text)
