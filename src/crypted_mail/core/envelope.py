from __future__ import annotations

import base64
import json

from crypted_mail.core.exceptions import EnvelopeError
from crypted_mail.core.models import MessageEnvelope


ENVELOPE_VERSION = 1
SHARED_PASSPHRASE_MODE = "shared_passphrase"
PUBLIC_KEY_MODE = "public_key"
SHARED_PASSPHRASE_ALGORITHM = "argon2id-xsalsa20poly1305-secretbox"
PUBLIC_KEY_ALGORITHM = "x25519-xsalsa20poly1305-sealedbox"
COMPACT_PREFIX = "cm1:"
ARMORED_HEADER = "-----BEGIN CRYPTED MAIL MESSAGE-----"
ARMORED_FOOTER = "-----END CRYPTED MAIL MESSAGE-----"


def serialize_envelope(envelope: MessageEnvelope) -> str:
    payload = json.dumps(envelope.to_dict(), sort_keys=True).encode("utf-8")
    body = base64.b64encode(payload).decode("ascii")
    return f"{COMPACT_PREFIX}{body}"


def parse_armored_message(armored_text: str) -> MessageEnvelope:
    encoded = ""
    if ARMORED_HEADER in armored_text and ARMORED_FOOTER in armored_text:
        start = armored_text.index(ARMORED_HEADER) + len(ARMORED_HEADER)
        end = armored_text.index(ARMORED_FOOTER)
        encoded = armored_text[start:end].strip()
    else:
        for line in armored_text.splitlines():
            stripped = line.strip()
            if stripped.startswith(COMPACT_PREFIX):
                encoded = stripped[len(COMPACT_PREFIX) :].strip()
                break
        if not encoded and armored_text.strip().startswith(COMPACT_PREFIX):
            encoded = armored_text.strip()[len(COMPACT_PREFIX) :].strip()
    if not encoded:
        raise EnvelopeError("Encrypted text does not contain a supported secure payload.")

    try:
        payload = base64.b64decode(encoded.encode("ascii"), validate=True)
        data = json.loads(payload.decode("utf-8"))
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise EnvelopeError("Encrypted message body is malformed or not valid base64 JSON.") from exc

    if "mode" not in data:
        if data.get("recipient_key_id"):
            data["mode"] = PUBLIC_KEY_MODE
        else:
            raise EnvelopeError("Encrypted message is missing its mode metadata.")
    if data.get("mode") == PUBLIC_KEY_MODE and data.get("algorithm") == "x25519-xsalsa20poly1305-sealedbox":
        data["algorithm"] = PUBLIC_KEY_ALGORITHM

    envelope = MessageEnvelope.from_dict(data)
    if envelope.version != ENVELOPE_VERSION:
        raise EnvelopeError(f"Unsupported encrypted message version: {envelope.version}.")
    if envelope.mode == SHARED_PASSPHRASE_MODE:
        if envelope.algorithm != SHARED_PASSPHRASE_ALGORITHM:
            raise EnvelopeError(f"Unsupported encryption algorithm: {envelope.algorithm}.")
        if not envelope.salt_b64 or not envelope.nonce_b64:
            raise EnvelopeError("Shared-passphrase messages are missing required encryption metadata.")
    elif envelope.mode == PUBLIC_KEY_MODE:
        if envelope.algorithm != PUBLIC_KEY_ALGORITHM:
            raise EnvelopeError(f"Unsupported encryption algorithm: {envelope.algorithm}.")
        if not envelope.recipient_key_id:
            raise EnvelopeError("Public-key messages are missing the recipient key id.")
    else:
        raise EnvelopeError(f"Unsupported encryption mode: {envelope.mode}.")
    return envelope


def build_email_body(armored_payload: str, note: str | None = None) -> str:
    lines = []
    if note:
        lines.append(f"Sender note: {note}")
        lines.append("")
    lines.append(armored_payload)
    lines.append("")
    return "\n".join(lines)
