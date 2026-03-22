from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timezone

from nacl import pwhash, secret, utils
from nacl.public import PrivateKey, PublicKey

from crypted_mail.core.exceptions import EnvelopeError, KeyProtectionError
from crypted_mail.core.models import ProtectedPrivateKey


PUBLIC_KEY_HEADER = "-----BEGIN CRYPTED MAIL PUBLIC KEY-----"
PUBLIC_KEY_FOOTER = "-----END CRYPTED MAIL PUBLIC KEY-----"
PRIVATE_KEY_FORMAT_VERSION = 1


def _b64_encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64_decode(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))


def compute_key_id(public_key_bytes: bytes) -> str:
    return hashlib.blake2b(public_key_bytes, digest_size=16).hexdigest()


def fingerprint_public_key(public_key_bytes: bytes) -> str:
    digest = hashlib.blake2b(public_key_bytes, digest_size=20).hexdigest()
    return ":".join(digest[idx : idx + 2] for idx in range(0, len(digest), 2))


def generate_keypair() -> tuple[PrivateKey, PublicKey]:
    private_key = PrivateKey.generate()
    return private_key, private_key.public_key


def protect_private_key(private_key: PrivateKey, passphrase: str) -> ProtectedPrivateKey:
    if not passphrase:
        raise KeyProtectionError("A non-empty passphrase is required.")

    salt = utils.random(pwhash.argon2id.SALTBYTES)
    opslimit = pwhash.argon2id.OPSLIMIT_MODERATE
    memlimit = pwhash.argon2id.MEMLIMIT_MODERATE
    key = pwhash.argon2id.kdf(secret.SecretBox.KEY_SIZE, passphrase.encode("utf-8"), salt, opslimit, memlimit)
    box = secret.SecretBox(key)
    encrypted = box.encrypt(bytes(private_key))
    nonce = encrypted[: secret.SecretBox.NONCE_SIZE]
    ciphertext = encrypted[secret.SecretBox.NONCE_SIZE :]
    public_key_bytes = bytes(private_key.public_key)
    return ProtectedPrivateKey(
        version=PRIVATE_KEY_FORMAT_VERSION,
        salt_b64=_b64_encode(salt),
        opslimit=opslimit,
        memlimit=memlimit,
        nonce_b64=_b64_encode(nonce),
        ciphertext_b64=_b64_encode(ciphertext),
        public_key_b64=_b64_encode(public_key_bytes),
        key_id=compute_key_id(public_key_bytes),
    )


def unlock_private_key(protected: ProtectedPrivateKey, passphrase: str) -> PrivateKey:
    if protected.version != PRIVATE_KEY_FORMAT_VERSION:
        raise KeyProtectionError(f"Unsupported private key format version: {protected.version}.")

    try:
        key = pwhash.argon2id.kdf(
            secret.SecretBox.KEY_SIZE,
            passphrase.encode("utf-8"),
            _b64_decode(protected.salt_b64),
            protected.opslimit,
            protected.memlimit,
        )
        box = secret.SecretBox(key)
        private_key_bytes = box.decrypt(_b64_decode(protected.nonce_b64) + _b64_decode(protected.ciphertext_b64))
        private_key = PrivateKey(private_key_bytes)
    except Exception as exc:
        raise KeyProtectionError("The passphrase is invalid or the private key data is corrupted.") from exc

    if compute_key_id(bytes(private_key.public_key)) != protected.key_id:
        raise KeyProtectionError("Unlocked private key does not match the stored public key.")
    return private_key


def export_public_key_block(name: str, email: str, public_key: PublicKey) -> str:
    public_key_bytes = bytes(public_key)
    metadata = {
        "version": 1,
        "name": name,
        "email": email,
        "public_key_b64": _b64_encode(public_key_bytes),
        "key_id": compute_key_id(public_key_bytes),
        "fingerprint": fingerprint_public_key(public_key_bytes),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    encoded = base64.b64encode(json.dumps(metadata, sort_keys=True).encode("utf-8")).decode("ascii")
    return f"{PUBLIC_KEY_HEADER}\n{encoded}\n{PUBLIC_KEY_FOOTER}"


def parse_public_key_block(text: str) -> dict[str, str]:
    if PUBLIC_KEY_HEADER not in text or PUBLIC_KEY_FOOTER not in text:
        raise EnvelopeError("Public key text is missing the expected armored markers.")
    start = text.index(PUBLIC_KEY_HEADER) + len(PUBLIC_KEY_HEADER)
    end = text.index(PUBLIC_KEY_FOOTER)
    encoded = text[start:end].strip()
    try:
        data = json.loads(base64.b64decode(encoded.encode("ascii"), validate=True).decode("utf-8"))
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise EnvelopeError("Public key text is malformed.") from exc

    required = {"name", "email", "public_key_b64", "key_id", "fingerprint"}
    missing = required - data.keys()
    if missing:
        raise EnvelopeError(f"Public key text is missing required fields: {', '.join(sorted(missing))}.")

    public_key_bytes = _b64_decode(data["public_key_b64"])
    actual_key_id = compute_key_id(public_key_bytes)
    if actual_key_id != data["key_id"]:
        raise EnvelopeError("Public key block key id does not match the encoded public key.")
    return data


def public_key_from_b64(value: str) -> PublicKey:
    return PublicKey(_b64_decode(value))
