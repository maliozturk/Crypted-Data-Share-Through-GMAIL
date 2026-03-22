from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(slots=True)
class ProtectedPrivateKey:
    version: int
    salt_b64: str
    opslimit: int
    memlimit: int
    nonce_b64: str
    ciphertext_b64: str
    public_key_b64: str
    key_id: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ProtectedPrivateKey":
        return cls(**data)


@dataclass(slots=True)
class RecipientRecord:
    name: str
    email: str
    public_key_b64: str
    key_id: str
    fingerprint: str
    created_at: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "RecipientRecord":
        return cls(**data)


@dataclass(slots=True)
class LocalProfile:
    email: str
    display_name: str
    public_key_b64: str
    key_id: str
    protected_private_key: ProtectedPrivateKey
    created_at: str

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["protected_private_key"] = self.protected_private_key.to_dict()
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "LocalProfile":
        return cls(
            email=data["email"],
            display_name=data["display_name"],
            public_key_b64=data["public_key_b64"],
            key_id=data["key_id"],
            protected_private_key=ProtectedPrivateKey.from_dict(data["protected_private_key"]),
            created_at=data["created_at"],
        )


@dataclass(slots=True)
class MessageEnvelope:
    version: int
    mode: str
    algorithm: str
    created_at: str
    ciphertext_b64: str
    recipient_key_id: str | None = None
    salt_b64: str | None = None
    nonce_b64: str | None = None
    sender_hint: str | None = None
    note: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "MessageEnvelope":
        return cls(**data)


@dataclass(slots=True)
class AppState:
    sender_email: str | None = None
    gmail_connected: bool = False
    gmail_account_email: str | None = None
    warnings_acknowledged: bool = False
    oauth_secret_path: str | None = None
    remember_default_passphrase: bool = False
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AppState":
        return cls(**data)
