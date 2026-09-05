from __future__ import annotations

from dataclasses import MISSING, asdict, dataclass, field, fields
from typing import Any


def _accept_known_fields(cls: type, data: dict[str, Any]) -> dict[str, Any]:
    """Filter *data* to the dataclass fields of *cls*, checking required ones."""
    names = {f.name for f in fields(cls)}
    accepted = {key: value for key, value in data.items() if key in names}
    required = {
        f.name
        for f in fields(cls)
        if f.default is MISSING and f.default_factory is MISSING
    }
    missing = required - accepted.keys()
    if missing:
        raise ValueError(f"missing required fields: {', '.join(sorted(missing))}")
    return accepted


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
        """Build an envelope, ignoring keys this version does not know about.

        A newer client may add fields; an older one must still be able to read
        the message text rather than dying with a TypeError. Missing *required*
        fields raise ValueError, which parse_armored_message already converts
        into a friendly EnvelopeError.
        """
        return cls(**_accept_known_fields(cls, data))


@dataclass(slots=True)
class AppState:
    sender_email: str | None = None
    gmail_connected: bool = False
    gmail_account_email: str | None = None
    warnings_acknowledged: bool = False
    oauth_secret_path: str | None = None
    remember_default_passphrase: bool = False
    auto_update_enabled: bool = True
    last_update_check_at: str | None = None
    update_check_backoff_until: str | None = None
    last_installed_version: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AppState":
        """Load saved state, tolerating keys written by a different version.

        Without this, a state.json written by a newer build crashes an older
        one on startup, before any UI exists to report the problem.
        """
        known = _accept_known_fields(cls, data)
        unknown = {
            key: value
            for key, value in data.items()
            if key != "extra" and key not in {f.name for f in fields(cls)}
        }
        state = cls(**known)
        if unknown:
            state.extra.update(unknown)
        return state
