from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(slots=True)
class MessageEnvelope:
    version: int
    mode: str
    algorithm: str
    created_at: str
    ciphertext_b64: str
    salt_b64: str | None = None
    nonce_b64: str | None = None
    sender_hint: str | None = None
    note: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "MessageEnvelope":
        return cls(**data)
