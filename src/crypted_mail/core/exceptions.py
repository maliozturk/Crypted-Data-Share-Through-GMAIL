class CryptedMailError(Exception):
    """Base exception for user-facing app failures."""


class EnvelopeError(CryptedMailError):
    """Raised when an encrypted message envelope is invalid."""


class KeyProtectionError(CryptedMailError):
    """Raised when a private key cannot be unlocked or protected."""


class ProfileNotInitializedError(CryptedMailError):
    """Raised when operations require an existing local profile."""


class RecipientNotFoundError(CryptedMailError):
    """Raised when the recipient keybook does not have a requested contact."""


class GmailConfigurationError(CryptedMailError):
    """Raised when Gmail OAuth setup is missing or invalid."""
