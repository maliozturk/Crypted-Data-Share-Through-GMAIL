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


class AttachmentError(CryptedMailError):
    """Base exception for encrypted attachment failures."""


class UnsupportedAttachmentTypeError(AttachmentError):
    """Raised when a chosen file is not a supported archive."""


class AttachmentTooLargeError(AttachmentError):
    """Raised when attachments exceed what Gmail will accept."""


class AttachmentDecryptionError(AttachmentError):
    """Raised when an encrypted attachment cannot be decrypted."""


class AttachmentIntegrityError(AttachmentError):
    """Raised when a recovered attachment fails its integrity checks."""


class AttachmentCancelled(AttachmentError):
    """Raised when the user cancels an attachment operation."""


class UpdateError(CryptedMailError):
    """Base exception for update failures."""


class UpdateCheckError(UpdateError):
    """Raised when the update check cannot complete."""


class UpdateVerificationError(UpdateError):
    """Raised when a downloaded update fails verification."""


class UpdateInstallError(UpdateError):
    """Raised when an update installer cannot be started."""
