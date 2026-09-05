"""Crypted Mail package."""

from typing import Any

__all__ = ["__version__", "CryptedMailClient"]

# Single source of truth for the version. setuptools parses this literal
# statically, so it must stay a plain string - no f-strings, no
# importlib.metadata lookup. scripts/get_version.py reads it too.
__version__ = "0.2.0"


def __getattr__(name: str) -> Any:
    """Expose CryptedMailClient lazily.

    Importing it eagerly would pull the Google client libraries in on every
    `import crypted_mail`, including during the build when setuptools reads
    __version__.
    """
    if name == "CryptedMailClient":
        from crypted_mail.client import CryptedMailClient

        return CryptedMailClient
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
