"""Streaming, authenticated encryption for file attachments (the ``.cmenc`` format).

Unlike :mod:`crypted_mail.core.crypto`, which seals a whole string with
``SecretBox``, this module streams a file through libsodium's *secretstream*
(XChaCha20-Poly1305). That buys three things a single SecretBox cannot give us:

* constant memory - a 200 MB archive never lands in RAM,
* per-chunk authentication with ordering guarantees,
* an explicit end-of-stream tag, so truncation is detectable.

File layout::

    offset   size          field
    ------   -----------   -------------------------------------------
    0        8             MAGIC          = b"CMENCRYP"
    8        2             FORMAT_VERSION = uint16 big-endian
    10       4             HEADER_LEN     = uint32 big-endian
    14       HEADER_LEN    HEADER_JSON    = UTF-8 JSON
             ---- bytes [0, 14 + HEADER_LEN) are the AD block ----
    14+HL    24            STREAM_HEADER  (secretstream init_push output)
    38+HL    ...           CHUNKS         each (plaintext_len + 17) bytes

The prologue and header are passed as *additional data* to the first chunk, so
the declared filename, size, digest and KDF parameters are all authenticated.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import struct
import tempfile
import unicodedata
from dataclasses import dataclass, fields
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from nacl import pwhash, utils
from nacl.bindings import (
    crypto_secretstream_xchacha20poly1305_ABYTES as ABYTES,
    crypto_secretstream_xchacha20poly1305_HEADERBYTES as HEADERBYTES,
    crypto_secretstream_xchacha20poly1305_KEYBYTES as KEYBYTES,
    crypto_secretstream_xchacha20poly1305_TAG_FINAL as TAG_FINAL,
    crypto_secretstream_xchacha20poly1305_TAG_MESSAGE as TAG_MESSAGE,
    crypto_secretstream_xchacha20poly1305_init_pull as _init_pull,
    crypto_secretstream_xchacha20poly1305_init_push as _init_push,
    crypto_secretstream_xchacha20poly1305_pull as _pull,
    crypto_secretstream_xchacha20poly1305_push as _push,
    crypto_secretstream_xchacha20poly1305_state as _State,
)
from nacl.exceptions import CryptoError

from crypted_mail.core.exceptions import (
    AttachmentCancelled,
    AttachmentDecryptionError,
    AttachmentError,
    AttachmentIntegrityError,
)


CMENC_MAGIC = b"CMENCRYP"
CMENC_VERSION = 1
CMENC_SUFFIX = ".cmenc"
CMENC_FORMAT = "cmenc"
CMENC_CIPHER = "xchacha20poly1305-secretstream"
CMENC_KDF = "argon2id"

CHUNK_SIZE = 256 * 1024
PROLOGUE_SIZE = len(CMENC_MAGIC) + 2 + 4

# Bounds applied to attacker-controlled header values *before* the KDF runs.
MAX_HEADER_BYTES = 64 * 1024
MIN_CHUNK_SIZE = 4 * 1024
MAX_CHUNK_SIZE = 4 * 1024 * 1024
MAX_KDF_MEMLIMIT = 1024 * 1024 * 1024
MAX_KDF_OPSLIMIT = 10

MAX_FILENAME_LENGTH = 120
_WINDOWS_RESERVED = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{index}" for index in range(1, 10)),
    *(f"LPT{index}" for index in range(1, 10)),
}
_ILLEGAL_FILENAME_CHARS = set('<>:"|?*')
# Bidi overrides let "exe.zip" render as "piz.exe" in a label.
_BIDI_CONTROLS = {chr(code) for code in range(0x202A, 0x202F)} | {chr(code) for code in range(0x2066, 0x206A)}

# Emit at most one progress callback per megabyte, not one per chunk.
_PROGRESS_STEP = 1024 * 1024

_DECRYPT_FAILED = (
    "Could not decrypt this attachment. The passphrase may be wrong, "
    "or the file may be damaged or modified."
)

ProgressCallback = Callable[[int, int], None]
CancelCallback = Callable[[], bool]


@dataclass(slots=True)
class AttachmentHeader:
    """Metadata describing one encrypted attachment.

    Everything here is authenticated by the secretstream AD binding - but only
    *after* a successful decryption. :func:`read_attachment_header` returns an
    unverified instance, so treat its values as untrusted until then.
    """

    filename: str
    plaintext_size: int
    plaintext_sha256: str
    kdf_salt_b64: str
    kdf_opslimit: int
    kdf_memlimit: int
    chunk_size: int
    created_at: str
    sender_hint: str | None = None
    format: str = CMENC_FORMAT
    version: int = CMENC_VERSION
    cipher: str = CMENC_CIPHER
    kdf: str = CMENC_KDF

    def to_dict(self) -> dict[str, Any]:
        return {
            "format": self.format,
            "version": self.version,
            "cipher": self.cipher,
            "kdf": self.kdf,
            "kdf_salt_b64": self.kdf_salt_b64,
            "kdf_opslimit": self.kdf_opslimit,
            "kdf_memlimit": self.kdf_memlimit,
            "chunk_size": self.chunk_size,
            "filename": self.filename,
            "plaintext_size": self.plaintext_size,
            "plaintext_sha256": self.plaintext_sha256,
            "created_at": self.created_at,
            "sender_hint": self.sender_hint,
        }

    def to_json_bytes(self) -> bytes:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":")).encode("utf-8")

    @classmethod
    def from_json_bytes(cls, raw: bytes) -> "AttachmentHeader":
        """Parse and bound-check a header. Unknown keys are ignored on purpose."""
        try:
            data = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise AttachmentError("This encrypted attachment has an unreadable header.") from exc
        if not isinstance(data, dict):
            raise AttachmentError("This encrypted attachment has a malformed header.")

        known = {field.name for field in fields(cls)}
        accepted = {key: value for key, value in data.items() if key in known}
        try:
            header = cls(**accepted)
        except TypeError as exc:
            raise AttachmentError("This encrypted attachment is missing required header fields.") from exc
        header.validate()
        return header

    def validate(self) -> None:
        """Bound-check every attacker-controlled value before it is used."""
        if self.format != CMENC_FORMAT or self.cipher != CMENC_CIPHER or self.kdf != CMENC_KDF:
            raise AttachmentError("This encrypted attachment uses an unsupported cipher.")
        if not isinstance(self.plaintext_size, int) or self.plaintext_size < 0:
            raise AttachmentError("This encrypted attachment declares an invalid size.")
        if not isinstance(self.chunk_size, int) or not MIN_CHUNK_SIZE <= self.chunk_size <= MAX_CHUNK_SIZE:
            raise AttachmentError("This encrypted attachment declares an unsupported chunk size.")
        if not isinstance(self.kdf_opslimit, int) or not 0 < self.kdf_opslimit <= MAX_KDF_OPSLIMIT:
            raise AttachmentError("This encrypted attachment declares unsupported key-derivation settings.")
        if not isinstance(self.kdf_memlimit, int) or not 0 < self.kdf_memlimit <= MAX_KDF_MEMLIMIT:
            raise AttachmentError("This encrypted attachment declares unsupported key-derivation settings.")
        if not isinstance(self.plaintext_sha256, str) or len(self.plaintext_sha256) != 64:
            raise AttachmentError("This encrypted attachment declares an invalid checksum.")
        try:
            bytes.fromhex(self.plaintext_sha256)
        except ValueError as exc:
            raise AttachmentError("This encrypted attachment declares an invalid checksum.") from exc
        if not isinstance(self.kdf_salt_b64, str):
            raise AttachmentError("This encrypted attachment has a malformed key-derivation salt.")
        try:
            salt = base64.b64decode(self.kdf_salt_b64.encode("ascii"), validate=True)
        except ValueError as exc:
            raise AttachmentError("This encrypted attachment has a malformed key-derivation salt.") from exc
        if len(salt) != pwhash.argon2id.SALTBYTES:
            raise AttachmentError("This encrypted attachment has a malformed key-derivation salt.")
        if not isinstance(self.filename, str) or not self.filename:
            raise AttachmentError("This encrypted attachment does not declare a filename.")

    @property
    def salt(self) -> bytes:
        return base64.b64decode(self.kdf_salt_b64.encode("ascii"))

    @property
    def display_filename(self) -> str:
        """The declared name, safe to render in a label (bidi controls removed)."""
        return "".join(char for char in self.filename if char not in _BIDI_CONTROLS)


def encrypted_name_for(source_path: Path) -> str:
    """``report.zip`` -> ``report.zip.cmenc``."""
    return sanitize_attachment_filename(Path(source_path).name) + CMENC_SUFFIX


def sanitize_attachment_filename(raw: str) -> str:
    """Reduce an untrusted declared name to a single safe filename component.

    This is only ever used to pre-fill a Save-As dialog - the user confirms the
    real destination - so it is defence in depth rather than the sole barrier.
    """
    text = raw or ""
    text = text.split("\x00", 1)[0]
    text = "".join(char for char in text if char not in _BIDI_CONTROLS)
    text = unicodedata.normalize("NFC", text)
    text = text.replace("\\", "/").rsplit("/", 1)[-1]
    text = "".join(
        "_" if char in _ILLEGAL_FILENAME_CHARS or ord(char) < 32 else char for char in text
    )
    text = text.strip().strip(".")
    if not text:
        return "attachment"
    stem, dot, suffix = text.partition(".")
    if stem.upper() in _WINDOWS_RESERVED:
        text = f"_{stem}{dot}{suffix}"
    if len(text) > MAX_FILENAME_LENGTH:
        root, separator, extension = text.rpartition(".")
        if separator and len(extension) < 16:
            text = f"{root[: MAX_FILENAME_LENGTH - len(extension) - 1]}.{extension}"
        else:
            text = text[:MAX_FILENAME_LENGTH]
    return text or "attachment"


def read_attachment_header(source_path: Path) -> AttachmentHeader:
    """Peek at a ``.cmenc`` header **without** verifying it.

    Nothing returned here is authenticated. Only a successful
    :func:`decrypt_file_with_passphrase` proves the declared values.
    """
    with Path(source_path).open("rb") as handle:
        _, header, _ = _read_prologue(handle)
    return header


def encrypt_file_with_passphrase(
    source_path: Path,
    destination_path: Path,
    passphrase: str,
    *,
    sender_hint: str | None = None,
    chunk_size: int = CHUNK_SIZE,
    on_progress: ProgressCallback | None = None,
    should_cancel: CancelCallback | None = None,
) -> AttachmentHeader:
    """Encrypt ``source_path`` into ``destination_path`` as a ``.cmenc`` file."""
    source_path = Path(source_path)
    destination_path = Path(destination_path)
    if not passphrase:
        raise AttachmentError("A shared passphrase is required to encrypt an attachment.")
    if not MIN_CHUNK_SIZE <= chunk_size <= MAX_CHUNK_SIZE:
        raise AttachmentError("Unsupported chunk size for attachment encryption.")

    # Pass 1: measure. The digest belongs in the header, which is written first.
    plaintext_size, digest_hex = _hash_file(source_path, chunk_size)

    salt = utils.random(pwhash.argon2id.SALTBYTES)
    opslimit = pwhash.argon2id.OPSLIMIT_MODERATE
    memlimit = pwhash.argon2id.MEMLIMIT_MODERATE
    key = pwhash.argon2id.kdf(KEYBYTES, passphrase.encode("utf-8"), salt, opslimit, memlimit)

    header = AttachmentHeader(
        filename=sanitize_attachment_filename(source_path.name),
        plaintext_size=plaintext_size,
        plaintext_sha256=digest_hex,
        kdf_salt_b64=base64.b64encode(salt).decode("ascii"),
        kdf_opslimit=opslimit,
        kdf_memlimit=memlimit,
        chunk_size=chunk_size,
        created_at=datetime.now(timezone.utc).isoformat(),
        sender_hint=sender_hint,
    )
    additional_data = _build_ad(header.to_json_bytes())

    staged = _staging_path(destination_path)
    reporter = _ProgressReporter(on_progress, plaintext_size)
    verify_digest = hashlib.sha256()
    written = 0
    try:
        with source_path.open("rb") as source, staged.open("wb") as target:
            target.write(additional_data)
            state = _State()
            target.write(_init_push(state, key))

            first = True
            current = source.read(chunk_size)
            while True:
                # One-chunk lookahead: we must know whether `current` is the last
                # chunk in order to tag it TAG_FINAL in a single forward pass.
                lookahead = source.read(chunk_size)
                tag = TAG_MESSAGE if lookahead else TAG_FINAL
                verify_digest.update(current)
                written += len(current)
                # push() rejects bytearray/memoryview - file.read() gives bytes.
                target.write(_push(state, current, additional_data if first else None, tag))
                first = False
                reporter.report(written)
                if should_cancel is not None and should_cancel():
                    raise AttachmentCancelled("Attachment encryption was cancelled.")
                if tag == TAG_FINAL:
                    break
                current = lookahead
            target.flush()
            os.fsync(target.fileno())

        if written != plaintext_size or verify_digest.hexdigest() != digest_hex:
            raise AttachmentIntegrityError(
                f"{source_path.name} changed on disk while it was being encrypted. Try again."
            )
        reporter.finish(plaintext_size)
        os.replace(staged, destination_path)
    except BaseException:
        staged.unlink(missing_ok=True)
        raise
    return header


def decrypt_file_with_passphrase(
    source_path: Path,
    destination_path: Path,
    passphrase: str,
    *,
    on_progress: ProgressCallback | None = None,
    should_cancel: CancelCallback | None = None,
) -> AttachmentHeader:
    """Recover the original archive from a ``.cmenc`` file."""
    source_path = Path(source_path)
    destination_path = Path(destination_path)
    if source_path.resolve() == destination_path.resolve():
        raise AttachmentError("The destination must differ from the encrypted file.")

    with source_path.open("rb") as source:
        additional_data, header, stream_header = _read_prologue(source)
        _check_free_space(destination_path.parent, header.plaintext_size)

        key = pwhash.argon2id.kdf(
            KEYBYTES,
            passphrase.encode("utf-8"),
            header.salt,
            header.kdf_opslimit,
            header.kdf_memlimit,
        )
        state = _State()
        try:
            _init_pull(state, stream_header, key)
        except CryptoError as exc:
            raise AttachmentDecryptionError(_DECRYPT_FAILED) from exc

        frame_size = header.chunk_size + ABYTES
        staged = _staging_path(destination_path)
        reporter = _ProgressReporter(on_progress, header.plaintext_size)
        digest = hashlib.sha256()
        written = 0
        first = True
        saw_final = False
        try:
            with staged.open("wb") as target:
                while not saw_final:
                    frame = _read_exact(source, frame_size)
                    if not frame:
                        break  # EOF before TAG_FINAL was seen
                    try:
                        message, tag = _pull(state, frame, additional_data if first else None)
                    except CryptoError as exc:
                        raise AttachmentDecryptionError(_DECRYPT_FAILED) from exc
                    first = False
                    digest.update(message)
                    written += len(message)
                    target.write(message)
                    saw_final = tag == TAG_FINAL
                    reporter.report(written)
                    if should_cancel is not None and should_cancel():
                        raise AttachmentCancelled("Attachment decryption was cancelled.")
                if saw_final and source.read(1):
                    raise AttachmentIntegrityError(
                        "Extra data follows the end of the encrypted stream."
                    )
                target.flush()
                os.fsync(target.fileno())

            # Three independent truncation defences. The first is the one that
            # catches a file cut on an exact chunk boundary, where every
            # surviving chunk still authenticates perfectly.
            if not saw_final:
                raise AttachmentIntegrityError(
                    "This encrypted attachment is incomplete - its end-of-file marker is missing."
                )
            if written != header.plaintext_size:
                raise AttachmentIntegrityError(
                    f"Recovered {written} bytes but the attachment declares {header.plaintext_size}."
                )
            if digest.hexdigest() != header.plaintext_sha256:
                raise AttachmentIntegrityError(
                    "The recovered file failed its SHA-256 integrity check."
                )
            reporter.finish(header.plaintext_size)
            os.replace(staged, destination_path)
        except BaseException:
            staged.unlink(missing_ok=True)
            raise
    return header


class _ProgressReporter:
    """Throttles progress callbacks so a large file cannot flood the event loop."""

    __slots__ = ("_callback", "_total", "_next")

    def __init__(self, callback: ProgressCallback | None, total: int) -> None:
        self._callback = callback
        self._total = total
        self._next = 0

    def report(self, done: int) -> None:
        if self._callback is None or done < self._next:
            return
        self._next = done + _PROGRESS_STEP
        self._callback(done, self._total)

    def finish(self, total: int) -> None:
        if self._callback is not None:
            self._callback(total, total)


def _build_ad(header_json: bytes) -> bytes:
    return (
        CMENC_MAGIC
        + struct.pack(">H", CMENC_VERSION)
        + struct.pack(">I", len(header_json))
        + header_json
    )


def _read_prologue(handle) -> tuple[bytes, AttachmentHeader, bytes]:
    """Read magic + header + stream header, returning the exact AD bytes.

    The AD must be the literal on-disk bytes; re-serialising the parsed JSON
    would not reproduce them byte-for-byte and authentication would fail.
    """
    prologue = _read_exact(handle, PROLOGUE_SIZE)
    if len(prologue) < PROLOGUE_SIZE or prologue[: len(CMENC_MAGIC)] != CMENC_MAGIC:
        raise AttachmentError("This file is not a Crypted Mail encrypted attachment.")
    (file_version,) = struct.unpack(">H", prologue[8:10])
    if file_version != CMENC_VERSION:
        raise AttachmentError(
            f"This attachment uses format version {file_version}; this app understands "
            f"version {CMENC_VERSION}. Update Crypted Mail."
        )
    (header_len,) = struct.unpack(">I", prologue[10:14])
    if not 0 < header_len <= MAX_HEADER_BYTES:
        raise AttachmentError("This encrypted attachment has a malformed header.")

    header_json = _read_exact(handle, header_len)
    if len(header_json) != header_len:
        raise AttachmentError("This encrypted attachment is truncated.")
    header = AttachmentHeader.from_json_bytes(header_json)

    stream_header = _read_exact(handle, HEADERBYTES)
    if len(stream_header) != HEADERBYTES:
        raise AttachmentError("This encrypted attachment is truncated.")
    return prologue + header_json, header, stream_header


def _read_exact(handle, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining > 0:
        block = handle.read(remaining)
        if not block:
            break
        chunks.append(block)
        remaining -= len(block)
    return b"".join(chunks)


def _hash_file(path: Path, chunk_size: int) -> tuple[int, str]:
    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(chunk_size), b""):
            digest.update(block)
            total += len(block)
    return total, digest.hexdigest()


def _staging_path(destination_path: Path) -> Path:
    parent = destination_path.parent
    parent.mkdir(parents=True, exist_ok=True)
    handle, name = tempfile.mkstemp(
        dir=str(parent), prefix=destination_path.name + ".", suffix=".part"
    )
    os.close(handle)
    return Path(name)


def _check_free_space(directory: Path, needed: int) -> None:
    try:
        free = shutil.disk_usage(str(directory)).free
    except OSError:
        return
    if free < needed * 1.05:
        raise AttachmentError(
            "There is not enough free disk space to save the decrypted attachment."
        )
