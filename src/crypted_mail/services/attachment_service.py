"""Orchestration for encrypted attachments: size policy and temp workspaces.

Mirrors the KeyService -> core.keys relationship: all the crypto lives in
:mod:`crypted_mail.core.attachments`, and this layer owns the decisions that
depend on how the app sends mail.
"""

from __future__ import annotations

import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Sequence

from crypted_mail.core.archives import validate_archive_file
from crypted_mail.core.attachments import (
    AttachmentHeader,
    ProgressCallback,
    decrypt_file_with_passphrase,
    encrypt_file_with_passphrase,
    encrypted_name_for,
)
from crypted_mail.core.exceptions import AttachmentTooLargeError


# Gmail caps a message at 25 MB. MIME base64 inflates attachments by 4/3, and
# .cmenc adds only ~0.007%, so ~19.6 MB of plaintext is the theoretical ceiling.
# 18 MB leaves headroom for the body and MIME boundaries.
MAX_SINGLE_ATTACHMENT_BYTES = 18 * 1024 * 1024
MAX_TOTAL_ATTACHMENT_BYTES = 18 * 1024 * 1024

# (bytes_done, bytes_total, label)
PrepareProgress = Callable[[int, int, str], None]


@dataclass(slots=True)
class PreparedAttachment:
    """One encrypted attachment, staged on disk and ready to send."""

    source_path: Path
    encrypted_path: Path
    encrypted_name: str
    plaintext_size: int
    encrypted_size: int
    plaintext_sha256: str


class AttachmentService:
    max_single_bytes: int = MAX_SINGLE_ATTACHMENT_BYTES
    max_total_bytes: int = MAX_TOTAL_ATTACHMENT_BYTES

    def validate_source(self, path: Path) -> int:
        """Check one candidate file and return its size in bytes."""
        return validate_archive_file(Path(path), max_bytes=self.max_single_bytes)

    def check_total_size(self, paths: Sequence[Path]) -> int:
        """Sum the sizes of *paths*, raising if they exceed what Gmail accepts."""
        total = sum(Path(path).stat().st_size for path in paths if Path(path).is_file())
        if total > self.max_total_bytes:
            raise AttachmentTooLargeError(
                f"Attachments are too large to send. Gmail allows about 25 MB per message, "
                f"and these files come to {human_size(total)}. Remove a file, or split the "
                f"archive into smaller parts."
            )
        return total

    def prepare(
        self,
        source_paths: Sequence[Path],
        passphrase: str,
        *,
        sender_hint: str | None = None,
        on_progress: PrepareProgress | None = None,
        should_cancel: Callable[[], bool] | None = None,
    ) -> tuple[Path, list[PreparedAttachment]]:
        """Encrypt every source file into a fresh temp workspace.

        Returns ``(workspace_dir, prepared)``. The caller **must** pass the
        workspace to :meth:`discard` in a ``finally`` block.
        """
        paths = [Path(path) for path in source_paths]
        for path in paths:
            self.validate_source(path)
        grand_total = self.check_total_size(paths)

        workspace = Path(tempfile.mkdtemp(prefix="crypted-mail-"))
        prepared: list[PreparedAttachment] = []
        completed = 0
        try:
            for path in paths:
                encrypted_name = encrypted_name_for(path)
                encrypted_path = workspace / encrypted_name
                offset = completed

                def relay(done: int, total: int, name: str = path.name) -> None:
                    if on_progress is not None:
                        on_progress(offset + done, grand_total, name)

                header = encrypt_file_with_passphrase(
                    path,
                    encrypted_path,
                    passphrase,
                    sender_hint=sender_hint,
                    on_progress=relay,
                    should_cancel=should_cancel,
                )
                completed += header.plaintext_size
                prepared.append(
                    PreparedAttachment(
                        source_path=path,
                        encrypted_path=encrypted_path,
                        encrypted_name=encrypted_name,
                        plaintext_size=header.plaintext_size,
                        encrypted_size=encrypted_path.stat().st_size,
                        plaintext_sha256=header.plaintext_sha256,
                    )
                )
        except BaseException:
            self.discard(workspace)
            raise
        return workspace, prepared

    def discard(self, workspace_dir: Path | None) -> None:
        """Delete a workspace and the ciphertext staged inside it."""
        if workspace_dir:
            shutil.rmtree(workspace_dir, ignore_errors=True)

    def recover(
        self,
        encrypted_path: Path,
        destination_path: Path,
        passphrase: str,
        *,
        on_progress: ProgressCallback | None = None,
        should_cancel: Callable[[], bool] | None = None,
    ) -> AttachmentHeader:
        """Decrypt one ``.cmenc`` file back to its original archive."""
        return decrypt_file_with_passphrase(
            Path(encrypted_path),
            Path(destination_path),
            passphrase,
            on_progress=on_progress,
            should_cancel=should_cancel,
        )

    def describe_manifest(self, prepared: Sequence[PreparedAttachment]) -> str:
        """Render the human-readable manifest appended to the encrypted text.

        This lives *inside* the ciphertext rather than in the message envelope:
        envelope fields travel in cleartext, so filenames and hashes there would
        be readable by Gmail, and adding a field would crash older clients.
        """
        if not prepared:
            return ""
        lines = ["", "-- Crypted Mail attachments --"]
        for item in prepared:
            lines.append(
                f"{item.source_path.name} - {human_size(item.plaintext_size)} - "
                f"sha256 {item.plaintext_sha256}"
            )
        lines.append(
            "Open each .cmenc file with Crypted Mail > Decrypt > Open Encrypted File."
        )
        return "\n".join(lines)


def human_size(num_bytes: int) -> str:
    value = float(num_bytes)
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024 or unit == "GB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} GB"
