from __future__ import annotations

import hashlib
import json
import os
import struct
import time

import pytest

from crypted_mail.core.attachments import (
    ABYTES,
    CMENC_MAGIC,
    HEADERBYTES,
    MIN_CHUNK_SIZE,
    PROLOGUE_SIZE,
    AttachmentHeader,
    decrypt_file_with_passphrase,
    encrypt_file_with_passphrase,
    encrypted_name_for,
    read_attachment_header,
    sanitize_attachment_filename,
)
from crypted_mail.core.exceptions import (
    AttachmentDecryptionError,
    AttachmentError,
    AttachmentIntegrityError,
)


PASSPHRASE = "correct horse battery staple"


def _write_archive(path, size: int):
    payload = b"PK\x03\x04" + os.urandom(max(0, size - 4)) if size >= 4 else os.urandom(size)
    path.write_bytes(payload[:size])
    return path


def _round_trip(tmp_path, size: int, chunk_size: int = MIN_CHUNK_SIZE):
    source = _write_archive(tmp_path / "report.zip", size)
    encrypted = tmp_path / "report.zip.cmenc"
    recovered = tmp_path / "out" / "report.zip"
    encrypt_file_with_passphrase(source, encrypted, PASSPHRASE, chunk_size=chunk_size)
    decrypt_file_with_passphrase(encrypted, recovered, PASSPHRASE)
    return source, encrypted, recovered


def test_cmenc_round_trip_preserves_bytes(tmp_path):
    source, encrypted, recovered = _round_trip(tmp_path, 100_000)
    assert recovered.read_bytes() == source.read_bytes()
    assert encrypted.read_bytes()[:8] == CMENC_MAGIC


@pytest.mark.parametrize("size", [0, 1, 4095, 4096, 4097, 8192, 12289])
def test_round_trip_across_chunk_boundaries(tmp_path, size):
    source, _, recovered = _round_trip(tmp_path, size)
    assert recovered.read_bytes() == source.read_bytes()
    assert recovered.stat().st_size == size


def test_header_declares_source_metadata(tmp_path):
    source, encrypted, _ = _round_trip(tmp_path, 5000)
    header = read_attachment_header(encrypted)
    assert header.filename == "report.zip"
    assert header.plaintext_size == 5000
    assert header.plaintext_sha256 == hashlib.sha256(source.read_bytes()).hexdigest()


def test_read_attachment_header_needs_no_passphrase(tmp_path):
    _, encrypted, _ = _round_trip(tmp_path, 2048)
    assert read_attachment_header(encrypted).chunk_size == MIN_CHUNK_SIZE


def test_wrong_passphrase_raises_attachment_decryption_error(tmp_path):
    _, encrypted, _ = _round_trip(tmp_path, 9000)
    target = tmp_path / "wrong" / "report.zip"
    with pytest.raises(AttachmentDecryptionError):
        decrypt_file_with_passphrase(encrypted, target, "not the passphrase")


def test_decrypt_leaves_no_partial_output_on_failure(tmp_path):
    _, encrypted, _ = _round_trip(tmp_path, 40_000)
    target = tmp_path / "wrong" / "report.zip"
    with pytest.raises(AttachmentDecryptionError):
        decrypt_file_with_passphrase(encrypted, target, "nope")
    assert not target.exists()
    assert not list(target.parent.glob("*.part"))


def test_tampered_ciphertext_is_rejected(tmp_path):
    _, encrypted, _ = _round_trip(tmp_path, 20_000)
    raw = bytearray(encrypted.read_bytes())
    raw[-20] ^= 0xFF
    encrypted.write_bytes(bytes(raw))
    with pytest.raises(AttachmentDecryptionError):
        decrypt_file_with_passphrase(encrypted, tmp_path / "out.zip", PASSPHRASE)


def test_tampered_header_is_rejected(tmp_path):
    """Rewrite the declared filename at *equal length* so HEADER_LEN stays valid.

    A different-length edit would be caught by the length prefix and would prove
    nothing about the additional-data binding.
    """
    _, encrypted, _ = _round_trip(tmp_path, 6000)
    raw = encrypted.read_bytes()
    assert b'"report.zip"' in raw
    encrypted.write_bytes(raw.replace(b'"report.zip"', b'"payrol.zip"', 1))

    assert read_attachment_header(encrypted).filename == "payrol.zip"
    with pytest.raises(AttachmentDecryptionError):
        decrypt_file_with_passphrase(encrypted, tmp_path / "out.zip", PASSPHRASE)


def test_truncated_final_chunk_is_rejected(tmp_path):
    _, encrypted, _ = _round_trip(tmp_path, 20_000)
    raw = encrypted.read_bytes()
    encrypted.write_bytes(raw[:-40])
    with pytest.raises((AttachmentIntegrityError, AttachmentDecryptionError)):
        decrypt_file_with_passphrase(encrypted, tmp_path / "out.zip", PASSPHRASE)


def test_removing_the_whole_final_chunk_is_rejected(tmp_path):
    """Truncate on an exact frame boundary.

    Every surviving chunk still authenticates, so only the missing TAG_FINAL
    reveals the truncation.
    """
    _, encrypted, _ = _round_trip(tmp_path, MIN_CHUNK_SIZE * 3)
    raw = encrypted.read_bytes()
    prologue_len = len(raw) - 3 * (MIN_CHUNK_SIZE + ABYTES)
    encrypted.write_bytes(raw[: prologue_len + 2 * (MIN_CHUNK_SIZE + ABYTES)])

    target = tmp_path / "out.zip"
    with pytest.raises(AttachmentIntegrityError):
        decrypt_file_with_passphrase(encrypted, target, PASSPHRASE)
    assert not target.exists()


def test_trailing_data_after_final_chunk_is_rejected(tmp_path):
    """An exact multiple of the chunk size leaves a full final frame.

    The appended bytes therefore land *after* a complete, authentic stream,
    which is the case the explicit trailing-data check exists for.
    """
    _, encrypted, _ = _round_trip(tmp_path, MIN_CHUNK_SIZE * 2)
    with encrypted.open("ab") as handle:
        handle.write(b"extra")
    with pytest.raises(AttachmentIntegrityError):
        decrypt_file_with_passphrase(encrypted, tmp_path / "out.zip", PASSPHRASE)


def test_trailing_data_inside_the_final_frame_is_rejected(tmp_path):
    """With a ragged final chunk the extra bytes corrupt that frame instead."""
    _, encrypted, _ = _round_trip(tmp_path, 5000)
    with encrypted.open("ab") as handle:
        handle.write(b"extra")
    with pytest.raises(AttachmentDecryptionError):
        decrypt_file_with_passphrase(encrypted, tmp_path / "out.zip", PASSPHRASE)


def test_non_cmenc_file_is_rejected(tmp_path):
    stray = tmp_path / "notes.txt"
    stray.write_bytes(b"just some text, definitely not an envelope")
    with pytest.raises(AttachmentError):
        read_attachment_header(stray)


def _rebuild_with_header(tmp_path, mutate):
    source, encrypted, _ = _round_trip(tmp_path, 3000)
    raw = encrypted.read_bytes()
    (header_len,) = struct.unpack(">I", raw[10:14])
    header = json.loads(raw[PROLOGUE_SIZE : PROLOGUE_SIZE + header_len].decode("utf-8"))
    mutate(header)
    new_json = json.dumps(header, sort_keys=True, separators=(",", ":")).encode("utf-8")
    hostile = tmp_path / "hostile.cmenc"
    hostile.write_bytes(
        raw[:10]
        + struct.pack(">I", len(new_json))
        + new_json
        + raw[PROLOGUE_SIZE + header_len :]
    )
    return hostile


def test_hostile_kdf_memlimit_is_rejected_before_kdf_runs(tmp_path):
    hostile = _rebuild_with_header(tmp_path, lambda h: h.update(kdf_memlimit=2**40))
    started = time.monotonic()
    with pytest.raises(AttachmentError):
        decrypt_file_with_passphrase(hostile, tmp_path / "out.zip", PASSPHRASE)
    assert time.monotonic() - started < 5.0


def test_hostile_chunk_size_is_rejected(tmp_path):
    hostile = _rebuild_with_header(tmp_path, lambda h: h.update(chunk_size=1 << 30))
    with pytest.raises(AttachmentError):
        decrypt_file_with_passphrase(hostile, tmp_path / "out.zip", PASSPHRASE)


def test_unknown_header_keys_are_ignored(tmp_path):
    """A v2 writer adding a field must not crash a v1 reader."""
    header = AttachmentHeader(
        filename="a.zip",
        plaintext_size=1,
        plaintext_sha256="ab" * 32,
        kdf_salt_b64=read_attachment_header(_round_trip(tmp_path, 100)[1]).kdf_salt_b64,
        kdf_opslimit=3,
        kdf_memlimit=268435456,
        chunk_size=MIN_CHUNK_SIZE,
        created_at="2026-08-24T00:00:00+00:00",
    )
    data = header.to_dict()
    data["future_field"] = {"nested": True}
    parsed = AttachmentHeader.from_json_bytes(json.dumps(data).encode("utf-8"))
    assert parsed.filename == "a.zip"


def test_progress_callback_is_monotonic_and_ends_at_total(tmp_path):
    source = _write_archive(tmp_path / "report.zip", 3_000_000)
    seen: list[tuple[int, int]] = []
    encrypt_file_with_passphrase(
        source,
        tmp_path / "report.zip.cmenc",
        PASSPHRASE,
        chunk_size=MIN_CHUNK_SIZE,
        on_progress=lambda done, total: seen.append((done, total)),
    )
    assert seen, "expected at least one progress callback"
    assert [done for done, _ in seen] == sorted(done for done, _ in seen)
    assert seen[-1] == (3_000_000, 3_000_000)
    assert len(seen) < 50, "progress callbacks should be throttled, not per-chunk"


def test_cancellation_stops_encryption_and_cleans_up(tmp_path):
    source = _write_archive(tmp_path / "report.zip", 200_000)
    encrypted = tmp_path / "report.zip.cmenc"
    with pytest.raises(AttachmentError):
        encrypt_file_with_passphrase(
            source, encrypted, PASSPHRASE, chunk_size=MIN_CHUNK_SIZE, should_cancel=lambda: True
        )
    assert not encrypted.exists()
    assert not list(tmp_path.glob("*.part"))


def test_encrypt_requires_a_passphrase(tmp_path):
    source = _write_archive(tmp_path / "report.zip", 10)
    with pytest.raises(AttachmentError):
        encrypt_file_with_passphrase(source, tmp_path / "out.cmenc", "")


def test_encrypted_name_for_appends_suffix(tmp_path):
    assert encrypted_name_for(tmp_path / "report.tar.gz") == "report.tar.gz.cmenc"


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("../../evil.zip", "evil.zip"),
        ("..\\..\\evil.zip", "evil.zip"),
        ("C:\\Windows\\evil.zip", "C_\\Windows\\evil.zip".replace("\\", "/").rsplit("/", 1)[-1]),
        ("a/b.zip", "b.zip"),
        ("CON", "_CON"),
        ("con.zip", "_con.zip"),
        ("", "attachment"),
        (".", "attachment"),
        ("...", "attachment"),
        ("a\x00b.zip", "a"),
        ("re<po>rt.zip", "re_po_rt.zip"),
    ],
)
def test_sanitize_attachment_filename(raw, expected):
    assert sanitize_attachment_filename(raw) == expected


def test_sanitize_strips_bidi_override(tmp_path):
    assert "\u202e" not in sanitize_attachment_filename("exe\u202egpj.zip")


def test_sanitize_caps_length():
    assert len(sanitize_attachment_filename("x" * 400 + ".zip")) <= 120


def test_header_bytes_layout(tmp_path):
    _, encrypted, _ = _round_trip(tmp_path, 1000)
    raw = encrypted.read_bytes()
    (version,) = struct.unpack(">H", raw[8:10])
    (header_len,) = struct.unpack(">I", raw[10:14])
    assert version == 1
    assert raw[PROLOGUE_SIZE + header_len :][:HEADERBYTES] != b"\x00" * HEADERBYTES
