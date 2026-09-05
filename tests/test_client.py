from __future__ import annotations

import hashlib

import pytest

from crypted_mail import CryptedMailClient


PASSPHRASE = "a long shared passphrase"


@pytest.fixture()
def client() -> CryptedMailClient:
    return CryptedMailClient()


def test_client_imports_without_qt():
    """The library surface must not drag in the desktop extra.

    Checked in a fresh interpreter: within the test session other modules have
    already imported PySide6, so sys.modules here would prove nothing.
    """
    import subprocess
    import sys
    import textwrap

    script = textwrap.dedent(
        """
        import sys
        from crypted_mail import CryptedMailClient
        from crypted_mail.client import CryptedMailClient as Direct
        assert CryptedMailClient is Direct
        leaked = sorted(n for n in sys.modules if n.split(".")[0] == "PySide6")
        print("LEAKED:" + ",".join(leaked))
        """
    )
    result = subprocess.run(
        [sys.executable, "-c", script], capture_output=True, text=True, check=True
    )
    assert "LEAKED:\n" in result.stdout or result.stdout.strip() == "LEAKED:"


def test_text_round_trip(client):
    armored = client.encrypt_with_passphrase("hello world", PASSPHRASE)
    assert armored.startswith("cm1:")
    assert client.decrypt_with_passphrase(armored, PASSPHRASE) == "hello world"


def test_encrypt_file_defaults_to_sibling_cmenc(client, tmp_path):
    source = tmp_path / "report.zip"
    source.write_bytes(b"PK\x03\x04" + b"\x42" * 5000)

    encrypted = client.encrypt_file(source, PASSPHRASE)
    assert encrypted.name == "report.zip.cmenc"
    assert encrypted.parent == tmp_path

    recovered = tmp_path / "out" / "report.zip"
    header = client.decrypt_file(encrypted, recovered, PASSPHRASE)
    assert recovered.read_bytes() == source.read_bytes()
    assert header.plaintext_sha256 == hashlib.sha256(source.read_bytes()).hexdigest()


def test_encrypt_file_accepts_explicit_destination(client, tmp_path):
    source = tmp_path / "notes.txt"
    source.write_bytes(b"any bytes at all")
    target = tmp_path / "custom.bin"

    assert client.encrypt_file(source, PASSPHRASE, target) == target
    assert target.exists()


def test_encrypt_and_send_attaches_encrypted_files(client, monkeypatch, tmp_path):
    source = tmp_path / "photos.tar.gz"
    source.write_bytes(b"\x1f\x8b\x08\x00" + b"\x09" * 3000)
    captured = {}

    def fake_send(**kwargs):
        captured.update(kwargs)
        return "gmail-id-1"

    monkeypatch.setattr(client._mail, "send_encrypted_email", fake_send)
    monkeypatch.setattr(
        CryptedMailClient, "credentials_from_any", staticmethod(lambda token: "creds")
    )

    message_id = client.encrypt_and_send_with_passphrase(
        sender="me@gmail.com",
        recipient_email="you@example.com",
        subject="Photos",
        plaintext="see attached",
        passphrase=PASSPHRASE,
        credentials_or_token="{}",
        attachments=[source],
    )

    assert message_id == "gmail-id-1"
    assert [path.name for path in captured["attachments"]] == ["photos.tar.gz.cmenc"]
    assert "photos.tar.gz.cmenc" in captured["armored_payload"]
    assert captured["credentials"] == "creds"


def test_credentials_from_any_rejects_other_types(client):
    with pytest.raises(TypeError):
        CryptedMailClient.credentials_from_any(42)


def test_mail_service_without_repository_refuses_local_storage():
    from crypted_mail.core.exceptions import GmailConfigurationError
    from crypted_mail.services.mail_service import MailService

    service = MailService()
    with pytest.raises(GmailConfigurationError):
        service.load_state()
