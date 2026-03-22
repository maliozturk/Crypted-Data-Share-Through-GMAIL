from __future__ import annotations

from PySide6.QtWidgets import QMessageBox

from crypted_mail.desktop.window import MainWindow


def test_send_succeeds_without_recipient_key(monkeypatch, qtbot, app_context):
    window = MainWindow(app_context)
    qtbot.addWidget(window)
    state = app_context.repository.load_state()
    state.gmail_connected = True
    state.gmail_account_email = "alice@example.com"
    state.sender_email = "alice@example.com"
    app_context.repository.save_state(state)

    monkeypatch.setattr(app_context.mail_service, "send_encrypted_email", lambda sender, recipient_email, subject, armored_payload: "msg-1")
    window.compose_recipient_email.setText("bob@example.com")
    window.compose_subject.setText("Secret")
    window.compose_passphrase.setText("shared secret")
    window.compose_passphrase_confirm.setText("shared secret")
    window.compose_plaintext.setPlainText("hello")
    window._send_message_model_a()

    assert "msg-1" in window.compose_status.text()


def test_passphrase_mismatch_blocks_send(monkeypatch, qtbot, app_context):
    window = MainWindow(app_context)
    qtbot.addWidget(window)
    state = app_context.repository.load_state()
    state.gmail_connected = True
    state.gmail_account_email = "alice@example.com"
    state.sender_email = "alice@example.com"
    app_context.repository.save_state(state)
    captured = {}

    def fake_critical(parent, title, text):
        captured["text"] = text
        return QMessageBox.StandardButton.Ok

    monkeypatch.setattr(QMessageBox, "critical", fake_critical)
    window.compose_recipient_email.setText("bob@example.com")
    window.compose_passphrase.setText("one")
    window.compose_passphrase_confirm.setText("two")
    window.compose_plaintext.setPlainText("hello")
    window._send_message_model_a()
    assert "do not match" in captured["text"]


def test_decrypt_screen_detects_shared_passphrase(monkeypatch, qtbot, app_context):
    window = MainWindow(app_context)
    qtbot.addWidget(window)
    armored = app_context.crypto_service.encrypt_with_passphrase("hello", "shared")
    window.decrypt_input.setPlainText(armored)
    window.decrypt_passphrase.setText("shared")
    window._decrypt_message()

    assert window.decrypt_output.toPlainText() == "hello"
    assert "shared passphrase" in window.decrypt_mode_label.text()


def test_advanced_mode_still_supports_legacy_keys(monkeypatch, qtbot, app_context):
    window = MainWindow(app_context)
    qtbot.addWidget(window)
    state = app_context.repository.load_state()
    state.gmail_connected = True
    state.gmail_account_email = "alice@example.com"
    state.sender_email = "alice@example.com"
    app_context.repository.save_state(state)
    app_context.key_service.create_profile("Alice", "alice@example.com", "profile passphrase")
    exported = app_context.key_service.export_public_key()
    app_context.key_service.import_recipient(exported)
    monkeypatch.setattr(app_context.mail_service, "send_encrypted_email", lambda sender, recipient_email, subject, armored_payload: "msg-2")

    window.advanced_recipient_email.setText("alice@example.com")
    window.advanced_subject.setText("Legacy")
    window.advanced_plaintext.setPlainText("legacy hello")
    window._send_message_advanced()

    assert "msg-2" in window.advanced_status.text()
