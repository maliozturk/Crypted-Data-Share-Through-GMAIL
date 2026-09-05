from __future__ import annotations

from pathlib import Path

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

    monkeypatch.setattr(app_context.mail_service, "send_encrypted_email", lambda sender, recipient_email, subject, armored_payload, attachments=None: "msg-1")
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


def _connected(app_context, window):
    state = app_context.repository.load_state()
    state.gmail_connected = True
    state.gmail_account_email = "alice@example.com"
    state.sender_email = "alice@example.com"
    app_context.repository.save_state(state)
    return window


def _zip(tmp_path, name="report.zip", size=4096):
    path = tmp_path / name
    path.write_bytes(b"PK\x03\x04" + b"\x77" * (size - 4))
    return path


def test_perform_send_encrypts_and_attaches(monkeypatch, qtbot, app_context, tmp_path):
    window = _connected(app_context, MainWindow(app_context))
    qtbot.addWidget(window)
    captured = {}

    def fake_send(sender, recipient_email, subject, armored_payload, attachments=None):
        captured["attachments"] = list(attachments or [])
        captured["body"] = armored_payload
        return "msg-att"

    monkeypatch.setattr(app_context.mail_service, "send_encrypted_email", fake_send)

    source = _zip(tmp_path)
    window._add_attachment_path(source)
    assert window.compose_attachments.count() == 1

    window.compose_recipient_email.setText("bob@example.com")
    window.compose_passphrase.setText("shared secret")
    window.compose_passphrase_confirm.setText("shared secret")
    window.compose_plaintext.setPlainText("hello")

    # Called synchronously: the threading lives in _start_send_task, not here.
    message_id = window._perform_send(window._build_send_request(), None)

    assert message_id == "msg-att"
    assert [path.name for path in captured["attachments"]] == ["report.zip.cmenc"]
    assert "report.zip.cmenc" in captured["body"]

    recovered = app_context.crypto_service.decrypt_with_passphrase(
        captured["body"], "shared secret"
    )
    assert "hello" in recovered
    assert "report.zip" in recovered


def test_send_cleans_up_the_temp_workspace(monkeypatch, qtbot, app_context, tmp_path):
    window = _connected(app_context, MainWindow(app_context))
    qtbot.addWidget(window)
    seen = {}

    def fake_send(sender, recipient_email, subject, armored_payload, attachments=None):
        seen["workspace"] = Path(list(attachments)[0]).parent
        return "msg-1"

    monkeypatch.setattr(app_context.mail_service, "send_encrypted_email", fake_send)
    window._add_attachment_path(_zip(tmp_path))
    window.compose_recipient_email.setText("bob@example.com")
    window.compose_passphrase.setText("pw")
    window.compose_passphrase_confirm.setText("pw")
    window._perform_send(window._build_send_request(), None)

    assert not seen["workspace"].exists()


def test_unsupported_attachment_type_is_rejected_at_add_time(
    monkeypatch, qtbot, app_context, tmp_path
):
    window = MainWindow(app_context)
    qtbot.addWidget(window)
    captured = {}
    monkeypatch.setattr(
        QMessageBox,
        "critical",
        lambda parent, title, text: captured.setdefault("text", text),
    )

    bad = tmp_path / "notes.pdf"
    bad.write_bytes(b"%PDF-1.7 nope")
    window._add_attachment_path(bad)

    assert window.compose_attachments.count() == 0
    assert "ZIP" in captured["text"] or ".zip" in captured["text"]


def test_duplicate_attachments_are_ignored(qtbot, app_context, tmp_path):
    window = MainWindow(app_context)
    qtbot.addWidget(window)
    source = _zip(tmp_path)
    window._add_attachment_path(source)
    window._add_attachment_path(source)
    assert window.compose_attachments.count() == 1


def test_removing_and_clearing_attachments(qtbot, app_context, tmp_path):
    window = MainWindow(app_context)
    qtbot.addWidget(window)
    window._add_attachment_path(_zip(tmp_path, "a.zip"))
    window._add_attachment_path(_zip(tmp_path, "b.zip"))
    assert window.compose_attachments.count() == 2

    window.compose_attachments.item(0).setSelected(True)
    window._remove_selected_attachments()
    assert window.compose_attachments.count() == 1

    window._clear_attachments()
    assert window.compose_attachments.count() == 0
    assert "No attachments" in window.compose_attachment_summary.text()


def test_text_only_send_stays_synchronous(monkeypatch, qtbot, app_context):
    """Regression guard: the legacy path must never spawn a thread."""
    window = _connected(app_context, MainWindow(app_context))
    qtbot.addWidget(window)
    monkeypatch.setattr(
        app_context.mail_service,
        "send_encrypted_email",
        lambda sender, recipient_email, subject, armored_payload, attachments=None: "msg-sync",
    )
    window.compose_recipient_email.setText("bob@example.com")
    window.compose_passphrase.setText("pw")
    window.compose_passphrase_confirm.setText("pw")
    window.compose_plaintext.setPlainText("hello")
    window._send_message_model_a()

    assert "msg-sync" in window.compose_status.text()
    assert window._send_thread is None


def test_decrypt_tab_recovers_an_attachment(qtbot, app_context, tmp_path):
    window = MainWindow(app_context)
    qtbot.addWidget(window)
    source = _zip(tmp_path, "report.zip", size=9000)
    workspace, prepared = app_context.attachment_service.prepare([source], "shared secret")
    try:
        encrypted = prepared[0].encrypted_path
        window._set_encrypted_attachment(encrypted)
        assert "report.zip" in window.decrypt_attachment_info.text()
        assert "not verified" in window.decrypt_attachment_info.text()

        window.decrypt_passphrase.setText("shared secret")
        target = tmp_path / "recovered.zip"
        window._recover_attachment_to(encrypted, target)

        assert target.read_bytes() == source.read_bytes()
        assert "SHA-256 verified" in window.decrypt_attachment_status.text()
    finally:
        app_context.attachment_service.discard(workspace)


def test_decrypt_tab_requires_a_selected_file(monkeypatch, qtbot, app_context):
    window = MainWindow(app_context)
    qtbot.addWidget(window)
    captured = {}
    monkeypatch.setattr(
        QMessageBox,
        "critical",
        lambda parent, title, text: captured.setdefault("text", text),
    )
    window._decrypt_attachment_file()
    assert "Choose an encrypted attachment" in captured["text"]


def test_auto_update_checkbox_defaults_on(qtbot, app_context):
    window = MainWindow(app_context)
    qtbot.addWidget(window)
    assert window.auto_update_checkbox.isChecked()


def test_auto_update_checkbox_persists(qtbot, app_context):
    window = MainWindow(app_context)
    qtbot.addWidget(window)
    window.auto_update_checkbox.setChecked(False)
    assert app_context.repository.load_state().auto_update_enabled is False


def test_up_to_date_slot_sets_label(qtbot, app_context):
    window = MainWindow(app_context)
    qtbot.addWidget(window)
    window._on_up_to_date("0.2.0")
    assert "Up to date" in window.update_status_label.text()
    assert app_context.repository.load_state().last_update_check_at


def test_failed_check_never_raises_or_prompts(monkeypatch, qtbot, app_context):
    shown = {}
    monkeypatch.setattr(
        QMessageBox, "critical", lambda *a, **k: shown.setdefault("shown", True)
    )
    window = MainWindow(app_context)
    qtbot.addWidget(window)
    window._on_update_check_failed("connection refused")
    assert "failed" in window.update_status_label.text().lower()
    assert "shown" not in shown


def test_pip_channel_shows_upgrade_command(monkeypatch, qtbot, app_context):
    from crypted_mail.services.update_service import UpdateChannel

    window = MainWindow(app_context)
    qtbot.addWidget(window)
    monkeypatch.setattr(window._update_service, "_channel", UpdateChannel.PYPI)
    window._on_update_available("0.3.0", "https://example.invalid")
    assert "pip install -U crypted-mail" in window.update_status_label.text()


def test_github_channel_shows_release_url(monkeypatch, qtbot, app_context):
    from crypted_mail.services.update_service import UpdateChannel

    window = MainWindow(app_context)
    qtbot.addWidget(window)
    monkeypatch.setattr(window._update_service, "_channel", UpdateChannel.GITHUB)
    window._on_update_available("0.3.0", "https://example.invalid/releases")
    assert "https://example.invalid/releases" in window.update_status_label.text()


def test_disabled_updates_are_reported(qtbot, app_context):
    window = MainWindow(app_context)
    qtbot.addWidget(window)
    # conftest sets CRYPTED_MAIL_DISABLE_UPDATES=1 for the whole suite.
    window._start_update_check(manual=True)
    assert "turned off" in window.update_status_label.text()


def test_window_title_carries_the_version(qtbot, app_context):
    from crypted_mail import __version__

    window = MainWindow(app_context)
    qtbot.addWidget(window)
    assert __version__ in window.windowTitle()
