from __future__ import annotations

from pathlib import Path

from PySide6.QtGui import QIcon
from PySide6.QtWidgets import (
    QCheckBox,
    QFileDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QPlainTextEdit,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from crypted_mail.core.envelope import PUBLIC_KEY_MODE, SHARED_PASSPHRASE_MODE, build_email_body
from crypted_mail.core.exceptions import CryptedMailError, GmailConfigurationError
from crypted_mail.services.app_context import AppContext


ICON_PATH = Path(__file__).resolve().parents[1] / "assets" / "crypted_mail.ico"
APP_STYLESHEET = """
QMainWindow {
    background: #f4f1ea;
}
QTabWidget::pane {
    border: 1px solid #d7ccb7;
    background: #fbf8f2;
}
QTabBar::tab {
    background: #eadfcf;
    color: #43382b;
    padding: 10px 18px;
    border: 1px solid #d7ccb7;
    margin-right: 2px;
}
QTabBar::tab:selected {
    background: #fbf8f2;
    font-weight: 700;
}
QGroupBox {
    border: 1px solid #d7ccb7;
    border-radius: 12px;
    margin-top: 14px;
    padding: 16px 12px 12px 12px;
    font-weight: 700;
    color: #43382b;
    background: #fffdf9;
}
QGroupBox::title {
    subcontrol-origin: margin;
    left: 12px;
    padding: 0 4px 0 4px;
}
QLabel {
    color: #43382b;
}
QCheckBox {
    color: #43382b;
}
QLineEdit, QPlainTextEdit, QListWidget {
    background: white;
    color: #2b241c;
    border: 1px solid #c6b79d;
    border-radius: 10px;
    padding: 8px;
    selection-background-color: #c25d2e;
    selection-color: #fffaf2;
}
QLineEdit[readOnly="true"], QPlainTextEdit[readOnly="true"] {
    color: #2b241c;
    background: #fffdf9;
}
QLineEdit::placeholder, QPlainTextEdit::placeholder {
    color: #8a7b66;
}
QPushButton {
    background: #1f3a5f;
    color: white;
    border: none;
    border-radius: 12px;
    padding: 10px 16px;
    font-weight: 700;
}
QPushButton:hover {
    background: #284e7b;
}
QPushButton#secondaryButton {
    background: #d8b98b;
    color: #34261c;
}
QPushButton#dangerButton {
    background: #8c3a2b;
}
"""


class MainWindow(QMainWindow):
    def __init__(self, app_context: AppContext):
        super().__init__()
        self.app_context = app_context
        self.setWindowTitle("Crypted Mail")
        self.resize(1080, 820)
        self.setStyleSheet(APP_STYLESHEET)
        if ICON_PATH.exists():
            self.setWindowIcon(QIcon(str(ICON_PATH)))

        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)
        self._build_setup_tab()
        self._build_compose_tab()
        self._build_decrypt_tab()
        self._build_advanced_tab()
        self._refresh_ui()

    def _build_setup_tab(self) -> None:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.addWidget(self._hero_label("Send encrypted email with a shared passphrase."))

        guidance = QLabel(
            "The Gmail account is only used to send mail. Share the passphrase separately by phone, chat, or in person."
        )
        guidance.setWordWrap(True)
        layout.addWidget(guidance)

        sender_box = QGroupBox("Sender Account")
        sender_layout = QFormLayout(sender_box)
        self.sender_email_input = QLineEdit()
        self.oauth_secret_path_input = QLineEdit()
        sender_layout.addRow("Sender Gmail", self.sender_email_input)
        sender_layout.addRow("OAuth secret JSON", self.oauth_secret_path_input)
        layout.addWidget(sender_box)

        sender_buttons = QHBoxLayout()
        browse_button = QPushButton("Browse OAuth JSON")
        browse_button.setObjectName("secondaryButton")
        browse_button.clicked.connect(self._choose_oauth_secret)
        connect_button = QPushButton("Connect Gmail")
        connect_button.clicked.connect(self._connect_gmail)
        disconnect_button = QPushButton("Disconnect Gmail")
        disconnect_button.setObjectName("dangerButton")
        disconnect_button.clicked.connect(self._disconnect_gmail)
        sender_buttons.addWidget(browse_button)
        sender_buttons.addWidget(connect_button)
        sender_buttons.addWidget(disconnect_button)
        layout.addLayout(sender_buttons)

        passphrase_box = QGroupBox("Remembered Passphrase")
        passphrase_layout = QFormLayout(passphrase_box)
        self.default_passphrase_input = QLineEdit()
        self.default_passphrase_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.remember_passphrase_checkbox = QCheckBox("Remember my default sender passphrase securely on this Windows machine")
        self.remember_passphrase_checkbox.stateChanged.connect(self._toggle_remembered_passphrase)
        passphrase_layout.addRow("Default passphrase", self.default_passphrase_input)
        passphrase_layout.addRow("", self.remember_passphrase_checkbox)
        layout.addWidget(passphrase_box)

        self.setup_status = QLabel()
        self.setup_status.setWordWrap(True)
        layout.addWidget(self.setup_status)
        layout.addStretch(1)
        self.tabs.addTab(page, "Setup")

    def _build_compose_tab(self) -> None:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.addWidget(self._hero_label("Encrypt with passphrase"))

        compose_box = QGroupBox("Message")
        form = QFormLayout(compose_box)
        self.compose_recipient_email = QLineEdit()
        self.compose_subject = QLineEdit()
        self.compose_note = QLineEdit()
        self.compose_passphrase = QLineEdit()
        self.compose_passphrase.setEchoMode(QLineEdit.EchoMode.Password)
        self.compose_passphrase_confirm = QLineEdit()
        self.compose_passphrase_confirm.setEchoMode(QLineEdit.EchoMode.Password)
        form.addRow("Recipient email", self.compose_recipient_email)
        form.addRow("Subject", self.compose_subject)
        form.addRow("Passphrase", self.compose_passphrase)
        form.addRow("Confirm passphrase", self.compose_passphrase_confirm)
        form.addRow("Optional note", self.compose_note)
        layout.addWidget(compose_box)

        self.compose_plaintext = QPlainTextEdit()
        self.compose_plaintext.setPlaceholderText("Write the plaintext you want to encrypt before sending.")
        layout.addWidget(self.compose_plaintext)

        actions = QHBoxLayout()
        use_default_button = QPushButton("Use Remembered Passphrase")
        use_default_button.setObjectName("secondaryButton")
        use_default_button.clicked.connect(self._load_default_passphrase_into_form)
        send_button = QPushButton("Encrypt And Send")
        send_button.clicked.connect(self._send_message_model_a)
        actions.addWidget(use_default_button)
        actions.addWidget(send_button)
        layout.addLayout(actions)

        self.compose_status = QLabel()
        self.compose_status.setWordWrap(True)
        layout.addWidget(self.compose_status)
        self.tabs.addTab(page, "Compose")

    def _build_decrypt_tab(self) -> None:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.addWidget(self._hero_label("Decrypt shared-passphrase or legacy public-key messages"))

        self.decrypt_input = QPlainTextEdit()
        self.decrypt_input.setPlaceholderText("Paste the armored encrypted block here.")
        layout.addWidget(self.decrypt_input)

        decrypt_box = QGroupBox("Decrypt")
        decrypt_form = QFormLayout(decrypt_box)
        self.decrypt_passphrase = QLineEdit()
        self.decrypt_passphrase.setEchoMode(QLineEdit.EchoMode.Password)
        self.decrypt_profile_passphrase = QLineEdit()
        self.decrypt_profile_passphrase.setEchoMode(QLineEdit.EchoMode.Password)
        decrypt_form.addRow("Shared passphrase", self.decrypt_passphrase)
        decrypt_form.addRow("Legacy profile passphrase", self.decrypt_profile_passphrase)
        layout.addWidget(decrypt_box)

        decrypt_button = QPushButton("Decrypt")
        decrypt_button.clicked.connect(self._decrypt_message)
        layout.addWidget(decrypt_button)

        self.decrypt_mode_label = QLabel("Paste a message to detect the decrypt mode.")
        self.decrypt_mode_label.setWordWrap(True)
        layout.addWidget(self.decrypt_mode_label)

        self.decrypt_output = QPlainTextEdit()
        self.decrypt_output.setReadOnly(True)
        layout.addWidget(self.decrypt_output)
        self.tabs.addTab(page, "Decrypt")

    def _build_advanced_tab(self) -> None:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.addWidget(self._hero_label("Advanced public-key mode"))

        info = QLabel(
            "This section preserves the original recipient key workflow for older messages and advanced users."
        )
        info.setWordWrap(True)
        layout.addWidget(info)

        profile_box = QGroupBox("Legacy Local Profile")
        profile_form = QFormLayout(profile_box)
        self.legacy_display_name_input = QLineEdit()
        self.legacy_profile_passphrase_input = QLineEdit()
        self.legacy_profile_passphrase_input.setEchoMode(QLineEdit.EchoMode.Password)
        profile_form.addRow("Display name", self.legacy_display_name_input)
        profile_form.addRow("Profile passphrase", self.legacy_profile_passphrase_input)
        layout.addWidget(profile_box)

        profile_buttons = QHBoxLayout()
        create_profile_button = QPushButton("Create Legacy Profile")
        create_profile_button.setObjectName("secondaryButton")
        create_profile_button.clicked.connect(self._create_legacy_profile)
        export_button = QPushButton("Export My Public Key")
        export_button.clicked.connect(self._export_public_key)
        profile_buttons.addWidget(create_profile_button)
        profile_buttons.addWidget(export_button)
        layout.addLayout(profile_buttons)

        self.public_key_output = QPlainTextEdit()
        self.public_key_output.setReadOnly(True)
        layout.addWidget(self.public_key_output)

        keys_box = QGroupBox("Recipient Keys")
        keys_layout = QVBoxLayout(keys_box)
        self.import_key_input = QPlainTextEdit()
        self.import_key_input.setPlaceholderText("Paste an armored recipient public key block here.")
        import_button = QPushButton("Import Recipient Public Key")
        import_button.clicked.connect(self._import_public_key)
        self.recipient_list = QListWidget()
        keys_layout.addWidget(self.import_key_input)
        keys_layout.addWidget(import_button)
        keys_layout.addWidget(self.recipient_list)
        layout.addWidget(keys_box)

        advanced_send_box = QGroupBox("Legacy Send")
        advanced_form = QFormLayout(advanced_send_box)
        self.advanced_recipient_email = QLineEdit()
        self.advanced_subject = QLineEdit()
        self.advanced_note = QLineEdit()
        advanced_form.addRow("Recipient email", self.advanced_recipient_email)
        advanced_form.addRow("Subject", self.advanced_subject)
        advanced_form.addRow("Note", self.advanced_note)
        layout.addWidget(advanced_send_box)

        self.advanced_plaintext = QPlainTextEdit()
        self.advanced_plaintext.setPlaceholderText("Legacy public-key plaintext.")
        layout.addWidget(self.advanced_plaintext)

        advanced_send_button = QPushButton("Encrypt And Send With Public Key")
        advanced_send_button.clicked.connect(self._send_message_advanced)
        layout.addWidget(advanced_send_button)

        self.advanced_status = QLabel()
        self.advanced_status.setWordWrap(True)
        layout.addWidget(self.advanced_status)
        self.tabs.addTab(page, "Advanced")

    def _hero_label(self, text: str) -> QLabel:
        label = QLabel(text)
        label.setStyleSheet("font-size: 22px; font-weight: 700; color: #1f3a5f; padding: 8px 0 8px 0;")
        label.setWordWrap(True)
        return label

    def _choose_oauth_secret(self) -> None:
        filename, _ = QFileDialog.getOpenFileName(self, "Select Google OAuth Secret JSON", "", "JSON Files (*.json)")
        if filename:
            self.oauth_secret_path_input.setText(filename)

    def _connect_gmail(self) -> None:
        try:
            email = self.sender_email_input.text().strip()
            secret_path = self.oauth_secret_path_input.text().strip()
            self.app_context.mail_service.connect_gmail_oauth(secret_path, email)
            state = self.app_context.repository.load_state()
            state.sender_email = email
            self.app_context.repository.save_state(state)
            self.setup_status.setText(f"Gmail connected for {email}.")
            self._refresh_ui()
        except Exception as exc:
            self._show_error(exc)

    def _disconnect_gmail(self) -> None:
        try:
            sender = self._current_sender_email()
            if not sender:
                raise GmailConfigurationError("There is no connected Gmail sender to disconnect.")
            self.app_context.mail_service.disconnect_gmail(sender)
            self.setup_status.setText("Gmail connection removed.")
            self._refresh_ui()
        except Exception as exc:
            self._show_error(exc)

    def _toggle_remembered_passphrase(self) -> None:
        state = self.app_context.repository.load_state()
        sender = self._current_sender_email()
        state.remember_default_passphrase = self.remember_passphrase_checkbox.isChecked()
        self.app_context.repository.save_state(state)
        try:
            if not sender:
                return
            if state.remember_default_passphrase:
                if not self.app_context.repository.secure_value_store.is_available():
                    self.remember_passphrase_checkbox.setChecked(False)
                    state.remember_default_passphrase = False
                    self.app_context.repository.save_state(state)
                    raise CryptedMailError("Secure Windows credential storage is unavailable, so remembering the passphrase is disabled.")
                self.app_context.repository.save_default_passphrase(sender, self.default_passphrase_input.text())
            else:
                self.app_context.repository.clear_default_passphrase(sender)
        except Exception as exc:
            self._show_error(exc)

    def _load_default_passphrase_into_form(self) -> None:
        sender = self._current_sender_email()
        if not sender:
            self._show_error(CryptedMailError("Connect Gmail first so the app knows which sender passphrase to load."))
            return
        saved = self.app_context.repository.load_default_passphrase(sender)
        if not saved:
            self._show_error(CryptedMailError("No remembered default passphrase is stored for this sender."))
            return
        self.compose_passphrase.setText(saved)
        self.compose_passphrase_confirm.setText(saved)

    def _send_message_model_a(self) -> None:
        try:
            sender = self._require_connected_sender()
            passphrase = self.compose_passphrase.text()
            confirm = self.compose_passphrase_confirm.text()
            if not passphrase:
                raise CryptedMailError("Enter a shared passphrase before sending.")
            if passphrase != confirm:
                raise CryptedMailError("The shared passphrase and confirmation do not match.")

            note = self.compose_note.text().strip() or None
            armored = self.app_context.crypto_service.encrypt_with_passphrase(
                plaintext=self.compose_plaintext.toPlainText(),
                passphrase=passphrase,
                sender_hint=sender,
                note=note,
            )
            email_body = build_email_body(armored, note=note)
            message_id = self.app_context.mail_service.send_encrypted_email(
                sender=sender,
                recipient_email=self.compose_recipient_email.text().strip(),
                subject=self.compose_subject.text().strip() or "Encrypted message",
                armored_payload=email_body,
            )
            self.compose_status.setText(f"Shared-passphrase email sent. Gmail message id: {message_id}")
            self._persist_default_passphrase_if_enabled(sender, passphrase)
        except Exception as exc:
            self._show_error(exc)

    def _decrypt_message(self) -> None:
        try:
            envelope = self.app_context.crypto_service.parse_message(self.decrypt_input.toPlainText())
            if envelope.mode == SHARED_PASSPHRASE_MODE:
                self.decrypt_mode_label.setText("Detected mode: shared passphrase")
                plaintext = self.app_context.crypto_service.decrypt_with_passphrase(
                    self.decrypt_input.toPlainText(), self.decrypt_passphrase.text()
                )
            elif envelope.mode == PUBLIC_KEY_MODE:
                self.decrypt_mode_label.setText("Detected mode: legacy public-key message")
                profile = self.app_context.key_service.get_profile()
                plaintext = self.app_context.crypto_service.decrypt_message(
                    self.decrypt_input.toPlainText(),
                    profile,
                    self.decrypt_profile_passphrase.text(),
                )
            else:
                raise CryptedMailError("Unsupported decrypt mode.")
            self.decrypt_output.setPlainText(plaintext)
        except Exception as exc:
            self._show_error(exc)

    def _create_legacy_profile(self) -> None:
        try:
            sender = self._current_sender_email()
            email = sender or self.sender_email_input.text().strip()
            profile = self.app_context.key_service.create_profile(
                self.legacy_display_name_input.text().strip() or "Crypted Mail User",
                email,
                self.legacy_profile_passphrase_input.text(),
            )
            self.advanced_status.setText(f"Legacy profile created for {profile.email}.")
            self._refresh_ui()
        except Exception as exc:
            self._show_error(exc)

    def _export_public_key(self) -> None:
        try:
            self.public_key_output.setPlainText(self.app_context.key_service.export_public_key())
        except Exception as exc:
            self._show_error(exc)

    def _import_public_key(self) -> None:
        try:
            recipient = self.app_context.key_service.import_recipient(self.import_key_input.toPlainText())
            self.import_key_input.clear()
            self._refresh_recipients()
            self._show_info(f"Imported key for {recipient.email}.")
        except Exception as exc:
            self._show_error(exc)

    def _send_message_advanced(self) -> None:
        try:
            profile = self.app_context.key_service.get_profile()
            recipient = self.app_context.key_service.get_recipient(self.advanced_recipient_email.text().strip())
            note = self.advanced_note.text().strip() or None
            armored = self.app_context.crypto_service.encrypt_for_recipient(
                plaintext=self.advanced_plaintext.toPlainText(),
                recipient=recipient,
                sender_hint=profile.email,
                note=note,
            )
            email_body = build_email_body(armored, note=note)
            message_id = self.app_context.mail_service.send_encrypted_email(
                sender=profile.email,
                recipient_email=recipient.email,
                subject=self.advanced_subject.text().strip() or "Encrypted message",
                armored_payload=email_body,
            )
            self.advanced_status.setText(f"Legacy public-key email sent. Gmail message id: {message_id}")
        except Exception as exc:
            self._show_error(exc)

    def _persist_default_passphrase_if_enabled(self, sender: str, passphrase: str) -> None:
        state = self.app_context.repository.load_state()
        if not state.remember_default_passphrase:
            return
        if not self.app_context.repository.secure_value_store.is_available():
            raise CryptedMailError("Secure Windows credential storage is unavailable, so the passphrase cannot be remembered.")
        self.app_context.repository.save_default_passphrase(sender, passphrase)

    def _require_connected_sender(self) -> str:
        sender = self._current_sender_email()
        if not sender:
            raise GmailConfigurationError("Connect Gmail first so the app can send mail.")
        return sender

    def _current_sender_email(self) -> str | None:
        state = self.app_context.repository.load_state()
        return (state.sender_email or state.gmail_account_email or "").strip() or None

    def _refresh_ui(self) -> None:
        state = self.app_context.repository.load_state()
        profile = self.app_context.repository.load_profile()
        sender = self._current_sender_email()
        if sender:
            self.sender_email_input.setText(sender)
        if state.oauth_secret_path:
            self.oauth_secret_path_input.setText(state.oauth_secret_path)
        self.remember_passphrase_checkbox.setChecked(state.remember_default_passphrase)
        if sender and state.remember_default_passphrase:
            saved = self.app_context.repository.load_default_passphrase(sender)
            if saved:
                self.default_passphrase_input.setText(saved)
        if profile is not None:
            self.legacy_display_name_input.setText(profile.display_name)
        self.setup_status.setText(self._status_text(state, profile))
        self._refresh_recipients()

    def _refresh_recipients(self) -> None:
        self.recipient_list.clear()
        for recipient in self.app_context.key_service.list_recipients():
            self.recipient_list.addItem(f"{recipient.name} <{recipient.email}> [{recipient.fingerprint}]")

    @staticmethod
    def _status_text(state, profile) -> str:
        gmail_status = f"Gmail connected: {state.gmail_account_email}" if state.gmail_connected else "Gmail not connected."
        profile_status = "Legacy public-key profile ready." if profile else "Legacy public-key profile not created."
        remember_status = "Remembered passphrase is enabled." if state.remember_default_passphrase else "Remembered passphrase is disabled."
        return f"{gmail_status} {profile_status} {remember_status}"

    def _show_error(self, exc: Exception) -> None:
        text = str(exc) if isinstance(exc, (CryptedMailError, GmailConfigurationError)) else f"Unexpected error: {exc}"
        QMessageBox.critical(self, "Crypted Mail", text)

    def _show_info(self, text: str) -> None:
        QMessageBox.information(self, "Crypted Mail", text)
