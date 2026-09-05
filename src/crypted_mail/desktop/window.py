from __future__ import annotations

import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from PySide6.QtCore import Qt, QThread, QTimer
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QFileDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QPlainTextEdit,
    QProgressBar,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from crypted_mail.core.archives import ARCHIVE_FILTER
from crypted_mail.core.attachments import CMENC_SUFFIX, read_attachment_header, sanitize_attachment_filename
from crypted_mail.core.envelope import PUBLIC_KEY_MODE, SHARED_PASSPHRASE_MODE, build_email_body
from crypted_mail.core.exceptions import CryptedMailError, GmailConfigurationError
from crypted_mail.services.app_context import AppContext
from crypted_mail.services.attachment_service import human_size
from crypted_mail import __version__
from crypted_mail.desktop.update_worker import UpdateWorker
from crypted_mail.desktop.workers import BackgroundTask
from crypted_mail.services.update_service import UpdateChannel, UpdateService


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


@dataclass(slots=True)
class SendRequest:
    """A snapshot of the compose form.

    The worker thread must never read live widgets, so everything it needs
    is captured on the GUI thread first.
    """

    sender: str
    recipient_email: str
    subject: str
    passphrase: str
    plaintext: str
    note: str | None = None
    attachment_paths: list[Path] = field(default_factory=list)


class MainWindow(QMainWindow):
    def __init__(self, app_context: AppContext):
        super().__init__()
        self.app_context = app_context
        self.setWindowTitle(f"Crypted Mail {__version__}")
        self.resize(1080, 820)
        self.setStyleSheet(APP_STYLESHEET)
        if ICON_PATH.exists():
            self.setWindowIcon(QIcon(str(ICON_PATH)))

        self._send_thread: QThread | None = None
        self._send_worker: BackgroundTask | None = None
        self._attachment_thread: QThread | None = None
        self._attachment_worker: BackgroundTask | None = None
        self._update_service = UpdateService(app_context.repository.paths)
        self._update_worker: UpdateWorker | None = None

        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)
        self._build_setup_tab()
        self._build_compose_tab()
        self._build_decrypt_tab()
        self._build_advanced_tab()
        self._refresh_ui()
        self._start_update_check_on_launch()

    def _start_update_check_on_launch(self) -> None:
        if "--updated" in sys.argv:
            self.update_status_label.setText(f"Updated to v{__version__}.")
            self._update_service.absorb_setup_log(__version__)
            self._record_installed_version()
            return
        # Delayed so the window paints first and does not compete with the
        # first-run Gmail OAuth flow.
        QTimer.singleShot(3000, self._start_update_check)

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

        updates_box = QGroupBox("Updates")
        updates_layout = QVBoxLayout(updates_box)
        self.update_status_label = QLabel(f"Crypted Mail v{__version__}")
        self.update_status_label.setWordWrap(True)
        # Selectable so the pip upgrade command can be copied out.
        self.update_status_label.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextBrowserInteraction
        )
        self.auto_update_checkbox = QCheckBox("Automatically install updates")
        self.auto_update_checkbox.setChecked(True)
        self.auto_update_checkbox.stateChanged.connect(self._toggle_auto_update)
        self.check_updates_button = QPushButton("Check for updates now")
        self.check_updates_button.setObjectName("secondaryButton")
        self.check_updates_button.clicked.connect(lambda: self._start_update_check(manual=True))
        updates_layout.addWidget(self.update_status_label)
        updates_layout.addWidget(self.auto_update_checkbox)
        updates_layout.addWidget(self.check_updates_button)
        layout.addWidget(updates_box)

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

        attachment_box = QGroupBox("Encrypted Attachments (.zip or .tar.gz)")
        attachment_layout = QVBoxLayout(attachment_box)
        self.compose_attachments = QListWidget()
        self.compose_attachments.setSelectionMode(QListWidget.SelectionMode.ExtendedSelection)
        attachment_layout.addWidget(self.compose_attachments)

        attachment_buttons = QHBoxLayout()
        add_attachment_button = QPushButton("Add Archive...")
        add_attachment_button.setObjectName("secondaryButton")
        add_attachment_button.clicked.connect(self._add_attachments)
        remove_attachment_button = QPushButton("Remove Selected")
        remove_attachment_button.setObjectName("dangerButton")
        remove_attachment_button.clicked.connect(self._remove_selected_attachments)
        clear_attachments_button = QPushButton("Clear All")
        clear_attachments_button.setObjectName("secondaryButton")
        clear_attachments_button.clicked.connect(self._clear_attachments)
        attachment_buttons.addWidget(add_attachment_button)
        attachment_buttons.addWidget(remove_attachment_button)
        attachment_buttons.addWidget(clear_attachments_button)
        attachment_layout.addLayout(attachment_buttons)

        self.compose_attachment_summary = QLabel()
        self.compose_attachment_summary.setWordWrap(True)
        attachment_layout.addWidget(self.compose_attachment_summary)
        layout.addWidget(attachment_box)

        self.compose_progress = QProgressBar()
        self.compose_progress.setVisible(False)
        layout.addWidget(self.compose_progress)

        actions = QHBoxLayout()
        use_default_button = QPushButton("Use Remembered Passphrase")
        use_default_button.setObjectName("secondaryButton")
        use_default_button.clicked.connect(self._load_default_passphrase_into_form)
        self.compose_send_button = QPushButton("Encrypt And Send")
        self.compose_send_button.clicked.connect(self._send_message_model_a)
        actions.addWidget(use_default_button)
        actions.addWidget(self.compose_send_button)
        layout.addLayout(actions)

        self.compose_status = QLabel()
        self.compose_status.setWordWrap(True)
        layout.addWidget(self.compose_status)
        self._refresh_attachment_summary()
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

        attachment_box = QGroupBox("Encrypted Attachment (.cmenc)")
        attachment_layout = QVBoxLayout(attachment_box)
        attachment_form = QFormLayout()
        self.decrypt_attachment_path = QLineEdit()
        self.decrypt_attachment_path.setReadOnly(True)
        self.decrypt_attachment_path.setPlaceholderText("No encrypted attachment selected.")
        attachment_form.addRow("Encrypted file", self.decrypt_attachment_path)
        attachment_layout.addLayout(attachment_form)

        self.decrypt_attachment_info = QLabel(
            "Pick a .cmenc file, then use the shared passphrase above to recover the original archive."
        )
        self.decrypt_attachment_info.setWordWrap(True)
        attachment_layout.addWidget(self.decrypt_attachment_info)

        attachment_buttons = QHBoxLayout()
        choose_attachment_button = QPushButton("Open Encrypted File...")
        choose_attachment_button.setObjectName("secondaryButton")
        choose_attachment_button.clicked.connect(self._choose_encrypted_attachment)
        self.decrypt_attachment_button = QPushButton("Decrypt And Save As...")
        self.decrypt_attachment_button.clicked.connect(self._decrypt_attachment_file)
        attachment_buttons.addWidget(choose_attachment_button)
        attachment_buttons.addWidget(self.decrypt_attachment_button)
        attachment_layout.addLayout(attachment_buttons)

        self.decrypt_attachment_progress = QProgressBar()
        self.decrypt_attachment_progress.setVisible(False)
        attachment_layout.addWidget(self.decrypt_attachment_progress)

        self.decrypt_attachment_status = QLabel()
        self.decrypt_attachment_status.setWordWrap(True)
        attachment_layout.addWidget(self.decrypt_attachment_status)
        layout.addWidget(attachment_box)

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

    # ------------------------------------------------------------------
    # Compose: attachments
    # ------------------------------------------------------------------

    def _add_attachments(self) -> None:
        """Open the file picker.

        Kept separate from the logic below so tests never face a modal dialog.
        """
        paths, _ = QFileDialog.getOpenFileNames(
            self, "Select archives to encrypt", "", ARCHIVE_FILTER
        )
        for name in paths:
            self._add_attachment_path(Path(name))

    def _add_attachment_path(self, path: Path) -> None:
        """Validate and list one archive.

        Validating here rather than at send time means the user learns about a
        bad file immediately, not after a long encryption run.
        """
        try:
            resolved = Path(path).resolve()
            size = self.app_context.attachment_service.validate_source(resolved)
            if resolved in self._attachment_paths():
                return
            item = QListWidgetItem(f"{resolved.name} - {human_size(size)}")
            item.setData(Qt.ItemDataRole.UserRole, str(resolved))
            self.compose_attachments.addItem(item)
            self._refresh_attachment_summary()
        except Exception as exc:
            self._show_error(exc)

    def _remove_selected_attachments(self) -> None:
        for item in self.compose_attachments.selectedItems():
            self.compose_attachments.takeItem(self.compose_attachments.row(item))
        self._refresh_attachment_summary()

    def _clear_attachments(self) -> None:
        self.compose_attachments.clear()
        self._refresh_attachment_summary()

    def _attachment_paths(self) -> list[Path]:
        return [
            Path(self.compose_attachments.item(row).data(Qt.ItemDataRole.UserRole))
            for row in range(self.compose_attachments.count())
        ]

    def _refresh_attachment_summary(self) -> None:
        service = self.app_context.attachment_service
        paths = self._attachment_paths()
        if not paths:
            self.compose_attachment_summary.setStyleSheet("")
            self.compose_attachment_summary.setText(
                "No attachments. Each archive you add is encrypted separately as a .cmenc file."
            )
            return
        total = sum(path.stat().st_size for path in paths if path.is_file())
        limit = service.max_total_bytes
        text = (
            f"{len(paths)} file(s), {human_size(total)} of {human_size(limit)} allowed. "
            "Each file is encrypted separately as a .cmenc attachment."
        )
        over_budget = total > limit
        self.compose_attachment_summary.setStyleSheet("color: #8c3a2b;" if over_budget else "")
        if over_budget:
            text += " Remove a file before sending."
        self.compose_attachment_summary.setText(text)

    # ------------------------------------------------------------------
    # Compose: sending
    # ------------------------------------------------------------------

    def _send_message_model_a(self) -> None:
        try:
            request = self._build_send_request()
        except Exception as exc:
            self._show_error(exc)
            return

        if not request.attachment_paths:
            # The text-only path is a sub-second operation and shipped this way.
            # A thread would add lifecycle risk and buy nothing.
            try:
                self._on_send_finished(self._perform_send(request, None))
            except Exception as exc:
                self._show_error(exc)
            return

        self._start_send_task(request)

    def _build_send_request(self) -> SendRequest:
        sender = self._require_connected_sender()
        passphrase = self.compose_passphrase.text()
        confirm = self.compose_passphrase_confirm.text()
        if not passphrase:
            raise CryptedMailError("Enter a shared passphrase before sending.")
        if passphrase != confirm:
            raise CryptedMailError("The shared passphrase and confirmation do not match.")

        attachment_paths = self._attachment_paths()
        if attachment_paths:
            self.app_context.attachment_service.check_total_size(attachment_paths)

        return SendRequest(
            sender=sender,
            recipient_email=self.compose_recipient_email.text().strip(),
            subject=self.compose_subject.text().strip() or "Encrypted message",
            passphrase=passphrase,
            plaintext=self.compose_plaintext.toPlainText(),
            note=self.compose_note.text().strip() or None,
            attachment_paths=attachment_paths,
        )

    def _perform_send(
        self, request: SendRequest, emit_progress: Callable[[int, int, str], None] | None
    ) -> str:
        """Encrypt, attach and send.

        Touches no widgets, so it is safe on any thread - and callable directly
        from tests.
        """
        service = self.app_context.attachment_service
        workspace = None
        try:
            prepared = []
            if request.attachment_paths:
                def on_progress(done: int, total: int, name: str) -> None:
                    if emit_progress is not None:
                        emit_progress(done, total, name)

                workspace, prepared = service.prepare(
                    request.attachment_paths,
                    request.passphrase,
                    sender_hint=request.sender,
                    on_progress=on_progress,
                )

            plaintext = request.plaintext + service.describe_manifest(prepared)
            armored = self.app_context.crypto_service.encrypt_with_passphrase(
                plaintext=plaintext,
                passphrase=request.passphrase,
                sender_hint=request.sender,
                note=request.note,
            )
            attachment_names = [item.encrypted_name for item in prepared]
            email_body = build_email_body(
                armored, note=request.note, attachment_names=attachment_names or None
            )
            return self.app_context.mail_service.send_encrypted_email(
                sender=request.sender,
                recipient_email=request.recipient_email,
                subject=request.subject,
                armored_payload=email_body,
                attachments=[item.encrypted_path for item in prepared] or None,
            )
        finally:
            service.discard(workspace)

    def _start_send_task(self, request: SendRequest) -> None:
        thread = QThread(self)
        worker = BackgroundTask(lambda emit: self._perform_send(request, emit))
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.progress.connect(self._on_send_progress)
        worker.finished.connect(self._on_send_finished)
        worker.failed.connect(self._show_error)
        worker.finished.connect(thread.quit)
        worker.failed.connect(thread.quit)
        thread.finished.connect(worker.deleteLater)
        thread.finished.connect(self._on_send_task_finished)
        # Strong references: without them Python collects the QThread mid-run.
        self._send_thread = thread
        self._send_worker = worker
        self._set_compose_busy(True)
        thread.start()

    def _set_compose_busy(self, busy: bool) -> None:
        self.compose_send_button.setEnabled(not busy)
        self.compose_progress.setVisible(busy)
        if busy:
            self.compose_progress.setRange(0, 0)
            self.compose_status.setText("Encrypting attachments...")

    def _on_send_progress(self, done: int, total: int, label: str) -> None:
        self.compose_progress.setRange(0, max(total, 1))
        self.compose_progress.setValue(done)
        self.compose_status.setText(
            f"Encrypting {label} - {human_size(done)} of {human_size(total)}"
        )

    def _on_send_finished(self, message_id: object) -> None:
        self.compose_status.setText(
            f"Shared-passphrase email sent. Gmail message id: {message_id}"
        )
        self._persist_default_passphrase_if_enabled(
            self._current_sender_email() or "", self.compose_passphrase.text()
        )

    def _on_send_task_finished(self) -> None:
        self._set_compose_busy(False)
        if self._send_thread is not None:
            self._send_thread.deleteLater()
        self._send_thread = None
        self._send_worker = None

    # ------------------------------------------------------------------
    # Decrypt: attachments
    # ------------------------------------------------------------------

    def _choose_encrypted_attachment(self) -> None:
        name, _ = QFileDialog.getOpenFileName(
            self,
            "Select an encrypted attachment",
            "",
            f"Crypted Mail attachments (*{CMENC_SUFFIX});;All Files (*)",
        )
        if name:
            self._set_encrypted_attachment(Path(name))

    def _set_encrypted_attachment(self, path: Path) -> None:
        self.decrypt_attachment_path.setText(str(path))
        try:
            header = read_attachment_header(path)
        except Exception as exc:
            self.decrypt_attachment_info.setText(str(exc))
            return
        self.decrypt_attachment_info.setText(
            f"Declares: {header.display_filename} - {human_size(header.plaintext_size)} - "
            f"created {header.created_at}. This name is not verified until decryption succeeds."
        )

    def _decrypt_attachment_file(self) -> None:
        try:
            source = self.decrypt_attachment_path.text().strip()
            if not source:
                raise CryptedMailError("Choose an encrypted attachment file first.")
            source_path = Path(source)
            header = read_attachment_header(source_path)
            suggested = sanitize_attachment_filename(header.filename)
            target, _ = QFileDialog.getSaveFileName(
                self,
                "Save decrypted file as",
                str(source_path.parent / suggested),
                "All Files (*)",
            )
            if not target:
                return
            self._recover_attachment_to(source_path, Path(target))
        except Exception as exc:
            self._show_error(exc)

    def _recover_attachment_to(self, source_path: Path, destination_path: Path) -> None:
        """Synchronous recovery, so tests can drive it without a thread."""
        header = self.app_context.attachment_service.recover(
            source_path, destination_path, self.decrypt_passphrase.text()
        )
        self.decrypt_attachment_status.setText(
            f"Saved {destination_path.name} ({human_size(header.plaintext_size)}). "
            "SHA-256 verified."
        )

    # ------------------------------------------------------------------
    # Updates
    # ------------------------------------------------------------------

    def _toggle_auto_update(self) -> None:
        state = self.app_context.repository.load_state()
        state.auto_update_enabled = self.auto_update_checkbox.isChecked()
        self.app_context.repository.save_state(state)

    def _start_update_check(self, manual: bool = False) -> None:
        if self._update_worker is not None and self._update_worker.isRunning():
            return
        if not self._update_service.is_enabled():
            self.update_status_label.setText("Automatic updates are turned off.")
            return

        state = self.app_context.repository.load_state()
        if not manual and not self._update_service.is_check_due(state):
            self.update_status_label.setText(f"Up to date - v{__version__}")
            return

        self.check_updates_button.setEnabled(False)
        self.update_status_label.setText("Checking for updates...")
        worker = UpdateWorker(
            self._update_service, auto_install=state.auto_update_enabled, parent=self
        )
        worker.status.connect(self.update_status_label.setText)
        worker.up_to_date.connect(self._on_up_to_date)
        worker.update_available.connect(self._on_update_available)
        worker.update_ready.connect(self._on_update_ready)
        worker.check_failed.connect(self._on_update_check_failed)
        worker.finished.connect(lambda: self.check_updates_button.setEnabled(True))
        self._update_worker = worker
        worker.start()

    def _record_check_time(self) -> None:
        state = self.app_context.repository.load_state()
        state.last_update_check_at = datetime.now(timezone.utc).isoformat()
        self.app_context.repository.save_state(state)

    def _record_installed_version(self) -> None:
        state = self.app_context.repository.load_state()
        state.last_installed_version = __version__
        self.app_context.repository.save_state(state)

    def _on_up_to_date(self, version: str) -> None:
        self.update_status_label.setText(f"Up to date - v{version}")
        self._record_check_time()

    def _on_update_available(self, version: str, release_url: str) -> None:
        self._record_check_time()
        if self._update_service.channel is UpdateChannel.PYPI:
            self.update_status_label.setText(
                f"Update available: v{version} - run:  {UpdateService.pip_upgrade_command()}"
            )
        else:
            self.update_status_label.setText(
                f"Update available: v{version} - download it from {release_url}"
            )

    def _on_update_ready(self, version: str, installer_path: str) -> None:
        self._record_check_time()
        try:
            self.update_status_label.setText("Installing update... Crypted Mail will restart.")
            self._update_service.launch_installer(Path(installer_path), version)
            # Give the installer a moment to start before we release the exe.
            QTimer.singleShot(1200, QApplication.instance().quit)
        except Exception as exc:
            self.update_status_label.setText(f"Update could not be installed: {exc}")

    def _on_update_check_failed(self, reason: str) -> None:
        # Never a dialog on the startup path.
        self.update_status_label.setText("Update check failed - will retry later.")

    def closeEvent(self, event) -> None:  # noqa: N802 - Qt naming
        for thread in (self._send_thread, self._attachment_thread):
            if thread is not None and thread.isRunning():
                thread.quit()
                thread.wait(3000)
        if self._update_worker is not None and self._update_worker.isRunning():
            self._update_worker.requestInterruption()
            self._update_worker.wait(2000)
        super().closeEvent(event)

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
        self.auto_update_checkbox.setChecked(state.auto_update_enabled)
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
