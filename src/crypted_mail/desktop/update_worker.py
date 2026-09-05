"""Background update checking for the desktop app.

Lives in ``desktop/`` so that ``services/`` stays free of Qt - that separation
is what lets the package be used as a plain library.

The worker never touches a widget and never writes app state. It emits ``str``
payloads that GUI-thread slots act on, which sidesteps the read-modify-write
race that ``AppRepository.load_state()`` / ``save_state()`` would otherwise have.
"""

from __future__ import annotations

from PySide6.QtCore import QThread, Signal

from crypted_mail.services.update_service import UpdateService


class UpdateWorker(QThread):
    status = Signal(str)
    up_to_date = Signal(str)
    update_available = Signal(str, str)  # version, release_url
    update_ready = Signal(str, str)  # version, verified installer path
    check_failed = Signal(str)

    def __init__(self, service: UpdateService, *, auto_install: bool, parent=None) -> None:
        super().__init__(parent)
        self._service = service
        # Snapshotted on the GUI thread; the worker never reads live state.
        self._auto_install = auto_install

    def run(self) -> None:
        try:
            info = self._service.check_quiet()
            if info is None:
                self._service.cleanup_downloads()
                self.up_to_date.emit(self._service.current_version)
                return

            if not (self._auto_install and self._service.can_self_install() and info.installable):
                self.update_available.emit(info.version, info.release_url)
                return

            if self.isInterruptionRequested():
                return
            self.status.emit(f"Downloading update {info.version}...")
            path = self._service.download(info)

            if self.isInterruptionRequested():
                return
            self.status.emit("Verifying update...")
            self._service.verify(path, info)
            self._service.cleanup_downloads(keep_version=info.version)
            self.update_ready.emit(info.version, str(path))
        except Exception as exc:  # noqa: BLE001 - a worker crash must not kill the app
            self._service.log(f"update worker failed: {type(exc).__name__}: {exc}")
            self.check_failed.emit(str(exc))
