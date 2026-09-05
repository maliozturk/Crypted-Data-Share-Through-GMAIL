"""Generic background task plumbing for the desktop layer.

The rest of the app has no concurrency at all, and that is deliberate: business
logic in ``core/`` and ``services/`` stays synchronous and Qt-free so it can be
tested by direct call. This module is the only place that knows about threads.

A worker must never touch a widget. It emits signals; the GUI thread's slots do
all the widget and state writing, via Qt's automatic queued connections.
"""

from __future__ import annotations

import threading
from typing import Any, Callable

from PySide6.QtCore import QObject, Signal


# (bytes_done, bytes_total, label)
ProgressEmitter = Callable[[int, int, str], None]


class BackgroundTask(QObject):
    """Runs one callable off the GUI thread and reports the outcome."""

    progress = Signal(int, int, str)
    finished = Signal(object)
    failed = Signal(object)

    def __init__(self, work: Callable[[ProgressEmitter], Any], parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._work = work
        self._cancelled = threading.Event()

    def cancel(self) -> None:
        self._cancelled.set()

    def is_cancelled(self) -> bool:
        return self._cancelled.is_set()

    def run(self) -> None:
        try:
            self.finished.emit(self._work(self.progress.emit))
        except Exception as exc:  # noqa: BLE001 - deliberately surfaced to the UI
            self.failed.emit(exc)
