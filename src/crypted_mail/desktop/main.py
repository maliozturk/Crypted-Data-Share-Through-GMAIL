from __future__ import annotations

import sys

from PySide6.QtWidgets import QApplication

from crypted_mail.desktop.window import MainWindow
from crypted_mail.services.app_context import AppContext


def main() -> int:
    app = QApplication(sys.argv)
    app.setApplicationName("Crypted Mail")
    window = MainWindow(AppContext.create_default())
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
