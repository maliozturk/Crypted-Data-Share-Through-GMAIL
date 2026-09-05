from __future__ import annotations

import sys


def main() -> int:
    try:
        from PySide6.QtWidgets import QApplication

        from crypted_mail.desktop.window import MainWindow
        from crypted_mail.services.app_context import AppContext
    except ImportError:
        print(
            "The Crypted Mail desktop app needs PySide6.\n"
            "Install it with:  pip install -U 'crypted-mail[desktop]'",
            file=sys.stderr,
        )
        return 1

    app = QApplication(sys.argv)
    app.setApplicationName("Crypted Mail")
    window = MainWindow(AppContext.create_default())
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
