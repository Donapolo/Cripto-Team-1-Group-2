"""PySide6 app initialization, independent from the cryptographic modules."""

import sys

from PySide6.QtWidgets import QApplication

from desktop.context import DesktopContext
from desktop.ui.main_window import MainWindow
from desktop.ui.theme import apply_theme


def create_window(data_dir=None) -> tuple[QApplication, MainWindow]:
    """Testable application factory. Only caller starts the Qt event loop."""
    app = QApplication.instance()
    if app is None:
        app = QApplication(sys.argv)
    apply_theme(app)
    context = DesktopContext(data_dir=data_dir)
    window = MainWindow(context)
    # Keep the context alive as long as the window exists.
    context.setParent(window)
    return app, window


def main() -> int:
    app, window = create_window()
    window.show()
    return app.exec()
