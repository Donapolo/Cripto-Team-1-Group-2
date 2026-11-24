"""Reusable password dialog for the desktop app (Yuki).

Rules:
- Fields are always hidden (Password echo mode).
- Optional confirmation field for NEW passwords (create profile, rotate).
- Cancel returns None; the caller must stop the operation.
- Messages never include the password, and the fields are cleared on close.
- It must run on the UI (main) thread. Workers ask through a signal.
"""

from __future__ import annotations

from typing import Callable, Optional

from PySide6.QtWidgets import (
    QDialog, QDialogButtonBox, QLabel, QLineEdit, QVBoxLayout, QWidget,
)


class PasswordDialog(QDialog):
    def __init__(self, parent: Optional[QWidget] = None, *, title: str = "Password",
                 message: str = "Enter the password:", confirm: bool = False):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setModal(True)
        self.setMinimumWidth(380)
        self._confirm = confirm

        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        info = QLabel(message)
        info.setWordWrap(True)
        layout.addWidget(info)

        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_edit.setPlaceholderText("Password")
        layout.addWidget(self.password_edit)

        self.confirm_edit = QLineEdit()
        self.confirm_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.confirm_edit.setPlaceholderText("Confirm password")
        self.confirm_edit.setVisible(confirm)
        layout.addWidget(self.confirm_edit)

        self.error_label = QLabel("")
        self.error_label.setObjectName("MutedText")
        self.error_label.setStyleSheet("color: #ef4444;")
        self.error_label.setWordWrap(True)
        layout.addWidget(self.error_label)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok |
                                   QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self._try_accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def validation_error(self) -> str:
        """Empty string if the input is valid; otherwise a message without secrets."""
        password = self.password_edit.text()
        if not password.strip():
            return "The password cannot be empty."
        if self._confirm and password != self.confirm_edit.text():
            return "The passwords do not match."
        return ""

    def _try_accept(self) -> None:
        error = self.validation_error()
        if error:
            self.error_label.setText(error)
            self.confirm_edit.clear()
            return
        self.accept()

    def password(self) -> str:
        return self.password_edit.text()

    def clear(self) -> None:
        self.password_edit.clear()
        self.confirm_edit.clear()


def ask_password(parent: Optional[QWidget], title: str, message: str, *,
                 confirm: bool = False) -> Optional[str]:
    """Show the dialog. Returns the password, or None if the user cancelled."""
    dialog = PasswordDialog(parent, title=title, message=message, confirm=confirm)
    try:
        if not dialog.exec():  # 0 = Rejected (Cancel / Esc / close)
            return None
        return dialog.password()
    finally:
        dialog.clear()
        dialog.deleteLater()


def key_password_provider(parent: Optional[QWidget]) -> Callable[[dict], str]:
    """PasswordProvider for VaultService (UI thread only).

    Shows which key is being unlocked (user, algorithm, short key_id) and raises
    if the user cancels, so the service operation stops without side effects.
    """
    def provider(entry: dict) -> str:
        key_id = str(entry.get("key_id", ""))
        message = (f"Password for {entry.get('user_id', 'user')} "
                   f"({entry.get('algorithm', 'key')} · {key_id[:16]}):")
        secret = ask_password(parent, "Key password", message)
        if secret is None:
            raise PasswordCancelled("Password entry cancelled.")
        return secret
    return provider


class PasswordCancelled(RuntimeError):
    """The user cancelled a password dialog."""
