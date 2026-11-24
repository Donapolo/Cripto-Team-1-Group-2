"""My Keys view (Yuki): identities, key status, rotation, revocation and backups.

The view never implements cryptography: every operation goes through VaultService.
It never shows or stores private keys or passwords; passwords are requested with
the shared PasswordDialog only when an operation needs them.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QBrush, QColor, QCursor
from PySide6.QtWidgets import (
    QAbstractItemView, QApplication, QFileDialog, QFrame, QGridLayout, QHBoxLayout,
    QHeaderView, QInputDialog, QLabel, QMessageBox, QPushButton, QTableWidget,
    QTableWidgetItem, QTextEdit, QVBoxLayout, QWidget,
)

from desktop.context import DesktopContext
from desktop.ui.dialogs.password_dialog import ask_password
from desktop.ui.theme import named

ALGORITHMS = ["both", "secp256k1", "Ed25519"]
COLUMNS = ["User", "Algorithm", "Key ID", "Status", "Expires"]
STATUS_COLORS = {"active": "#32CBA7", "retired": "#A9B9CC", "revoked": "#ef4444",
                 "expired": "#f59e0b"}


class DialogAsker:
    """All user prompts in one place. Every method returns None on cancel.

    Tests replace it with a fake, so the operations can be checked without
    opening real windows.
    """

    def __init__(self, parent: QWidget):
        self.parent = parent

    def text(self, title: str, label: str) -> Optional[str]:
        value, ok = QInputDialog.getText(self.parent, title, label)
        return value.strip() if ok and value.strip() else None

    def item(self, title: str, label: str, items: list[str]) -> Optional[str]:
        value, ok = QInputDialog.getItem(self.parent, title, label, items, 0, False)
        return value if ok else None

    def password(self, title: str, message: str, *, confirm: bool = False) -> Optional[str]:
        return ask_password(self.parent, title, message, confirm=confirm)

    def confirm(self, title: str, message: str) -> bool:
        answer = QMessageBox.warning(
            self.parent, title, message,
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Cancel)
        return answer == QMessageBox.StandardButton.Yes

    def save_file(self, title: str) -> Optional[str]:
        path, _ = QFileDialog.getSaveFileName(self.parent, title, "", "JSON (*.json)")
        return path or None

    def open_file(self, title: str) -> Optional[str]:
        path, _ = QFileDialog.getOpenFileName(self.parent, title, "", "JSON (*.json)")
        return path or None

    def directory(self, title: str) -> Optional[str]:
        path = QFileDialog.getExistingDirectory(self.parent, title)
        return path or None


def _display_status(entry: dict, now: Optional[datetime] = None) -> str:
    """'expired' is computed from expires_at; it is not a stored state."""
    status = entry.get("status", "")
    if status in ("active", "retired"):
        try:
            expires = datetime.fromisoformat(entry["expires_at"])
            if expires <= (now or datetime.now(timezone.utc)):
                return "expired"
        except (KeyError, ValueError, TypeError):
            pass
    return status


class KeysView(QWidget):
    operation_completed = Signal(str, object)
    operation_failed = Signal(str, str)

    def __init__(self, context: Optional[DesktopContext] = None,
                 parent: Optional[QWidget] = None, *, vault_service=None):
        super().__init__(parent)
        self.context = context
        self._service = vault_service
        self.ask = DialogAsker(self)
        self._entries: list[dict] = []
        self._build_ui()
        if context is not None:
            context.data_dir_changed.connect(self._on_data_dir_changed)
        self.refresh()

    # ---------- UI ----------

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(28, 22, 28, 22)
        layout.setSpacing(12)

        top = QHBoxLayout()
        title = named(QLabel("My Keys"), "SectionTitle")
        top.addWidget(title)
        top.addStretch()
        self.lock_state = named(QLabel("Locked"), "MutedText")
        top.addWidget(self.lock_state)
        self.unlock_btn = self._button("Unlock vault", self.on_unlock, primary=True)
        self.lock_btn = self._button("Lock", self.lock)
        top.addWidget(self.unlock_btn)
        top.addWidget(self.lock_btn)
        layout.addLayout(top)

        note = named(QLabel(
            "Private keys are never shown. Passwords are asked only when an operation "
            "needs them and are not stored."), "MutedText")
        note.setWordWrap(True)
        layout.addWidget(note)

        self.table = QTableWidget(0, len(COLUMNS))
        self.table.setHorizontalHeaderLabels(COLUMNS)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.table, 1)

        panel = named(QFrame(), "InfoPanel")
        grid = QGridLayout(panel)
        grid.setContentsMargins(16, 14, 16, 14)
        grid.setSpacing(8)
        self.create_btn = self._button("Create profile", self.on_create_profile, primary=True)
        self.rotate_btn = self._button("Rotate selected key", self.on_rotate)
        self.revoke_btn = self._button("Revoke selected key", self.on_revoke)
        self.backup_key_btn = self._button("Back up selected keystore", self.on_backup_key)
        self.restore_key_btn = self._button("Restore selected keystore", self.on_restore_key)
        self.backup_vault_btn = self._button("Full backup (registry + keystores)",
                                             self.on_backup_vault)
        self.restore_vault_btn = self._button("Restore full backup", self.on_restore_vault)
        for i, button in enumerate([self.create_btn, self.rotate_btn, self.revoke_btn,
                                    self.backup_key_btn, self.restore_key_btn,
                                    self.backup_vault_btn, self.restore_vault_btn]):
            grid.addWidget(button, i // 3, i % 3)
        layout.addWidget(panel)

        self.status_badge = QLabel("Ready")
        self.status_badge.setStyleSheet("font-weight: 600;")
        layout.addWidget(self.status_badge)
        self.log = QTextEdit()
        self.log.setReadOnly(True)
        self.log.setMaximumHeight(110)
        layout.addWidget(self.log)

    def _button(self, text: str, slot: Callable, *, primary: bool = False) -> QPushButton:
        button = QPushButton(text)
        button.setObjectName("PrimaryButton" if primary else "SecondaryButton")
        button.clicked.connect(lambda _checked=False: slot())
        return button

    # ---------- state ----------

    @property
    def unlocked(self) -> bool:
        return self._service is not None

    def _registry_exists(self) -> bool:
        if self._service is not None:
            return Path(self._service.registry_path).is_file()
        return self.context is not None and self.context.registry_exists

    def _on_data_dir_changed(self, _path: str) -> None:
        self.lock()

    def lock(self) -> None:
        """Forget the service (and its registry password reference)."""
        self._service = None
        self.refresh()

    def refresh(self) -> None:
        self._entries = []
        if self._service is not None and self._registry_exists():
            try:
                self._entries = self._service.list_keys()
            except Exception as exc:
                self._fail("refresh", f"Unable to read the registry: {exc}")
        self.table.setRowCount(len(self._entries))
        for row, entry in enumerate(self._entries):
            status = _display_status(entry)
            values = [entry.get("user_id", ""), entry.get("algorithm", ""),
                      entry.get("key_id", "")[:16] + "…", status,
                      str(entry.get("expires_at", ""))[:10]]
            for col, value in enumerate(values):
                item = QTableWidgetItem(value)
                if col == 2:
                    item.setToolTip(entry.get("key_id", ""))
                if col == 3:
                    item.setForeground(QBrush(QColor("#FFFFFF")))
                    item.setBackground(QBrush(QColor(STATUS_COLORS.get(status, "#334253"))))
                item.setData(Qt.ItemDataRole.UserRole, entry.get("key_id", ""))
                self.table.setItem(row, col, item)
        if self._service is None:
            self.lock_state.setText("Locked" if self._registry_exists()
                                    else "No vault in this folder yet")
        else:
            self.lock_state.setText(f"Unlocked · {len(self._entries)} key(s)")
        self.unlock_btn.setEnabled(self._service is None)
        self.lock_btn.setEnabled(self._service is not None)

    def selected_entry(self) -> Optional[dict]:
        rows = self.table.selectionModel().selectedRows() if self.table.selectionModel() else []
        if not rows:
            return None
        index = rows[0].row()
        return self._entries[index] if 0 <= index < len(self._entries) else None

    def select_key(self, key_id: str) -> bool:
        for row, entry in enumerate(self._entries):
            if entry.get("key_id") == key_id:
                self.table.selectRow(row)
                return True
        return False

    # ---------- messages ----------

    def _ok(self, operation: str, message: str, result: object = None) -> None:
        self.status_badge.setText("Completed")
        self.status_badge.setStyleSheet("font-weight: 600; color: #22c55e;")
        self.log.append(message)
        self.operation_completed.emit(operation, result)

    def _fail(self, operation: str, message: str) -> None:
        self.status_badge.setText("Rejected")
        self.status_badge.setStyleSheet("font-weight: 600; color: #ef4444;")
        self.log.append(f"[{operation}] {message}")
        self.operation_failed.emit(operation, message)

    def _cancelled(self, operation: str) -> None:
        self.status_badge.setText("Cancelled")
        self.status_badge.setStyleSheet("font-weight: 600;")
        self.log.append(f"[{operation}] Cancelled. Nothing was changed.")

    def _run(self, operation: str, action: Callable, success: Callable[[object], str]):
        """Run one service call. Any error is shown; the view stays usable."""
        QApplication.setOverrideCursor(QCursor(Qt.CursorShape.WaitCursor))
        try:
            result = action()
        except Exception as exc:
            self._fail(operation, _readable(exc))
            return None
        finally:
            QApplication.restoreOverrideCursor()
            self.refresh()
        self._ok(operation, success(result), result)
        return result

    # ---------- unlock ----------

    def on_unlock(self) -> bool:
        if self.context is None:
            self._fail("unlock", "No data folder is configured.")
            return False
        if not self.context.registry_exists:
            self._fail("unlock", f"No vault found in {self.context.data_dir}. "
                                 "Use 'Create profile' to initialize it.")
            return False
        password = self.ask.password("Unlock vault", "Registry password:")
        if password is None:
            self._cancelled("unlock")
            return False
        return self.unlock(password)

    def unlock(self, registry_password: str) -> bool:
        try:
            service = self.context.make_service(registry_password)
            service.list_keys()  # authenticates the registry MAC
        except Exception as exc:
            self._fail("unlock", f"Unable to open the vault: {_readable(exc)}")
            return False
        self._service = service
        self.refresh()
        self._ok("unlock", "Vault unlocked.")
        return True

    def _need_service(self, operation: str) -> bool:
        if self._service is not None:
            return True
        if self._registry_exists():
            return self.on_unlock()
        self._fail(operation, "No vault yet. Use 'Create profile' first.")
        return False

    # ---------- create profile ----------

    def on_create_profile(self) -> None:
        new_service = None
        if self._service is None:
            if self._registry_exists():
                if not self.on_unlock():
                    return
            else:
                if self.context is None:
                    self._fail("create", "No data folder is configured.")
                    return
                reg_pw = self.ask.password(
                    "New vault", "No vault in this folder yet. Choose a registry password "
                    "(it protects the key states against edits):", confirm=True)
                if reg_pw is None:
                    self._cancelled("create")
                    return
                new_service = self.context.make_service(reg_pw)
        user = self.ask.text("Create profile", "User ID (letters, digits, '_' or '-'):")
        if user is None:
            self._cancelled("create")
            return
        algorithm = self.ask.item("Create profile", "Keys to create:", ALGORITHMS)
        if algorithm is None:
            self._cancelled("create")
            return
        password = self.ask.password("Create profile",
                                     f"New password for {user}'s keystores:", confirm=True)
        if password is None:
            self._cancelled("create")
            return
        self.create_profile(user, algorithm, password, new_service=new_service)

    def create_profile(self, user_id: str, algorithm: str, password: str, *, new_service=None):
        """new_service: only for the very first profile of an empty folder."""
        if new_service is not None:
            self._service = new_service
        result = self._run(
            "create", lambda: self._service.init_user(user_id, password, algorithm=algorithm),
            lambda entries: f"Profile {user_id}: {len(entries)} key(s) created.")
        if result is None and new_service is not None and not self._registry_exists():
            self._service = None  # first profile failed: stay locked
            self.refresh()
        return result

    # ---------- rotate / revoke ----------

    def _selected_or_fail(self, operation: str) -> Optional[dict]:
        entry = self.selected_entry()
        if entry is None:
            self._fail(operation, "Select a key in the table first.")
        return entry

    def on_rotate(self) -> None:
        if not self._need_service("rotate"):
            return
        entry = self._selected_or_fail("rotate")
        if entry is None:
            return
        if entry["status"] != "active":
            self._fail("rotate", f"Only an active key can be rotated (this one is {entry['status']}).")
            return
        if not self.ask.confirm("Rotate key",
                                f"A new {entry['algorithm']} key will be created for "
                                f"{entry['user_id']}. The current key becomes retired: it can still "
                                "open old documents, but it cannot encrypt or sign new ones."):
            self._cancelled("rotate")
            return
        password = self.ask.password("Rotate key", "Password for the NEW keystore:", confirm=True)
        if password is None:
            self._cancelled("rotate")
            return
        self.rotate_key(entry["key_id"], password)

    def rotate_key(self, key_id: str, new_password: str):
        entry = self._entry(key_id)
        if entry is None or entry["status"] != "active":
            self._fail("rotate", "Only an active key can be rotated.")
            return None
        return self._run(
            "rotate", lambda: self._service.rotate(entry["user_id"], entry["algorithm"], new_password),
            lambda new: f"Key rotated. New key {new['key_id'][:16]}…; old key is now retired.")

    def on_revoke(self) -> None:
        if not self._need_service("revoke"):
            return
        entry = self._selected_or_fail("revoke")
        if entry is None:
            return
        if entry["status"] == "revoked":
            self._fail("revoke", "This key is already revoked.")
            return
        reason = self.ask.text("Revoke key", "Reason (required, e.g. 'laptop stolen'):")
        if reason is None:
            self._cancelled("revoke")
            return
        if not self.ask.confirm("Revoke key",
                                "Revocation cannot be undone. The key will be blocked for every "
                                "operation. Documents encrypted for it must be re-encrypted, and "
                                "copies an attacker already has are not protected by this."):
            self._cancelled("revoke")
            return
        self.revoke_key(entry["key_id"], reason)

    def revoke_key(self, key_id: str, reason: str):
        return self._run("revoke", lambda: self._service.revoke(key_id, reason),
                         lambda _r: f"Key {key_id[:16]}… revoked.")

    # ---------- single keystore backup ----------

    def on_backup_key(self) -> None:
        if not self._need_service("backup"):
            return
        entry = self._selected_or_fail("backup")
        if entry is None:
            return
        path = self.ask.save_file("Save keystore backup")
        if path is None:
            self._cancelled("backup")
            return
        self.backup_key(entry["key_id"], path)

    def backup_key(self, key_id: str, path: str | Path):
        return self._run("backup", lambda: self._service.backup_keystore(key_id, path),
                         lambda _r: f"Encrypted keystore backed up to {path}.")

    def on_restore_key(self) -> None:
        if not self._need_service("restore"):
            return
        entry = self._selected_or_fail("restore")
        if entry is None:
            return
        path = self.ask.open_file("Select keystore backup")
        if path is None:
            self._cancelled("restore")
            return
        self.restore_key(entry["key_id"], path)

    def restore_key(self, key_id: str, path: str | Path):
        return self._run("restore", lambda: self._service.restore_keystore(key_id, path),
                         lambda target: f"Keystore restored to {target}.")

    # ---------- full backup (registry + keystores) ----------

    def on_backup_vault(self) -> None:
        if not self._need_service("vault_backup"):
            return
        folder = self.ask.directory("Choose an EMPTY folder for the full backup")
        if folder is None:
            self._cancelled("vault_backup")
            return
        self.backup_vault(folder)

    def backup_vault(self, folder: str | Path):
        return self._run(
            "vault_backup", lambda: self._service.create_vault_backup(folder),
            lambda s: (f"Full backup created in {folder}: {len(s['keystores_backed_up'])} "
                       f"keystore(s); revoked keys skipped: {len(s['skipped_revoked'])}."))

    def on_restore_vault(self) -> None:
        folder = self.ask.directory("Select the full backup folder")
        if folder is None:
            self._cancelled("vault_restore")
            return
        exists = self._registry_exists()
        warning = (
            "Restoring replaces the registry and keystores of this vault with the backup.\n\n"
            "• An older backup cannot undo later rotations or revocations: it will be rejected.\n"
            "• Everything is checked before writing. If a write still fails, the app tries to "
            "undo it; if that also fails, it lists the files you must recover manually.\n"
            "• The current registry password is required."
            if exists else
            "There is no vault in this folder. The backup will be restored here. "
            "You will need the registry password used when the backup was made.")
        if not self.ask.confirm("Restore full backup", warning):
            self._cancelled("vault_restore")
            return
        temporary = None
        if self._service is None:
            if self.context is None:
                self._fail("vault_restore", "No data folder is configured.")
                return
            reg_pw = self.ask.password("Restore full backup", "Registry password:")
            if reg_pw is None:
                self._cancelled("vault_restore")
                return
            temporary = self.context.make_service(reg_pw)
        self.restore_vault(folder, overwrite=exists, new_service=temporary)

    def restore_vault(self, folder: str | Path, *, overwrite: bool = False, new_service=None):
        """new_service: a service built just for this restore (vault was locked)."""
        if new_service is not None:
            self._service = new_service
        result = self._run(
            "vault_restore",
            lambda: self._service.restore_vault_backup(folder, overwrite=overwrite),
            lambda s: f"Backup restored: {len(s['keystores_restored'])} keystore(s).")
        if result is None and new_service is not None:
            self._service = None  # the password was not verified: stay locked
            self.refresh()
        return result

    # ---------- helpers ----------

    def _entry(self, key_id: str) -> Optional[dict]:
        return next((e for e in self._entries if e.get("key_id") == key_id), None)


def _readable(exc: Exception) -> str:
    """Readable message for the user. Backend messages never contain secrets."""
    name = type(exc).__name__
    text = str(exc) or name
    if isinstance(exc, FileExistsError):
        return f"Refusing to overwrite an existing file. {text}"
    if "could not be restored" in text:
        return f"INCOMPLETE RECOVERY — {text}"
    if "integrity" in text.lower() or "authentication failed" in text.lower():
        return f"Wrong password or modified file. {text}"
    return text
