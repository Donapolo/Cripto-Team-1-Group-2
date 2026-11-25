"""Shared *non-secret* desktop state.

DesktopContext does not hold registry or keystore passwords. Individual
views may hold a VaultService while authenticated; the shared lock signal
clears their cached references. A running operation cannot be interrupted
safely in every phase, so locking is refused while crypto work is active.
"""

from pathlib import Path

from PySide6.QtCore import QObject, QSettings, Signal

# Same default as src.cli.DEFAULT_DATA_DIR, without importing the backend at GUI startup.
DEFAULT_DATA_DIR = Path.home() / ".secure-document-vault"


class DesktopContext(QObject):
    data_dir_changed = Signal(str)
    vault_lock_requested = Signal()
    crypto_session_changed = Signal(bool)

    def __init__(self, data_dir: str | Path | None = None, parent: QObject | None = None):
        super().__init__(parent)
        # Explicit data_dir is useful in tests and does not alter user settings.
        self._persist = data_dir is None
        self._settings = QSettings("Cripto-Team-1-Group-2", "Secure Document Vault")
        saved = self._settings.value("data_dir", str(DEFAULT_DATA_DIR))
        initial = saved if data_dir is None else data_dir
        self._data_dir = self._normalize(initial)
        # Busy state is non-secret; it prevents presenting an in-flight crypto
        # operation as if it had been cancelled by the Lock action.
        self._crypto_busy = False
        self._crypto_unlocked = False

    @staticmethod
    def _normalize(value: str | Path) -> Path:
        text = str(value).strip()
        if not text:
            raise ValueError("Select a valid data folder.")
        return Path(text).expanduser().resolve(strict=False)

    @property
    def data_dir(self) -> Path:
        return self._data_dir

    @property
    def crypto_busy(self) -> bool:
        return self._crypto_busy

    def set_crypto_busy(self, busy: bool) -> None:
        self._crypto_busy = bool(busy)

    @property
    def crypto_unlocked(self) -> bool:
        return self._crypto_unlocked

    def set_crypto_unlocked(self, unlocked: bool) -> None:
        unlocked = bool(unlocked)
        if unlocked != self._crypto_unlocked:
            self._crypto_unlocked = unlocked
            self.crypto_session_changed.emit(unlocked)

    @property
    def registry_exists(self) -> bool:
        """Presence only, NOT a claim that registry authentication succeeded."""
        return (self._data_dir / "registry.json").is_file()

    def set_data_dir(self, value: str | Path) -> None:
        new_path = self._normalize(value)
        if new_path == self._data_dir:
            return
        self._data_dir = new_path
        if self._persist:
            self._settings.setValue("data_dir", str(new_path))
        self.data_dir_changed.emit(str(new_path))

    def make_service(self, registry_password: str):
        """For future views; no password is retained by DesktopContext."""
        from src.services.vault_service import VaultService

        return VaultService(self._data_dir, registry_password)
