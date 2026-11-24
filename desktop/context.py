"""Shared *non-secret* desktop state.

The GUI never stores registry or keystore passwords. Views may ask the user
for a password and create a short-lived VaultService via ``make_service``.
"""

from pathlib import Path

from PySide6.QtCore import QObject, QSettings, Signal

# Same default as src.cli.DEFAULT_DATA_DIR, without importing the backend at GUI startup.
DEFAULT_DATA_DIR = Path.home() / ".secure-document-vault"


class DesktopContext(QObject):
    data_dir_changed = Signal(str)

    def __init__(self, data_dir: str | Path | None = None, parent: QObject | None = None):
        super().__init__(parent)
        # Explicit data_dir is useful in tests and does not alter user settings.
        self._persist = data_dir is None
        self._settings = QSettings("Cripto-Team-1-Group-2", "Secure Document Vault")
        saved = self._settings.value("data_dir", str(DEFAULT_DATA_DIR))
        initial = saved if data_dir is None else data_dir
        self._data_dir = self._normalize(initial)

    @staticmethod
    def _normalize(value: str | Path) -> Path:
        text = str(value).strip()
        if not text:
            raise ValueError("Selecciona una carpeta de datos válida.")
        return Path(text).expanduser().resolve(strict=False)

    @property
    def data_dir(self) -> Path:
        return self._data_dir

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
