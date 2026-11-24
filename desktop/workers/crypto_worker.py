"""Non-blocking Qt worker for VaultService encryption and decryption flows."""

from __future__ import annotations

import threading
from pathlib import Path
from typing import Callable, Iterable, Optional

from PySide6.QtCore import QObject, Signal, Slot

from src.crypto.key_lifecycle import KeyLifecycleError
from src.crypto.secure_keystore import KeystoreError
from src.services.vault_service import VaultService

try:
    from src.crypto.hybrid_vault import IntegrityError
except ImportError:  # pragma: no cover
    IntegrityError = RuntimeError  # type: ignore[misc, assignment]


class OperationCancelledError(RuntimeError):
    """Raised when the user cancels a requested password prompt."""


class CryptoWorker(QObject):
    """Executes VaultService encrypt/decrypt operations off the UI thread.

    Password requests are bridged back to the main thread so Qt dialogs never
    run directly inside a worker thread.
    """

    password_requested = Signal(dict)
    finished = Signal(object)
    error = Signal(str, str)

    def __init__(
        self,
        vault_service: VaultService,
        operation: str,
        params: dict,
        *,
        password_callback: Optional[Callable[[dict], str]] = None,
        parent: Optional[QObject] = None,
    ) -> None:
        super().__init__(parent)
        if operation not in {"encrypt", "decrypt"}:
            raise ValueError(f"Unsupported crypto operation: {operation!r}")

        self._vault_service = vault_service
        self._operation = operation
        self._params = dict(params)
        self._password_callback = password_callback

        self._lock = threading.Lock()
        self._password_event = threading.Event()
        self._pending_password: Optional[str] = None
        self._password_cancelled = False
        self._cancelled = False

    def cancel(self) -> None:
        """Request cancellation of a pending password wait."""
        with self._lock:
            self._cancelled = True
            self._password_cancelled = True
            self._pending_password = None
        self._password_event.set()

    @Slot(str)
    def submit_password(self, password: str) -> None:
        """Provide password from the UI thread in response to password_requested."""
        with self._lock:
            self._pending_password = password
            self._password_cancelled = False
        self._password_event.set()

    @Slot()
    def cancel_password(self) -> None:
        """Notify the worker that the user cancelled the password dialog."""
        with self._lock:
            self._pending_password = None
            self._password_cancelled = True
        self._password_event.set()

    def _provide_password(self, key_entry: dict) -> str:
        """PasswordProvider passed to VaultService."""
        if self._password_callback is not None:
            return self._password_callback(key_entry)

        with self._lock:
            if self._cancelled:
                raise OperationCancelledError("Operation cancelled by user.")
            self._password_event.clear()
            self._pending_password = None
            self._password_cancelled = False

        self.password_requested.emit(dict(key_entry))
        self._password_event.wait()

        with self._lock:
            if self._cancelled or self._password_cancelled:
                raise OperationCancelledError("Password entry cancelled.")
            secret = self._pending_password
            self._pending_password = None

        if not isinstance(secret, str) or not secret:
            raise ValueError("Keystore password is required.")
        return secret

    @Slot()
    def run(self) -> None:
        """Execute the configured VaultService operation and emit outcome signals."""
        try:
            if self._operation == "encrypt":
                result_path = self._run_encrypt()
            else:
                result_path = self._run_decrypt()
            self.finished.emit(result_path)
        except OperationCancelledError as exc:
            self.error.emit("cancelled", str(exc) or "Operation cancelled.")
        except FileExistsError as exc:
            self.error.emit("file_exists", f"Output file already exists: {exc}")
        except FileNotFoundError as exc:
            self.error.emit("file_not_found", f"File not found: {exc}")
        except KeyLifecycleError as exc:
            self.error.emit("lifecycle_error", str(exc))
        except KeystoreError as exc:
            self.error.emit("keystore_error", str(exc))
        except IntegrityError as exc:
            self.error.emit("integrity_error", str(exc))
        except ValueError as exc:
            self.error.emit("validation_error", str(exc))
        except Exception as exc:  # pragma: no cover
            self.error.emit("unexpected_error", f"Unexpected error: {exc}")

    def _run_encrypt(self) -> Path:
        source = Path(self._params["source"])
        output = Path(self._params["output"])
        signer_user = str(self._params["signer_user"])
        raw_recipients = self._params.get("recipients") or []
        recipients: list[str] = (
            list(raw_recipients)
            if isinstance(raw_recipients, Iterable) and not isinstance(raw_recipients, (str, bytes))
            else []
        )
        return self._vault_service.encrypt_file(
            source=source,
            output=output,
            signer_user=signer_user,
            recipients=recipients,
            password_provider=self._provide_password,
        )

    def _run_decrypt(self) -> Path:
        source = Path(self._params["source"])
        output = Path(self._params["output"])
        user_id = str(self._params["user_id"])
        return self._vault_service.decrypt_file(
            source=source,
            output=output,
            user_id=user_id,
            password_provider=self._provide_password,
        )