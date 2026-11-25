"""Encryption and decryption view for the Desktop MVP."""

from __future__ import annotations

from pathlib import Path
from typing import Callable, Optional

from PySide6.QtCore import QThread, Qt, Signal, Slot
from PySide6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QPushButton,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from desktop.context import DesktopContext
from desktop.workers.crypto_worker import CryptoWorker
from src.services.vault_service import PasswordProvider, VaultService


def _default_password_dialog(parent: QWidget, key_entry: dict) -> tuple[str, bool]:
    """Modal key password prompt executed on the main UI thread."""
    user_id = key_entry.get("user_id", "user")
    algorithm = key_entry.get("algorithm", "key")
    key_id = key_entry.get("key_id", "")
    label = (
        f"Password for {user_id} ({algorithm} - {key_id}):"
        if key_id
        else f"Password for {user_id} ({algorithm}):"
    )
    secret, ok = QInputDialog.getText(
        parent,
        "Key Authentication",
        label,
        QLineEdit.EchoMode.Password,
    )
    return secret, ok


class CryptoView(QWidget):
    """Provides non-blocking encryption and decryption workflows backed by VaultService."""

    operation_completed = Signal(str, object)
    operation_failed = Signal(str, str, str)

    def __init__(
        self,
        context: Optional[DesktopContext] = None,
        parent: Optional[QWidget] = None,
        *,
        vault_service: Optional[VaultService] = None,
        password_provider: Optional[Callable[[dict], str]] = None,
    ) -> None:
        super().__init__(parent)
        self.context = context
        self._vault_service = vault_service
        self._password_provider: Optional[Callable[[dict], str]] = password_provider
        self._thread: Optional[QThread] = None
        self._worker: Optional[CryptoWorker] = None
        self._build_ui()
        self.refresh_identities()

        if self.context is not None:
            self.context.set_crypto_unlocked(self._vault_service is not None)
            self.context.data_dir_changed.connect(self._on_data_dir_changed)
            self.context.vault_lock_requested.connect(self.lock_vault)

    def _on_data_dir_changed(self, _path: str) -> None:
        self.lock_vault()

    def lock_vault(self) -> None:
        """Forget authenticated registry state for subsequent operations.

        Lock is allowed only when no crypto job is running (enforced by My Keys).
        This also clears editable identity selectors: they must not look like
        authenticated, loaded identities after the vault has been locked.
        """
        self._vault_service = None
        if self.context is not None:
            self.context.set_crypto_unlocked(False)
        self.refresh_identities()
        for combo in (self._enc_signer_combo, self._enc_rec1_combo,
                      self._enc_rec2_combo, self._enc_rec3_combo,
                      self._dec_user_combo):
            combo.clear()
            combo.setEditText("")

    def set_vault_service(self, vault_service: Optional[VaultService]) -> None:
        """Assign or update the VaultService instance used by the view."""
        self._vault_service = vault_service
        if self.context is not None:
            self.context.set_crypto_unlocked(vault_service is not None)
        self.refresh_identities()

    def set_password_provider(self, password_provider: Optional[Callable[[dict], str]]) -> None:
        """Assign a custom UI-thread password provider (e.g., for testing or shared dialogs)."""
        self._password_provider = password_provider

    def set_input_file(self, path: str | Path) -> None:
        """Populate input file path (useful when receiving a file from DocumentsView)."""
        target_path = Path(path)
        target = str(target_path)
        if target_path.suffix.lower() == ".json":
            self._tabs.setCurrentIndex(1)
            self._dec_source_edit.setText(target)
        else:
            self._tabs.setCurrentIndex(0)
            self._enc_source_edit.setText(target)

    def _ensure_vault_service(self) -> Optional[VaultService]:
        """Return configured VaultService or initialize one from DesktopContext on the UI thread."""
        if self._vault_service is not None:
            return self._vault_service

        if self.context is None:
            self._report_rejection("service_missing", "No VaultService instance is configured.")
            return None

        if not self.context.registry_exists:
            self._report_rejection(
                "registry_missing",
                f"No vault registry found in {self.context.data_dir}. Initialize the vault first.",
            )
            return None

        reg_password, ok = QInputDialog.getText(
            self,
            "Vault Registry Authentication",
            "Enter registry password to unlock identities:",
            QLineEdit.EchoMode.Password,
        )
        if not ok or not reg_password:
            self._report_rejection("cancelled", "Registry unlock cancelled.")
            return None

        try:
            service = self.context.make_service(reg_password)
            service.list_keys()
        except Exception as exc:
            self._report_rejection("registry_error", f"Unable to open vault registry: {exc}")
            return None

        self._vault_service = service
        if self.context is not None:
            self.context.set_crypto_unlocked(True)
        self.refresh_identities()
        return service

    def refresh_identities(self) -> None:
        """Populate signer and recipient selectors from VaultService registry if available."""
        signers: list[str] = []
        recipients: list[str] = []

        if self._vault_service is not None:
            try:
                keys = self._vault_service.list_keys()
                signers = sorted(
                    {
                        k["user_id"]
                        for k in keys
                        if k.get("algorithm") == "Ed25519" and k.get("status") == "active"
                    }
                )
                recipients = sorted(
                    {
                        k["user_id"]
                        for k in keys
                        if k.get("algorithm") == "secp256k1" and k.get("status") == "active"
                    }
                )
            except Exception:
                signers = []
                recipients = []

        self._populate_combo(self._enc_signer_combo, signers, editable=True)
        self._populate_combo(self._enc_rec1_combo, recipients, editable=True)
        self._populate_combo(self._enc_rec2_combo, recipients, editable=True)
        self._populate_combo(self._enc_rec3_combo, recipients, editable=True)
        self._populate_combo(self._dec_user_combo, recipients, editable=True)

        if len(recipients) >= 2 and self._enc_rec2_combo.count() >= 2:
            self._enc_rec2_combo.setCurrentIndex(1)

    @staticmethod
    def _populate_combo(combo: QComboBox, values: list[str], *, editable: bool = False) -> None:
        current_text = combo.currentText().strip()
        combo.blockSignals(True)
        combo.clear()
        combo.addItems(values)
        combo.setEditable(editable)
        if current_text:
            combo.setCurrentText(current_text)
        combo.blockSignals(False)

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        title = QLabel("Encrypt / Decrypt Documents")
        title.setStyleSheet("font-size: 18px; font-weight: 600;")
        layout.addWidget(title)

        self._tabs = QTabWidget(self)
        self._tabs.addTab(self._build_encrypt_tab(), "Encrypt")
        self._tabs.addTab(self._build_decrypt_tab(), "Decrypt")
        layout.addWidget(self._tabs)

        status_group = QGroupBox("Operation Status and Result")
        status_layout = QVBoxLayout(status_group)

        self._status_badge = QLabel("Ready")
        self._status_badge.setStyleSheet("font-weight: 600;")
        self._result_log = QTextEdit()
        self._result_log.setReadOnly(True)
        self._result_log.setMaximumHeight(130)

        status_layout.addWidget(self._status_badge)
        status_layout.addWidget(self._result_log)
        layout.addWidget(status_group)

    def _build_encrypt_tab(self) -> QWidget:
        tab = QWidget()
        form = QFormLayout(tab)
        form.setSpacing(10)

        self._enc_source_edit = QLineEdit()
        self._enc_source_edit.setPlaceholderText("Select input file...")
        enc_src_btn = QPushButton("Browse...")
        enc_src_btn.clicked.connect(self._browse_encrypt_source)
        form.addRow("Input File:", self._wrap_path_row(self._enc_source_edit, enc_src_btn))

        self._enc_output_edit = QLineEdit()
        self._enc_output_edit.setPlaceholderText("Output container path (must not already exist)...")
        enc_out_btn = QPushButton("Save As...")
        enc_out_btn.clicked.connect(self._browse_encrypt_output)
        form.addRow("Output File:", self._wrap_path_row(self._enc_output_edit, enc_out_btn))

        self._enc_signer_combo = QComboBox()
        form.addRow("Signer (Ed25519):", self._enc_signer_combo)

        self._enc_rec1_combo = QComboBox()
        self._enc_rec2_combo = QComboBox()
        self._enc_rec3_combo = QComboBox()
        self._enc_extra_recipients_edit = QLineEdit()
        self._enc_extra_recipients_edit.setPlaceholderText(
            "Additional recipients separated by comma (optional)"
        )

        form.addRow("Recipient 1:", self._enc_rec1_combo)
        form.addRow("Recipient 2:", self._enc_rec2_combo)
        form.addRow("Recipient 3 (optional):", self._enc_rec3_combo)
        form.addRow("Other Recipients:", self._enc_extra_recipients_edit)

        self._encrypt_btn = QPushButton("Encrypt and Sign Document")
        self._encrypt_btn.clicked.connect(self._start_encrypt)
        form.addRow("", self._encrypt_btn)

        return tab

    def _build_decrypt_tab(self) -> QWidget:
        tab = QWidget()
        form = QFormLayout(tab)
        form.setSpacing(10)

        self._dec_source_edit = QLineEdit()
        self._dec_source_edit.setPlaceholderText("Select encrypted container...")
        dec_src_btn = QPushButton("Browse...")
        dec_src_btn.clicked.connect(self._browse_decrypt_source)
        form.addRow("Encrypted Container:", self._wrap_path_row(self._dec_source_edit, dec_src_btn))

        self._dec_user_combo = QComboBox()
        form.addRow("Recipient Identity:", self._dec_user_combo)

        self._dec_output_edit = QLineEdit()
        self._dec_output_edit.setPlaceholderText("Recovered output path (must not already exist)...")
        dec_out_btn = QPushButton("Save As...")
        dec_out_btn.clicked.connect(self._browse_decrypt_output)
        form.addRow("Output File:", self._wrap_path_row(self._dec_output_edit, dec_out_btn))

        self._decrypt_btn = QPushButton("Verify and Decrypt")
        self._decrypt_btn.clicked.connect(self._start_decrypt)
        form.addRow("", self._decrypt_btn)

        return tab

    @staticmethod
    def _wrap_path_row(line_edit: QLineEdit, button: QPushButton) -> QWidget:
        row = QWidget()
        hl = QHBoxLayout(row)
        hl.setContentsMargins(0, 0, 0, 0)
        hl.addWidget(line_edit)
        hl.addWidget(button)
        return row

    def _browse_encrypt_source(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Select File to Encrypt")
        if path:
            self._enc_source_edit.setText(path)

    def _browse_encrypt_output(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, "Save Encrypted Container")
        if path:
            self._enc_output_edit.setText(path)

    def _browse_decrypt_source(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Select Container to Decrypt")
        if path:
            self._dec_source_edit.setText(path)

    def _browse_decrypt_output(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, "Save Decrypted File")
        if path:
            self._dec_output_edit.setText(path)

    def _collect_recipients(self) -> list[str]:
        candidates = [
            self._enc_rec1_combo.currentText().strip(),
            self._enc_rec2_combo.currentText().strip(),
            self._enc_rec3_combo.currentText().strip(),
        ]
        extra = [item.strip() for item in self._enc_extra_recipients_edit.text().split(",")]
        candidates.extend(extra)
        return [item for item in candidates if item]

    def _resolve_password_provider(self) -> Optional[PasswordProvider]:
        """Return an explicit provider if injected; otherwise use password_requested signal."""
        return self._password_provider

    @Slot(dict)
    def _on_password_requested(self, key_entry: dict) -> None:
        """Handle password_requested on the main UI thread and reply to the worker."""
        worker = self._worker
        if worker is None:
            return
        secret, ok = _default_password_dialog(self, key_entry)
        if not ok:
            worker.cancel_password()
            return
        worker.submit_password(secret)

    def _validate_output_not_existing(self, output_path: Path) -> Optional[str]:
        if output_path.exists():
            return f"Operation rejected: output path already exists ({output_path})."
        return None

    def _start_encrypt(self) -> None:
        service = self._ensure_vault_service()
        if service is None:
            return

        source_text = self._enc_source_edit.text().strip()
        output_text = self._enc_output_edit.text().strip()
        signer_user = self._enc_signer_combo.currentText().strip()
        recipients = self._collect_recipients()

        if not source_text:
            self._report_rejection("validation_error", "Select an input file.")
            return
        if not output_text:
            self._report_rejection("validation_error", "Provide an output path for the container.")
            return
        if not signer_user:
            self._report_rejection("validation_error", "Select or enter a signer.")
            return
        if len(recipients) < 2 or len(set(recipients)) != len(recipients):
            self._report_rejection(
                "validation_error",
                "Provide at least two distinct recipients.",
            )
            return

        source_path = Path(source_text)
        output_path = Path(output_text)
        if not source_path.is_file():
            self._report_rejection("file_not_found", f"Input file does not exist: {source_path}")
            return

        collision_msg = self._validate_output_not_existing(output_path)
        if collision_msg:
            self._report_rejection("file_exists", collision_msg)
            return

        self._launch_worker(
            service,
            "encrypt",
            {
                "source": source_path,
                "output": output_path,
                "signer_user": signer_user,
                "recipients": recipients,
            },
        )

    def _start_decrypt(self) -> None:
        service = self._ensure_vault_service()
        if service is None:
            return

        source_text = self._dec_source_edit.text().strip()
        output_text = self._dec_output_edit.text().strip()
        user_id = self._dec_user_combo.currentText().strip()

        if not source_text:
            self._report_rejection("validation_error", "Select an encrypted container.")
            return
        if not output_text:
            self._report_rejection("validation_error", "Provide an output path for the recovered file.")
            return
        if not user_id:
            self._report_rejection("validation_error", "Select or enter a recipient identity.")
            return

        source_path = Path(source_text)
        output_path = Path(output_text)
        if not source_path.is_file():
            self._report_rejection("file_not_found", f"Container does not exist: {source_path}")
            return

        collision_msg = self._validate_output_not_existing(output_path)
        if collision_msg:
            self._report_rejection("file_exists", collision_msg)
            return

        self._launch_worker(
            service,
            "decrypt",
            {
                "source": source_path,
                "output": output_path,
                "user_id": user_id,
            },
        )

    def _launch_worker(self, service: VaultService, operation: str, params: dict) -> None:
        if self._thread is not None and self._thread.isRunning():
            self._report_rejection("busy", "An operation is already in progress.")
            return

        self._set_busy(True)
        self._status_badge.setText("Running operation...")
        self._status_badge.setStyleSheet("font-weight: 600; color: #38bdf8;")

        thread = QThread()
        provider = self._resolve_password_provider()
        worker = CryptoWorker(
            service,
            operation,
            params,
            password_callback=provider,
        )
        worker.moveToThread(thread)

        if provider is None:
            worker.password_requested.connect(
                self._on_password_requested,
                Qt.ConnectionType.QueuedConnection,
            )

        thread.started.connect(worker.run)
        worker.finished.connect(lambda res: self._on_worker_finished(operation, res))
        worker.error.connect(lambda code, msg: self._on_worker_error(operation, code, msg))
        worker.finished.connect(thread.quit)
        worker.error.connect(thread.quit)
        thread.finished.connect(self._on_thread_cleaned)

        self._thread = thread
        self._worker = worker
        thread.start()

    def _on_worker_finished(self, operation: str, result_path: object) -> None:
        self._set_busy(False)
        action_label = "Encryption completed" if operation == "encrypt" else "Decryption completed"
        msg = f"{action_label}: {result_path}"
        self._status_badge.setText("Completed")
        self._status_badge.setStyleSheet("font-weight: 600; color: #22c55e;")
        self._result_log.append(msg)
        self.operation_completed.emit(operation, result_path)

    def _on_worker_error(self, operation: str, code: str, message: str) -> None:
        self._set_busy(False)
        self._report_rejection(code, message, operation=operation)

    def _report_rejection(self, code: str, message: str, *, operation: str = "") -> None:
        readable = self._format_readable_error(code, message)
        self._status_badge.setText("Rejected")
        self._status_badge.setStyleSheet("font-weight: 600; color: #ef4444;")
        self._result_log.append(f"[{code}] {readable}")
        self.operation_failed.emit(operation, code, readable)

    @staticmethod
    def _format_readable_error(code: str, message: str) -> str:
        lowered = message.lower()
        if code == "file_exists":
            return f"Prevented overwriting an existing file. {message}"
        if code == "lifecycle_error":
            if "revoked" in lowered:
                return f"Blocked by D6 policy (revoked key): {message}"
            if "retired" in lowered:
                return f"Blocked by D6 policy (retired key): {message}"
            return f"Rejected by D6 key lifecycle policy: {message}"
        if code == "integrity_error" or "signature" in lowered or "tamper" in lowered or "tag" in lowered:
            return (
                "Verification failed (tampered file, invalid signature, or unauthorized recipient): "
                f"{message}"
            )
        return message

    def _on_thread_cleaned(self) -> None:
        thread = self._thread
        worker = self._worker
        self._worker = None
        self._thread = None
        if worker is not None:
            worker.deleteLater()
        if thread is not None:
            thread.deleteLater()
        self._set_busy(False)

    def _set_busy(self, busy: bool) -> None:
        if self.context is not None:
            self.context.set_crypto_busy(busy)
        self._encrypt_btn.setEnabled(not busy)
        self._decrypt_btn.setEnabled(not busy)