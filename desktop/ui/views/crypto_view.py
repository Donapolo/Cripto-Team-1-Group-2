"""Encryption and decryption view for the Desktop MVP."""

from __future__ import annotations

from pathlib import Path
from typing import Callable, Optional

from PySide6.QtCore import QThread, Qt, Signal
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

from desktop.workers.crypto_worker import CryptoWorker
from src.services.vault_service import PasswordProvider, VaultService


def _default_password_dialog(parent: QWidget, key_entry: dict) -> str:
    """Fallback modal password prompt on the UI thread until Yuki's dialog is wired."""
    user_id = key_entry.get("user_id", "usuario")
    algorithm = key_entry.get("algorithm", "clave")
    key_id = key_entry.get("key_id", "")
    label = (
        f"Contraseña para {user_id} ({algorithm} - {key_id}):"
        if key_id
        else f"Contraseña para {user_id} ({algorithm}):"
    )
    secret, ok = QInputDialog.getText(
        parent,
        "Autenticación de clave",
        label,
        QLineEdit.EchoMode.Password,
    )
    return secret if ok else ""


class CryptoView(QWidget):
    """Provides non-blocking encryption and decryption workflows backed by VaultService."""

    operation_completed = Signal(str, object)
    operation_failed = Signal(str, str, str)

    def __init__(
        self,
        vault_service: Optional[VaultService] = None,
        password_provider: Optional[Callable[[dict], str]] = None,
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)
        self._vault_service = vault_service
        self._password_provider: Optional[Callable[[dict], str]] = password_provider
        self._thread: Optional[QThread] = None
        self._worker: Optional[CryptoWorker] = None
        self._build_ui()
        self.refresh_identities()

    def set_vault_service(self, vault_service: Optional[VaultService]) -> None:
        """Assign or update the VaultService instance used by the view."""
        self._vault_service = vault_service
        self.refresh_identities()

    def set_password_provider(self, password_provider: Optional[Callable[[dict], str]]) -> None:
        """Assign a custom UI-thread password provider (e.g., Yuki's shared dialog)."""
        self._password_provider = password_provider

    def set_input_file(self, path: str | Path) -> None:
        """Populate input file path (useful when receiving a file from DocumentsView)."""
        target = str(Path(path))
        if self._tabs.currentIndex() == 0:
            self._enc_source_edit.setText(target)
        else:
            self._dec_source_edit.setText(target)

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

        title = QLabel("Cifrar / Descifrar documentos")
        title.setStyleSheet("font-size: 18px; font-weight: 600;")
        layout.addWidget(title)

        self._tabs = QTabWidget(self)
        self._tabs.addTab(self._build_encrypt_tab(), "Cifrar")
        self._tabs.addTab(self._build_decrypt_tab(), "Descifrar")
        layout.addWidget(self._tabs)

        status_group = QGroupBox("Estado y resultado de la operación")
        status_layout = QVBoxLayout(status_group)

        self._status_badge = QLabel("Listo")
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
        self._enc_source_edit.setPlaceholderText("Selecciona el archivo de entrada...")
        enc_src_btn = QPushButton("Examinar...")
        enc_src_btn.clicked.connect(self._browse_encrypt_source)
        form.addRow("Archivo de entrada:", self._wrap_path_row(self._enc_source_edit, enc_src_btn))

        self._enc_output_edit = QLineEdit()
        self._enc_output_edit.setPlaceholderText("Ruta de salida del contenedor (no debe existir)...")
        enc_out_btn = QPushButton("Guardar como...")
        enc_out_btn.clicked.connect(self._browse_encrypt_output)
        form.addRow("Archivo de salida:", self._wrap_path_row(self._enc_output_edit, enc_out_btn))

        self._enc_signer_combo = QComboBox()
        form.addRow("Firmante (Ed25519):", self._enc_signer_combo)

        self._enc_rec1_combo = QComboBox()
        self._enc_rec2_combo = QComboBox()
        self._enc_rec3_combo = QComboBox()
        self._enc_extra_recipients_edit = QLineEdit()
        self._enc_extra_recipients_edit.setPlaceholderText("Destinatarios adicionales separados por coma (opcional)")

        form.addRow("Destinatario 1:", self._enc_rec1_combo)
        form.addRow("Destinatario 2:", self._enc_rec2_combo)
        form.addRow("Destinatario 3 (opcional):", self._enc_rec3_combo)
        form.addRow("Otros destinatarios:", self._enc_extra_recipients_edit)

        self._encrypt_btn = QPushButton("Cifrar y firmar documento")
        self._encrypt_btn.clicked.connect(self._start_encrypt)
        form.addRow("", self._encrypt_btn)

        return tab

    def _build_decrypt_tab(self) -> QWidget:
        tab = QWidget()
        form = QFormLayout(tab)
        form.setSpacing(10)

        self._dec_source_edit = QLineEdit()
        self._dec_source_edit.setPlaceholderText("Selecciona el contenedor cifrado...")
        dec_src_btn = QPushButton("Examinar...")
        dec_src_btn.clicked.connect(self._browse_decrypt_source)
        form.addRow("Contenedor cifrado:", self._wrap_path_row(self._dec_source_edit, dec_src_btn))

        self._dec_user_combo = QComboBox()
        form.addRow("Identidad destinataria:", self._dec_user_combo)

        self._dec_output_edit = QLineEdit()
        self._dec_output_edit.setPlaceholderText("Ruta de salida recuperada (no debe existir)...")
        dec_out_btn = QPushButton("Guardar como...")
        dec_out_btn.clicked.connect(self._browse_decrypt_output)
        form.addRow("Archivo de salida:", self._wrap_path_row(self._dec_output_edit, dec_out_btn))

        self._decrypt_btn = QPushButton("Verificar y descifrar")
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
        path, _ = QFileDialog.getOpenFileName(self, "Seleccionar archivo a cifrar")
        if path:
            self._enc_source_edit.setText(path)

    def _browse_encrypt_output(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, "Guardar contenedor cifrado")
        if path:
            self._enc_output_edit.setText(path)

    def _browse_decrypt_source(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Seleccionar contenedor a descifrar")
        if path:
            self._dec_source_edit.setText(path)

    def _browse_decrypt_output(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, "Guardar archivo descifrado")
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

    def _resolve_password_provider(self) -> PasswordProvider:
        if self._password_provider is not None:
            return self._password_provider
        return lambda entry: _default_password_dialog(self, entry)

    def _validate_output_not_existing(self, output_path: Path) -> Optional[str]:
        if output_path.exists():
            return f"Operación rechazada: la ruta de salida ya existe ({output_path})."
        return None

    def _start_encrypt(self) -> None:
        if self._vault_service is None:
            self._report_rejection("service_missing", "No hay un VaultService configurado.")
            return

        source_text = self._enc_source_edit.text().strip()
        output_text = self._enc_output_edit.text().strip()
        signer_user = self._enc_signer_combo.currentText().strip()
        recipients = self._collect_recipients()

        if not source_text:
            self._report_rejection("validation_error", "Selecciona un archivo de entrada.")
            return
        if not output_text:
            self._report_rejection("validation_error", "Indica una ruta de salida para el contenedor.")
            return
        if not signer_user:
            self._report_rejection("validation_error", "Selecciona o indica un firmante.")
            return
        if len(recipients) < 2 or len(set(recipients)) != len(recipients):
            self._report_rejection(
                "validation_error",
                "Debes indicar al menos dos destinatarios distintos.",
            )
            return

        source_path = Path(source_text)
        output_path = Path(output_text)
        if not source_path.is_file():
            self._report_rejection("file_not_found", f"El archivo de entrada no existe: {source_path}")
            return

        collision_msg = self._validate_output_not_existing(output_path)
        if collision_msg:
            self._report_rejection("file_exists", collision_msg)
            return

        self._launch_worker(
            "encrypt",
            {
                "source": source_path,
                "output": output_path,
                "signer_user": signer_user,
                "recipients": recipients,
            },
        )

    def _start_decrypt(self) -> None:
        if self._vault_service is None:
            self._report_rejection("service_missing", "No hay un VaultService configurado.")
            return

        source_text = self._dec_source_edit.text().strip()
        output_text = self._dec_output_edit.text().strip()
        user_id = self._dec_user_combo.currentText().strip()

        if not source_text:
            self._report_rejection("validation_error", "Selecciona un contenedor cifrado.")
            return
        if not output_text:
            self._report_rejection("validation_error", "Indica una ruta de salida para el archivo recuperado.")
            return
        if not user_id:
            self._report_rejection("validation_error", "Selecciona o indica una identidad destinataria.")
            return

        source_path = Path(source_text)
        output_path = Path(output_text)
        if not source_path.is_file():
            self._report_rejection("file_not_found", f"El contenedor no existe: {source_path}")
            return

        collision_msg = self._validate_output_not_existing(output_path)
        if collision_msg:
            self._report_rejection("file_exists", collision_msg)
            return

        self._launch_worker(
            "decrypt",
            {
                "source": source_path,
                "output": output_path,
                "user_id": user_id,
            },
        )

    def _launch_worker(self, operation: str, params: dict) -> None:
        if self._thread is not None and self._thread.isRunning():
            self._report_rejection("busy", "Ya hay una operación en curso.")
            return

        self._set_busy(True)
        self._status_badge.setText("Ejecutando operación...")
        self._status_badge.setStyleSheet("font-weight: 600; color: #38bdf8;")

        thread = QThread()
        worker = CryptoWorker(
            self._vault_service,
            operation,
            params,
            password_callback=self._resolve_password_provider(),
        )
        worker.moveToThread(thread)

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
        action_label = "Cifrado completado" if operation == "encrypt" else "Descifrado completado"
        msg = f"{action_label}: {result_path}"
        self._status_badge.setText("Concluida")
        self._status_badge.setStyleSheet("font-weight: 600; color: #22c55e;")
        self._result_log.append(msg)
        self.operation_completed.emit(operation, result_path)

    def _on_worker_error(self, operation: str, code: str, message: str) -> None:
        self._set_busy(False)
        self._report_rejection(code, message, operation=operation)

    def _report_rejection(self, code: str, message: str, *, operation: str = "") -> None:
        readable = self._format_readable_error(code, message)
        self._status_badge.setText("Rechazada")
        self._status_badge.setStyleSheet("font-weight: 600; color: #ef4444;")
        self._result_log.append(f"[{code}] {readable}")
        self.operation_failed.emit(operation, code, readable)

    @staticmethod
    def _format_readable_error(code: str, message: str) -> str:
        lowered = message.lower()
        if code == "file_exists":
            return f"Se evitó sobrescribir un archivo existente. {message}"
        if code == "lifecycle_error":
            if "revoked" in lowered:
                return f"Acceso bloqueado por política D6 (clave revocada): {message}"
            if "retired" in lowered:
                return f"Acceso bloqueado por política D6 (clave retirada): {message}"
            return f"Rechazado por política de ciclo de vida D6: {message}"
        if code == "integrity_error" or "signature" in lowered or "tamper" in lowered or "tag" in lowered:
            return f"Verificación fallida (archivo alterado, firma inválida o destinatario no autorizado): {message}"
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
        self._encrypt_btn.setEnabled(not busy)
        self._decrypt_btn.setEnabled(not busy)