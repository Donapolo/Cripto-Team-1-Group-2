"""Local document selection and inspection view for the Desktop MVP."""

from __future__ import annotations

from pathlib import Path
from typing import Iterable, Optional

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QAbstractItemView,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)


class DocumentsView(QWidget):
    """Allows selecting local files without copying them and inspecting status."""

    files_changed = Signal(object)
    send_to_crypto = Signal(object)

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._documents: list[Path] = []
        self._build_ui()
        self._refresh_table()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        header_layout = QHBoxLayout()
        title_label = QLabel("Documentos locales")
        title_label.setStyleSheet("font-size: 18px; font-weight: 600;")

        self._summary_label = QLabel("0 archivos seleccionados")
        self._summary_label.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)

        header_layout.addWidget(title_label)
        header_layout.addStretch()
        header_layout.addWidget(self._summary_label)
        layout.addLayout(header_layout)

        actions_layout = QHBoxLayout()
        self._add_btn = QPushButton("Seleccionar archivos...")
        self._refresh_btn = QPushButton("Actualizar estado")
        self._remove_btn = QPushButton("Quitar selección")
        self._clear_btn = QPushButton("Limpiar lista")
        self._use_crypto_btn = QPushButton("Usar en Cifrar / Descifrar")

        self._add_btn.clicked.connect(self._on_browse_files)
        self._refresh_btn.clicked.connect(self.refresh_statuses)
        self._remove_btn.clicked.connect(self.remove_selected)
        self._clear_btn.clicked.connect(self.clear_files)
        self._use_crypto_btn.clicked.connect(self._on_use_in_crypto)

        actions_layout.addWidget(self._add_btn)
        actions_layout.addWidget(self._refresh_btn)
        actions_layout.addWidget(self._remove_btn)
        actions_layout.addWidget(self._clear_btn)
        actions_layout.addStretch()
        actions_layout.addWidget(self._use_crypto_btn)
        layout.addLayout(actions_layout)

        self._table = QTableWidget(0, 3, self)
        self._table.setHorizontalHeaderLabels(["Nombre", "Ruta", "Estado"])
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self._table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._table.verticalHeader().setVisible(False)

        header = self._table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)

        self._table.itemSelectionChanged.connect(self._sync_action_states)
        layout.addWidget(self._table)

    @staticmethod
    def describe_file_status(path: Path) -> str:
        """Return a readable status for a local path without copying or modifying it."""
        if not path.exists():
            return "No encontrado"
        if path.is_dir():
            return "Directorio"
        if not path.is_file():
            return "No es archivo regular"
        return "Disponible"

    def add_files(self, paths: Iterable[str | Path]) -> int:
        """Register local file paths in place without copying them."""
        added = 0
        existing_keys = {str(p.resolve()) if p.exists() else str(p) for p in self._documents}

        for raw in paths:
            candidate = Path(raw).expanduser()
            key = str(candidate.resolve()) if candidate.exists() else str(candidate)
            if key not in existing_keys:
                self._documents.append(candidate)
                existing_keys.add(key)
                added += 1

        if added > 0:
            self._refresh_table()
            self.files_changed.emit(self.selected_paths())
        return added

    def selected_paths(self) -> list[Path]:
        """Return all currently tracked local file paths."""
        return list(self._documents)

    def current_selected_path(self) -> Optional[Path]:
        """Return the first currently highlighted file path, if any."""
        rows = sorted({idx.row() for idx in self._table.selectedIndexes()})
        if not rows:
            return self._documents[0] if self._documents else None
        row = rows[0]
        if 0 <= row < len(self._documents):
            return self._documents[row]
        return None

    def refresh_statuses(self) -> None:
        """Re-evaluate existence/status of tracked local files."""
        self._refresh_table()

    def remove_selected(self) -> None:
        """Remove highlighted rows from the view list (never deletes source files)."""
        rows = sorted({idx.row() for idx in self._table.selectedIndexes()}, reverse=True)
        if not rows:
            return
        for row in rows:
            if 0 <= row < len(self._documents):
                del self._documents[row]
        self._refresh_table()
        self.files_changed.emit(self.selected_paths())

    def clear_files(self) -> None:
        """Clear all tracked items from the view list."""
        if not self._documents:
            return
        self._documents.clear()
        self._refresh_table()
        self.files_changed.emit(self.selected_paths())

    def _on_browse_files(self) -> None:
        files, _ = QFileDialog.getOpenFileNames(
            self,
            "Seleccionar archivos locales",
            "",
            "Todos los archivos (*)",
        )
        if files:
            self.add_files(files)

    def _on_use_in_crypto(self) -> None:
        target = self.current_selected_path()
        if target is not None:
            self.send_to_crypto.emit(target)

    def _refresh_table(self) -> None:
        self._table.setRowCount(len(self._documents))
        for row, path in enumerate(self._documents):
            name_item = QTableWidgetItem(path.name or str(path))
            path_item = QTableWidgetItem(str(path))
            status_text = self.describe_file_status(path)
            status_item = QTableWidgetItem(status_text)

            path_item.setToolTip(str(path))
            status_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)

            self._table.setItem(row, 0, name_item)
            self._table.setItem(row, 1, path_item)
            self._table.setItem(row, 2, status_item)

        count = len(self._documents)
        self._summary_label.setText(
            f"{count} archivo seleccionado" if count == 1 else f"{count} archivos seleccionados"
        )
        self._sync_action_states()

    def _sync_action_states(self) -> None:
        has_any = len(self._documents) > 0
        has_selection = len(self._table.selectedIndexes()) > 0
        self._refresh_btn.setEnabled(has_any)
        self._remove_btn.setEnabled(has_selection)
        self._clear_btn.setEnabled(has_any)
        self._use_crypto_btn.setEnabled(has_any)