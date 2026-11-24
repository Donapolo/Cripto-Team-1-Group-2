"""Minimal local storage settings; intentionally never handles passwords."""

from PySide6.QtWidgets import (
    QFileDialog, QFrame, QHBoxLayout, QLabel, QLineEdit, QMessageBox,
    QPushButton, QVBoxLayout, QWidget,
)

from desktop.context import DesktopContext, DEFAULT_DATA_DIR
from desktop.ui.theme import named


class SettingsView(QWidget):
    def __init__(self, context: DesktopContext, parent: QWidget | None = None):
        super().__init__(parent)
        self.context = context
        layout = QVBoxLayout(self)
        layout.setContentsMargins(28, 28, 28, 28)
        layout.setSpacing(18)

        header = named(QLabel("Local data folder"), "SectionTitle")
        layout.addWidget(header)
        description = QLabel(
            "The authenticated registry and encrypted keystores are stored here. "
            "Changing this folder selects a different vault; it does not move or delete files."
        )
        description.setWordWrap(True)
        description.setObjectName("MutedText")
        layout.addWidget(description)

        panel = named(QFrame(), "InfoPanel")
        panel_layout = QVBoxLayout(panel)
        panel_layout.setContentsMargins(20, 20, 20, 20)
        panel_layout.setSpacing(12)
        self.path_input = QLineEdit(str(context.data_dir))
        self.path_input.setReadOnly(True)
        panel_layout.addWidget(self.path_input)
        buttons = QHBoxLayout()
        browse = QPushButton("Choose folder")
        browse.setObjectName("PrimaryButton")
        browse.clicked.connect(self.choose_folder)
        reset = QPushButton("Restore default location")
        reset.setObjectName("SecondaryButton")
        reset.clicked.connect(self.reset_default)
        buttons.addWidget(browse)
        buttons.addWidget(reset)
        buttons.addStretch()
        panel_layout.addLayout(buttons)
        layout.addWidget(panel)

        note = QLabel(
            "The application only stores this folder preference. "
            "It does not store passwords or private keys in settings."
        )
        note.setWordWrap(True)
        note.setObjectName("MutedText")
        layout.addWidget(note)
        layout.addStretch()
        context.data_dir_changed.connect(self.path_input.setText)

    def choose_folder(self) -> None:
        directory = QFileDialog.getExistingDirectory(
            self, "Select data folder", str(self.context.data_dir)
        )
        if directory:
            self._confirm_change(directory)

    def reset_default(self) -> None:
        self._confirm_change(str(DEFAULT_DATA_DIR))

    def _confirm_change(self, directory: str) -> None:
        if str(self.context.data_dir) == str(self.context._normalize(directory)):
            return
        answer = QMessageBox.question(
            self,
            "Change local data folder",
            "The application will use a different key registry. "
            "Existing files will not be moved. Continue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer == QMessageBox.StandardButton.Yes:
            self.context.set_data_dir(directory)
