"""Home dashboard — real navigation, no fake cryptographic state."""

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QFrame, QGridLayout, QHBoxLayout, QLabel, QPushButton, QScrollArea,
    QSizePolicy, QVBoxLayout, QWidget,
)

from desktop.context import DesktopContext
from desktop.ui.theme import COLORS, icon, named


class HomeView(QWidget):
    navigate_requested = Signal(str)

    def __init__(self, context: DesktopContext, parent: QWidget | None = None):
        super().__init__(parent)
        self.context = context
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(28, 28, 28, 28)
        layout.setSpacing(22)

        hero = named(QFrame(), "HeroPanel")
        hero_layout = QHBoxLayout(hero)
        hero_layout.setContentsMargins(26, 28, 26, 28)
        left = QVBoxLayout()
        left.setSpacing(10)
        eyebrow = QLabel("SECURE DOCUMENT VAULT  /  DESKTOP")
        eyebrow.setStyleSheet("color:#55B1FF; font-weight:700; font-size:11px;")
        title = named(QLabel("Tus documentos, bajo tu control."), "HeroTitle")
        title.setWordWrap(True)
        subtitle = QLabel(
            "Cifra, descifra y administra tus claves desde una aplicación local. "
            "Tus operaciones usan el motor criptográfico del proyecto D2–D6.",
        )
        subtitle.setObjectName("HeroSubtitle")
        subtitle.setWordWrap(True)
        subtitle.setMaximumWidth(660)
        left.addWidget(eyebrow)
        left.addWidget(title)
        left.addWidget(subtitle)
        hero_layout.addLayout(left, 1)
        shield = QLabel()
        shield.setPixmap(icon("shield", COLORS["accent"], 76).pixmap(76, 76))
        hero_layout.addWidget(shield, 0, Qt.AlignmentFlag.AlignTop)
        layout.addWidget(hero)

        section = named(QLabel("¿Qué quieres hacer hoy?"), "SectionTitle")
        layout.addWidget(section)

        grid = QGridLayout()
        grid.setSpacing(16)
        actions = [
            ("Cifrar documento", "Protege un archivo y fírmalo para dos o más destinatarios.", "lock", "crypto"),
            ("Descifrar documento", "Recupera un archivo autorizado después de verificar su integridad.", "unlock", "crypto"),
            ("Verificar firmas", "Consulta la validez y autorización del firmante de un contenedor.", "signature", "signatures"),
            ("Administrar claves", "Consulta tus claves locales y su estado de ciclo de vida.", "key", "keys"),
        ]
        for index, (title_text, description, symbol, destination) in enumerate(actions):
            card = self._card(title_text, description, symbol, destination)
            grid.addWidget(card, index // 2, index % 2)
        layout.addLayout(grid)

        panel = named(QFrame(), "InfoPanel")
        status_layout = QVBoxLayout(panel)
        status_layout.setContentsMargins(20, 17, 20, 17)
        status_layout.setSpacing(6)
        status_title = QLabel("Entorno local")
        status_title.setStyleSheet("font-weight:700;")
        self.status_label = QLabel()
        self.status_label.setObjectName("MutedText")
        self.status_label.setWordWrap(True)
        self.data_label = QLabel()
        self.data_label.setObjectName("MutedText")
        self.data_label.setWordWrap(True)
        self.data_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        status_layout.addWidget(status_title)
        status_layout.addWidget(self.status_label)
        status_layout.addWidget(self.data_label)
        layout.addWidget(panel)
        layout.addStretch(1)

        scroll.setWidget(content)
        root.addWidget(scroll)
        context.data_dir_changed.connect(self.refresh_status)
        self.refresh_status()

    def _card(self, heading: str, description: str, symbol: str, page: str) -> QFrame:
        card = named(QFrame(), "ActionCard")
        card.setMinimumHeight(185)
        card.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        box = QVBoxLayout(card)
        box.setContentsMargins(20, 20, 20, 18)
        box.setSpacing(11)
        pictogram = QLabel()
        pictogram.setPixmap(icon(symbol, COLORS["accent"], 28).pixmap(28, 28))
        box.addWidget(pictogram)
        name = named(QLabel(heading), "CardTitle")
        name.setWordWrap(True)
        box.addWidget(name)
        desc = named(QLabel(description), "CardDescription")
        desc.setWordWrap(True)
        box.addWidget(desc)
        box.addStretch()
        action = QPushButton("Abrir módulo")
        action.setObjectName("PrimaryButton")
        action.setCursor(Qt.CursorShape.PointingHandCursor)
        action.setSizePolicy(QSizePolicy.Policy.Maximum, QSizePolicy.Policy.Fixed)
        action.clicked.connect(lambda _checked=False, destination=page: self.navigate_requested.emit(destination))
        box.addWidget(action)
        return card

    def refresh_status(self, _path: str = "") -> None:
        # File presence is not equivalent to integrity/authentication verification.
        self.status_label.setText(
            "Registro local detectado (autenticidad pendiente de validar)."
            if self.context.registry_exists
            else "No se ha detectado un registro local en esta carpeta."
        )
        self.data_label.setText(f"Carpeta configurada: {self.context.data_dir}")
