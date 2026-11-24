"""Main window and navigation contract for the four team members.

Future views must be QWidget subclasses with the constructor:
    def __init__(self, context: DesktopContext, parent: QWidget | None = None)

and must be named as defined in EXTERNAL_VIEWS. They are loaded when the
application starts; missing modules show an honest placeholder.
"""

from importlib import import_module
from importlib.util import find_spec

from PySide6.QtCore import QSize, Qt
from PySide6.QtWidgets import (
    QFrame, QHBoxLayout, QLabel, QMainWindow, QPushButton, QStackedWidget,
    QVBoxLayout, QWidget,
)

from desktop.context import DesktopContext
from desktop.ui.theme import COLORS, icon, named
from desktop.ui.views.home_view import HomeView
from desktop.ui.views.settings_view import SettingsView


NAVIGATION = [
    ("home", "Inicio", "home", "Accesos rápidos y estado del entorno"),
    ("documents", "Documentos", "folder", "Selecciona tus documentos locales"),
    ("crypto", "Cifrar / Descifrar", "lock", "Protección y recuperación de archivos"),
    ("signatures", "Firmas", "signature", "Verificación de contenedores firmados"),
    ("keys", "Mis claves", "key", "Identidades, estados y respaldos"),
    ("settings", "Configuración", "settings", "Almacenamiento y preferencias locales"),
]

# Contract: filename, import path, exported QWidget subclass and responsible team member.
EXTERNAL_VIEWS = {
    "documents": ("desktop.ui.views.documents_view", "DocumentsView", "Jonathan"),
    "crypto": ("desktop.ui.views.crypto_view", "CryptoView", "Jonathan"),
    "signatures": ("desktop.ui.views.signatures_view", "SignaturesView", "Jesús"),
    "keys": ("desktop.ui.views.keys_view", "KeysView", "Yuki"),
}


class PlaceholderView(QWidget):
    """Visible and navigable until a teammate delivers the real page."""

    def __init__(self, page_name: str, assignee: str, parent: QWidget | None = None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(28, 28, 28, 28)
        layout.setSpacing(12)
        label = QLabel(page_name)
        label.setObjectName("HeroTitle")
        layout.addWidget(label)
        status = QLabel(f"Módulo en desarrollo · Responsable: {assignee}")
        status.setObjectName("MutedText")
        layout.addWidget(status)
        info = QLabel(
            "Esta sección todavía no está conectada. "
            "Se mostrará la pantalla real cuando se integre el archivo del equipo."
        )
        info.setWordWrap(True)
        info.setObjectName("MutedText")
        layout.addWidget(info)
        layout.addStretch()


class FailedView(QWidget):
    """Show a real integration failure, not an apparently complete feature."""

    def __init__(self, page_name: str, detail: str, parent: QWidget | None = None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(28, 28, 28, 28)
        title = QLabel(f"No se pudo cargar: {page_name}")
        title.setObjectName("SectionTitle")
        details = QLabel(detail)
        details.setWordWrap(True)
        details.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        details.setObjectName("MutedText")
        layout.addWidget(title)
        layout.addWidget(details)
        layout.addStretch()


class MainWindow(QMainWindow):
    def __init__(self, context: DesktopContext, parent: QWidget | None = None):
        super().__init__(parent)
        self.context = context
        self.setWindowTitle("Secure Document Vault")
        self.setMinimumSize(920, 610)
        self.resize(1180, 760)
        self._page_indices: dict[str, int] = {}
        self._nav_buttons: dict[str, QPushButton] = {}
        self._pages: dict[str, QWidget] = {}

        root = QWidget()
        root.setObjectName("AppRoot")
        self.setCentralWidget(root)
        horizontal = QHBoxLayout(root)
        horizontal.setContentsMargins(0, 0, 0, 0)
        horizontal.setSpacing(0)

        sidebar = self._make_sidebar()
        horizontal.addWidget(sidebar)

        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(0)

        topbar = named(QFrame(), "Topbar")
        topbar_layout = QVBoxLayout(topbar)
        topbar_layout.setContentsMargins(28, 17, 28, 17)
        topbar_layout.setSpacing(3)
        self.page_title = named(QLabel(), "PageTitle")
        self.page_subtitle = named(QLabel(), "PageSubtitle")
        topbar_layout.addWidget(self.page_title)
        topbar_layout.addWidget(self.page_subtitle)
        right_layout.addWidget(topbar)

        self.stack = QStackedWidget()
        right_layout.addWidget(self.stack, 1)
        horizontal.addWidget(right, 1)

        self._install_views()
        self.navigate("home")

    def _make_sidebar(self) -> QFrame:
        bar = named(QFrame(), "Sidebar")
        bar.setFixedWidth(250)
        layout = QVBoxLayout(bar)
        layout.setContentsMargins(15, 23, 15, 20)
        layout.setSpacing(9)

        brand_line = QHBoxLayout()
        brand_icon = QLabel()
        brand_icon.setPixmap(icon("shield", COLORS["accent"], 29).pixmap(29, 29))
        brand = named(QLabel("Secure Document Vault"), "BrandName")
        brand.setWordWrap(True)
        brand_line.addWidget(brand_icon)
        brand_line.addWidget(brand, 1)
        layout.addLayout(brand_line)
        layout.addSpacing(33)

        section = named(QLabel("NAVEGACIÓN"), "SidebarSection")
        layout.addWidget(section)
        layout.addSpacing(4)

        for page_id, label, symbol, _subtitle in NAVIGATION:
            if page_id == "settings":
                layout.addStretch(1)
                layout.addSpacing(12)
            button = QPushButton(label)
            button.setObjectName("NavigationButton")
            button.setCheckable(True)
            button.setCursor(Qt.CursorShape.PointingHandCursor)
            button.setIcon(icon(symbol))
            button.setIconSize(QSize(20, 20))
            button.setMinimumHeight(46)
            button.clicked.connect(lambda _checked=False, name=page_id: self.navigate(name))
            layout.addWidget(button)
            self._nav_buttons[page_id] = button

        footnote = QLabel("D2–D6  ·  Aplicación local")
        footnote.setObjectName("MutedText")
        footnote.setStyleSheet("font-size:11px;")
        layout.addWidget(footnote)
        return bar

    def _install_views(self) -> None:
        for page_id, label, _symbol, _subtitle in NAVIGATION:
            if page_id == "home":
                view = HomeView(self.context, self.stack)
                view.navigate_requested.connect(self.navigate)
            elif page_id == "settings":
                view = SettingsView(self.context, self.stack)
            else:
                view = self._external_view(page_id, label)
            self._page_indices[page_id] = self.stack.addWidget(view)
            self._pages[page_id] = view

    def _external_view(self, page_id: str, label: str) -> QWidget:
        module_name, class_name, assignee = EXTERNAL_VIEWS[page_id]
        if find_spec(module_name) is None:
            return PlaceholderView(label, assignee, self.stack)
        try:
            page_class = getattr(import_module(module_name), class_name)
            view = page_class(self.context, self.stack)
            if not isinstance(view, QWidget):
                raise TypeError(f"{class_name} must be a QWidget subclass")
            return view
        except Exception as exc:
            return FailedView(label, f"Revisa {module_name}.{class_name}: {exc}", self.stack)

    def navigate(self, page_id: str) -> None:
        """Shared navigation API for sidebar, home cards and future modules."""
        if page_id not in self._page_indices:
            raise ValueError(f"Unknown navigation page: {page_id}")
        self.stack.setCurrentIndex(self._page_indices[page_id])
        for key, button in self._nav_buttons.items():
            button.setChecked(key == page_id)
        for key, label, _symbol, subtitle in NAVIGATION:
            if key == page_id:
                self.page_title.setText(label)
                self.page_subtitle.setText(subtitle)
                break

    @property
    def current_page(self) -> str:
        index = self.stack.currentIndex()
        return next(name for name, position in self._page_indices.items() if position == index)
