"""Single source of truth for the desktop's dark/blue visual language."""

from PySide6.QtCore import QByteArray, Qt
from PySide6.QtGui import QColor, QFont, QIcon, QPainter, QPalette, QPixmap
from PySide6.QtSvg import QSvgRenderer
from PySide6.QtWidgets import QApplication


COLORS = {
    "window": "#121820",
    "sidebar": "#171F2A",
    "surface": "#1D2733",
    "surface_hover": "#263446",
    "border": "#334253",
    "text": "#F1F5FB",
    "muted": "#A9B9CC",
    "accent": "#2587E9",
    "accent_hover": "#3999F5",
    "success": "#32CBA7",
}

# Simple hand-authored line icons, rendered with Qt (no web or external assets).
_PATHS = {
    "shield": '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10Z"/><path d="m9 12 2 2 4-4"/>',
    "home": '<path d="m3 10 9-7 9 7v10a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1z"/><path d="M9 21v-8h6v8"/>',
    "folder": '<path d="M3 7a2 2 0 0 1 2-2h5l2 2h7a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/>',
    "lock": '<rect x="5" y="10" width="14" height="11" rx="2"/><path d="M8 10V7a4 4 0 1 1 8 0v3"/>',
    "unlock": '<rect x="5" y="10" width="14" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0"/>',
    "signature": '<path d="M4 20h16"/><path d="m8 16 9-9 3 3-9 9-4 1z"/><path d="m15 9 3 3"/>',
    "key": '<circle cx="8" cy="15" r="4"/><path d="m11 12 9-9 2 2-2 2 2 2-2 2-2-2-4 4"/>',
    "settings": '<circle cx="12" cy="12" r="3"/><path d="M12 2v3m0 14v3M2 12h3m14 0h3M4.9 4.9l2.2 2.2m9.8 9.8 2.2 2.2M19.1 4.9l-2.2 2.2m-9.8 9.8-2.2 2.2"/>',
    "arrow": '<path d="M5 12h14m-6-6 6 6-6 6"/>',
}


def icon(name: str, color: str = "#A9B9CC", size: int = 22) -> QIcon:
    if name not in _PATHS:
        raise ValueError(f"Unknown icon: {name}")
    svg = (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" '
        f'viewBox="0 0 24 24" fill="none" stroke="{color}" '
        f'stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">'
        f'{_PATHS[name]}</svg>'
    )
    canvas = QPixmap(size, size)
    canvas.fill(Qt.GlobalColor.transparent)
    renderer = QSvgRenderer(QByteArray(svg.encode("utf-8")))
    painter = QPainter(canvas)
    renderer.render(painter)
    painter.end()
    return QIcon(canvas)


STYLESHEET = """
QWidget { color: #F1F5FB; font-size: 14px; }
QMainWindow, QWidget#AppRoot { background: #121820; }
QFrame#Sidebar { background: #171F2A; border-right: 1px solid #334253; }
QLabel#BrandName { color: #F1F5FB; font-size: 16px; font-weight: 700; }
QLabel#SidebarSection { color: #738BA4; font-size: 11px; font-weight: 700; letter-spacing: 1px; }
QPushButton#NavigationButton { background: transparent; text-align: left;
    color: #A9B9CC; border-radius: 10px; padding: 13px 14px; font-weight: 500; }
QPushButton#NavigationButton:hover { background: #263446; color: #F1F5FB; }
QPushButton#NavigationButton:checked { background: #1668BA; color: white; font-weight: 700; }
QFrame#Topbar { background: #121820; border-bottom: 1px solid #273443; }
QLabel#PageTitle { font-size: 19px; font-weight: 700; }
QLabel#PageSubtitle { color: #A9B9CC; font-size: 12px; }
QLabel#HeroTitle { font-size: 29px; font-weight: 700; }
QLabel#HeroSubtitle { font-size: 14px; color: #A9B9CC; }
QFrame#HeroPanel { background: #1D2733; border: 1px solid #334253; border-radius: 18px; }
QFrame#ActionCard { background: #1D2733; border: 1px solid #334253; border-radius: 15px; }
QFrame#ActionCard:hover { background: #263446; border-color: #2587E9; }
QLabel#CardTitle { font-size: 17px; font-weight: 700; }
QLabel#CardDescription { color: #A9B9CC; font-size: 12px; }
QLabel#SectionTitle { font-size: 18px; font-weight: 700; }
QFrame#InfoPanel { background: #1D2733; border: 1px solid #334253; border-radius: 12px; }
QLabel#MutedText { color: #A9B9CC; }
QPushButton#PrimaryButton { background: #1679D0; border: 1px solid #288DE0;
    color: white; border-radius: 9px; padding: 9px 16px; font-weight: 700; }
QPushButton#PrimaryButton:hover { background: #2587E9; }
QPushButton#SecondaryButton { background: #273646; border: 1px solid #405166;
    color: #F1F5FB; border-radius: 9px; padding: 9px 16px; }
QPushButton#SecondaryButton:hover { background: #34465C; }
QLineEdit { background: #111923; border: 1px solid #405166; border-radius: 9px;
    padding: 10px; selection-background-color: #2587E9; }
QLineEdit:focus { border-color: #2587E9; }
QScrollArea, QScrollArea > QWidget > QWidget { background: transparent; border: none; }
QMessageBox { background: #171F2A; }
"""


def apply_theme(app: QApplication) -> None:
    app.setStyle("Fusion")
    palette = QPalette()
    palette.setColor(QPalette.ColorRole.Window, QColor(COLORS["window"]))
    palette.setColor(QPalette.ColorRole.WindowText, QColor(COLORS["text"]))
    palette.setColor(QPalette.ColorRole.Base, QColor("#111923"))
    palette.setColor(QPalette.ColorRole.AlternateBase, QColor(COLORS["surface"]))
    palette.setColor(QPalette.ColorRole.Text, QColor(COLORS["text"]))
    palette.setColor(QPalette.ColorRole.Button, QColor(COLORS["surface"]))
    palette.setColor(QPalette.ColorRole.ButtonText, QColor(COLORS["text"]))
    palette.setColor(QPalette.ColorRole.Highlight, QColor(COLORS["accent"]))
    palette.setColor(QPalette.ColorRole.HighlightedText, QColor("#FFFFFF"))
    app.setPalette(palette)
    font = QFont("Segoe UI", 10)
    app.setFont(font)
    app.setStyleSheet(STYLESHEET)


def named(widget, object_name: str):
    """Assign Qt objectName without relying on constructor keyword properties."""
    widget.setObjectName(object_name)
    return widget
