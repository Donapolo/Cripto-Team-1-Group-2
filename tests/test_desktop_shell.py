"""Basic desktop smoke tests (run with QT_QPA_PLATFORM=offscreen in CI)."""

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest

pytest.importorskip("PySide6")

from desktop.app import create_window
from desktop.context import DesktopContext, DEFAULT_DATA_DIR
from desktop.ui.main_window import NAVIGATION, MainWindow
from desktop.ui.views.home_view import HomeView
from PySide6.QtWidgets import QWidget


def test_desktop_navigation(tmp_path):
    app, window = create_window(tmp_path / "local-vault")
    assert len(NAVIGATION) == 6
    assert window.stack.count() == 6
    assert window.current_page == "home"
    for page_id, *_ in NAVIGATION:
        window.navigate(page_id)
        assert window.current_page == page_id
        assert window._nav_buttons[page_id].isChecked()
    window.close()


def test_dashboard_card_opens_page(tmp_path):
    app, window = create_window(tmp_path)
    home = window._pages["home"]
    assert isinstance(home, HomeView)
    home.navigate_requested.emit("keys")
    assert window.current_page == "keys"
    window.close()


def test_local_path_changes_and_registry_detection(tmp_path):
    context = DesktopContext(data_dir=tmp_path / "one")
    assert context.registry_exists is False
    folder = tmp_path / "two"
    folder.mkdir()
    (folder / "registry.json").write_text("not-a-valid-registry", encoding="utf-8")
    signals = []
    context.data_dir_changed.connect(signals.append)
    context.set_data_dir(folder)
    assert context.registry_exists is True  # Presence only: *not* authenticated.
    assert signals == [str(folder.resolve())]


def test_teammate_pages_have_valid_widgets(tmp_path):
    app, window = create_window(tmp_path)
    # Remains valid after the team replaces placeholders with real pages.
    for page in ("documents", "crypto", "signatures", "keys"):
        assert isinstance(window._pages[page], QWidget)
    window.close()
