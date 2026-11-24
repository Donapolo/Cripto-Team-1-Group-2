import pytest
from PySide6.QtWidgets import QApplication

# pyside6 verification
pytest.importorskip("PySide6")

from desktop.ui.views.signatures_view import SignaturesView

@pytest.fixture(scope="session")
def qapp():
    """Ensure a QApplication exists for the GUI tests."""
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    yield app

def test_signatures_view_initialization(qapp):
    """Smoke test: Ensure the SignaturesView opens without crashing."""
    view = SignaturesView()
    assert view is not None
    assert view.btn_verify.isEnabled() is False  # Verify button should be disabled initially
    assert view.lbl_file_status.text() == "No container loaded."