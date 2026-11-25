import pytest
from unittest.mock import MagicMock

pytest.importorskip("PySide6")

from PySide6.QtWidgets import QApplication, QMainWindow, QStackedWidget
from desktop.ui.views.signatures_view import SignaturesView
from src.crypto.key_lifecycle import KeyLifecycleError
from src.crypto.signature_manager import SignatureVerificationError

@pytest.fixture(scope="session")
def qapp():
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    yield app

@pytest.fixture
def mock_context():
    context = MagicMock()
    mock_service = MagicMock()
    mock_service.registry.return_value = {"version": "1.0", "keys": {}}
    context.make_service.return_value = mock_service
    return context

@pytest.fixture(autouse=True)
def mock_ask_password(monkeypatch):
    monkeypatch.setattr("desktop.ui.views.signatures_view.ask_password", lambda *args, **kwargs: "mocked_password")

def test_signatures_view_initialization(qapp, mock_context):
    view = SignaturesView(context=mock_context, parent=None)
    assert view is not None
    assert view.btn_verify.isEnabled() is False

def test_signature_valid(qapp, mock_context, monkeypatch):
    view = SignaturesView(context=mock_context)
    view.container_data = {"signer_id": "test123"}
    monkeypatch.setattr("desktop.ui.views.signatures_view.verify_container_with_registry", lambda *args: True)
    
    view.verify_signature()
    assert "✅ Signature Valid" in view.txt_results.toHtml()
    mock_context.make_service.assert_called_once_with("mocked_password")

def test_signature_tampered(qapp, mock_context, monkeypatch):
    view = SignaturesView(context=mock_context)
    view.container_data = {"signer_id": "test123"}
    
    def raise_tampered(*args, **kwargs):
        raise SignatureVerificationError("Tampered container")
        
    monkeypatch.setattr("desktop.ui.views.signatures_view.verify_container_with_registry", raise_tampered)
    
    view.verify_signature()
    assert "❌ Invalid Signature" in view.txt_results.toHtml()
    assert "Tampered container" in view.txt_results.toHtml()

def test_signature_revoked(qapp, mock_context, monkeypatch):
    view = SignaturesView(context=mock_context)
    view.container_data = {"signer_id": "revoked_user"}
    
    def raise_revoked(*args, **kwargs):
        raise KeyLifecycleError("Key is revoked.")
        
    monkeypatch.setattr("desktop.ui.views.signatures_view.verify_container_with_registry", raise_revoked)
    
    view.verify_signature()
    assert "❌ Signer Rejected (D6 Policy)" in view.txt_results.toHtml()
    assert "Key is revoked." in view.txt_results.toHtml()

def test_main_window_integration(qapp, mock_context):
    main_window = QMainWindow()
    stack = QStackedWidget()
    sig_view = SignaturesView(context=mock_context, parent=main_window)
    stack.addWidget(sig_view)
    assert stack.count() == 1
    assert isinstance(stack.widget(0), SignaturesView)