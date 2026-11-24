"""Tests for non-blocking crypto worker, documents view, crypto view, and MainWindow integration."""

from pathlib import Path

import pytest
from PySide6.QtCore import QThread
from PySide6.QtWidgets import QApplication

from desktop.context import DesktopContext
from desktop.ui.main_window import FailedView, MainWindow, PlaceholderView
from desktop.ui.views.crypto_view import CryptoView
from desktop.ui.views.documents_view import DocumentsView
from desktop.workers.crypto_worker import CryptoWorker
from src.services.vault_service import VaultService

KEY_PASSWORD = "Desktop-Test-Password-2026!"
REGISTRY_PASSWORD = "Desktop-Registry-Password-2026!"


@pytest.fixture(scope="module")
def qt_app():
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


@pytest.fixture
def vault_env(tmp_path):
    pytest.importorskip("ecies")
    pytest.importorskip("coincurve")

    data_dir = tmp_path / "vault_data"
    service = VaultService(data_dir, REGISTRY_PASSWORD)
    service.init_user("sender", KEY_PASSWORD, algorithm="Ed25519")
    service.init_user("alice", KEY_PASSWORD, algorithm="secp256k1")
    service.init_user("bob", KEY_PASSWORD, algorithm="secp256k1")

    source_file = tmp_path / "reporte_confidencial.txt"
    payload = b"Contenido confidencial para prueba de escritorio D6."
    source_file.write_bytes(payload)

    return {
        "service": service,
        "data_dir": data_dir,
        "source_file": source_file,
        "payload": payload,
        "tmp_path": tmp_path,
    }


def _run_worker_in_thread(qt_app, worker: CryptoWorker):
    outcomes: dict[str, object] = {}
    thread = QThread()
    worker.moveToThread(thread)

    def on_finished(result):
        outcomes["result"] = result
        thread.quit()

    def on_error(code, message):
        outcomes["error"] = (code, message)
        thread.quit()

    worker.finished.connect(on_finished)
    worker.error.connect(on_error)
    thread.started.connect(worker.run)
    thread.start()

    while thread.isRunning():
        qt_app.processEvents()

    thread.wait()
    for _ in range(10):
        qt_app.processEvents()
    return outcomes


def test_worker_encrypt_and_decrypt_roundtrip(qt_app, vault_env):
    service: VaultService = vault_env["service"]
    tmp_path: Path = vault_env["tmp_path"]
    container_path = tmp_path / "out" / "reporte.d5.json"
    recovered_path = tmp_path / "out" / "reporte_recuperado.txt"

    enc_worker = CryptoWorker(
        service,
        "encrypt",
        {
            "source": vault_env["source_file"],
            "output": container_path,
            "signer_user": "sender",
            "recipients": ["alice", "bob"],
        },
        password_callback=lambda _entry: KEY_PASSWORD,
    )
    enc_out = _run_worker_in_thread(qt_app, enc_worker)
    assert "error" not in enc_out
    assert enc_out["result"] == container_path
    assert container_path.exists()

    dec_worker = CryptoWorker(
        service,
        "decrypt",
        {
            "source": container_path,
            "output": recovered_path,
            "user_id": "alice",
        },
        password_callback=lambda _entry: KEY_PASSWORD,
    )
    dec_out = _run_worker_in_thread(qt_app, dec_worker)
    assert "error" not in dec_out
    assert dec_out["result"] == recovered_path
    assert recovered_path.read_bytes() == vault_env["payload"]


def test_worker_rejects_fewer_than_two_recipients_and_existing_output(qt_app, vault_env):
    service: VaultService = vault_env["service"]
    tmp_path: Path = vault_env["tmp_path"]

    bad_recipients_worker = CryptoWorker(
        service,
        "encrypt",
        {
            "source": vault_env["source_file"],
            "output": tmp_path / "single_recipient.d5.json",
            "signer_user": "sender",
            "recipients": ["alice"],
        },
        password_callback=lambda _entry: KEY_PASSWORD,
    )
    out_single = _run_worker_in_thread(qt_app, bad_recipients_worker)
    assert "error" in out_single
    assert out_single["error"][0] == "validation_error"

    existing_out = tmp_path / "already_exists.d5.json"
    existing_out.write_text("existing", encoding="utf-8")

    overwrite_worker = CryptoWorker(
        service,
        "encrypt",
        {
            "source": vault_env["source_file"],
            "output": existing_out,
            "signer_user": "sender",
            "recipients": ["alice", "bob"],
        },
        password_callback=lambda _entry: KEY_PASSWORD,
    )
    out_overwrite = _run_worker_in_thread(qt_app, overwrite_worker)
    assert "error" in out_overwrite
    assert out_overwrite["error"][0] == "file_exists"
    assert existing_out.read_text(encoding="utf-8") == "existing"


def test_worker_revoked_recipient_fails_before_password_callback(qt_app, vault_env):
    service: VaultService = vault_env["service"]
    tmp_path: Path = vault_env["tmp_path"]
    container_path = tmp_path / "doc.d5.json"

    enc_worker = CryptoWorker(
        service,
        "encrypt",
        {
            "source": vault_env["source_file"],
            "output": container_path,
            "signer_user": "sender",
            "recipients": ["alice", "bob"],
        },
        password_callback=lambda _entry: KEY_PASSWORD,
    )
    enc_out = _run_worker_in_thread(qt_app, enc_worker)
    assert "error" not in enc_out

    alice_key = next(k for k in service.list_keys() if k["user_id"] == "alice")
    service.revoke(alice_key["key_id"], "compromised in desktop test")

    def fail_if_called(_entry):
        pytest.fail("Password callback must not be invoked for a revoked key.")

    dec_worker = CryptoWorker(
        service,
        "decrypt",
        {
            "source": container_path,
            "output": tmp_path / "should_not_exist.txt",
            "user_id": "alice",
        },
        password_callback=fail_if_called,
    )
    dec_out = _run_worker_in_thread(qt_app, dec_worker)
    assert "error" in dec_out
    assert dec_out["error"][0] == "lifecycle_error"
    assert not (tmp_path / "should_not_exist.txt").exists()


def test_documents_view_tracks_local_files_without_copying(qt_app, tmp_path):
    source_a = tmp_path / "nota_a.txt"
    source_b = tmp_path / "nota_b.txt"
    source_a.write_text("alpha", encoding="utf-8")
    source_b.write_text("beta", encoding="utf-8")

    view = DocumentsView()
    added = view.add_files([source_a, source_b])
    assert added == 2
    assert view.selected_paths() == [source_a, source_b]
    assert view._table.rowCount() == 2
    assert view._table.item(0, 0).text() == "nota_a.txt"
    assert view._table.item(0, 2).text() == "Available"
    assert source_a.read_text(encoding="utf-8") == "alpha"
    assert source_b.read_text(encoding="utf-8") == "beta"

    source_b.unlink()
    view.refresh_statuses()
    assert view._table.item(1, 2).text() == "Not found"


def test_crypto_view_validates_recipients_and_prevents_overwrite(qt_app, vault_env):
    service: VaultService = vault_env["service"]
    tmp_path: Path = vault_env["tmp_path"]

    view = CryptoView(
        vault_service=service,
        password_provider=lambda _entry: KEY_PASSWORD,
    )

    view._enc_source_edit.setText(str(vault_env["source_file"]))
    view._enc_output_edit.setText(str(tmp_path / "one_rec.d5.json"))
    view._enc_signer_combo.setCurrentText("sender")
    view._enc_rec1_combo.setCurrentText("alice")
    view._enc_rec2_combo.setCurrentText("alice")
    view._enc_rec3_combo.setCurrentText("")
    view._enc_extra_recipients_edit.clear()
    view._start_encrypt()
    assert "Rejected" in view._status_badge.text()

    container_path = tmp_path / "valid_out.d5.json"
    view._enc_output_edit.setText(str(container_path))
    view._enc_rec1_combo.setCurrentText("alice")
    view._enc_rec2_combo.setCurrentText("bob")
    view._enc_rec3_combo.setCurrentText("")
    view._enc_extra_recipients_edit.clear()
    view._start_encrypt()

    while view._thread is not None and view._thread.isRunning():
        qt_app.processEvents()

    for _ in range(10):
        qt_app.processEvents()

    assert container_path.exists(), (
        f"badge={view._status_badge.text()!r} | log={view._result_log.toPlainText()!r}"
    )
    assert "Completed" in view._status_badge.text()

    view._enc_output_edit.setText(str(container_path))
    view._start_encrypt()
    assert "Rejected" in view._status_badge.text()


def test_main_window_opens_documents_and_crypto_views_and_navigates(qt_app, tmp_path):
    sample_file = tmp_path / "spec.txt"
    sample_file.write_text("specification", encoding="utf-8")

    context = DesktopContext(data_dir=tmp_path / "vault")
    window = MainWindow(context)

    window.navigate("documents")
    assert window.current_page == "documents"
    docs_page = window._pages["documents"]
    assert isinstance(docs_page, DocumentsView)
    assert not isinstance(docs_page, (PlaceholderView, FailedView))

    docs_page.add_files([sample_file])
    docs_page.send_to_crypto.emit(sample_file)
    qt_app.processEvents()

    assert window.current_page == "crypto"
    crypto_page = window._pages["crypto"]
    assert isinstance(crypto_page, CryptoView)
    assert not isinstance(crypto_page, (PlaceholderView, FailedView))
    assert crypto_page._enc_source_edit.text() == str(sample_file)