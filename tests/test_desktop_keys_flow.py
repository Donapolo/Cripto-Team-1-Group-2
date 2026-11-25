"""Yuki - Desktop 'My Keys' flow: key states, backups and cancellation.

Service tests run everywhere. Qt tests need PySide6 (run offscreen) and use a
fake dialog helper, so no real window waits for a click.
"""

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest

from src.crypto.key_backup import KeyBackupError
from src.crypto.key_lifecycle import KeyLifecycleError, check_key_usable
from src.services.vault_service import VaultService

KEY_PW = "Keys-Test-Password-2026!"
REG_PW = "Keys-Registry-Password-2026!"


def _entry(service, user, algorithm, status):
    return next(e for e in service.list_keys()
                if e["user_id"] == user and e["algorithm"] == algorithm and e["status"] == status)


# ---------- service layer (create_vault_backup / restore_vault_backup) ----------

def test_service_full_backup_keeps_states_after_restore(tmp_path):
    service = VaultService(tmp_path / "vault", REG_PW)
    service.init_user("alice", KEY_PW)
    old = _entry(service, "alice", "secp256k1", "active")
    service.rotate("alice", "secp256k1", KEY_PW)
    signer = _entry(service, "alice", "Ed25519", "active")
    service.revoke(signer["key_id"], "laptop stolen")
    summary = service.create_vault_backup(tmp_path / "backup")
    assert summary["keys_in_registry"] == 3

    fresh = VaultService(tmp_path / "restored", REG_PW)
    fresh.restore_vault_backup(tmp_path / "backup")
    states = {e["key_id"]: e["status"] for e in fresh.list_keys()}
    assert states[old["key_id"]] == "retired"
    assert states[signer["key_id"]] == "revoked"


def test_retired_key_cannot_be_used_for_new_operations(tmp_path):
    service = VaultService(tmp_path / "vault", REG_PW)
    service.init_user("alice", KEY_PW, algorithm="secp256k1")
    old = _entry(service, "alice", "secp256k1", "active")
    service.rotate("alice", "secp256k1", KEY_PW)
    registry = service.registry()
    with pytest.raises(KeyLifecycleError):
        check_key_usable(registry, old["key_id"], "encrypt_to")
    assert check_key_usable(registry, old["key_id"], "decrypt")  # old documents still open


def test_old_backup_cannot_undo_a_revocation(tmp_path):
    service = VaultService(tmp_path / "vault", REG_PW)
    service.init_user("alice", KEY_PW, algorithm="Ed25519")
    key = _entry(service, "alice", "Ed25519", "active")
    service.create_vault_backup(tmp_path / "before")
    service.revoke(key["key_id"], "compromised")
    with pytest.raises(KeyBackupError, match="undo"):
        service.restore_vault_backup(tmp_path / "before", overwrite=True)
    assert _entry(service, "alice", "Ed25519", "revoked")
    with pytest.raises(KeyLifecycleError):
        check_key_usable(service.registry(), key["key_id"], "sign")


# ---------- Qt view ----------

class FakeAsker:
    """Answers the dialogs in order. None = the user pressed Cancel."""

    def __init__(self, **answers):
        self.answers = {name: list(values) for name, values in answers.items()}
        self.asked = []

    def _next(self, kind, *args):
        self.asked.append((kind, args[0] if args else ""))
        queue = self.answers.get(kind, [])
        return queue.pop(0) if queue else None

    def text(self, *a): return self._next("text", *a)
    def item(self, *a): return self._next("item", *a)
    def password(self, *a, **k): return self._next("password", *a)
    def confirm(self, *a): return bool(self._next("confirm", *a))
    def save_file(self, *a): return self._next("save_file", *a)
    def open_file(self, *a): return self._next("open_file", *a)
    def directory(self, *a): return self._next("directory", *a)


@pytest.fixture
def qt():
    pytest.importorskip("PySide6")
    from PySide6.QtWidgets import QApplication
    app = QApplication.instance() or QApplication([])
    return app


@pytest.fixture
def view(qt, tmp_path):
    from desktop.context import DesktopContext
    from desktop.ui.views.keys_view import KeysView
    context = DesktopContext(data_dir=tmp_path / "vault")
    return KeysView(context)


def _table_text(view):
    return " ".join(view.table.item(r, c).text()
                    for r in range(view.table.rowCount()) for c in range(5))


def _create_alice(view, algorithm="both"):
    view.ask = FakeAsker(password=[REG_PW, KEY_PW], text=["alice"], item=[algorithm])
    view.on_create_profile()
    assert view.unlocked


def test_password_dialog_hides_and_validates(qt):
    from PySide6.QtWidgets import QLineEdit
    from desktop.ui.dialogs.password_dialog import PasswordDialog
    dialog = PasswordDialog(None, title="t", message="m", confirm=True)
    assert dialog.password_edit.echoMode() == QLineEdit.EchoMode.Password
    assert dialog.confirm_edit.echoMode() == QLineEdit.EchoMode.Password
    assert dialog.validation_error() == "The password cannot be empty."
    dialog.password_edit.setText("secret-1")
    dialog.confirm_edit.setText("secret-2")
    assert dialog.validation_error() == "The passwords do not match."
    dialog._try_accept()
    assert "secret" not in dialog.error_label.text()  # never echoes the password
    assert dialog.confirm_edit.text() == ""
    dialog.confirm_edit.setText("secret-1")
    assert dialog.validation_error() == ""
    dialog.clear()
    assert dialog.password() == ""


def test_cancelled_key_password_stops_the_operation(qt, monkeypatch):
    import desktop.ui.dialogs.password_dialog as pd
    monkeypatch.setattr(pd, "ask_password", lambda *a, **k: None)
    provider = pd.key_password_provider(None)
    with pytest.raises(pd.PasswordCancelled):
        provider({"user_id": "alice", "algorithm": "secp256k1", "key_id": "ab" * 32})


def test_create_rotate_revoke_from_the_view(view):
    _create_alice(view)
    assert view.table.rowCount() == 2
    service = view._service
    enc = _entry(service, "alice", "secp256k1", "active")
    assert enc["key_id"][:16] in _table_text(view)
    assert "private" not in _table_text(view).lower()

    # rotate: old key retired, new key active
    assert view.select_key(enc["key_id"])
    view.ask = FakeAsker(confirm=[True], password=[KEY_PW])
    view.on_rotate()
    assert _entry(service, "alice", "secp256k1", "retired")["key_id"] == enc["key_id"]
    new = _entry(service, "alice", "secp256k1", "active")
    with pytest.raises(KeyLifecycleError):
        check_key_usable(service.registry(), enc["key_id"], "encrypt_to")

    # a retired key cannot be rotated again
    view.select_key(enc["key_id"])
    view.ask = FakeAsker(confirm=[True], password=[KEY_PW])
    view.on_rotate()
    assert view.status_badge.text() == "Rejected"
    assert len(service.list_keys()) == 3

    # revoke the new key
    view.select_key(new["key_id"])
    view.ask = FakeAsker(text=["laptop stolen"], confirm=[True])
    view.on_revoke()
    assert _entry(service, "alice", "secp256k1", "revoked")["key_id"] == new["key_id"]
    assert KEY_PW not in view.log.toPlainText() and REG_PW not in view.log.toPlainText()


def test_cancel_changes_nothing(view):
    _create_alice(view, algorithm="Ed25519")
    service = view._service
    before = service.registry_path.read_bytes()
    key = service.list_keys()[0]

    view.select_key(key["key_id"])
    view.ask = FakeAsker(text=[None])                 # cancel the reason
    view.on_revoke()
    view.ask = FakeAsker(text=["x"], confirm=[False])  # cancel the warning
    view.on_revoke()
    view.ask = FakeAsker(confirm=[True], password=[None])  # cancel the new password
    view.on_rotate()
    view.ask = FakeAsker(text=["bob"], item=["both"], password=[None])
    view.on_create_profile()
    view.ask = FakeAsker(directory=[None])
    view.on_backup_vault()

    assert service.registry_path.read_bytes() == before
    assert view.status_badge.text() == "Cancelled"
    assert "Nothing was changed" in view.log.toPlainText()


def test_revocation_stays_after_restoring_backups(view, tmp_path):
    _create_alice(view, algorithm="Ed25519")
    service = view._service
    key = service.list_keys()[0]
    assert view.backup_vault(tmp_path / "before") is not None
    view.revoke_key(key["key_id"], "compromised")

    # an older backup cannot bring the key back
    assert view.restore_vault(tmp_path / "before", overwrite=True) is None
    assert view.status_badge.text() == "Rejected"
    assert "undo" in view.log.toPlainText()
    assert _entry(service, "alice", "Ed25519", "revoked")

    # a newer backup restored in an empty folder keeps it revoked
    assert view.backup_vault(tmp_path / "after") is not None
    from desktop.context import DesktopContext
    from desktop.ui.views.keys_view import KeysView
    other = KeysView(DesktopContext(data_dir=tmp_path / "restored"))
    other.ask = FakeAsker(directory=[str(tmp_path / "after")], confirm=[True], password=[REG_PW])
    other.on_restore_vault()
    assert other.unlocked
    assert other._service.list_keys()[0]["status"] == "revoked"


def test_wrong_registry_password_keeps_the_view_locked(view, tmp_path):
    _create_alice(view, algorithm="Ed25519")
    view.lock()
    assert not view.unlock("wrong-password")
    assert not view.unlocked
    assert view.table.rowCount() == 0

    # a restore attempt with a wrong password also leaves it locked
    view.ask = FakeAsker(directory=[str(tmp_path)], confirm=[True], password=["wrong-password"])
    view.on_restore_vault()
    assert not view.unlocked


def test_single_keystore_backup_and_restore(view, tmp_path):
    _create_alice(view, algorithm="secp256k1")
    service = view._service
    key = service.list_keys()[0]
    keystore = service.keystore_dir / key["keystore_file"]
    view.select_key(key["key_id"])
    view.ask = FakeAsker(save_file=[str(tmp_path / "alice.backup.json")])
    view.on_backup_key()
    keystore.unlink()
    view.select_key(key["key_id"])
    view.ask = FakeAsker(open_file=[str(tmp_path / "alice.backup.json")])
    view.on_restore_key()
    assert keystore.is_file()
    assert view.status_badge.text() == "Completed"


def test_main_window_loads_the_keys_view(qt, tmp_path):
    from desktop.app import create_window
    from desktop.ui.views.keys_view import KeysView
    _app, window = create_window(tmp_path / "vault")
    assert isinstance(window._pages["keys"], KeysView)
    window.navigate("keys")
    assert window.current_page == "keys"
    window.close()


# ---------- review of PR #36 ----------

def test_existing_passwords_preserve_whitespace_exactly(qt):
    from desktop.ui.dialogs.password_dialog import PasswordDialog
    dialog = PasswordDialog(None, title="t", message="m")
    for secret in ["   ", " secret", "secret ", " secret ", "my secret"]:
        dialog.password_edit.setText(secret)
        assert dialog.validation_error() == "", repr(secret)
        assert dialog.password() == secret  # never strip or normalize
    dialog.password_edit.setText("")
    assert dialog.validation_error() == "The password cannot be empty."


def test_new_password_enforces_spacing_and_exact_confirmation(qt):
    from desktop.ui.dialogs.password_dialog import PasswordDialog
    dialog = PasswordDialog(None, title="t", message="m", confirm=True)
    for weak in ["   ", " secret", "secret ", " secret "]:
        dialog.password_edit.setText(weak)
        dialog.confirm_edit.setText(weak)
        assert dialog.validation_error() != "", repr(weak)
    dialog.password_edit.setText("secret phrase")
    dialog.confirm_edit.setText("secret phrase ")
    assert dialog.validation_error() == "The passwords do not match."
    dialog.confirm_edit.setText("secret phrase")
    assert dialog.validation_error() == ""


def test_existing_registry_with_spaces_unlocks_in_gui(qt, tmp_path):
    from desktop.context import DesktopContext
    from desktop.ui.views.keys_view import KeysView
    secret = "  registry secret  "
    data_dir = tmp_path / "vault"
    VaultService(data_dir, secret).init_user("alice", KEY_PW, algorithm="Ed25519")
    view = KeysView(DesktopContext(data_dir=data_dir))
    assert view.unlock(secret)
    assert view.unlocked
    view.lock()
    assert not view.unlocked


def test_keys_lock_clears_crypto_session_and_selectors(qt, tmp_path):
    from desktop.app import create_window
    from desktop.ui.views.crypto_view import CryptoView
    _app, window = create_window(tmp_path / "vault")
    keys = window._pages["keys"]
    crypto = window._pages["crypto"]
    assert isinstance(crypto, CryptoView)
    service = VaultService(tmp_path / "vault", REG_PW)
    service.init_user("alice", KEY_PW)
    service.init_user("bob", KEY_PW)
    assert keys.unlock(REG_PW)
    crypto.set_vault_service(service)
    assert crypto._vault_service is not None
    assert crypto._enc_signer_combo.count() > 0
    assert keys.lock()
    assert not keys.unlocked
    assert crypto._vault_service is None
    assert crypto._enc_signer_combo.currentText() == ""
    assert crypto._enc_rec1_combo.currentText() == ""
    assert crypto._dec_user_combo.currentText() == ""
    window.close()


def test_my_keys_can_lock_crypto_only_session(qt, tmp_path):
    from desktop.app import create_window
    _app, window = create_window(tmp_path / "vault")
    keys = window._pages["keys"]
    crypto = window._pages["crypto"]
    service = VaultService(tmp_path / "vault", REG_PW)
    service.init_user("alice", KEY_PW)
    crypto.set_vault_service(service)
    assert not keys.unlocked  # Only Encrypt / Decrypt was unlocked.
    assert keys.lock_btn.isEnabled()
    assert keys.lock_state.text() == "Unlocked in Encrypt / Decrypt"
    assert keys.lock()
    assert crypto._vault_service is None
    assert not keys.lock_btn.isEnabled()
    window.close()


def test_switching_data_folder_locks_both_modules(qt, tmp_path):
    from desktop.app import create_window
    _app, window = create_window(tmp_path / "vault")
    keys = window._pages["keys"]
    crypto = window._pages["crypto"]
    service = VaultService(tmp_path / "vault", REG_PW)
    service.init_user("alice", KEY_PW)
    assert keys.unlock(REG_PW)
    crypto.set_vault_service(service)
    window.context.set_data_dir(tmp_path / "another_vault")
    assert not keys.unlocked
    assert crypto._vault_service is None
    assert not window.context.crypto_unlocked
    window.close()


def test_lock_refused_during_active_crypto_operation(qt, tmp_path):
    from desktop.app import create_window
    _app, window = create_window(tmp_path / "vault")
    keys = window._pages["keys"]
    crypto = window._pages["crypto"]
    service = VaultService(tmp_path / "vault", REG_PW)
    service.init_user("alice", KEY_PW)
    assert keys.unlock(REG_PW)
    crypto.set_vault_service(service)
    crypto._set_busy(True)  # simulate an in-flight worker
    try:
        assert not keys.lock()
        assert keys.unlocked
        assert crypto._vault_service is service
        assert "Wait for" in keys.log.toPlainText()
    finally:
        crypto._set_busy(False)
    assert keys.lock()
    assert crypto._vault_service is None
    window.close()


def test_buttons_follow_lock_state_and_selection(view):
    actions = ["rotate_btn", "revoke_btn", "backup_key_btn", "restore_key_btn", "backup_vault_btn"]
    assert not any(getattr(view, b).isEnabled() for b in actions)  # locked
    assert view.create_btn.isEnabled() and view.restore_vault_btn.isEnabled()

    _create_alice(view, algorithm="secp256k1")
    assert view.backup_vault_btn.isEnabled()
    assert not view.rotate_btn.isEnabled()  # unlocked but nothing selected
    assert not view.revoke_btn.isEnabled()

    key = view._service.list_keys()[0]
    view.select_key(key["key_id"])
    assert all(getattr(view, b).isEnabled() for b in actions)  # active key selected

    view.revoke_key(key["key_id"], "test")
    view.select_key(key["key_id"])
    assert not view.rotate_btn.isEnabled() and not view.revoke_btn.isEnabled()
    assert view.backup_key_btn.isEnabled()

    view.lock()
    assert not any(getattr(view, b).isEnabled() for b in actions)
