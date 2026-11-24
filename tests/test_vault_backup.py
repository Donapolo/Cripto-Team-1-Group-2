"""Tests del respaldo completo (registro + keystores) de src/crypto/key_backup.py."""

import json
from datetime import datetime, timedelta, timezone

import pytest

from src.crypto.key_backup import KeyBackupError, create_vault_backup, restore_vault_backup
from src.crypto.key_lifecycle import (
    KeyLifecycleError,
    check_key_usable,
    generate_key,
    load_registry,
    revoke_key,
    rotate_key,
)
from src.crypto.secure_keystore import decrypt_private_key, load_keystore

PASSWORD = "StrongPass!2026"
REG_PW = "RegistryPass!2026"
RAPIDO = {"scrypt_n": 16384, "registry_password": REG_PW}
T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)


@pytest.fixture
def vault(tmp_path):
    """Registro con historial: una llave retirada, una activa y una de firma revocada."""
    reg, ks = tmp_path / "registry.json", tmp_path / "keystores"
    vieja = generate_key(reg, "alice", "secp256k1", PASSWORD, ks, now=T0, **RAPIDO)
    nueva = rotate_key(reg, "alice", "secp256k1", PASSWORD, ks, now=T0 + timedelta(days=30), **RAPIDO)
    firma = generate_key(reg, "alice", "Ed25519", PASSWORD, ks, now=T0, **RAPIDO)
    revoke_key(reg, firma["key_id"], "laptop stolen", registry_password=REG_PW, now=T0 + timedelta(days=40))
    return {"reg": reg, "ks": ks, "tmp": tmp_path, "vieja": vieja, "nueva": nueva, "firma": firma}


def respaldar(v):
    return create_vault_backup(v["reg"], v["ks"], v["tmp"] / "backup", registry_password=REG_PW)


def restaurar(v, overwrite=False):
    return restore_vault_backup(v["tmp"] / "backup", v["tmp"] / "new" / "registry.json",
                                v["tmp"] / "new" / "keystores", registry_password=REG_PW,
                                overwrite=overwrite)


def test_restore_keeps_states_history_and_keys(vault):
    respaldar(vault)
    restaurar(vault)
    original = load_registry(vault["reg"], REG_PW)
    restaurado = load_registry(vault["tmp"] / "new" / "registry.json", REG_PW)
    assert restaurado == original  # mismos estados, fechas y motivo de revocacion
    estados = {k: e["status"] for k, e in restaurado["keys"].items()}
    assert estados[vault["vieja"]["key_id"]] == "retired"
    assert estados[vault["nueva"]["key_id"]] == "active"
    assert estados[vault["firma"]["key_id"]] == "revoked"
    for e in restaurado["keys"].values():  # cada llave se abre con la misma contrasena
        ks = load_keystore(vault["tmp"] / "new" / "keystores" / e["keystore_file"])
        assert decrypt_private_key(ks, PASSWORD, expected_key_id=e["key_id"])


def test_retired_key_after_restore_still_decrypts_but_cannot_encrypt(vault):
    respaldar(vault)
    restaurar(vault)
    reg = load_registry(vault["tmp"] / "new" / "registry.json", REG_PW)
    vieja = vault["vieja"]["key_id"]
    now = T0 + timedelta(days=60)
    assert check_key_usable(reg, vieja, "decrypt", now=now)
    with pytest.raises(KeyLifecycleError):
        check_key_usable(reg, vieja, "encrypt_to", now=now)


def test_revoked_key_stays_revoked_after_restore(vault):
    respaldar(vault)
    restaurar(vault)
    reg = load_registry(vault["tmp"] / "new" / "registry.json", REG_PW)
    with pytest.raises(KeyLifecycleError):
        check_key_usable(reg, vault["firma"]["key_id"], "verify", now=T0 + timedelta(days=60))


def test_backup_with_wrong_registry_password_writes_nothing(vault):
    with pytest.raises(KeyBackupError):
        create_vault_backup(vault["reg"], vault["ks"], vault["tmp"] / "backup",
                            registry_password="wrong-password")
    assert not (vault["tmp"] / "backup").exists()


def test_edited_registry_in_backup_is_rejected_and_nothing_restored(vault):
    respaldar(vault)
    ruta = vault["tmp"] / "backup" / "registry.json"
    datos = json.loads(ruta.read_text(encoding="utf-8"))
    datos["keys"][vault["firma"]["key_id"]]["status"] = "active"  # "des-revocar" a mano
    datos["keys"][vault["firma"]["key_id"]]["reason"] = None
    ruta.write_text(json.dumps(datos), encoding="utf-8")
    with pytest.raises(KeyBackupError, match="Invalid registry"):
        restaurar(vault)
    assert not (vault["tmp"] / "new").exists()


def test_swapped_keystore_in_backup_is_rejected_before_writing(vault):
    respaldar(vault)
    carpeta = vault["tmp"] / "backup" / "keystores"
    a = carpeta / vault["vieja"]["keystore_file"]
    b = carpeta / vault["nueva"]["keystore_file"]
    a_txt, b_txt = a.read_text(encoding="utf-8"), b.read_text(encoding="utf-8")
    a.write_text(b_txt, encoding="utf-8")  # intercambiar keystores
    b.write_text(a_txt, encoding="utf-8")
    with pytest.raises(KeyBackupError, match="expected key_id"):
        restaurar(vault)
    assert not (vault["tmp"] / "new").exists()


def test_missing_keystore_of_active_key_fails_but_revoked_can_be_skipped(vault):
    (vault["ks"] / vault["firma"]["keystore_file"]).unlink()  # revocada: se permite omitir
    resumen = respaldar(vault)
    assert resumen["skipped_revoked"] == [vault["firma"]["key_id"]]
    restaurar(vault)

    (vault["ks"] / vault["nueva"]["keystore_file"]).unlink()  # activa: debe fallar
    with pytest.raises(KeyBackupError, match="non-revoked"):
        create_vault_backup(vault["reg"], vault["ks"], vault["tmp"] / "backup2", registry_password=REG_PW)


def test_restore_refuses_to_overwrite_existing_files(vault):
    respaldar(vault)
    restaurar(vault)
    with pytest.raises(KeyBackupError, match="overwrite"):
        restaurar(vault)
    restaurar(vault, overwrite=True)


# ---- correcciones de la revision del PR #31 ----

def _estado(reg_path, key_id):
    return load_registry(reg_path, REG_PW)["keys"][key_id]["status"]


def test_old_backup_cannot_undo_a_later_revocation(vault):
    respaldar(vault)
    nueva = vault["nueva"]["key_id"]
    revoke_key(vault["reg"], nueva, "laptop stolen", registry_password=REG_PW,
               now=T0 + timedelta(days=50))
    antes = vault["reg"].read_bytes()
    with pytest.raises(KeyBackupError, match="undo"):
        restore_vault_backup(vault["tmp"] / "backup", vault["reg"], vault["ks"],
                             registry_password=REG_PW, overwrite=True)
    assert vault["reg"].read_bytes() == antes  # no se escribio nada
    assert _estado(vault["reg"], nueva) == "revoked"


def test_old_backup_missing_newer_keys_is_rejected(vault):
    respaldar(vault)
    generate_key(vault["reg"], "bob", "secp256k1", PASSWORD, vault["ks"],
                 now=T0 + timedelta(days=50), **RAPIDO)
    with pytest.raises(KeyBackupError, match="older"):
        restore_vault_backup(vault["tmp"] / "backup", vault["reg"], vault["ks"],
                             registry_password=REG_PW, overwrite=True)


def test_restore_over_registry_with_other_password_is_rejected(vault):
    respaldar(vault)
    with pytest.raises(KeyBackupError, match="Invalid registry"):
        restore_vault_backup(vault["tmp"] / "backup", vault["reg"], vault["ks"],
                             registry_password="otra-password", overwrite=True)


def test_failed_backup_leaves_no_partial_files(vault):
    reg = load_registry(vault["reg"], REG_PW)
    no_revocadas = [k for k, e in reg["keys"].items() if e["status"] != "revoked"]
    ultima = max(no_revocadas)  # la ultima en orden: las demas ya se habrian procesado
    (vault["ks"] / reg["keys"][ultima]["keystore_file"]).unlink()
    with pytest.raises(KeyBackupError, match="non-revoked"):
        respaldar(vault)
    assert not (vault["tmp"] / "backup").exists()


def test_write_error_during_restore_rolls_back(vault, monkeypatch):
    import src.crypto.key_backup as kb
    respaldar(vault)
    restaurar(vault)
    destino_reg = vault["tmp"] / "new" / "registry.json"
    carpeta = vault["tmp"] / "new" / "keystores"
    antes = {p.name: p.read_bytes() for p in carpeta.iterdir()}
    antes_reg = destino_reg.read_bytes()
    for p in carpeta.iterdir():  # simular keystores danados que el respaldo debe corregir
        p.write_text("danado", encoding="utf-8")
    danados = {p.name: p.read_bytes() for p in carpeta.iterdir()}

    original, llamadas = kb.os.replace, []
    def replace_que_falla(a, b):
        llamadas.append(b)
        if len(llamadas) == 2:  # falla a la mitad de la escritura
            raise OSError("disk full")
        return original(a, b)
    monkeypatch.setattr(kb.os, "replace", replace_que_falla)
    with pytest.raises(KeyBackupError, match="nothing was changed"):
        restaurar(vault, overwrite=True)
    monkeypatch.setattr(kb.os, "replace", original)

    assert {p.name: p.read_bytes() for p in carpeta.iterdir()} == danados  # todo como estaba
    assert destino_reg.read_bytes() == antes_reg
    assert not list(carpeta.glob("*.tmp"))
    restaurar(vault, overwrite=True)  # sin la falla, la restauracion si corrige todo
    assert {p.name: p.read_bytes() for p in carpeta.iterdir()} == antes


def test_e2e_old_document_decrypts_after_rotation_and_restore(tmp_path, monkeypatch):
    pytest.importorskip("ecies")
    pytest.importorskip("coincurve")
    import getpass
    import shutil
    from src.crypto.key_lifecycle import decrypt_with_registry, encrypt_with_registry
    from src.crypto.secure_keystore import decrypt_private_key as abrir

    reg, ks = tmp_path / "registry.json", tmp_path / "keystores"
    alice = generate_key(reg, "alice", "secp256k1", PASSWORD, ks, **RAPIDO)
    bob = generate_key(reg, "bob", "secp256k1", PASSWORD, ks, **RAPIDO)
    emisor = generate_key(reg, "sender", "Ed25519", PASSWORD, ks, **RAPIDO)
    firma = abrir(load_keystore(ks / emisor["keystore_file"]), PASSWORD,
                  expected_usage="signing", expected_key_id=emisor["key_id"])

    # documento viejo, cifrado para la llave vieja de alice
    viejo = encrypt_with_registry(load_registry(reg, REG_PW), b"documento viejo", "viejo.txt",
                                  {"alice": alice["public_key"], "bob": bob["public_key"]}, firma)
    nueva = rotate_key(reg, "alice", "secp256k1", PASSWORD, ks, **RAPIDO)

    # respaldo completo y perdida total del registro y los keystores
    create_vault_backup(reg, ks, tmp_path / "backup", registry_password=REG_PW)
    reg.unlink()
    shutil.rmtree(ks)
    restore_vault_backup(tmp_path / "backup", reg, ks, registry_password=REG_PW)
    restaurado = load_registry(reg, REG_PW)
    assert restaurado["keys"][alice["key_id"]]["status"] == "retired"

    monkeypatch.setattr(getpass, "getpass", lambda *a, **k: PASSWORD)
    # la llave retirada sigue abriendo el documento viejo
    assert decrypt_with_registry(restaurado, viejo, "alice",
                                 ks / alice["keystore_file"]) == b"documento viejo"
    # pero ya no se puede cifrar nada nuevo para ella
    with pytest.raises(KeyLifecycleError):
        encrypt_with_registry(restaurado, b"nuevo", "nuevo.txt",
                              {"alice": alice["public_key"], "bob": bob["public_key"]}, firma)
    # y lo nuevo va para la llave nueva
    nuevo = encrypt_with_registry(restaurado, b"documento nuevo", "nuevo.txt",
                                  {"alice": nueva["public_key"], "bob": bob["public_key"]}, firma)
    assert decrypt_with_registry(restaurado, nuevo, "alice",
                                 ks / nueva["keystore_file"]) == b"documento nuevo"


def test_failed_rollback_is_reported_not_hidden(vault, monkeypatch):
    import pathlib
    import src.crypto.key_backup as kb
    respaldar(vault)
    restaurar(vault)
    original_replace, original_write = kb.os.replace, pathlib.Path.write_bytes
    llamadas = []
    def replace_que_falla(a, b):
        llamadas.append(b)
        if len(llamadas) == 2:
            raise OSError("disk full")
        return original_replace(a, b)
    def write_que_falla(self, datos):  # el regreso a como estaba tambien falla
        raise OSError("disk full")
    monkeypatch.setattr(kb.os, "replace", replace_que_falla)
    monkeypatch.setattr(pathlib.Path, "write_bytes", write_que_falla)
    with pytest.raises(KeyBackupError, match="could not be restored") as error:
        restaurar(vault, overwrite=True)
    assert "nothing was changed" not in str(error.value)


def test_temp_file_is_cleaned_if_its_write_fails(vault, monkeypatch):
    import pathlib
    respaldar(vault)
    original = pathlib.Path.write_text
    def write_que_falla(self, *a, **k):
        if self.name.endswith(".tmp"):
            original(self, "a medias", encoding="utf-8")  # alcanza a crear el archivo...
            raise OSError("disk full")                    # ...y luego falla
        return original(self, *a, **k)
    monkeypatch.setattr(pathlib.Path, "write_text", write_que_falla)
    with pytest.raises(KeyBackupError, match="nothing was changed"):
        restaurar(vault)
    monkeypatch.setattr(pathlib.Path, "write_text", original)
    nuevo = vault["tmp"] / "new"
    assert not list(nuevo.rglob("*.tmp"))
    assert not list(nuevo.rglob("*.json"))
