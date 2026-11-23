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
