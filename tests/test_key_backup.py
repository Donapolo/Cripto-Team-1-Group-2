"""Tests for src/crypto/key_backup.py (D6: backup and recovery)."""

import copy
import json

import pytest

from src.crypto.key_manager import ECIESKeyManager
from src.crypto.secure_keystore import (
    KeystoreError,
    create_keystore,
    decrypt_private_key,
    load_keystore,
    save_keystore,
)
from src.crypto.key_backup import (
    KeyBackupError,
    create_backup,
    keystore_checksum,
    load_backup,
    restore_backup,
    verify_backup,
)

PASSWORD = "StrongPass!2026"
FAST_KDF = {"scrypt_n": 16384}  # keeps the tests fast; same code path as the default


@pytest.fixture
def keystore_env(tmp_path):
    pair = ECIESKeyManager.generate_key_pair()
    keystore = create_keystore(
        pair["private_key"], PASSWORD, key_id=pair["key_id"], user_id="alice", **FAST_KDF
    )
    path = save_keystore(keystore, tmp_path / "alice_keystore.json")
    return pair, path, tmp_path


def test_backup_and_restore_recovers_the_original_key(keystore_env):
    pair, ks_path, tmp = keystore_env
    backup = tmp / "backup" / "alice.backup.json"
    create_backup(ks_path, backup)

    restored = restore_backup(backup, tmp / "restored.json", expected_key_id=pair["key_id"])
    recovered = decrypt_private_key(
        load_keystore(restored), PASSWORD,
        expected_usage="decryption", expected_key_id=pair["key_id"],
    )
    assert recovered == pair["private_key"]
    assert load_keystore(restored) == load_keystore(ks_path)  # byte-for-byte same content


def test_backup_never_contains_plaintext_key_or_password(keystore_env):
    pair, ks_path, tmp = keystore_env
    backup = tmp / "alice.backup.json"
    create_backup(ks_path, backup)
    text = backup.read_text(encoding="utf-8")
    assert pair["private_key"] not in text
    assert PASSWORD not in text


def test_backup_preserves_key_identity_and_summary_is_public_only(keystore_env):
    pair, ks_path, tmp = keystore_env
    summary = create_backup(ks_path, tmp / "b.json")
    assert summary["key_id"] == pair["key_id"]
    assert summary["algorithm"] == "secp256k1"
    assert summary["user_id"] == "alice"
    assert "encrypted_private_key" not in json.dumps(summary)
    assert verify_backup(tmp / "b.json", expected_key_id=pair["key_id"]) == summary


def test_backup_with_wrong_expected_key_id_is_rejected(keystore_env):
    _, ks_path, tmp = keystore_env
    other = ECIESKeyManager.generate_key_pair()
    create_backup(ks_path, tmp / "b.json")
    with pytest.raises(KeyBackupError, match="expected key_id"):
        verify_backup(tmp / "b.json", expected_key_id=other["key_id"])
    with pytest.raises(KeyBackupError, match="expected key_id"):
        restore_backup(tmp / "b.json", tmp / "r.json", expected_key_id=other["key_id"])
    assert not (tmp / "r.json").exists()


def test_damaged_backup_is_detected_by_checksum(keystore_env):
    _, ks_path, tmp = keystore_env
    backup = tmp / "b.json"
    create_backup(ks_path, backup)
    data = json.loads(backup.read_text(encoding="utf-8"))
    ct = data["keystore"]["encrypted_private_key"]
    data["keystore"]["encrypted_private_key"] = ("0" if ct[0] != "0" else "1") + ct[1:]
    backup.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(KeyBackupError, match="checksum"):
        verify_backup(backup)
    with pytest.raises(KeyBackupError, match="checksum"):
        restore_backup(backup, tmp / "r.json")
    assert not (tmp / "r.json").exists()


def test_recomputed_checksum_does_not_bypass_the_keystore_tag(keystore_env):
    """The checksum is not a security control: AES-GCM in the keystore still fails."""
    pair, ks_path, tmp = keystore_env
    backup = tmp / "b.json"
    create_backup(ks_path, backup)
    data = json.loads(backup.read_text(encoding="utf-8"))
    ct = data["keystore"]["encrypted_private_key"]
    data["keystore"]["encrypted_private_key"] = ("0" if ct[0] != "0" else "1") + ct[1:]
    data["checksum_sha256"] = keystore_checksum(data["keystore"])
    backup.write_text(json.dumps(data), encoding="utf-8")

    restored = restore_backup(backup, tmp / "r.json")  # looks valid...
    with pytest.raises(KeystoreError):                  # ...but cannot be decrypted
        decrypt_private_key(load_keystore(restored), PASSWORD)


def test_backup_tampered_metadata_fails_at_decrypt(keystore_env):
    _, ks_path, tmp = keystore_env
    backup = tmp / "b.json"
    create_backup(ks_path, backup)
    data = json.loads(backup.read_text(encoding="utf-8"))
    data["keystore"]["metadata"]["user_id"] = "mallory"
    data["checksum_sha256"] = keystore_checksum(data["keystore"])
    backup.write_text(json.dumps(data), encoding="utf-8")
    restored = restore_backup(backup, tmp / "r.json")
    with pytest.raises(KeystoreError, match="wrong password or tampered keystore"):
        decrypt_private_key(load_keystore(restored), PASSWORD)


def test_identity_fields_must_match_keystore(keystore_env):
    _, ks_path, tmp = keystore_env
    backup = tmp / "b.json"
    create_backup(ks_path, backup)
    data = json.loads(backup.read_text(encoding="utf-8"))
    data["key_id"] = "0" * 64
    backup.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(KeyBackupError, match="does not match"):
        load_backup(backup)


def test_existing_files_are_never_overwritten_by_default(keystore_env):
    _, ks_path, tmp = keystore_env
    backup = tmp / "b.json"
    create_backup(ks_path, backup)
    original = backup.read_text(encoding="utf-8")

    with pytest.raises(KeyBackupError, match="overwrite"):
        create_backup(ks_path, backup)
    assert backup.read_text(encoding="utf-8") == original

    existing = tmp / "existing_keystore.json"
    existing.write_text("precious", encoding="utf-8")
    with pytest.raises(KeyBackupError, match="overwrite"):
        restore_backup(backup, existing)
    assert existing.read_text(encoding="utf-8") == "precious"

    restore_backup(backup, existing, overwrite=True)  # explicit opt-in works
    assert load_keystore(existing) == load_keystore(ks_path)


def test_same_path_is_rejected(keystore_env):
    _, ks_path, tmp = keystore_env
    with pytest.raises(KeyBackupError, match="different"):
        create_backup(ks_path, ks_path, overwrite=True)
    backup = tmp / "b.json"
    create_backup(ks_path, backup)
    with pytest.raises(KeyBackupError, match="different"):
        restore_backup(backup, backup, overwrite=True)
    assert load_backup(backup)  # still intact


def test_malformed_backups_are_rejected(keystore_env):
    _, ks_path, tmp = keystore_env
    backup = tmp / "b.json"
    create_backup(ks_path, backup)
    good = json.loads(backup.read_text(encoding="utf-8"))

    extra = copy.deepcopy(good); extra["note"] = "x"
    missing = copy.deepcopy(good); del missing["checksum_sha256"]
    bad_version = copy.deepcopy(good); bad_version["backup_version"] = "9.9"
    for index, bad in enumerate([extra, missing, bad_version, [], "text"]):
        path = tmp / f"bad{index}.json"
        path.write_text(json.dumps(bad), encoding="utf-8")
        with pytest.raises(KeyBackupError):
            load_backup(path)

    garbage = tmp / "garbage.json"
    garbage.write_text("{not json", encoding="utf-8")
    with pytest.raises(KeyBackupError, match="parse"):
        load_backup(garbage)
    with pytest.raises(KeyBackupError, match="not found"):
        load_backup(tmp / "missing.json")


def test_cannot_back_up_an_invalid_keystore(tmp_path):
    bogus = tmp_path / "bogus.json"
    bogus.write_text(json.dumps({"hello": "world"}), encoding="utf-8")
    with pytest.raises(KeyBackupError, match="Cannot back up"):
        create_backup(bogus, tmp_path / "b.json")
    assert not (tmp_path / "b.json").exists()


def test_restored_keystore_works_with_hybrid_decryption(keystore_env, monkeypatch):
    """Integration: a key recovered from backup opens a real hybrid container."""
    pytest.importorskip("ecies")
    pytest.importorskip("coincurve")
    from src.crypto.hybrid_vault import decrypt_hybrid_with_keystore, encrypt_hybrid
    from src.crypto.signature_manager import generate_key_pair as signing_pair

    pair, ks_path, tmp = keystore_env
    signer = signing_pair()
    container = encrypt_hybrid(
        file_bytes=b"top secret", filename="doc.txt",
        recipients={
            "alice": pair["public_key"],
            "bob": ECIESKeyManager.generate_key_pair()["public_key"],
        },
        signing_private_key=signer["private_key"],
    )
    backup = tmp / "b.json"
    create_backup(ks_path, backup)
    ks_path.unlink()  # the original keystore is lost
    restored = restore_backup(backup, tmp / "recovered.json")

    monkeypatch.setattr("getpass.getpass", lambda *a, **k: PASSWORD)
    plaintext = decrypt_hybrid_with_keystore(
        container, "alice", restored,
        trusted_signers={signer["signer_id"]: signer["public_key"]},
        expected_key_id=pair["key_id"],
    )
    assert plaintext == b"top secret"
