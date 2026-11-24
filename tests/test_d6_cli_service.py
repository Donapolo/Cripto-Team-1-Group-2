"""Tests for the shared service layer and interactive CLI with local-only secrets."""

import json
from pathlib import Path

import pytest

from src import cli
from src.crypto.aad_builder import build_metadata, build_recipient_entry
from src.crypto.key_lifecycle import KeyLifecycleError, load_registry, revoke_key
from src.crypto.secure_keystore import decrypt_private_key, load_keystore
from src.crypto.signature_manager import sign_container
from src.services.vault_service import VaultService

REG_PASSWORD = "D6-CLI-Test-Registry-2026!"
KEY_PASSWORD = "D6-CLI-Test-Keys-2026!"


@pytest.fixture
def service(tmp_path):
    return VaultService(tmp_path / "vault", REG_PASSWORD)


def test_init_user_creates_both_algorithms_and_refuses_duplicates(service):
    entries = service.init_user("alice", KEY_PASSWORD)
    assert {e["algorithm"] for e in entries} == {"secp256k1", "Ed25519"}
    assert len(service.list_keys()) == 2
    with pytest.raises(KeyLifecycleError):
        service.init_user("alice", KEY_PASSWORD)
    assert len(service.list_keys()) == 2
    assert KEY_PASSWORD not in service.registry_path.read_text()


def test_rotate_and_revoke_service(service):
    original = service.init_user("alice", KEY_PASSWORD, algorithm="Ed25519")[0]
    new = service.rotate("alice", "Ed25519", KEY_PASSWORD)
    assert new["key_id"] != original["key_id"]
    assert service.registry()["keys"][original["key_id"]]["status"] == "retired"
    service.revoke(new["key_id"], "compromised")
    assert service.registry()["keys"][new["key_id"]]["status"] == "revoked"


def test_single_keystore_backup_and_restore_without_overwriting(service, tmp_path):
    entry = service.init_user("alice", KEY_PASSWORD, algorithm="Ed25519")[0]
    path = service.keystore_dir / entry["keystore_file"]
    backup = tmp_path / "copy.json"
    service.backup_keystore(entry["key_id"], backup)
    assert backup.is_file()
    path.unlink()
    assert service.restore_keystore(entry["key_id"], backup) == path
    with pytest.raises(ValueError, match="overwrite"):
        service.restore_keystore(entry["key_id"], backup)


def test_cli_init_and_list_never_show_secret(service, tmp_path, monkeypatch, capsys):
    answers = iter([REG_PASSWORD, KEY_PASSWORD, KEY_PASSWORD, REG_PASSWORD])
    monkeypatch.setattr(cli.getpass, "getpass", lambda *args: next(answers))
    args = ["--data-dir", str(service.data_dir)]
    assert cli.main(args + ["init-user", "--user", "alice"]) == 0
    assert cli.main(args + ["list-keys"]) == 0
    output = capsys.readouterr().out
    assert "alice" in output and "Ed25519" in output and "secp256k1" in output
    assert REG_PASSWORD not in output and KEY_PASSWORD not in output


def test_cli_rejects_wrong_registry_password(service, monkeypatch, capsys):
    service.init_user("alice", KEY_PASSWORD, algorithm="Ed25519")
    monkeypatch.setattr(cli.getpass, "getpass", lambda *args: "incorrect")
    assert cli.main(["--data-dir", str(service.data_dir), "list-keys"]) == 1
    assert "ERROR" in capsys.readouterr().err


def _valid_container_for(service, signer, recipient):
    registry = service.registry()
    ks = load_keystore(service.keystore_dir / signer["keystore_file"])
    private = decrypt_private_key(ks, KEY_PASSWORD, expected_usage="signing")
    return sign_container(
        build_metadata("file.txt"),
        [build_recipient_entry("alice", "ab" * 40, key_id=recipient["key_id"]),
         build_recipient_entry("bob", "bc" * 40, key_id="00" * 32)],
        b"\x01" * 12, b"ciphertext", b"\x02" * 16, private)


def test_decrypt_rejects_revoked_signer_before_password_request(service, tmp_path):
    recipient = service.init_user("alice", KEY_PASSWORD, algorithm="secp256k1")[0]
    signer = service.init_user("sender", KEY_PASSWORD, algorithm="Ed25519")[0]
    container = _valid_container_for(service, signer, recipient)
    path = tmp_path / "encrypted.json"
    path.write_text(json.dumps(container))
    revoke_key(service.registry_path, signer["key_id"], "compromised",
               registry_password=REG_PASSWORD)
    asked = []
    def provider(entry):
        asked.append(entry)
        return KEY_PASSWORD
    with pytest.raises(KeyLifecycleError, match="revoked"):
        service.decrypt_file(path, tmp_path / "decrypted.txt", "alice", provider)
    assert asked == [] and not (tmp_path / "decrypted.txt").exists()


def test_decrypt_rejects_mismatched_recipient_before_password_request(service, tmp_path):
    recipient = service.init_user("alice", KEY_PASSWORD, algorithm="secp256k1")[0]
    signer = service.init_user("sender", KEY_PASSWORD, algorithm="Ed25519")[0]
    container = _valid_container_for(service, signer, recipient)
    # A mathematically valid signer can sign a container with another key ID;
    # the service must verify its registered recipient ID before prompting.
    container["recipients"][0]["key_id"] = "ff" * 32
    # Re-sign after modifying; otherwise it would fail at the signature check.
    ks = load_keystore(service.keystore_dir / signer["keystore_file"])
    private = decrypt_private_key(ks, KEY_PASSWORD, expected_usage="signing")
    from src.crypto.aad_builder import a_hex, build_signing_payload
    from src.crypto.signature_manager import sign_payload
    c = container
    payload = build_signing_payload(c["metadata"], c["recipients"], c["nonce"],
                                    c["ciphertext"], c["tag"], c["signer_id"])
    c["signature"] = a_hex(sign_payload(private, payload))
    path = tmp_path / "encrypted.json"
    path.write_text(json.dumps(c))
    called = []
    with pytest.raises(KeyLifecycleError, match="Unknown"):
        service.decrypt_file(path, tmp_path / "decrypted.txt", "alice",
                             lambda entry: called.append(entry) or KEY_PASSWORD)
    assert called == []


def test_encrypt_rejects_one_recipient_without_prompt(service, tmp_path):
    called = []
    with pytest.raises(ValueError, match="two"):
        service.encrypt_file(tmp_path / "file.txt", tmp_path / "file.sdv", "alice",
                             ["alice"], lambda e: called.append(e) or KEY_PASSWORD)
    assert called == []


def test_cli_rotate_revoke_and_backup_commands(service, tmp_path, monkeypatch, capsys):
    entry = service.init_user("alice", KEY_PASSWORD, algorithm="Ed25519")[0]
    backup_path = tmp_path / "alice-backup.json"
    arguments = ["--data-dir", str(service.data_dir)]
    prompts = iter([REG_PASSWORD, REG_PASSWORD, KEY_PASSWORD, KEY_PASSWORD,
                    REG_PASSWORD])
    monkeypatch.setattr(cli.getpass, "getpass", lambda *args: next(prompts))
    assert cli.main(arguments + ["backup", "--key-id", entry["key_id"],
                                  "--output", str(backup_path)]) == 0
    assert backup_path.exists()
    assert cli.main(arguments + ["rotate-key", "--user", "alice",
                                 "--algorithm", "Ed25519"]) == 0
    new = [e for e in service.list_keys() if e["status"] == "active"][0]
    assert cli.main(arguments + ["revoke-key", "--key-id", new["key_id"],
                                 "--reason", "compromised"]) == 0
    assert service.registry()["keys"][new["key_id"]]["status"] == "revoked"
    assert KEY_PASSWORD not in capsys.readouterr().out


def test_decrypt_rejects_tampering_before_password_request(service, tmp_path):
    recipient = service.init_user("alice", KEY_PASSWORD, algorithm="secp256k1")[0]
    signer = service.init_user("sender", KEY_PASSWORD, algorithm="Ed25519")[0]
    container = _valid_container_for(service, signer, recipient)
    container["ciphertext"] = "ff" * 10
    path = tmp_path / "encrypted.json"
    path.write_text(json.dumps(container))
    calls = []
    with pytest.raises(ValueError):
        service.decrypt_file(path, tmp_path / "decrypted.txt", "alice",
                             lambda entry: calls.append(entry) or KEY_PASSWORD)
    assert not calls
