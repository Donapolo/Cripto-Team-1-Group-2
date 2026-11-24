"""D6 - Acceptance and end-to-end tests 

The five mandatory acceptance cases run with ``cryptography`` alone.
Real ECIES/hybrid integration requires ``eciespy`` and ``coincurve`` and is
explicitly skipped when either dependency is unavailable.

All keys, keystores, backups, and documents created here are disposable test data.
"""

import copy
import getpass
import json
from datetime import datetime, timezone

import pytest

from src.crypto.key_backup import create_backup, restore_backup
from src.crypto.key_lifecycle import (
    KeyLifecycleError,
    generate_key,
    generate_key_material,
    load_registry,
    revoke_key,
)
from src.crypto.secure_keystore import (
    KeystoreError,
    create_keystore,
    decrypt_private_key,
    load_keystore,
    save_keystore,
)

# Only for ephemeral test identities; never use these credentials for real keys.
KEY_PASSWORD = "D6-Test-Password-2026!"
REGISTRY_PASSWORD = "D6-Test-Registry-Password-2026!"
FAST_SCRYPT_N = 16384  # Allowed security minimum, reduces test execution time.


@pytest.fixture
def protected_key(tmp_path):
    pair = generate_key_material("secp256k1")
    keystore = create_keystore(
        pair["private_key"],
        KEY_PASSWORD,
        key_id=pair["key_id"],
        user_id="alice",
        scrypt_n=FAST_SCRYPT_N,
    )
    original_path = save_keystore(keystore, tmp_path / "alice.keystore.json")
    return pair, original_path, tmp_path


# ----- The five required D6 acceptance scenarios -----


def test_d6_01_correct_password_allows_private_key_access(protected_key):
    pair, path, _ = protected_key
    recovered = decrypt_private_key(
        load_keystore(path),
        KEY_PASSWORD,
        expected_usage="decryption",
        expected_key_id=pair["key_id"],
    )
    assert recovered == pair["private_key"]


def test_d6_02_wrong_password_denies_access(protected_key):
    _, path, _ = protected_key
    with pytest.raises(KeystoreError, match="authentication failed"):
        decrypt_private_key(load_keystore(path), "Incorrect-Password-2026")


def test_d6_03_modified_keystore_is_rejected(protected_key):
    _, path, _ = protected_key
    keystore = load_keystore(path)

    # Manipulate ciphertext while keeping valid hexadecimal and JSON schema.
    altered = copy.deepcopy(keystore)
    ct = altered["encrypted_private_key"]
    altered["encrypted_private_key"] = ("0" if ct[0] != "0" else "1") + ct[1:]
    with pytest.raises(KeystoreError, match="authentication failed"):
        decrypt_private_key(altered, KEY_PASSWORD)

    # Manipulate AAD-bound metadata without changing the stored ciphertext.
    altered_metadata = copy.deepcopy(keystore)
    altered_metadata["metadata"]["user_id"] = "mallory"
    with pytest.raises(KeystoreError, match="authentication failed"):
        decrypt_private_key(altered_metadata, KEY_PASSWORD)


def test_d6_04_backup_restore_recovers_same_private_key(protected_key):
    pair, path, base = protected_key
    backup_path = base / "backups" / "alice.backup.json"
    create_backup(path, backup_path)
    path.unlink()  # Simulate accidental loss of the original keystore.
    assert not path.exists()

    restored_path = restore_backup(
        backup_path,
        base / "recovered.keystore.json",
        expected_key_id=pair["key_id"],
    )
    recovered = decrypt_private_key(
        load_keystore(restored_path),
        KEY_PASSWORD,
        expected_usage="decryption",
        expected_key_id=pair["key_id"],
    )
    assert recovered == pair["private_key"]


def test_d6_05_stolen_keystore_alone_does_not_unlock_key(protected_key):
    pair, path, _ = protected_key
    stolen_bytes = path.read_bytes()

    # A stolen keystore contains no plaintext key or password.
    assert pair["private_key"].encode("ascii") not in stolen_bytes
    assert KEY_PASSWORD.encode("utf-8") not in stolen_bytes
    assert "encrypted_private_key" in json.loads(stolen_bytes)

    # An attacker without the user's secret cannot unlock it using an invalid password.
    with pytest.raises(KeystoreError, match="authentication failed"):
        decrypt_private_key(load_keystore(path), "Attacker-Does-Not-Know-Password")


# ----- Cross-module security and full hybrid-workflow integration -----


def test_d6_06_authenticated_registry_rejects_manual_revocation_rollback(tmp_path):
    registry_path = tmp_path / "registry.json"
    entry = generate_key(
        registry_path, "alice", "secp256k1", KEY_PASSWORD,
        tmp_path / "keystores", registry_password=REGISTRY_PASSWORD,
        scrypt_n=FAST_SCRYPT_N,
    )
    revoke_key(
        registry_path, entry["key_id"], "test device compromise",
        registry_password=REGISTRY_PASSWORD,
    )
    data = json.loads(registry_path.read_text(encoding="utf-8"))
    data["keys"][entry["key_id"]]["status"] = "active"
    registry_path.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(KeyLifecycleError, match="integrity"):
        load_registry(registry_path, REGISTRY_PASSWORD)


@pytest.fixture
def hybrid_environment(tmp_path):
    # This fixture is only requested after a test checks the ECIES dependencies.
    registry_path = tmp_path / "registry.json"
    key_dir = tmp_path / "keystores"
    credentials = {}
    for user, algorithm in (
        ("alice", "secp256k1"),
        ("bob", "secp256k1"),
        ("sender", "Ed25519"),
    ):
        credentials[user] = generate_key(
            registry_path, user, algorithm, KEY_PASSWORD, key_dir,
            registry_password=REGISTRY_PASSWORD, scrypt_n=FAST_SCRYPT_N,
        )
    registry = load_registry(registry_path, REGISTRY_PASSWORD)
    signing_store = key_dir / credentials["sender"]["keystore_file"]
    signer_private_key = decrypt_private_key(
        load_keystore(signing_store), KEY_PASSWORD,
        expected_usage="signing", expected_key_id=credentials["sender"]["key_id"],
    )
    return {
        "registry": registry,
        "registry_path": registry_path,
        "keys_dir": key_dir,
        "credentials": credentials,
        "signer_private_key": signer_private_key,
        "payload": b"D6 end-to-end test: confidential document",
        "tmp_path": tmp_path,
    }


def test_d6_07_full_hybrid_encryption_backup_restore_and_decryption(
    hybrid_environment, monkeypatch
):
    pytest.importorskip("ecies")
    pytest.importorskip("coincurve")
    from src.crypto.key_lifecycle import decrypt_with_registry, encrypt_with_registry

    env = hybrid_environment
    entries = env["credentials"]
    container = encrypt_with_registry(
        env["registry"],
        env["payload"],
        "documento_d6.txt",
        {"alice": entries["alice"]["public_key"], "bob": entries["bob"]["public_key"]},
        env["signer_private_key"],
    )

    original_path = env["keys_dir"] / entries["alice"]["keystore_file"]
    backup_path = env["tmp_path"] / "alice.backup.json"
    create_backup(original_path, backup_path)
    original_path.unlink()
    restored_path = restore_backup(
        backup_path, env["tmp_path"] / "alice.restored.json",
        expected_key_id=entries["alice"]["key_id"],
    )

    # A stolen copy, even after restoration, does not open a real document
    # without its correct password.
    monkeypatch.setattr(getpass, "getpass", lambda *_args, **_kwargs: "Wrong-Password")
    with pytest.raises(ValueError, match="Access Denied"):
        decrypt_with_registry(env["registry"], container, "alice", restored_path)

    monkeypatch.setattr(getpass, "getpass", lambda *_args, **_kwargs: KEY_PASSWORD)
    assert decrypt_with_registry(
        env["registry"], container, "alice", restored_path,
    ) == env["payload"]


def test_d6_08_revocation_blocks_use_before_asking_password(
    hybrid_environment, monkeypatch
):
    pytest.importorskip("ecies")
    pytest.importorskip("coincurve")
    from src.crypto.key_lifecycle import decrypt_with_registry, encrypt_with_registry

    env = hybrid_environment
    entries = env["credentials"]
    container = encrypt_with_registry(
        env["registry"], env["payload"], "documento_d6.txt",
        {"alice": entries["alice"]["public_key"], "bob": entries["bob"]["public_key"]},
        env["signer_private_key"],
    )
    keystore_path = env["keys_dir"] / entries["alice"]["keystore_file"]

    revoke_key(
        env["registry_path"], entries["alice"]["key_id"],
        "compromised device", registry_password=REGISTRY_PASSWORD,
    )
    trusted_registry = load_registry(env["registry_path"], REGISTRY_PASSWORD)
    monkeypatch.setattr(
        getpass, "getpass",
        lambda *_args, **_kwargs: pytest.fail("Password must not be requested for revoked key"),
    )
    with pytest.raises(KeyLifecycleError, match="revoked"):
        decrypt_with_registry(trusted_registry, container, "alice", keystore_path)

    # Even a fresh encrypted document cannot be sent to the revoked recipient.
    with pytest.raises(KeyLifecycleError, match="revoked"):
        encrypt_with_registry(
            trusted_registry, b"new file", "new.txt",
            {"alice": entries["alice"]["public_key"], "bob": entries["bob"]["public_key"]},
            env["signer_private_key"],
        )


def test_d6_09_tampered_signed_container_fails_before_password_prompt(
    hybrid_environment, monkeypatch
):
    pytest.importorskip("ecies")
    pytest.importorskip("coincurve")
    from src.crypto.hybrid_vault import IntegrityError
    from src.crypto.key_lifecycle import decrypt_with_registry, encrypt_with_registry

    env = hybrid_environment
    entries = env["credentials"]
    container = encrypt_with_registry(
        env["registry"], env["payload"], "documento_d6.txt",
        {"alice": entries["alice"]["public_key"], "bob": entries["bob"]["public_key"]},
        env["signer_private_key"],
    )
    tampered = copy.deepcopy(container)
    old = tampered["ciphertext"]
    tampered["ciphertext"] = ("0" if old[0] != "0" else "1") + old[1:]
    alice_path = env["keys_dir"] / entries["alice"]["keystore_file"]

    monkeypatch.setattr(
        getpass, "getpass",
        lambda *_args, **_kwargs: pytest.fail("Tampered documents must fail before password prompt"),
    )
    with pytest.raises(IntegrityError):
        decrypt_with_registry(env["registry"], tampered, "alice", alice_path)


def test_d6_10_revoked_signing_key_blocked_for_new_and_existing_containers(
    hybrid_environment, monkeypatch
):
    """Verify revoked Ed25519 signing keys are blocked for new and existing containers."""
    pytest.importorskip("ecies")
    pytest.importorskip("coincurve")
    from src.crypto.hybrid_vault import IntegrityError
    from src.crypto.key_lifecycle import decrypt_with_registry, encrypt_with_registry

    env = hybrid_environment
    entries = env["credentials"]
    recipients = {
        "alice": entries["alice"]["public_key"],
        "bob": entries["bob"]["public_key"],
    }

    # Document signed before revoking the sender's Ed25519 key.
    signed_container = encrypt_with_registry(
        env["registry"], env["payload"], "signed_before_revocation.txt",
        recipients, env["signer_private_key"],
    )

    # Revoke the sender's signing key in the registry.
    revoke_key(
        env["registry_path"], entries["sender"]["key_id"],
        "signing key compromised", registry_password=REGISTRY_PASSWORD,
    )
    updated_registry = load_registry(env["registry_path"], REGISTRY_PASSWORD)

    # New containers cannot be encrypted/signed with a revoked signing key.
    with pytest.raises(KeyLifecycleError, match="revoked"):
        encrypt_with_registry(
            updated_registry, b"new document", "new.txt",
            recipients, env["signer_private_key"],
        )

    # Decrypting a container signed by a revoked key must fail closed
    # before prompting for the recipient's password.
    alice_ks_path = env["keys_dir"] / entries["alice"]["keystore_file"]
    monkeypatch.setattr(
        getpass, "getpass",
        lambda *_args, **_kwargs: pytest.fail("Password must not be requested for revoked signer"),
    )
    with pytest.raises((KeyLifecycleError, IntegrityError)):
        decrypt_with_registry(updated_registry, signed_container, "alice", alice_ks_path)


def test_d6_11_key_rotation_preserves_access_to_previous_documents(
    hybrid_environment, monkeypatch
):
    """Verify key rotation keeps historical documents decryptable via retired keystores."""
    pytest.importorskip("ecies")
    pytest.importorskip("coincurve")
    from src.crypto.key_lifecycle import (
        decrypt_with_registry,
        encrypt_with_registry,
        rotate_key,
    )

    env = hybrid_environment
    entries = env["credentials"]
    old_alice_key_id = entries["alice"]["key_id"]
    old_alice_ks_path = env["keys_dir"] / entries["alice"]["keystore_file"]

    # Encrypt a document using Alice's initial active key.
    legacy_container = encrypt_with_registry(
        env["registry"], env["payload"], "historical_pre_rotation.txt",
        {"alice": entries["alice"]["public_key"], "bob": entries["bob"]["public_key"]},
        env["signer_private_key"],
    )

    # Rotate Alice's secp256k1 key so the previous key becomes 'retired'.
    new_alice_entry = rotate_key(
        env["registry_path"], "alice", "secp256k1", KEY_PASSWORD, env["keys_dir"],
        registry_password=REGISTRY_PASSWORD, scrypt_n=FAST_SCRYPT_N,
    )
    assert new_alice_entry["key_id"] != old_alice_key_id

    rotated_registry = load_registry(env["registry_path"], REGISTRY_PASSWORD)
    assert rotated_registry["keys"][old_alice_key_id]["status"] == "retired"
    assert rotated_registry["keys"][new_alice_entry["key_id"]]["status"] == "active"

    # Alice still decrypts documents encrypted prior to rotation.
    monkeypatch.setattr(getpass, "getpass", lambda *_args, **_kwargs: KEY_PASSWORD)
    recovered = decrypt_with_registry(
        rotated_registry, legacy_container, "alice", old_alice_ks_path,
    )
    assert recovered == env["payload"]


def test_d6_12_direct_hybrid_vault_encrypt_and_decrypt_with_registry(
    hybrid_environment, monkeypatch
):
    """Verify direct calls to hybrid_vault functions enforce registry lifecycle states."""
    pytest.importorskip("ecies")
    pytest.importorskip("coincurve")
    from src.crypto.hybrid_vault import (
        decrypt_hybrid,
        decrypt_hybrid_with_keystore,
        encrypt_hybrid,
    )
    from src.crypto.key_lifecycle import build_trusted_signers

    env = hybrid_environment
    entries = env["credentials"]
    recipients = {
        "alice": entries["alice"]["public_key"],
        "bob": entries["bob"]["public_key"],
    }
    trusted_signers = build_trusted_signers(env["registry"])

    container = encrypt_hybrid(
        env["payload"],
        "direct_hybrid.txt",
        recipients,
        signing_private_key=env["signer_private_key"],
        registry=env["registry"],
    )

    alice_ks_path = env["keys_dir"] / entries["alice"]["keystore_file"]
    monkeypatch.setattr(getpass, "getpass", lambda *_args, **_kwargs: KEY_PASSWORD)
    alice_private_key = decrypt_private_key(
        load_keystore(alice_ks_path),
        KEY_PASSWORD,
        expected_usage="decryption",
        expected_key_id=entries["alice"]["key_id"],
    )

    assert (
        decrypt_hybrid(
            container,
            "alice",
            alice_private_key,
            trusted_signers=trusted_signers,
            registry=env["registry"],
        )
        == env["payload"]
    )
    assert (
        decrypt_hybrid_with_keystore(
            container,
            "alice",
            alice_ks_path,
            trusted_signers=trusted_signers,
            registry=env["registry"],
        )
        == env["payload"]
    )


def test_d6_13_direct_hybrid_vault_blocks_revoked_recipient_and_signer(
    hybrid_environment, monkeypatch
):
    """Verify direct hybrid_vault calls block revoked keys before password prompts."""
    pytest.importorskip("ecies")
    pytest.importorskip("coincurve")
    from src.crypto.hybrid_vault import (
        IntegrityError,
        decrypt_hybrid_with_keystore,
        encrypt_hybrid,
    )
    from src.crypto.key_lifecycle import build_trusted_signers

    env = hybrid_environment
    entries = env["credentials"]
    recipients = {
        "alice": entries["alice"]["public_key"],
        "bob": entries["bob"]["public_key"],
    }
    initial_signers = build_trusted_signers(env["registry"])

    container = encrypt_hybrid(
        env["payload"],
        "direct_revocation.txt",
        recipients,
        signing_private_key=env["signer_private_key"],
        registry=env["registry"],
    )

    # Revoke Alice's encryption key and verify direct encrypt_hybrid & decrypt_hybrid_with_keystore fail.
    revoke_key(
        env["registry_path"],
        entries["alice"]["key_id"],
        "recipient key revoked",
        registry_password=REGISTRY_PASSWORD,
    )
    reg_after_alice_revoke = load_registry(env["registry_path"], REGISTRY_PASSWORD)

    with pytest.raises(KeyLifecycleError, match="revoked"):
        encrypt_hybrid(
            b"after revoke",
            "after_revoke.txt",
            recipients,
            signing_private_key=env["signer_private_key"],
            registry=reg_after_alice_revoke,
        )

    alice_ks_path = env["keys_dir"] / entries["alice"]["keystore_file"]
    monkeypatch.setattr(
        getpass,
        "getpass",
        lambda *_args, **_kwargs: pytest.fail("Password must not be requested for revoked key"),
    )
    with pytest.raises(KeyLifecycleError, match="revoked"):
        decrypt_hybrid_with_keystore(
            container,
            "alice",
            alice_ks_path,
            trusted_signers=initial_signers,
            registry=reg_after_alice_revoke,
        )

    # Revoke sender's Ed25519 key and verify direct encrypt_hybrid & decrypt_hybrid_with_keystore fail.
    revoke_key(
        env["registry_path"],
        entries["sender"]["key_id"],
        "signer key revoked",
        registry_password=REGISTRY_PASSWORD,
    )
    reg_after_signer_revoke = load_registry(env["registry_path"], REGISTRY_PASSWORD)

    with pytest.raises(KeyLifecycleError, match="revoked"):
        encrypt_hybrid(
            b"after signer revoke",
            "after_signer_revoke.txt",
            recipients,
            signing_private_key=env["signer_private_key"],
            registry=reg_after_signer_revoke,
        )

    bob_ks_path = env["keys_dir"] / entries["bob"]["keystore_file"]
    with pytest.raises((KeyLifecycleError, IntegrityError)):
        decrypt_hybrid_with_keystore(
            container,
            "bob",
            bob_ks_path,
            trusted_signers=initial_signers,
            registry=reg_after_signer_revoke,
        )
def test_d6_13_direct_hybrid_vault_blocks_revoked_recipient(
    hybrid_environment, monkeypatch
):
    """Verify direct hybrid_vault calls block a revoked recipient key."""
    pytest.importorskip("ecies")
    pytest.importorskip("coincurve")
    from src.crypto.hybrid_vault import (
        decrypt_hybrid_with_keystore,
        encrypt_hybrid,
    )
    from src.crypto.key_lifecycle import build_trusted_signers

    env = hybrid_environment
    entries = env["credentials"]
    recipients = {
        "alice": entries["alice"]["public_key"],
        "bob": entries["bob"]["public_key"],
    }
    trusted_signers = build_trusted_signers(env["registry"])

    container = encrypt_hybrid(
        env["payload"],
        "direct_revoked_recipient.txt",
        recipients,
        signing_private_key=env["signer_private_key"],
        registry=env["registry"],
    )

    revoke_key(
        env["registry_path"],
        entries["alice"]["key_id"],
        "recipient key revoked",
        registry_password=REGISTRY_PASSWORD,
    )
    updated_registry = load_registry(env["registry_path"], REGISTRY_PASSWORD)

    with pytest.raises(KeyLifecycleError, match="revoked"):
        encrypt_hybrid(
            b"after recipient revoke",
            "after_recipient_revoke.txt",
            recipients,
            signing_private_key=env["signer_private_key"],
            registry=updated_registry,
        )

    alice_ks_path = env["keys_dir"] / entries["alice"]["keystore_file"]
    monkeypatch.setattr(
        getpass,
        "getpass",
        lambda *_args, **_kwargs: pytest.fail("Password must not be requested for revoked key"),
    )
    with pytest.raises(KeyLifecycleError, match="revoked"):
        decrypt_hybrid_with_keystore(
            container,
            "alice",
            alice_ks_path,
            trusted_signers=trusted_signers,
            registry=updated_registry,
        )


def test_d6_14_direct_hybrid_vault_blocks_revoked_signer(
    hybrid_environment, monkeypatch
):
    """Verify direct hybrid_vault calls block a revoked Ed25519 signing key."""
    pytest.importorskip("ecies")
    pytest.importorskip("coincurve")
    from src.crypto.hybrid_vault import (
        IntegrityError,
        decrypt_hybrid_with_keystore,
        encrypt_hybrid,
    )
    from src.crypto.key_lifecycle import build_trusted_signers

    env = hybrid_environment
    entries = env["credentials"]
    recipients = {
        "alice": entries["alice"]["public_key"],
        "bob": entries["bob"]["public_key"],
    }
    initial_signers = build_trusted_signers(env["registry"])

    container = encrypt_hybrid(
        env["payload"],
        "direct_revoked_signer.txt",
        recipients,
        signing_private_key=env["signer_private_key"],
        registry=env["registry"],
    )

    revoke_key(
        env["registry_path"],
        entries["sender"]["key_id"],
        "signer key revoked",
        registry_password=REGISTRY_PASSWORD,
    )
    updated_registry = load_registry(env["registry_path"], REGISTRY_PASSWORD)

    with pytest.raises(KeyLifecycleError, match="revoked"):
        encrypt_hybrid(
            b"after signer revoke",
            "after_signer_revoke.txt",
            recipients,
            signing_private_key=env["signer_private_key"],
            registry=updated_registry,
        )

    bob_ks_path = env["keys_dir"] / entries["bob"]["keystore_file"]
    monkeypatch.setattr(
        getpass,
        "getpass",
        lambda *_args, **_kwargs: pytest.fail("Password must not be requested for revoked signer"),
    )
    with pytest.raises((KeyLifecycleError, IntegrityError)):
        decrypt_hybrid_with_keystore(
            container,
            "bob",
            bob_ks_path,
            trusted_signers=initial_signers,
            registry=updated_registry,
        )