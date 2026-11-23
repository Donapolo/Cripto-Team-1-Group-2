"""D6 Ed25519 authorization tests independent of the optional ECIES libraries."""

from datetime import datetime, timedelta, timezone

import pytest

from src.crypto.aad_builder import build_metadata, build_recipient_entry
from src.crypto.key_lifecycle import (
    KeyLifecycleError, generate_key, load_registry, revoke_key, rotate_key,
)
from src.crypto.secure_keystore import decrypt_private_key, load_keystore
from src.crypto.signature_manager import (
    sign_container_with_registry, sign_payload_with_registry,
    verify_container_with_registry, verify_payload_with_registry,
)

PASSWORD = "DevTest-Keystore-Password-2026!"
REGISTRY_PASSWORD = "DevTest-Registry-Password-2026!"
T0 = datetime(2026, 11, 1, tzinfo=timezone.utc)


@pytest.fixture
def signer(tmp_path):
    registry_path = tmp_path / "registry.json"
    keystore_dir = tmp_path / "keystores"
    entry = generate_key(registry_path, "alice", "Ed25519", PASSWORD, keystore_dir,
                         registry_password=REGISTRY_PASSWORD, scrypt_n=16384,
                         validity_days=365, now=T0)
    private_key = decrypt_private_key(load_keystore(keystore_dir / entry["keystore_file"]),
                                      PASSWORD, expected_usage="signing")
    return registry_path, keystore_dir, entry, private_key


def _container(registry, private, *, now=T0):
    return sign_container_with_registry(
        registry, build_metadata("sample.pdf"),
        [build_recipient_entry("alice", "aa" * 40),
         build_recipient_entry("bob", "bb" * 40)],
        b"\x01" * 12, b"ciphertext", b"\x02" * 16, private, now=now)


def test_active_signer_can_sign_and_verify_payload_and_container(signer):
    path, _, entry, private = signer
    registry = load_registry(path, REGISTRY_PASSWORD)
    signature = sign_payload_with_registry(registry, private, b"text", now=T0)
    verify_payload_with_registry(registry, entry["key_id"], b"text", signature, now=T0)
    container = _container(registry, private)
    verify_container_with_registry(registry, container, now=T0)


def test_revoked_signer_cannot_sign_or_verify_mathematically_valid_signatures(signer):
    path, _, entry, private = signer
    before = load_registry(path, REGISTRY_PASSWORD)
    signature = sign_payload_with_registry(before, private, b"document", now=T0)
    container = _container(before, private)
    revoke_key(path, entry["key_id"], "compromised", registry_password=REGISTRY_PASSWORD, now=T0)
    after = load_registry(path, REGISTRY_PASSWORD)

    with pytest.raises(KeyLifecycleError, match="revoked"):
        sign_payload_with_registry(after, private, b"new", now=T0)
    with pytest.raises(KeyLifecycleError, match="revoked"):
        verify_payload_with_registry(after, entry["key_id"], b"document", signature, now=T0)
    with pytest.raises(KeyLifecycleError, match="revoked"):
        verify_container_with_registry(after, container, now=T0)
    with pytest.raises(KeyLifecycleError, match="revoked"):
        _container(after, private)


def test_retired_key_verifies_older_but_cannot_sign_new(signer):
    path, ksdir, entry, private = signer
    before = load_registry(path, REGISTRY_PASSWORD)
    container = _container(before, private)
    rotate_key(path, "alice", "Ed25519", PASSWORD, ksdir,
               registry_password=REGISTRY_PASSWORD, scrypt_n=16384,
               now=T0 + timedelta(days=1))
    after = load_registry(path, REGISTRY_PASSWORD)
    verify_container_with_registry(after, container, now=T0 + timedelta(days=2))
    with pytest.raises(KeyLifecycleError, match="retired"):
        _container(after, private, now=T0 + timedelta(days=2))


def test_unknown_signer_rejected_and_expired_key_cannot_sign(signer):
    path, _, entry, private = signer
    reg = load_registry(path, REGISTRY_PASSWORD)
    signature = sign_payload_with_registry(reg, private, b"data", now=T0)
    with pytest.raises(KeyLifecycleError, match="Unknown"):
        verify_payload_with_registry(reg, "00" * 32, b"data", signature)
    with pytest.raises(KeyLifecycleError, match="expired"):
        sign_payload_with_registry(reg, private, b"data", now=T0 + timedelta(days=400))
    # Old documents remain verifiable by an expired but not revoked signer.
    verify_payload_with_registry(reg, entry["key_id"], b"data", signature,
                                 now=T0 + timedelta(days=400))


def test_tampered_signature_rejected_even_if_signer_is_active(signer):
    path, _, _, private = signer
    reg = load_registry(path, REGISTRY_PASSWORD)
    container = _container(reg, private)
    container["ciphertext"] = "00" * len(bytes.fromhex(container["ciphertext"]))
    with pytest.raises(ValueError):
        verify_container_with_registry(reg, container, now=T0)
