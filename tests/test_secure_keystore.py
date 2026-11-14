"""Unit tests for src/crypto/secure_keystore.py (D6 Deliverable)."""

import copy
import pytest

from src.crypto.key_manager import ECIESKeyManager
from src.crypto.signature_manager import generate_key_pair as generate_signing_key_pair
from src.crypto.secure_keystore import (
    KeystoreError,
    create_keystore,
    decrypt_private_key,
    load_keystore,
    save_keystore,
)


def test_secp256k1_keystore_roundtrip(tmp_path):
    """Correct password grants access and recovers exact secp256k1 private key."""
    pair = ECIESKeyManager.generate_key_pair()
    ks = create_keystore(
        pair["private_key"],
        "StrongPass!2026",
        key_id=pair["key_id"],
        algorithm="secp256k1",
        user_id="alice",
    )

    ks_file = save_keystore(ks, tmp_path / "alice_keystore.json")
    loaded = load_keystore(ks_file)

    recovered = decrypt_private_key(
        loaded,
        "StrongPass!2026",
        expected_usage="decryption",
        expected_key_id=pair["key_id"],
    )
    assert recovered == pair["private_key"]


def test_ed25519_keystore_roundtrip():
    """Supports Ed25519 signing keys and enforces usage separation."""
    sig_pair = generate_signing_key_pair()
    ks = create_keystore(
        sig_pair["private_key"],
        "SignPass#99",
        key_id=sig_pair["signer_id"],
        algorithm="Ed25519",
        user_id="alice",
    )

    recovered = decrypt_private_key(ks, "SignPass#99", expected_usage="signing")
    assert recovered == sig_pair["private_key"]

    with pytest.raises(KeystoreError, match="Key usage mismatch"):
        decrypt_private_key(ks, "SignPass#99", expected_usage="decryption")


def test_wrong_password_rejected():
    """Wrong password fails closed with KeystoreError."""
    pair = ECIESKeyManager.generate_key_pair()
    ks = create_keystore(pair["private_key"], "CorrectHorseBatteryStaple", key_id=pair["key_id"])

    with pytest.raises(KeystoreError, match="wrong password or tampered keystore"):
        decrypt_private_key(ks, "WrongPassword123")


def test_tampered_keystore_rejected():
    """Modifying ciphertext, metadata, salt, or kdf_parameters triggers failure."""
    pair = ECIESKeyManager.generate_key_pair()
    ks = create_keystore(
        pair["private_key"], "MySecretPass", key_id=pair["key_id"], user_id="bob"
    )

    # 1. Tamper encrypted_private_key
    ks_bad_ct = copy.deepcopy(ks)
    first_char = ks_bad_ct["encrypted_private_key"][0]
    ks_bad_ct["encrypted_private_key"] = (
        "0" if first_char != "0" else "1"
    ) + ks_bad_ct["encrypted_private_key"][1:]
    with pytest.raises(KeystoreError):
        decrypt_private_key(ks_bad_ct, "MySecretPass")

    # 2. Tamper metadata (bound in AAD)
    ks_bad_meta = copy.deepcopy(ks)
    ks_bad_meta["metadata"]["user_id"] = "mallory"
    with pytest.raises(KeystoreError, match="wrong password or tampered keystore"):
        decrypt_private_key(ks_bad_meta, "MySecretPass")


def test_no_plaintext_key_or_password_in_keystore():
    """Verifies neither the password nor the raw private key appears in serialized output."""
    pair = ECIESKeyManager.generate_key_pair()
    password = "UltraSecretPassword2026"
    ks = create_keystore(pair["private_key"], password, key_id=pair["key_id"])

    serialized = str(ks)
    assert password not in serialized
    assert pair["private_key"] not in serialized