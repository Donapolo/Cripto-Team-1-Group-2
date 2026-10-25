import os
import pytest
from src.crypto.key_manager import ECIESKeyManager


def test_authorized_recipient_recovers_dek():
    bob = ECIESKeyManager.generate_key_pair()
    dek = os.urandom(32)
    entries = ECIESKeyManager.encrypt_dek_for_recipients(
        dek, {"bob": bob["public_key"]}
    )
    assert ECIESKeyManager.decrypt_dek(entries[0]["encrypted_key"], bob["private_key"]) == dek


def test_unauthorized_user_has_no_recipient_entry():
    bob = ECIESKeyManager.generate_key_pair()
    dek = os.urandom(32)
    entries = ECIESKeyManager.encrypt_dek_for_recipients(
        dek, {"bob": bob["public_key"]}
    )
    assert not any(entry["id"] == "eve" for entry in entries)


def test_wrong_private_key_cannot_recover_dek():
    bob = ECIESKeyManager.generate_key_pair()
    eve = ECIESKeyManager.generate_key_pair()
    encrypted = ECIESKeyManager.encrypt_dek(os.urandom(32), bob["public_key"])
    with pytest.raises(ValueError, match="Unable to recover DEK"):
        ECIESKeyManager.decrypt_dek(encrypted, eve["private_key"])


def test_public_key_id_is_deterministic():
    bob = ECIESKeyManager.generate_key_pair()
    assert ECIESKeyManager.get_key_id(bob["public_key"]) == bob["key_id"]


def test_invalid_dek_is_rejected():
    bob = ECIESKeyManager.generate_key_pair()
    with pytest.raises(ValueError, match="32 bytes"):
        ECIESKeyManager.encrypt_dek(b"short", bob["public_key"])
