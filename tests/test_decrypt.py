import pytest
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from ecies import encrypt as ecies_encrypt
from ecies.keys import PrivateKey

# Import building tools
from src.crypto.aad_builder import (
    build_metadata,
    build_recipient_entry,
    build_container,
    build_aad
)
from src.crypto.hybrid_vault import decrypt_hybrid


def _make_keypair():
    sk = PrivateKey("secp256k1")
    return sk, sk.to_hex(), sk.public_key.to_hex(True)


def _build_valid_container(recipients_data, original_data, filename):
    """Helper: builds a valid container"""
    dek = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(dek)
    nonce = os.urandom(12)

    # 1. Build valid metadata
    metadata = build_metadata(filename)

    # 2. Build valid recipient entries
    encrypted_recipients = []
    for rec in recipients_data:
        enc_dek = ecies_encrypt(rec["public_key"], dek)
        encrypted_recipients.append(
            build_recipient_entry(rec["id"], enc_dek.hex())
        )

    # 3. Build the AAD directly
    aad_data = build_aad(metadata, encrypted_recipients)
    
    # 4. Encrypt
    ciphertext_with_tag = aesgcm.encrypt(nonce, original_data, aad_data)

    # 5. Use the function to build the final container
    return build_container(
        metadata,
        encrypted_recipients,
        nonce,
        ciphertext_with_tag[:-16],
        ciphertext_with_tag[-16:]
    )


def test_decrypt_hybrid_success():
    _, sk_bob_hex, pk_bob_hex = _make_keypair()
    _, _, pk_alice_hex = _make_keypair()

    original_data = b"Secret document shared between Bob and Alice."
    recipients = [
        {"id": "Bob", "public_key": pk_bob_hex},
        {"id": "Alice", "public_key": pk_alice_hex},
    ]
    container = _build_valid_container(recipients, original_data, "report_d3.pdf")

    assert decrypt_hybrid(container, "Bob", sk_bob_hex) == original_data


def test_decrypt_hybrid_unauthorized_user():
    sk_bob = PrivateKey("secp256k1")
    # For this test, it doesn't matter if the container is valid or not,
    # because we want it to fail at the access validation first.
    # But to avoid failing in validate_container, we pass a valid one.
    _, _, pk_alice_hex = _make_keypair()
    container = _build_valid_container(
        [{"id": "Alice", "public_key": pk_alice_hex}], 
        b"data", 
        "test.txt"
    )
    
    with pytest.raises(ValueError, match="not authorized"):
        decrypt_hybrid(container, "Bob", sk_bob.to_hex())


def test_decrypt_hybrid_wrong_private_key():
    _, _, pk_bob_hex = _make_keypair()
    _, sk_alice_hex, pk_alice_hex = _make_keypair()

    recipients = [
        {"id": "Bob", "public_key": pk_bob_hex},
        {"id": "Alice", "public_key": pk_alice_hex},
    ]
    container = _build_valid_container(recipients, b"payload", "doc.bin")

    with pytest.raises(ValueError, match="Decryption error"):
        decrypt_hybrid(container, "Bob", sk_alice_hex)


def test_decrypt_hybrid_tampered_other_recipient_key():
    _, sk_bob_hex, pk_bob_hex = _make_keypair()
    _, _, pk_alice_hex = _make_keypair()

    recipients = [
        {"id": "Bob", "public_key": pk_bob_hex},
        {"id": "Alice", "public_key": pk_alice_hex},
    ]
    container = _build_valid_container(recipients, b"payload", "doc.bin")

    # Alter Alice's key (it's still valid hex to pass the validation)
    for rec in container["recipients"]:
        if rec["id"] == "Alice":
            rec["encrypted_key"] = "00" * len(bytes.fromhex(rec["encrypted_key"]))
            break

    with pytest.raises(RuntimeError, match="Integrity failure"):
        decrypt_hybrid(container, "Bob", sk_bob_hex)


def test_decrypt_hybrid_tampered_filename():
    _, sk_bob_hex, pk_bob_hex = _make_keypair()
    _, _, pk_alice_hex = _make_keypair()

    recipients = [
        {"id": "Bob", "public_key": pk_bob_hex},
        {"id": "Alice", "public_key": pk_alice_hex},
    ]
    container = _build_valid_container(recipients, b"payload", "doc.bin")
    container["metadata"]["filename"] = "tampered.bin"

    with pytest.raises(RuntimeError, match="Integrity failure"):
        decrypt_hybrid(container, "Bob", sk_bob_hex)


def test_decrypt_hybrid_tampered_recipients_list():
    _, sk_bob_hex, pk_bob_hex = _make_keypair()
    _, _, pk_alice_hex = _make_keypair()

    recipients = [
        {"id": "Bob", "public_key": pk_bob_hex},
        {"id": "Alice", "public_key": pk_alice_hex},
    ]
    container = _build_valid_container(recipients, b"payload", "doc.bin")
    
    # Add Eve (valid hex and valid ID so it passes validation)
    container["recipients"].append({"id": "Eve", "encrypted_key": "00" * 32})

    with pytest.raises(RuntimeError, match="Integrity failure"):
        decrypt_hybrid(container, "Bob", sk_bob_hex)


def test_decrypt_hybrid_tampered_ciphertext():
    _, sk_bob_hex, pk_bob_hex = _make_keypair()
    _, _, pk_alice_hex = _make_keypair()

    recipients = [
        {"id": "Bob", "public_key": pk_bob_hex},
        {"id": "Alice", "public_key": pk_alice_hex},
    ]
    container = _build_valid_container(recipients, b"payload", "doc.bin")
    ct = container["ciphertext"]
    container["ciphertext"] = ("00" if ct[:2] != "00" else "11") + ct[2:]

    with pytest.raises(RuntimeError, match="Integrity failure"):
        decrypt_hybrid(container, "Bob", sk_bob_hex)


def test_decrypt_hybrid_invalid_container_structure():
    sk_bob_hex = PrivateKey("secp256k1").to_hex()

    # Empty container
    with pytest.raises(ValueError, match="Invalid container"):
        decrypt_hybrid({}, "Bob", sk_bob_hex)

    # Container with invalid nonce
    with pytest.raises(ValueError, match="Invalid container"):
        decrypt_hybrid(
            {
                "metadata": {},
                "recipients": [{"id": "Bob", "encrypted_key": "aabbcc"}],
                "nonce": "zz",
                "ciphertext": "11" * 16,
                "tag": "22" * 16,
            },
            "Bob",
            sk_bob_hex,
        )