import pytest
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from ecies import encrypt as ecies_encrypt
from ecies.keys import PrivateKey  # Modern eciespy API
from src.crypto.hybrid_vault import decrypt_hybrid


def test_decrypt_hybrid_success():
    """
    Simulates a valid hybrid container and verifies that Bob (user_id='Bob')
    can decrypt it correctly using his private key.
    """
    # 1. Generate ECIES key pairs for Bob and Alice using the modern API
    sk_bob = PrivateKey("secp256k1")
    sk_bob_hex = sk_bob.to_hex()
    pk_bob_hex = sk_bob.public_key.to_hex(True)  # True = compressed format

    sk_alice = PrivateKey("secp256k1")
    pk_alice_hex = sk_alice.public_key.to_hex(True)

    # 2. Generate a simulated DEK and encrypt test data with AES-GCM
    dek = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(dek)
    nonce = os.urandom(12)
    original_data = b"Secret document shared between Bob and Alice."
    filename = "report_d3.pdf"

    recipients_list = [
        {"id": "Bob", "public_key": pk_bob_hex},
        {"id": "Alice", "public_key": pk_alice_hex},
    ]

    # Encrypt the DEK for each recipient using ECIES
    encrypted_recipients = []
    for rec in recipients_list:
        enc_dek = ecies_encrypt(rec["public_key"], dek)
        encrypted_recipients.append({
            "id": rec["id"],
            "encrypted_key": enc_dek.hex(),
        })

    # Build the canonical AAD
    sorted_ids = sorted([r["id"] for r in encrypted_recipients])
    aad_data = f"{filename}|{sorted_ids}".encode("utf-8")

    ciphertext_with_tag = aesgcm.encrypt(nonce, original_data, aad_data)

    # Assemble the fake container
    container = {
        "metadata": {"filename": filename},
        "recipients": encrypted_recipients,
        "nonce": nonce.hex(),
        "ciphertext": ciphertext_with_tag[:-16].hex(),
        "tag": ciphertext_with_tag[-16:].hex(),
    }

    # 3. Test the decryption function as Bob
    decrypted_data = decrypt_hybrid(container, "Bob", sk_bob_hex)

    # 4. Verify that the plaintext matches exactly
    assert decrypted_data == original_data, "Hybrid decryption failed."


def test_decrypt_hybrid_unauthorized_user():
    """
    Verifies that a user who is not in the recipients list is rejected.
    """
    sk_bob = PrivateKey("secp256k1")
    sk_bob_hex = sk_bob.to_hex()

    container = {
        "metadata": {"filename": "test.txt"},
        "recipients": [{"id": "Alice", "encrypted_key": "aabbcc"}],
        "nonce": "00" * 12,
        "ciphertext": "11" * 16,
        "tag": "22" * 16,
    }

    with pytest.raises(ValueError, match="not authorized"):
        decrypt_hybrid(container, "Bob", sk_bob_hex)
        