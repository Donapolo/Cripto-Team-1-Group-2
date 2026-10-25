from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from ecies import decrypt as ecies_decrypt


def decrypt_hybrid(container: dict, user_id: str, private_key: str) -> bytes:
    """
    Hybrid Decryption Engine (assigned to Jesús)
    1. Deterministic lookup of user_id in the recipients list.
    2. DEK decryption using ECIES with the user's private key.
    3. AAD reconstruction and AES-GCM decryption (Fail-Closed policy).
    """
    # 1. Deterministic lookup of the user in the recipients list
    recipient_entry = None
    for rec in container.get("recipients", []):
        if rec.get("id") == user_id:
            recipient_entry = rec
            break

    if not recipient_entry:
        raise ValueError(
            f"Access denied: User '{user_id}' is not authorized for this container."
        )

    # 2. Unpack and decrypt the DEK using ECIES and the private key
    try:
        enc_dek_bytes = bytes.fromhex(recipient_entry["encrypted_key"])
        dek = ecies_decrypt(private_key, enc_dek_bytes)
    except Exception as e:
        raise ValueError(
            "Decryption error: Incorrect private key or corrupted container."
        ) from e

    # 3. Rebuild the canonical AAD (metadata + sorted list of recipient IDs)
    metadata = container.get("metadata", {})
    filename = metadata.get("filename", "unknown")
    sorted_ids = sorted([r["id"] for r in container["recipients"]])
    aad_data = f"{filename}|{sorted_ids}".encode("utf-8")

    # 4. Extract cryptographic components
    nonce = bytes.fromhex(container["nonce"])
    ciphertext = bytes.fromhex(container["ciphertext"])
    tag = bytes.fromhex(container["tag"])
    ciphertext_with_tag = ciphertext + tag

    # 5. Decrypt the file with AES-GCM (Fail-Closed policy)
    aesgcm = AESGCM(dek)
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, aad_data)
    except Exception as e:
        raise RuntimeError(
            "Integrity failure: The file or metadata has been tampered with."
        ) from e

    return plaintext