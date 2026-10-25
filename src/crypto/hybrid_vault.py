from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from ecies import decrypt as ecies_decrypt

# Importamos las funciones y errores de Gabriel
from src.crypto.aad_builder import (
    aad_from_container,
    validate_container,
    ContainerFormatError
)


def decrypt_hybrid(container: dict, user_id: str, private_key: str) -> bytes:
    """
    Hybrid Decryption Engine (assigned to Jesús)
    1. Validate the container structure using Gabriel's strict schema.
    2. Deterministic lookup of user_id in the recipients list.
    3. DEK decryption using ECIES with the user's private key.
    4. AAD reconstruction via Gabriel's aad_builder.
    5. AES-GCM decryption (Fail-Closed policy).
    """
    # 1. Structural validation (using Gabriel's strict rules)
    try:
        validate_container(container)
    except ContainerFormatError as e:
        raise ValueError(f"Invalid container: {e}") from e

    # 2. Deterministic lookup of the user in the recipients list
    recipient_entry = None
    for rec in container["recipients"]:
        if rec["id"] == user_id:
            recipient_entry = rec
            break

    if not recipient_entry:
        raise ValueError(
            f"Access denied: User '{user_id}' is not authorized for this container."
        )

    # 3. Unpack and decrypt the DEK using ECIES and the private key
    try:
        enc_dek_bytes = bytes.fromhex(recipient_entry["encrypted_key"])
        dek = ecies_decrypt(private_key, enc_dek_bytes)
    except Exception as e:
        raise ValueError(
            "Decryption error: Incorrect private key or corrupted container."
        ) from e

    # 4. Rebuild the canonical AAD using Gabriel's function
    # (This re-validates the container internally and builds the AAD bytes)
    aad_data = aad_from_container(container)

    # 5. Extract cryptographic components
    nonce = bytes.fromhex(container["nonce"])
    ciphertext = bytes.fromhex(container["ciphertext"])
    tag = bytes.fromhex(container["tag"])
    ciphertext_with_tag = ciphertext + tag

    # 6. Decrypt the file with AES-GCM (Fail-Closed policy)
    aesgcm = AESGCM(dek)
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, aad_data)
    except Exception as e:
        raise RuntimeError(
            "Integrity failure: The file or metadata has been tampered with."
        ) from e

    return plaintext