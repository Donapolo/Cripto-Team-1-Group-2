from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from ecies import decrypt as ecies_decrypt

from src.crypto.aad_builder import build_aad


_NONCE_LEN = 12
_TAG_LEN = 16


def _validate_container(container: dict) -> None:
    """
    Validate the structural shape of a container before any crypto operation.

    Raises ValueError with a descriptive message on any structural problem,
    so callers get a controlled failure instead of a TypeError/KeyError.
    """
    if not isinstance(container, dict):
        raise ValueError("Invalid container: expected a dict.")

    for field in ("recipients", "nonce", "ciphertext", "tag"):
        if field not in container:
            raise ValueError(f"Invalid container: missing field '{field}'.")

    if not isinstance(container["recipients"], list) or not container["recipients"]:
        raise ValueError("Invalid container: 'recipients' must be a non-empty list.")

    for i, rec in enumerate(container["recipients"]):
        if not isinstance(rec, dict):
            raise ValueError(f"Invalid container: recipient[{i}] must be a dict.")
        if "id" not in rec or not isinstance(rec["id"], str):
            raise ValueError(f"Invalid container: recipient[{i}]['id'] must be a string.")
        if "encrypted_key" not in rec:
            raise ValueError(f"Invalid container: recipient[{i}] missing 'encrypted_key'.")
        try:
            bytes.fromhex(rec["encrypted_key"])
        except (ValueError, TypeError):
            raise ValueError(
                f"Invalid container: recipient[{i}]['encrypted_key'] is not valid hex."
            )

    for field in ("nonce", "ciphertext", "tag"):
        try:
            bytes.fromhex(container[field])
        except (ValueError, TypeError):
            raise ValueError(f"Invalid container: '{field}' is not valid hex.")

    if len(bytes.fromhex(container["nonce"])) != _NONCE_LEN:
        raise ValueError(f"Invalid container: 'nonce' must be {_NONCE_LEN} bytes.")

    if len(bytes.fromhex(container["tag"])) != _TAG_LEN:
        raise ValueError(f"Invalid container: 'tag' must be {_TAG_LEN} bytes.")

    metadata = container.get("metadata", {})
    if not isinstance(metadata, dict):
        raise ValueError("Invalid container: 'metadata' must be a dict.")


def decrypt_hybrid(container: dict, user_id: str, private_key: str) -> bytes:
    """
    Hybrid Decryption Engine (assigned to Jesús)
    1. Validate the container structure (controlled rejection of malformed data).
    2. Deterministic lookup of user_id in the recipients list.
    3. DEK decryption using ECIES with the user's private key.
    4. AAD reconstruction via aad_builder.build_aad().
    5. AES-GCM decryption (Fail-Closed policy).
    """
    # 1. Structural validation
    _validate_container(container)

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

    # 4. Rebuild the canonical AAD via aad_builder
    aad_data = build_aad(container.get("metadata", {}), container["recipients"])

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