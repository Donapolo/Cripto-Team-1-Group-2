import os
from typing import Union, List, Dict
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from ecies import decrypt as ecies_decrypt
from coincurve import PublicKey as CoincurvePublicKey

try:
    from src.crypto.aad_builder import (
        build_metadata,
        build_aad,
        build_container,
        aad_from_container,
        validate_container,
        ContainerFormatError,
        NONCE_SIZE,
        TAG_SIZE,
    )
    from src.crypto.key_manager import ECIESKeyManager
except ModuleNotFoundError:
    from aad_builder import (
        build_metadata,
        build_aad,
        build_container,
        aad_from_container,
        validate_container,
        ContainerFormatError,
        NONCE_SIZE,
        TAG_SIZE,
    )
    from key_manager import ECIESKeyManager


class IntegrityError(RuntimeError, ValueError):
    """Raised when container decryption or integrity verification fails."""
    pass


def _ensure_compressed_public_key(pub_key_hex: str) -> str:
    """Normalizes any secp256k1 public key to 33-byte compressed hex."""
    clean_hex = pub_key_hex.removeprefix("0x")
    raw = bytes.fromhex(clean_hex)
    if len(raw) == 33 and raw[0] in (2, 3):
        return clean_hex
    if len(raw) == 64:
        raw = b"\x04" + raw
    pk = CoincurvePublicKey(raw)
    return pk.format(compressed=True).hex()


class HybridVault:
    DEK_SIZE_BYTES = 32  # 256-bit symmetric key for AES-GCM

    @classmethod
    def encrypt_hybrid(
        cls,
        file_bytes: bytes,
        filename: str,
        recipients: Union[Dict[str, str], List[Dict[str, str]]],
    ) -> dict:
        """
        Encrypts payload using hybrid encryption adhering to the D3 specification:
        1. Generates a fresh 256-bit AES-GCM Data Encryption Key (DEK).
        2. Encapsulates the DEK for each recipient via ECIESKeyManager (secp256k1).
        3. Constructs canonical metadata and builds AAD binding both metadata and recipients.
        4. Encrypts file bytes with AES-256-GCM and packages the output into a validated container.
        """
        if not isinstance(file_bytes, (bytes, bytearray)):
            raise TypeError("file_bytes must be raw bytes or bytearray.")

        # Normalize recipients to a mapping {user_id: public_key_hex}
        recipients_map: Dict[str, str] = {}
        if isinstance(recipients, dict):
            for uid, pk in recipients.items():
                recipients_map[uid] = _ensure_compressed_public_key(pk)
        elif isinstance(recipients, list):
            for entry in recipients:
                if not isinstance(entry, dict) or "id" not in entry or "public_key" not in entry:
                    raise ValueError("Each recipient in list must contain 'id' and 'public_key'.")
                recipient_id = entry["id"]
                if recipient_id in recipients_map:
                    raise ValueError(f"Duplicate recipient identifier detected: '{recipient_id}'.")
                recipients_map[recipient_id] = _ensure_compressed_public_key(entry["public_key"])
        else:
            raise TypeError("recipients must be a dictionary or a list of dictionaries.")

        # Security requirement: Enforce multi-recipient encryption (minimum 2 recipients)
        if len(recipients_map) < 2:
            raise ValueError("Encryption requires at least 2 distinct authorized recipients.")

        # Step 1: Generate a single-use 256-bit DEK using the OS CSPRNG
        dek = os.urandom(cls.DEK_SIZE_BYTES)

        # Step 2: Encapsulate DEK for all recipients using ECIESKeyManager
        recipient_entries = ECIESKeyManager.encrypt_dek_for_recipients(dek, recipients_map)

        # Step 3: Construct metadata according to aad_builder schema
        metadata = build_metadata(filename=filename)

        # Step 4: Generate canonical AAD binding metadata and recipient entries
        aad_bytes = build_aad(metadata, recipient_entries)

        # Step 5: Perform AES-256-GCM authenticated encryption
        nonce = os.urandom(NONCE_SIZE)
        aesgcm = AESGCM(dek)
        ciphertext_with_tag = aesgcm.encrypt(nonce, bytes(file_bytes), aad_bytes)

        # Step 6: Separate ciphertext and GHASH authentication tag
        ciphertext = ciphertext_with_tag[:-TAG_SIZE]
        tag = ciphertext_with_tag[-TAG_SIZE:]

        # Step 7: Build and validate canonical container (hex-encoded fields)
        return build_container(
            metadata=metadata,
            recipients=recipient_entries,
            nonce=nonce,
            ciphertext=ciphertext,
            tag=tag,
        )


encrypt_hybrid = HybridVault.encrypt_hybrid


def decrypt_hybrid(container: dict, user_id: str, private_key: str) -> bytes:
    """
    Hybrid Decryption Engine (assigned to Jesús)
    1. Validate the container structure using Gabriel's strict schema.
    2. Deterministic lookup of user_id in the recipients list.
    3. DEK decryption using ECIES with the user's private key.
    4. AAD reconstruction via Gabriel's aad_builder.
    5. AES-GCM decryption (Fail-Closed policy).
    """
    try:
        validate_container(container)
    except ContainerFormatError as e:
        raise ValueError(f"Invalid container: {e}") from e

    recipient_entry = None
    for rec in container["recipients"]:
        if rec["id"] == user_id:
            recipient_entry = rec
            break

    if not recipient_entry:
        raise ValueError(
            f"Access denied: User '{user_id}' is not authorized for this container."
        )

    try:
        enc_dek_bytes = bytes.fromhex(recipient_entry["encrypted_key"])
        dek = ecies_decrypt(private_key, enc_dek_bytes)
    except Exception as e:
        raise ValueError(
            "Decryption error: Incorrect private key or corrupted container."
        ) from e

    aad_data = aad_from_container(container)

    nonce = bytes.fromhex(container["nonce"])
    ciphertext = bytes.fromhex(container["ciphertext"])
    tag = bytes.fromhex(container["tag"])
    ciphertext_with_tag = ciphertext + tag

    aesgcm = AESGCM(dek)
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, aad_data)
    except Exception as e:
        raise IntegrityError(
            "Integrity failure: The file or metadata has been tampered with."
        ) from e

    return plaintext