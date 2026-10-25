import os
from typing import Union, List, Dict
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

try:
    from src.crypto.aad_builder import (
        build_metadata,
        build_aad,
        build_container,
        NONCE_SIZE,
        TAG_SIZE,
    )
    from src.crypto.key_manager import ECIESKeyManager
except ModuleNotFoundError:
    from aad_builder import (
        build_metadata,
        build_aad,
        build_container,
        NONCE_SIZE,
        TAG_SIZE,
    )
    from key_manager import ECIESKeyManager


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

        :param file_bytes: Raw plaintext file bytes to encrypt.
        :param filename: Original name of the payload file.
        :param recipients: Either a dict {user_id: public_key_hex} or
                           a list of dicts [{"id": user_id, "public_key": public_key_hex}, ...].
        :return: Validated D3 container dictionary with hex-encoded fields.
        """
        if not isinstance(file_bytes, (bytes, bytearray)):
            raise TypeError("file_bytes must be raw bytes or bytearray.")

        # Normalize recipients to a mapping {user_id: public_key_hex}
        recipients_map: Dict[str, str] = {}
        if isinstance(recipients, dict):
            recipients_map = recipients
        elif isinstance(recipients, list):
            for entry in recipients:
                if not isinstance(entry, dict) or "id" not in entry or "public_key" not in entry:
                    raise ValueError("Each recipient in list must contain 'id' and 'public_key'.")
                recipient_id = entry["id"]
                if recipient_id in recipients_map:
                    raise ValueError(f"Duplicate recipient identifier detected: '{recipient_id}'.")
                recipients_map[recipient_id] = entry["public_key"]
        else:
            raise TypeError("recipients must be a dictionary or a list of dictionaries.")

        # Security requirement: Enforce multi-recipient encryption (minimum 2 recipients)
        if len(recipients_map) < 2:
            raise ValueError("Encryption requires at least 2 distinct authorized recipients.")

        # Step 1: Generate a single-use 256-bit DEK using the OS CSPRNG
        dek = os.urandom(cls.DEK_SIZE_BYTES)

        # Step 2: Encapsulate DEK for all recipients using ECIESKeyManager
        # Output contains: [{"id": ..., "key_id": ..., "encrypted_key": ...}, ...] in canonical hex
        recipient_entries = ECIESKeyManager.encrypt_dek_for_recipients(dek, recipients_map)

        # Step 3: Construct metadata according to aad_builder schema
        metadata = build_metadata(filename=filename)

        # Step 4: Generate canonical AAD binding metadata and recipient entries
        # Secures both metadata and encapsulated keys against ciphertext/recipient tampering
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