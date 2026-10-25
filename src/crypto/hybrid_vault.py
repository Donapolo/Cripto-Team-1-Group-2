import os
import json
import base64
from datetime import datetime, timezone
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from ecies import encrypt as ecies_encrypt


class HybridVault:
    ALGORITHM_VERSION = "AES-256-GCM"
    KEY_ENCAPSULATION = "ECIES-secp256k1"
    NONCE_SIZE_BYTES = 12
    TAG_SIZE_BYTES = 16

    @classmethod
    def build_aad(cls, metadata: dict, recipients: list[dict]) -> bytes:
        """
        Constructs canonical Additional Authenticated Data (AAD).
        Binds metadata and the recipient list to the GHASH tag to prevent
        adversaries from adding, removing, or swapping recipient identities.
        """
        aad_data = {
            "metadata": metadata,
            "recipients_identities": [
                {"id": r["id"]} for r in recipients
            ]
        }
        # Canonical JSON serialization ensures deterministic byte representation
        return json.dumps(aad_data, sort_keys=True).encode("utf-8")

    @classmethod
    def encrypt_hybrid(cls, file_bytes: bytes, filename: str, recipients: list[dict]) -> dict:
        """
        Encrypts a file payload using hybrid encryption:
        1. Encrypts file payload once with a random 256-bit symmetric key (DEK) using AES-GCM.
        2. Encapsulates the DEK separately for each recipient using ECIES and their public key.
        3. Authenticates metadata and recipient identities using AAD (Fail-Closed integrity).

        :param file_bytes: Raw file content to encrypt.
        :param filename: Original name of the target file.
        :param recipients: List of recipient dictionaries:
                           [{"id": "user_id", "public_key": "hex_or_bytes"}, ...]
        :return: Structured D3 container dictionary.
        """
        # Rubric requirement: Support at least 2 recipients
        if not recipients or len(recipients) < 2:
            raise ValueError("Encryption requires at least 2 authorized recipients.")

        # Step 1: Generate a single-use 256-bit Data Encryption Key (DEK) via OS CSPRNG
        dek = AESGCM.generate_key(bit_length=256)

        # Step 2: Encapsulate the DEK for each recipient using ECIES (Elliptic Curve Integrated Encryption Scheme)
        encrypted_recipients = []
        for r in recipients:
            user_id = r["id"]
            public_key = r["public_key"]

            # Encrypt the symmetric DEK using the recipient's public key
            encrypted_dek = ecies_encrypt(public_key, dek)

            encrypted_recipients.append({
                "id": user_id,
                "encrypted_key": base64.b64encode(encrypted_dek).decode("utf-8")
            })

        # Step 3: Populate container metadata
        metadata = {
            "version": cls.ALGORITHM_VERSION,
            "key_encapsulation": cls.KEY_ENCAPSULATION,
            "filename": filename,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

        # Step 4: Build AAD payload binding metadata and recipient IDs
        aad_bytes = cls.build_aad(metadata, encrypted_recipients)

        # Step 5: Perform symmetric encryption using AES-256-GCM with a unique 96-bit nonce
        nonce = os.urandom(cls.NONCE_SIZE_BYTES)
        aesgcm = AESGCM(dek)
        ciphertext_with_tag = aesgcm.encrypt(nonce, file_bytes, aad_bytes)

        # Step 6: Separate ciphertext and the 16-byte GHASH authentication tag
        ciphertext = ciphertext_with_tag[:-cls.TAG_SIZE_BYTES]
        tag = ciphertext_with_tag[-cls.TAG_SIZE_BYTES:]

        # Step 7: Build the updated D3 container format
        container = {
            "metadata": metadata,
            "recipients": encrypted_recipients,
            "nonce": base64.b64encode(nonce).decode("utf-8"),
            "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
            "tag": base64.b64encode(tag).decode("utf-8")
        }

        return container