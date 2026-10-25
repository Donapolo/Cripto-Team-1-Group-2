import os
import json
import base64
from datetime import datetime, timezone
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

class SecureVaultEncryption:
    ALGORITHM_VERSION = "AES-256-GCM"
    NONCE_SIZE_BYTES = 12

    @staticmethod
    def generate_key() -> bytes:
        """Generate a fresh 256-bit symmetric key using the OS CSPRNG."""
        return AESGCM.generate_key(bit_length=256)

    @classmethod
    def encrypt_file(cls, file_bytes: bytes, filename: str, key: bytes) -> dict:
        """Encrypt payload using AES-256-GCM and bind metadata as AAD."""
        aesgcm = AESGCM(key)
        nonce = os.urandom(cls.NONCE_SIZE_BYTES)
        
        metadata = {
            "version": cls.ALGORITHM_VERSION,
            "filename": filename,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "params": {"key_size_bits": 256, "tag_size_bits": 128}
        }
        
        # Serialize metadata to bytes for AAD integrity binding
        aad_bytes = json.dumps(metadata, sort_keys=True).encode('utf-8')
        
        # Encrypt payload incorporating AAD (generates ciphertext + tag)
        ciphertext_with_tag = aesgcm.encrypt(nonce, file_bytes, aad_bytes)
        
        container = {
            "header": metadata,
            "nonce": base64.b64encode(nonce).decode('utf-8'),
            "payload": base64.b64encode(ciphertext_with_tag).decode('utf-8')
        }
        return container

    @classmethod
    def decrypt_file(cls, container: dict, key: bytes) -> bytes:
        """Decrypt container validating AEAD tag and AAD metadata (Fail-Closed)."""
        aesgcm = AESGCM(key)
        
        try:
            metadata = container["header"]
            nonce = base64.b64decode(container["nonce"])
            ciphertext_with_tag = base64.b64decode(container["payload"])
            
            aad_bytes = json.dumps(metadata, sort_keys=True).encode('utf-8')
            
            # Decrypt and authenticate
            plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, aad_bytes)
            return plaintext
            
        except (KeyError, ValueError, TypeError) as e:
            raise ValueError("Container structure is malformed or corrupted.") from e
        except InvalidTag as e:
            raise RuntimeError("CRITICAL: Integrity check failed. Ciphertext or metadata was tampered with.") from e