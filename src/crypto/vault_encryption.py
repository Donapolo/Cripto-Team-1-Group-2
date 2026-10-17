import os
import json
import base64
from datetime import datetime, timezone
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # pyright: ignore[reportMissingImports]
from cryptography.exceptions import InvalidTag  # pyright: ignore[reportMissingImports]

class SecureVaultEncryption:
    ALGORITHM_VERSION = "AES-256-GCM"
    NONCE_SIZE_BYTES = 12  # 96 bits recomendado para AES-GCM

    @staticmethod
    def generate_key() -> bytes:
        """Genera una clave simétrica fresca de 256 bits usando el CSPRNG del SO."""
        return AESGCM.generate_key(bit_length=256)

    @classmethod
    def encrypt_file(cls, file_bytes: bytes, filename: str, key: bytes) -> dict:
        """
        Cifra el contenido del archivo usando AES-256-GCM y vincula los metadatos como AAD.
        """
        aesgcm = AESGCM(key)
        nonce = os.urandom(cls.NONCE_SIZE_BYTES)
        
        # Definir metadatos requeridos por la rúbrica
        metadata = {
            "version": cls.ALGORITHM_VERSION,
            "filename": filename,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "params": {"key_size_bits": 256, "tag_size_bits": 128}
        }
        
        # Serializar metadatos a bytes ordenados para usarlos como AAD
        aad_bytes = json.dumps(metadata, sort_keys=True).encode('utf-8')
        
        # Cifrar payload integrando el AAD (genera ciphertext + tag automáticamente)
        ciphertext_with_tag = aesgcm.encrypt(nonce, file_bytes, aad_bytes)
        
        # Construir el contenedor del vault (codificando binarios en Base64 para transporte seguro)
        container = {
            "header": metadata,
            "nonce": base64.b64encode(nonce).decode('utf-8'),
            "payload": base64.b64encode(ciphertext_with_tag).decode('utf-8')
        }
        return container

    @classmethod
    def decrypt_file(cls, container: dict, key: bytes) -> bytes:
        """
        Descifra el contenedor validando estrictamente el tag AEAD y los metadatos (AAD).
        Implementa una política fail-closed ante cualquier alteración.
        """
        aesgcm = AESGCM(key)
        
        try:
            metadata = container["header"]
            nonce = base64.b64decode(container["nonce"])
            ciphertext_with_tag = base64.b64decode(container["payload"])
            
            # Reconstruir el AAD idéntico al de la fase de cifrado
            aad_bytes = json.dumps(metadata, sort_keys=True).encode('utf-8')
            
            # Intentar descifrar y autenticar
            plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, aad_bytes)
            return plaintext
            
        except (KeyError, ValueError, TypeError) as e:
            raise ValueError("Container structure is malformed or corrupted.") from e
        except InvalidTag as e:
            raise RuntimeError("CRITICAL: Integrity check failed. Ciphertext or metadata was tampered with.") from e