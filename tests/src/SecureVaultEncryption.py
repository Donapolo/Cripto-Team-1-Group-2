import base64
import json
import os
from datetime import datetime, timezone

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class DecryptionError(Exception):
    """Falla de autenticacion o contenedor invalido. Mensaje generico a proposito."""


def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"), validate=True)


class SecureVaultEncryption:
    ALGORITHM = "AES-256-GCM"
    FORMAT_VERSION = 1
    KEY_SIZE = 32   
    NONCE_SIZE = 12 
    TAG_SIZE = 16   

    #AAD
    @staticmethod
    def _aad(header: dict) -> bytes:
        #Serializacion canonica
        return json.dumps(header, sort_keys=True, separators=(",", ":")).encode("utf-8")
#API en memoria
    def encrypt(self, plaintext: bytes, filename: str | None = None):
        """Devuelve (container, key), la llave es nueva en cada llamada."""
        key = AESGCM.generate_key(bit_length=256)
        nonce = os.urandom(self.NONCE_SIZE)
        header = {
            "filename": filename,
            "algorithm_version": f"{self.ALGORITHM}/v{self.FORMAT_VERSION}",
            "encryption_parameters": {
                "key_bits": 256,
                "nonce_bytes": self.NONCE_SIZE,
                "tag_bytes": self.TAG_SIZE,
            },
            "creation_timestamp": datetime.now(timezone.utc).isoformat(),
        }
        sealed = AESGCM(key).encrypt(nonce, plaintext, self._aad(header))
        container = {
            "header": header,
            "nonce": _b64e(nonce),
            "ciphertext": _b64e(sealed[: -self.TAG_SIZE]),
            "authentication_tag": _b64e(sealed[-self.TAG_SIZE:]),
        }
        return container, key

    def decrypt(self, container: dict, key: bytes) -> bytes:
        try:
            header = container["header"]
            nonce = _b64d(container["nonce"])
            sealed = _b64d(container["ciphertext"]) + _b64d(container["authentication_tag"])
            return AESGCM(key).decrypt(nonce, sealed, self._aad(header))
        except (InvalidTag, KeyError, ValueError, TypeError):
            # Fallo seguro: no revelamos cual parte fallo ni devolvemos datos parciales
            raise DecryptionError("Authentication failed") from None

    #API de archivos
    def encrypt_file(self, src_path: str, dst_path: str) -> bytes:
        with open(src_path, "rb") as f:
            data = f.read()
        container, key = self.encrypt(data, filename=os.path.basename(src_path))
        with open(dst_path, "w", encoding="utf-8") as f:
            json.dump(container, f, indent=2)
        return key

    def decrypt_file(self, container_path: str, key: bytes, out_path: str) -> None:
        with open(container_path, "r", encoding="utf-8") as f:
            container = json.load(f)
        data = self.decrypt(container, key)  # si falla, no se escribe nada
        with open(out_path, "wb") as f:
            f.write(data)