"""D6 - Respaldo y recuperacion de llaves.

El respaldo es una copia del keystore (que ya viene cifrado con Scrypt + AES-GCM)
dentro de un sobre con checksum. Nunca se pide la contrasena ni se descifra nada.
El checksum solo detecta archivos danados; la proteccion real contra manipulacion
es el tag AES-GCM del keystore, que se revisa al descifrar la llave.
"""

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path

try:
    from src.crypto.secure_keystore import KeystoreError, load_keystore, validate_keystore_schema
except ModuleNotFoundError:
    from secure_keystore import KeystoreError, load_keystore, validate_keystore_schema

CAMPOS = {"backup_version", "created_at", "key_id", "algorithm", "checksum_sha256", "keystore"}


class KeyBackupError(ValueError):
    pass


def keystore_checksum(keystore):
    canonico = json.dumps(keystore, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonico.encode("utf-8")).hexdigest()


def _escribir(ruta, datos, overwrite):
    ruta = Path(ruta)
    if ruta.exists() and not overwrite:
        raise KeyBackupError(f"Refusing to overwrite existing file: {ruta}")
    ruta.parent.mkdir(parents=True, exist_ok=True)
    temporal = ruta.with_name(ruta.name + ".tmp")  # primero temporal, luego renombrar
    temporal.write_text(json.dumps(datos, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    try:
        os.chmod(temporal, 0o600)  # en Windows puede no aplicar
    except OSError:
        pass
    os.replace(temporal, ruta)


def load_backup(backup_path):
    """Lee el respaldo y lo valida completo. Si algo no cuadra, falla."""
    ruta = Path(backup_path)
    if not ruta.is_file():
        raise KeyBackupError(f"Backup file not found: {ruta}")
    try:
        backup = json.loads(ruta.read_text(encoding="utf-8"))
    except ValueError:
        raise KeyBackupError("Failed to parse backup JSON file.") from None
    if not isinstance(backup, dict) or set(backup) != CAMPOS:
        raise KeyBackupError("Backup has missing or unexpected fields.")
    if backup["backup_version"] != "1.0":
        raise KeyBackupError("Unsupported backup version.")
    try:
        validate_keystore_schema(backup["keystore"])
    except KeystoreError as e:
        raise KeyBackupError(f"Backup contains an invalid keystore: {e}") from None
    meta = backup["keystore"]["metadata"]
    if backup["key_id"] != meta["key_id"] or backup["algorithm"] != meta["algorithm"]:
        raise KeyBackupError("Backup identity does not match the keystore metadata.")
    if backup["checksum_sha256"] != keystore_checksum(backup["keystore"]):
        raise KeyBackupError("Backup checksum mismatch: the file is damaged or was modified.")
    return backup


def _resumen(backup):
    meta = backup["keystore"]["metadata"]
    return {
        "key_id": backup["key_id"],
        "algorithm": backup["algorithm"],
        "user_id": meta.get("user_id"),
        "backup_created_at": backup["created_at"],
        "checksum_sha256": backup["checksum_sha256"],
    }


def create_backup(keystore_path, backup_path, *, overwrite=False):
    if Path(keystore_path).resolve() == Path(backup_path).resolve():
        raise KeyBackupError("Backup path must be different from the keystore path.")
    try:
        keystore = load_keystore(keystore_path)
    except KeystoreError as e:
        raise KeyBackupError(f"Cannot back up: {e}") from None
    backup = {
        "backup_version": "1.0",
        "created_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "key_id": keystore["metadata"]["key_id"],
        "algorithm": keystore["metadata"]["algorithm"],
        "checksum_sha256": keystore_checksum(keystore),
        "keystore": keystore,
    }
    _escribir(backup_path, backup, overwrite)
    return _resumen(backup)


def verify_backup(backup_path, *, expected_key_id=None):
    backup = load_backup(backup_path)
    if expected_key_id is not None and backup["key_id"] != expected_key_id:
        raise KeyBackupError("Backup key_id does not match the expected key_id.")
    return _resumen(backup)


def restore_backup(backup_path, target_path, *, overwrite=False, expected_key_id=None):
    if Path(backup_path).resolve() == Path(target_path).resolve():
        raise KeyBackupError("Restore target must be different from the backup file.")
    backup = load_backup(backup_path)
    if expected_key_id is not None and backup["key_id"] != expected_key_id:
        raise KeyBackupError("Backup key_id does not match the expected key_id.")
    _escribir(target_path, backup["keystore"], overwrite)
    return Path(target_path)
