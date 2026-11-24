"""D6 - Respaldo y recuperacion de llaves.

El respaldo es una copia del keystore (que ya viene cifrado con Scrypt + AES-GCM)
dentro de un sobre con checksum. Nunca se pide la contrasena ni se descifra nada.
El checksum solo detecta archivos danados; la proteccion real contra manipulacion
es el tag AES-GCM del keystore, que se revisa al descifrar la llave.

Respaldo completo (create_vault_backup / restore_vault_backup): guarda el registro del
ciclo de vida junto con los keystores. Asi, al restaurar, no se pierde que llaves estaban
activas, retiradas o revocadas. El registro se copia tal cual, con su MAC.
Ambas operaciones son todo o nada, y una restauracion nunca deshace rotaciones ni
revocaciones que el registro actual ya tiene.
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

try:
    from src.crypto.key_lifecycle import KeyLifecycleError, load_registry
except ModuleNotFoundError:
    from key_lifecycle import KeyLifecycleError, load_registry

CAMPOS = {"backup_version", "created_at", "key_id", "algorithm", "checksum_sha256", "keystore"}


class KeyBackupError(ValueError):
    pass


def keystore_checksum(keystore):
    canonico = json.dumps(keystore, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonico.encode("utf-8")).hexdigest()


def _texto(datos):
    return json.dumps(datos, indent=2, sort_keys=True) + "\n"


def _escribir(ruta, datos, overwrite):
    ruta = Path(ruta)
    if ruta.exists() and not overwrite:
        raise KeyBackupError(f"Refusing to overwrite existing file: {ruta}")
    ruta.parent.mkdir(parents=True, exist_ok=True)
    temporal = ruta.with_name(ruta.name + ".tmp")  # primero temporal, luego renombrar
    temporal.write_text(_texto(datos), encoding="utf-8")
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


def _armar_backup(keystore_path):
    """Lee y valida el keystore y arma el sobre del respaldo, sin escribir nada."""
    try:
        keystore = load_keystore(keystore_path)
    except KeystoreError as e:
        raise KeyBackupError(f"Cannot back up: {e}") from None
    return {
        "backup_version": "1.0",
        "created_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "key_id": keystore["metadata"]["key_id"],
        "algorithm": keystore["metadata"]["algorithm"],
        "checksum_sha256": keystore_checksum(keystore),
        "keystore": keystore,
    }


def create_backup(keystore_path, backup_path, *, overwrite=False):
    if Path(keystore_path).resolve() == Path(backup_path).resolve():
        raise KeyBackupError("Backup path must be different from the keystore path.")
    backup = _armar_backup(keystore_path)
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


# ---- respaldo completo: registro + keystores ----

# Orden de los estados: una restauracion nunca puede mover una llave hacia atras.
_ORDEN_ESTADO = {"active": 0, "retired": 1, "revoked": 2}


def _leer_registro(ruta, registry_password):
    """Verifica el MAC del registro y regresa (registro, archivo crudo con MAC)."""
    try:
        registry = load_registry(ruta, registry_password)
    except KeyLifecycleError as e:
        raise KeyBackupError(f"Invalid registry: {e}") from None
    crudo = json.loads(Path(ruta).read_text(encoding="utf-8"))
    return registry, crudo


def _aplicar(cambios):
    """Escribe varios archivos como un solo paso: todo o nada.

    cambios: lista de (ruta, texto). 1) escribe cada texto en un temporal; 2) guarda
    el contenido viejo de lo que se va a reemplazar; 3) renombra los temporales.
    Si algo falla, borra los temporales y regresa lo ya reemplazado a como estaba.
    Si regresarlo tambien falla, lo dice: no afirma que nada cambio.
    """
    temporales, viejos, hechos = [], {}, []
    try:
        for ruta, texto in cambios:
            ruta = Path(ruta)
            ruta.parent.mkdir(parents=True, exist_ok=True)
            tmp = ruta.with_name(ruta.name + ".tmp")
            temporales.append((tmp, ruta))  # se anota ANTES de escribir, para limpiarlo si falla
            viejos[ruta] = ruta.read_bytes() if ruta.exists() else None
            tmp.write_text(texto, encoding="utf-8")
            try:
                os.chmod(tmp, 0o600)  # en Windows puede no aplicar
            except OSError:
                pass
        for tmp, ruta in temporales:
            os.replace(tmp, ruta)
            hechos.append(ruta)
    except OSError as e:
        sin_recuperar = []
        for ruta in reversed(hechos):  # deshacer lo ya reemplazado
            try:
                if viejos[ruta] is None:
                    ruta.unlink(missing_ok=True)
                else:
                    ruta.write_bytes(viejos[ruta])
            except OSError:
                sin_recuperar.append(str(ruta))
        for tmp, _ in temporales:
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass
        if sin_recuperar:
            raise KeyBackupError(
                f"Write failed ({e}) and these files could not be restored: "
                f"{', '.join(sin_recuperar)}. Restore them manually from the backup.") from None
        raise KeyBackupError(f"Write failed, nothing was changed: {e}") from None


def _sin_retroceso(actual, respaldo):
    """Un respaldo viejo no puede deshacer rotaciones ni revocaciones posteriores.

    Cada llave del registro actual debe estar en el respaldo con el mismo estado o uno
    posterior (active -> retired -> revoked). Si no, el respaldo es mas viejo que el
    registro actual y restaurarlo devolveria llaves retiradas o revocadas a uso.
    """
    for key_id, e in actual["keys"].items():
        r = respaldo["keys"].get(key_id)
        if r is None:
            raise KeyBackupError(
                f"Backup is older than the current registry: it does not contain key {key_id[:16]}...")
        if _ORDEN_ESTADO[r["status"]] < _ORDEN_ESTADO[e["status"]]:
            raise KeyBackupError(
                f"Restore would undo a later {e['status']} state for key {key_id[:16]}...")


def create_vault_backup(registry_path, keystore_dir, backup_dir, *, registry_password, overwrite=False):
    """Respalda el registro (con su historial de estados) y el keystore de cada llave.

    Primero revisa y arma TODO en memoria; si algo falla, no escribe nada.
    Si falta el keystore de una llave revocada se omite (es normal borrarlo tras un
    compromiso). Si falta el de una llave activa o retirada, falla.
    """
    registry, crudo = _leer_registro(registry_path, registry_password)
    destino = Path(backup_dir)

    # 1) revisar y armar todo
    cambios, respaldos, omitidas = [], [], []
    for key_id, e in sorted(registry["keys"].items()):
        ks = Path(keystore_dir) / e["keystore_file"]
        if not ks.is_file():
            if e["status"] == "revoked":
                omitidas.append(key_id)
                continue
            raise KeyBackupError(f"Missing keystore for a non-revoked key: {e['keystore_file']}")
        backup = _armar_backup(ks)
        if backup["key_id"] != key_id:
            raise KeyBackupError(f"Keystore {e['keystore_file']} does not match its registry entry.")
        ruta = destino / "keystores" / e["keystore_file"]
        if ruta.exists() and not overwrite:
            raise KeyBackupError(f"Refusing to overwrite existing file: {ruta}")
        cambios.append((ruta, _texto(backup)))
        respaldos.append(key_id)
    ruta_registro = destino / "registry.json"
    if ruta_registro.exists() and not overwrite:
        raise KeyBackupError(f"Refusing to overwrite existing file: {ruta_registro}")
    cambios.append((ruta_registro, _texto(crudo)))  # copia exacta, conserva el MAC; va al final

    # 2) escribir todo junto
    _aplicar(cambios)
    return {"keys_in_registry": len(registry["keys"]), "keystores_backed_up": respaldos,
            "skipped_revoked": omitidas}


def restore_vault_backup(backup_dir, registry_path, keystore_dir, *, registry_password, overwrite=False):
    """Restaura registro y keystores. Primero revisa TODO; si algo falla, no escribe nada.

    Si ya existe un registro, debe abrirse con la misma registry_password y el respaldo no
    puede deshacer rotaciones ni revocaciones que ese registro ya tiene (_sin_retroceso).
    """
    origen = Path(backup_dir)
    registry, crudo = _leer_registro(origen / "registry.json", registry_password)

    # 1) revisar todo antes de escribir
    if Path(registry_path).exists():
        if not overwrite:
            raise KeyBackupError(f"Refusing to overwrite existing file: {registry_path}")
        actual, _ = _leer_registro(registry_path, registry_password)
        _sin_retroceso(actual, registry)

    cambios, restauradas = [], []
    for key_id, e in sorted(registry["keys"].items()):
        respaldo = origen / "keystores" / e["keystore_file"]
        if not respaldo.is_file():
            if e["status"] == "revoked":
                continue
            raise KeyBackupError(f"Backup is missing the keystore of a non-revoked key: {e['keystore_file']}")
        backup = load_backup(respaldo)  # valida sobre, keystore y checksum
        if backup["key_id"] != key_id:  # el keystore debe ser el de esa llave
            raise KeyBackupError("Backup key_id does not match the expected key_id.")
        destino = Path(keystore_dir) / e["keystore_file"]
        if destino.exists() and not overwrite:
            raise KeyBackupError(f"Refusing to overwrite existing file: {destino}")
        cambios.append((destino, _texto(backup["keystore"])))
        restauradas.append(key_id)
    cambios.append((Path(registry_path), _texto(crudo)))  # el registro va al final

    # 2) escribir todo junto
    _aplicar(cambios)
    return {"keys_in_registry": len(registry["keys"]), "keystores_restored": restauradas}
