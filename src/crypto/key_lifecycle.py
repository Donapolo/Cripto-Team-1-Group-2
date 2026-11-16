"""D6 - Ciclo de vida de llaves: generar, rotar, expirar y revocar.

El registro es un JSON con datos PUBLICOS (llave publica, estado, fechas). Las llaves
privadas solo viven en keystores cifrados con contrasena (secure_keystore.py).

Estados: active, retired (rotada), revoked. "Expirada" se calcula con expires_at.
- active:  se puede todo.
- retired / expirada: NO cifra ni firma cosas nuevas, pero sigue descifrando/verificando lo viejo.
- revoked: nada, salvo descifrar con recovery=True (para recuperar documentos viejos).
secp256k1 -> encrypt_to, decrypt | Ed25519 -> sign, verify

Integridad: el archivo lleva un MAC (HMAC-SHA256) con una llave derivada de una contrasena
del registro (registry_password). Si alguien edita el JSON a mano (por ejemplo, volver a
poner una llave revocada como activa), la carga falla. Limite: un atacante con acceso al
archivo puede restaurar una copia ANTERIOR valida (rollback); eso requiere un ancla externa.

Limite: revocar es logico. Si alguien ya tiene la llave y una copia del contenedor,
puede descifrar offline; hay que recifrar los documentos.
"""

import hashlib
import hmac
import json
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

try:
    from src.crypto.secure_keystore import KeystoreError, create_keystore
except ModuleNotFoundError:
    from secure_keystore import KeystoreError, create_keystore

PROPOSITOS = {"secp256k1": {"encrypt_to", "decrypt"}, "Ed25519": {"sign", "verify"}}
USO = {"secp256k1": "decryption", "Ed25519": "signing"}
NUEVOS = {"encrypt_to", "sign"}  # propositos que crean material nuevo
CAMPOS = {"key_id", "user_id", "algorithm", "public_key", "status", "created_at",
          "expires_at", "changed_at", "reason", "keystore_file"}


class KeyLifecycleError(ValueError):
    pass


def _ahora(now):
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise KeyLifecycleError("'now' must be timezone-aware.")
    return now.astimezone(timezone.utc).replace(microsecond=0)


def generate_key_material(algorithm):
    """Par de llaves en hex: private_key, public_key y key_id (SHA-256 de la publica)."""
    if algorithm == "secp256k1":
        priv = ec.generate_private_key(ec.SECP256K1())
        priv_hex = priv.private_numbers().private_value.to_bytes(32, "big").hex()
        pub = priv.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)
    elif algorithm == "Ed25519":
        priv = ed25519.Ed25519PrivateKey.generate()
        priv_hex = priv.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                      serialization.NoEncryption()).hex()
        pub = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    else:
        raise KeyLifecycleError(f"Unsupported algorithm: {algorithm}")
    return {"private_key": priv_hex, "public_key": pub.hex(), "key_id": hashlib.sha256(pub).hexdigest()}


# ---- registro ----

def new_registry():
    return {"version": "1.0", "keys": {}}


def validate_registry(registry):
    """Valida todo el registro. Ante cualquier duda, falla."""
    if not isinstance(registry, dict) or set(registry) != {"version", "keys"} or registry["version"] != "1.0":
        raise KeyLifecycleError("Invalid registry structure or version.")
    if not isinstance(registry["keys"], dict):
        raise KeyLifecycleError("Registry 'keys' must be an object.")
    activas = set()
    for key_id, e in registry["keys"].items():
        if not isinstance(e, dict) or set(e) != CAMPOS or e["key_id"] != key_id:
            raise KeyLifecycleError("Registry entry has missing or unexpected fields.")
        if e["algorithm"] not in PROPOSITOS or e["status"] not in ("active", "retired", "revoked"):
            raise KeyLifecycleError("Invalid algorithm or status in registry entry.")
        try:
            pub = bytes.fromhex(e["public_key"])
            ok = hashlib.sha256(pub).hexdigest() == key_id and len(pub) == (33 if e["algorithm"] == "secp256k1" else 32)
            creada = datetime.fromisoformat(e["created_at"])
            expira = datetime.fromisoformat(e["expires_at"])
        except (ValueError, TypeError):
            raise KeyLifecycleError("Malformed registry entry.") from None
        if not ok or creada.tzinfo is None or expira.tzinfo is None or expira <= creada:
            raise KeyLifecycleError("key_id does not match the public key, or dates are invalid.")
        if not isinstance(e["keystore_file"], str) or Path(e["keystore_file"]).name != e["keystore_file"]:
            raise KeyLifecycleError("keystore_file must be a plain file name.")
        if e["status"] == "revoked" and not e["reason"]:
            raise KeyLifecycleError("Revoked key needs a reason.")
        if e["status"] == "active":
            par = (e["user_id"], e["algorithm"])
            if par in activas:
                raise KeyLifecycleError("More than one active key for the same user and algorithm.")
            activas.add(par)


def _mac(nucleo, password, salt_hex):
    if not isinstance(password, str) or not password.strip():
        raise KeyLifecycleError("registry_password must be a non-empty string.")
    llave = hashlib.scrypt(password.encode("utf-8"), salt=bytes.fromhex(salt_hex),
                           n=16384, r=8, p=1, dklen=32)
    canonico = json.dumps(nucleo, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hmac.new(llave, canonico, hashlib.sha256).hexdigest()


def load_registry(registry_path, registry_password):
    """Lee el registro, verifica su MAC y luego lo valida. Si algo falla, no se usa."""
    ruta = Path(registry_path)
    if not ruta.is_file():
        raise KeyLifecycleError(f"Registry file not found: {ruta}")
    try:
        datos = json.loads(ruta.read_text(encoding="utf-8"))
        salt, mac = datos.pop("mac_salt"), datos.pop("mac")
        esperado = _mac(datos, registry_password, salt)
    except KeyLifecycleError:
        raise
    except Exception:
        raise KeyLifecycleError("Failed to parse registry JSON file.") from None
    if not isinstance(mac, str) or not hmac.compare_digest(esperado, mac):
        raise KeyLifecycleError("Registry integrity check failed: wrong password or file modified.")
    validate_registry(datos)
    return datos


def save_registry(registry, registry_path, registry_password):
    validate_registry(registry)
    salt = os.urandom(16).hex()
    completo = dict(registry, mac_salt=salt, mac=_mac(registry, registry_password, salt))
    ruta = Path(registry_path)
    ruta.parent.mkdir(parents=True, exist_ok=True)
    temporal = ruta.with_name(ruta.name + ".tmp")
    temporal.write_text(json.dumps(completo, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporal, ruta)


def _cargar_o_nuevo(ruta, password):
    return load_registry(ruta, password) if Path(ruta).exists() else new_registry()


def _activa(registry, user_id, algorithm):
    for e in registry["keys"].values():
        if e["user_id"] == user_id and e["algorithm"] == algorithm and e["status"] == "active":
            return e
    return None


# ---- operaciones ----

def _crear(registry, user_id, algorithm, password, keystore_dir, dias, ahora, kdf):
    if not isinstance(user_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", user_id):
        raise KeyLifecycleError("Invalid user ID: use 1-64 letters, digits, '_' or '-'.")
    if not isinstance(dias, int) or not 1 <= dias <= 3650:
        raise KeyLifecycleError("validity_days must be an integer between 1 and 3650.")
    if set(kdf) - {"scrypt_n", "scrypt_r", "scrypt_p"}:
        raise KeyLifecycleError("Unsupported option(s) for the KDF.")
    mat = generate_key_material(algorithm)
    try:
        ks = create_keystore(mat["private_key"], password, key_id=mat["key_id"],
                             algorithm=algorithm, user_id=user_id, **kdf)
    except KeystoreError as e:
        raise KeyLifecycleError(f"Could not create keystore: {e}") from None
    nombre = f"{user_id}_{algorithm.lower()}_{mat['key_id'][:16]}.json"
    ruta = Path(keystore_dir) / nombre
    if ruta.exists():
        raise KeyLifecycleError(f"Refusing to overwrite existing file: {ruta}")
    ruta.parent.mkdir(parents=True, exist_ok=True)
    ruta.write_text(json.dumps(ks, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    try:
        os.chmod(ruta, 0o600)
    except OSError:
        pass
    entrada = {"key_id": mat["key_id"], "user_id": user_id, "algorithm": algorithm,
               "public_key": mat["public_key"], "status": "active",
               "created_at": ahora.isoformat(), "expires_at": (ahora + timedelta(days=dias)).isoformat(),
               "changed_at": None, "reason": None, "keystore_file": nombre}
    registry["keys"][mat["key_id"]] = entrada
    return entrada, ruta


def _guardar(registry, registry_path, registry_password, archivos_nuevos):
    # si falla guardar el registro, borra los keystores recien creados
    try:
        save_registry(registry, registry_path, registry_password)
    except Exception:
        for a in archivos_nuevos:
            a.unlink(missing_ok=True)
        raise


def generate_key(registry_path, user_id, algorithm, password, keystore_dir, *, registry_password,
                 validity_days=365, now=None, **kdf_options):
    """Crea la PRIMERA llave activa de (user_id, algorithm). Para cambiarla, usar rotate_key."""
    registry = _cargar_o_nuevo(registry_path, registry_password)
    if _activa(registry, user_id, algorithm):
        raise KeyLifecycleError("User already has an active key for this algorithm; use rotate_key.")
    entrada, ruta = _crear(registry, user_id, algorithm, password, keystore_dir,
                           validity_days, _ahora(now), kdf_options)
    _guardar(registry, registry_path, registry_password, [ruta])
    return dict(entrada)


def rotate_key(registry_path, user_id, algorithm, password, keystore_dir, *, registry_password,
               validity_days=365, now=None, **kdf_options):
    """Retira la llave activa y activa una nueva. La vieja sigue descifrando/verificando."""
    registry = _cargar_o_nuevo(registry_path, registry_password)
    vieja = _activa(registry, user_id, algorithm)
    if vieja is None:
        raise KeyLifecycleError("No active key to rotate; use generate_key.")
    ahora = _ahora(now)
    nueva, ruta = _crear(registry, user_id, algorithm, password, keystore_dir,
                         validity_days, ahora, kdf_options)
    vieja["status"], vieja["changed_at"] = "retired", ahora.isoformat()
    _guardar(registry, registry_path, registry_password, [ruta])
    return dict(nueva)


def _revocar(entrada, reason, ahora):
    if not isinstance(reason, str) or not reason.strip():
        raise KeyLifecycleError("A revocation reason is required.")
    if entrada["status"] == "revoked":
        raise KeyLifecycleError("Key is already revoked.")
    entrada["status"], entrada["changed_at"], entrada["reason"] = "revoked", ahora.isoformat(), reason.strip()


def revoke_key(registry_path, key_id, reason, *, registry_password, now=None):
    registry = load_registry(registry_path, registry_password)
    if key_id not in registry["keys"]:
        raise KeyLifecycleError("Unknown key_id.")
    entrada = registry["keys"][key_id]
    _revocar(entrada, reason, _ahora(now))
    _guardar(registry, registry_path, registry_password, [])
    return dict(entrada)


def handle_compromise(registry_path, key_id, reason, password, keystore_dir, *, registry_password,
                      validity_days=365, now=None, **kdf_options):
    """Revoca la llave y, si era la activa, crea su reemplazo (todo se guarda junto)."""
    registry = load_registry(registry_path, registry_password)
    if key_id not in registry["keys"]:
        raise KeyLifecycleError("Unknown key_id.")
    entrada = registry["keys"][key_id]
    ahora = _ahora(now)
    era_activa = entrada["status"] == "active"
    _revocar(entrada, reason, ahora)
    reemplazo, nuevos = None, []
    if era_activa:
        reemplazo, ruta = _crear(registry, entrada["user_id"], entrada["algorithm"], password,
                                 keystore_dir, validity_days, ahora, kdf_options)
        nuevos.append(ruta)
    _guardar(registry, registry_path, registry_password, nuevos)
    if entrada["algorithm"] == "secp256k1":
        pasos = ["Re-encrypt the affected documents to the replacement key (decrypt with recovery=True).",
                 "Tell senders to stop encrypting to the revoked key."]
    else:
        pasos = ["Remove the revoked signer from every trusted_signers registry.",
                 "Re-sign important documents and tell recipients to trust the replacement key."]
    pasos.append("Delete or secure old keystore files and backups of the revoked key.")
    return {"revoked": dict(entrada), "replacement": dict(reemplazo) if reemplazo else None,
            "actions_required": pasos}


def check_key_usable(registry, key_id, purpose, *, now=None, recovery=False):
    """Devuelve la entrada si la llave puede usarse para ese proposito; si no, lanza error."""
    validate_registry(registry)
    e = registry["keys"].get(key_id)
    if e is None:
        raise KeyLifecycleError("Unknown key_id.")
    if purpose not in PROPOSITOS[e["algorithm"]]:
        raise KeyLifecycleError(f"Purpose '{purpose}' is not valid for {e['algorithm']} keys.")
    if e["status"] == "revoked":
        if purpose == "decrypt" and recovery:
            return dict(e)
        raise KeyLifecycleError("Key is revoked.")
    if purpose in NUEVOS:
        if e["status"] == "retired":
            raise KeyLifecycleError("Key is retired: it can no longer be used for new material.")
        if datetime.fromisoformat(e["expires_at"]) <= _ahora(now):
            raise KeyLifecycleError("Key has expired: it can no longer be used for new material.")
    return dict(e)


def get_active_key(registry, user_id, algorithm, *, now=None):
    validate_registry(registry)
    e = _activa(registry, user_id, algorithm)
    if e is None:
        raise KeyLifecycleError("No active key for this user and algorithm.")
    if datetime.fromisoformat(e["expires_at"]) <= _ahora(now):
        raise KeyLifecycleError("The active key has expired: rotate it.")
    return dict(e)


def build_trusted_signers(registry, *, now=None):
    """{signer_id: public_key} para decrypt_hybrid(trusted_signers=...). Sin llaves revocadas."""
    validate_registry(registry)
    confiables = {}
    for key_id, e in registry["keys"].items():
        if e["algorithm"] == "Ed25519" and e["status"] != "revoked":
            confiables[key_id] = e["public_key"]
    return confiables


# ---- integracion: las reglas se aplican en las operaciones reales de cifrado/descifrado ----

def _id_de_publica(public_key_hex):
    try:
        return hashlib.sha256(bytes.fromhex(public_key_hex.removeprefix("0x"))).hexdigest()
    except (ValueError, AttributeError):
        raise KeyLifecycleError("Malformed public key hex.") from None


def encrypt_with_registry(registry, file_bytes, filename, recipients, signing_private_key, *, now=None):
    """Cifra con hybrid_vault, pero SOLO si el registro permite cada llave involucrada.

    Rechaza destinatarios desconocidos, retirados, expirados o revocados (encrypt_to) y un
    firmante que no pueda firmar (sign). Ademas, cada llave debe pertenecer a su usuario.
    """
    try:
        from src.crypto.hybrid_vault import encrypt_hybrid
    except ModuleNotFoundError:
        from hybrid_vault import encrypt_hybrid
    for usuario, publica in recipients.items():
        entrada = check_key_usable(registry, _id_de_publica(publica), "encrypt_to", now=now)
        if entrada["user_id"] != usuario:
            raise KeyLifecycleError("Recipient key does not belong to that user.")
    try:
        firmante = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(signing_private_key))
    except (ValueError, TypeError):
        raise KeyLifecycleError("Invalid signing private key.") from None
    pub = firmante.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    check_key_usable(registry, hashlib.sha256(pub).hexdigest(), "sign", now=now)
    return encrypt_hybrid(file_bytes=file_bytes, filename=filename, recipients=recipients,
                          signing_private_key=signing_private_key)


def decrypt_with_registry(registry, container, user_id, keystore_path, *, now=None, recovery=False):
    """Descifra con el keystore, pero solo si la llave esta permitida en el registro.

    Revisa estado/expiracion ANTES de pedir la contrasena y usa como trusted_signers solo los
    firmantes que el registro todavia acepta (los revocados quedan fuera).
    """
    try:
        from src.crypto.hybrid_vault import decrypt_hybrid_with_keystore
        from src.crypto.secure_keystore import load_keystore
    except ModuleNotFoundError:
        from hybrid_vault import decrypt_hybrid_with_keystore
        from secure_keystore import load_keystore
    try:
        key_id = load_keystore(keystore_path)["metadata"]["key_id"]
    except KeystoreError as e:
        raise KeyLifecycleError(f"Cannot read keystore: {e}") from None
    entrada = check_key_usable(registry, key_id, "decrypt", now=now, recovery=recovery)
    if entrada["user_id"] != user_id:
        raise KeyLifecycleError("Keystore does not belong to that user.")
    return decrypt_hybrid_with_keystore(
        container, user_id, keystore_path,
        trusted_signers=build_trusted_signers(registry, now=now), expected_key_id=key_id)
