import copy
import json
import re
from datetime import datetime, timezone


CONTAINER_VERSION=1
AEAD_ALGORITHMS=("AES-256-GCM",)
KEY_WRAP_ALGORITHMS=("ECIES-secp256k1",)  # cambiar si el equipo usa otro nombre
NONCE_SIZE=12
TAG_SIZE=16
MAX_RECIPIENTS=256
MAX_FILENAME_LEN=255
MAX_ENCRYPTED_KEY_LEN=4096

# Prefijo para que estos bytes solo sirvan como AAD de este formato
AAD_DOMINIO=b"vault-d3-aad/v1\x00"

# Ids de usuario: letras, numeros y . _ @ - (maximo 64)
ID_REGEX=re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@-]{0,63}$")

# Campos permitidos en cada parte del contenedor (todo lo demas se rechaza)
CAMPOS_METADATA={
    "version", "filename", "aead_algorithm", "key_wrap_algorithm", "creation_timestamp",
}
CAMPOS_DESTINATARIO_OBLIGATORIOS={"id", "encrypted_key"}
CAMPOS_DESTINATARIO_OPCIONALES={"key_id"}
CAMPOS_CONTENEDOR={"metadata", "recipients", "nonce", "ciphertext", "tag"}


class ContainerFormatError(ValueError):
    """El contenedor, la metadata o los destinatarios no cumplen el esquema."""


# Funciones auxiliares

def revisar_campos(objeto, obligatorios, opcionales, donde):
    """Revisa que sea un dict con los campos justos, sin faltantes ni extras."""
    if not isinstance(objeto, dict):
        raise ContainerFormatError(f"{donde}: debe ser un objeto")
    claves=set(objeto)
    faltantes=obligatorios-claves
    extras=claves-obligatorios-opcionales
    if faltantes:
        raise ContainerFormatError(f"{donde}: faltan campos {sorted(map(str, faltantes))}")
    if extras:
        raise ContainerFormatError(f"{donde}: campos no permitidos {sorted(map(str, extras))}")


def a_hex(datos):
    """bytes -> texto hexadecimal (minusculas)"""
    return datos.hex()


def leer_hex(valor, donde, tamano=None):
    """Decodifica hex estricto y canonico (solo minusculas, sin espacios)."""
    if not isinstance(valor, str):
        raise ContainerFormatError(f"{donde}: debe ser texto hexadecimal")
    try:
        crudo = bytes.fromhex(valor)
    except ValueError:
        raise ContainerFormatError(f"{donde}: hexadecimal invalido") from None
    # fromhex acepta mayusculas y espacios; si al volver a codificar no sale igual, no es canonico
    if crudo.hex() != valor:
        raise ContainerFormatError(f"{donde}: hexadecimal no canonico")
    if tamano is not None and len(crudo) != tamano:
        raise ContainerFormatError(f"{donde}: debe medir {tamano} bytes")
    return crudo


# Validacion

def validate_metadata(metadata):
    """Valida la metadata: campos exactos, version, algoritmos y timestamp."""
    revisar_campos(metadata, CAMPOS_METADATA, set(), "metadata")

    # type(...) is int porque True tambien cuenta como int
    if type(metadata["version"]) is not int or metadata["version"] != CONTAINER_VERSION:
        raise ContainerFormatError("metadata.version no soportada")

    # El filename es solo informativo (nunca se usa como ruta)
    filename=metadata["filename"]
    if filename is not None and (not isinstance(filename, str) or len(filename) > MAX_FILENAME_LEN):
        raise ContainerFormatError("metadata.filename invalido")

    # Solo algoritmos de la lista permitida
    if metadata["aead_algorithm"] not in AEAD_ALGORITHMS:
        raise ContainerFormatError("metadata.aead_algorithm no permitido")
    if metadata["key_wrap_algorithm"] not in KEY_WRAP_ALGORITHMS:
        raise ContainerFormatError("metadata.key_wrap_algorithm no permitido")

    # Fecha ISO con zona horaria
    try:
        fecha=datetime.fromisoformat(metadata["creation_timestamp"])
    except (TypeError, ValueError):
        raise ContainerFormatError("metadata.creation_timestamp invalido") from None
    if fecha.tzinfo is None:
        raise ContainerFormatError("metadata.creation_timestamp debe incluir zona horaria")


def validate_recipients(recipients):
    """Valida la lista de destinatarios: ids validos y sin repetir."""
    if not isinstance(recipients, list) or not 1 <= len(recipients) <= MAX_RECIPIENTS:
        raise ContainerFormatError(f"recipients: debe ser una lista de 1 a {MAX_RECIPIENTS} entradas")

    vistos = set()
    for i, entrada in enumerate(recipients):
        donde = f"recipients[{i}]"
        revisar_campos(entrada, CAMPOS_DESTINATARIO_OBLIGATORIOS, CAMPOS_DESTINATARIO_OPCIONALES, donde)

        # id: formato permitido y unico
        rid = entrada["id"]
        if not isinstance(rid, str) or not ID_REGEX.fullmatch(rid):
            raise ContainerFormatError(f"{donde}.id invalido")
        if rid in vistos:
            raise ContainerFormatError(f"{donde}.id duplicado")
        vistos.add(rid)

        # llave envuelta: hexadecimal canonico, no vacio
        llave = entrada["encrypted_key"]
        if not isinstance(llave, str) or not 0 < len(llave) <= MAX_ENCRYPTED_KEY_LEN:
            raise ContainerFormatError(f"{donde}.encrypted_key invalido")
        leer_hex(llave, f"{donde}.encrypted_key")

        # key_id es opcional
        if "key_id" in entrada:
            kid = entrada["key_id"]
            if not isinstance(kid, str) or not 0 < len(kid) <= 128:
                raise ContainerFormatError(f"{donde}.key_id invalido")


def validate_container(container):
    """Validacion estructural completa. Se llama ANTES de descifrar."""
    revisar_campos(container, CAMPOS_CONTENEDOR, set(), "container")
    validate_metadata(container["metadata"])
    validate_recipients(container["recipients"])
    leer_hex(container["nonce"], "nonce", NONCE_SIZE)
    leer_hex(container["ciphertext"], "ciphertext")
    leer_hex(container["tag"], "tag", TAG_SIZE)


# Construccion

def build_metadata(filename, aead_algorithm="AES-256-GCM",
                   key_wrap_algorithm="ECIES-secp256k1", creation_timestamp=None):
    """Arma la metadata del contenedor (con fecha actual si no se da una)."""
    metadata={
        "version": CONTAINER_VERSION,
        "filename": filename,
        "aead_algorithm": aead_algorithm,
        "key_wrap_algorithm": key_wrap_algorithm,
        "creation_timestamp": creation_timestamp or datetime.now(timezone.utc).isoformat(),
    }
    validate_metadata(metadata)
    return metadata


def build_recipient_entry(user_id, encrypted_key, key_id=None):
    """Arma la entrada de un destinatario (key_id solo si se manda)."""
    entrada = {"id": user_id, "encrypted_key": encrypted_key}
    if key_id is not None:
        entrada["key_id"] = key_id
    return entrada


def build_aad(metadata, recipients):
    """Bytes canonicos que se pasan como AAD a AES-GCM (en cifrar y en descifrar)."""
    validate_metadata(metadata)
    validate_recipients(recipients)

    # La lista de destinatarios va en el AAD: si la tocan, el tag ya no valida
    documento = {"metadata": metadata, "recipients": recipients}
    # Serializacion canonica: llaves ordenadas y sin espacios
    cuerpo = json.dumps(documento, sort_keys=True, separators=(",", ":"),
                        ensure_ascii=True, allow_nan=False)
    return AAD_DOMINIO + cuerpo.encode("ascii")


def aad_from_container(container):
    """Valida el contenedor y reconstruye su AAD (lado descifrado)."""
    validate_container(container)
    return build_aad(container["metadata"], container["recipients"])


def build_container(metadata, recipients, nonce, ciphertext, tag):
    """Arma el contenedor final (nonce, ciphertext y tag entran como bytes)."""
    for nombre, valor in (("nonce", nonce), ("ciphertext", ciphertext), ("tag", tag)):
        if not isinstance(valor, (bytes, bytearray)):
            raise ContainerFormatError(f"{nombre}: debe ser bytes")

    # deepcopy para no compartir objetos con quien lo llamo
    container = {
        "metadata": copy.deepcopy(metadata),
        "recipients": copy.deepcopy(recipients),
        "nonce": a_hex(bytes(nonce)),
        "ciphertext": a_hex(bytes(ciphertext)),
        "tag": a_hex(bytes(tag)),
    }
    validate_container(container)
    return container


def load_container(text):
    """Lee un contenedor desde texto JSON y lo valida."""
    try:
        container = json.loads(text)
    except (TypeError, ValueError):
        raise ContainerFormatError("container: JSON invalido") from None
    validate_container(container)
    return container