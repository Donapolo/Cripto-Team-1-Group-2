import copy
import hashlib
import json
import re
from datetime import datetime, timezone


CONTAINER_VERSION = 1
AEAD_ALGORITHMS = ("AES-256-GCM",)
KEY_WRAP_ALGORITHMS = ("ECIES-secp256k1",)  # Change if the team uses another name
NONCE_SIZE = 12
TAG_SIZE = 16
SIGNATURE_SIZE = 64  # Ed25519 signature size
MAX_RECIPIENTS = 256
MAX_FILENAME_LEN = 255
MAX_ENCRYPTED_KEY_LEN = 4096

# Domain prefix so these bytes only work as AAD for this format
AAD_DOMINIO = b"vault-d3-aad/v1\x00"

# Exclusive domain prefix for the D5 signature
SIGNATURE_DOMINIO = b"vault-d5-signature/v1\x00"

# User IDs: letters, numbers, and . _ @ - (max 64)
ID_REGEX = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@-]{0,63}$")

# signer_id: SHA-256 fingerprint of the Ed25519 public key (64 hex characters)
SIGNER_ID_REGEX = re.compile(r"^[0-9a-f]{64}$")

# Allowed fields in each part of the container (everything else is rejected)
CAMPOS_METADATA = {
    "version", "filename", "aead_algorithm", "key_wrap_algorithm", "creation_timestamp",
}
CAMPOS_DESTINATARIO_OBLIGATORIOS = {"id", "encrypted_key"}
CAMPOS_DESTINATARIO_OPCIONALES = {"key_id"}

# D5: The container now requires signature and signer_id
CAMPOS_CONTENEDOR = {
    "metadata", "recipients", "nonce", "ciphertext", "tag", 
    "signature", "signer_id"
}


class ContainerFormatError(ValueError):
    """The container, metadata, or recipients do not meet the schema."""


# Helper functions

def revisar_campos(objeto, obligatorios, opcionales, donde):
    """Checks that it is a dict with exactly the required fields, no missing or extras."""
    if not isinstance(objeto, dict):
        raise ContainerFormatError(f"{donde}: must be an object")
    claves = set(objeto)
    faltantes = obligatorios - claves
    extras = claves - obligatorios - opcionales
    if faltantes:
        raise ContainerFormatError(f"{donde}: missing fields {sorted(map(str, faltantes))}")
    if extras:
        raise ContainerFormatError(f"{donde}: fields not allowed {sorted(map(str, extras))}")


def a_hex(datos):
    """bytes -> hexadecimal text (lowercase)"""
    return datos.hex()


def leer_hex(valor, donde, tamano=None):
    """Strict and canonical hex decoding (lowercase only, no spaces)."""
    if not isinstance(valor, str):
        raise ContainerFormatError(f"{donde}: must be hexadecimal text")
    try:
        crudo = bytes.fromhex(valor)
    except ValueError:
        raise ContainerFormatError(f"{donde}: invalid hexadecimal") from None
    # fromhex accepts uppercase and spaces; if encoding again doesn't match, it's not canonical
    if crudo.hex() != valor:
        raise ContainerFormatError(f"{donde}: non-canonical hexadecimal")
    if tamano is not None and len(crudo) != tamano:
        raise ContainerFormatError(f"{donde}: must be {tamano} bytes long")
    return crudo


# Validation

def validate_metadata(metadata):
    """Validates metadata: exact fields, version, algorithms, and timestamp."""
    revisar_campos(metadata, CAMPOS_METADATA, set(), "metadata")

    # type(...) is int because True also counts as int
    if type(metadata["version"]) is not int or metadata["version"] != CONTAINER_VERSION:
        raise ContainerFormatError("metadata.version not supported")

    # Filename is only informative (never used as a path)
    filename = metadata["filename"]
    if filename is not None and (not isinstance(filename, str) or len(filename) > MAX_FILENAME_LEN):
        raise ContainerFormatError("metadata.filename invalid")

    # Only algorithms from the allowed list
    if metadata["aead_algorithm"] not in AEAD_ALGORITHMS:
        raise ContainerFormatError("metadata.aead_algorithm not allowed")
    if metadata["key_wrap_algorithm"] not in KEY_WRAP_ALGORITHMS:
        raise ContainerFormatError("metadata.key_wrap_algorithm not allowed")

    # ISO date with timezone
    try:
        fecha = datetime.fromisoformat(metadata["creation_timestamp"])
    except (TypeError, ValueError):
        raise ContainerFormatError("metadata.creation_timestamp invalid") from None
    if fecha.tzinfo is None:
        raise ContainerFormatError("metadata.creation_timestamp must include timezone")


def validate_recipients(recipients):
    """Validates the recipient list: valid IDs and no duplicates."""
    if not isinstance(recipients, list) or not 1 <= len(recipients) <= MAX_RECIPIENTS:
        raise ContainerFormatError(f"recipients: must be a list of 1 to {MAX_RECIPIENTS} entries")

    vistos = set()
    for i, entrada in enumerate(recipients):
        donde = f"recipients[{i}]"
        revisar_campos(entrada, CAMPOS_DESTINATARIO_OBLIGATORIOS, CAMPOS_DESTINATARIO_OPCIONALES, donde)

        # id: allowed format and unique
        rid = entrada["id"]
        if not isinstance(rid, str) or not ID_REGEX.fullmatch(rid):
            raise ContainerFormatError(f"{donde}.id invalid")
        if rid in vistos:
            raise ContainerFormatError(f"{donde}.id duplicated")
        vistos.add(rid)

        # Wrapped key: canonical hex, not empty
        llave = entrada["encrypted_key"]
        if not isinstance(llave, str) or not 0 < len(llave) <= MAX_ENCRYPTED_KEY_LEN:
            raise ContainerFormatError(f"{donde}.encrypted_key invalid")
        leer_hex(llave, f"{donde}.encrypted_key")

        # key_id is optional
        if "key_id" in entrada:
            kid = entrada["key_id"]
            if not isinstance(kid, str) or not 0 < len(kid) <= 128:
                raise ContainerFormatError(f"{donde}.key_id invalid")


def validate_signer_id(signer_id):
    """Validates that signer_id is a canonical hex SHA-256 fingerprint."""
    if not isinstance(signer_id, str) or not SIGNER_ID_REGEX.fullmatch(signer_id):
        raise ContainerFormatError(
            "signer_id invalid: expected 64-character lowercase hex SHA-256"
        )
    return signer_id


def validate_signature(signature):
    """Validates Ed25519 signature encoded as canonical 64-byte hex."""
    leer_hex(signature, "signature", SIGNATURE_SIZE)


def validate_container(container):
    """Complete structural validation D5. Called BEFORE verifying signature and decrypting."""
    revisar_campos(container, CAMPOS_CONTENEDOR, set(), "container")
    validate_metadata(container["metadata"])
    validate_recipients(container["recipients"])
    leer_hex(container["nonce"], "nonce", NONCE_SIZE)
    leer_hex(container["ciphertext"], "ciphertext")
    leer_hex(container["tag"], "tag", TAG_SIZE)
    validate_signature(container["signature"])
    validate_signer_id(container["signer_id"])


# Construction

def build_metadata(filename, aead_algorithm="AES-256-GCM",
                   key_wrap_algorithm="ECIES-secp256k1", creation_timestamp=None):
    """Builds container metadata (with current date if none is provided)."""
    metadata = {
        "version": CONTAINER_VERSION,
        "filename": filename,
        "aead_algorithm": aead_algorithm,
        "key_wrap_algorithm": key_wrap_algorithm,
        "creation_timestamp": creation_timestamp or datetime.now(timezone.utc).isoformat(),
    }
    validate_metadata(metadata)
    return metadata


def build_recipient_entry(user_id, encrypted_key, key_id=None):
    """Builds a recipient entry (key_id only if provided)."""
    entrada = {"id": user_id, "encrypted_key": encrypted_key}
    if key_id is not None:
        entrada["key_id"] = key_id
    return entrada


def build_aad(metadata, recipients):
    """Canonical bytes passed as AAD to AES-GCM (when encrypting and decrypting)."""
    validate_metadata(metadata)
    validate_recipients(recipients)

    documento = {"metadata": metadata, "recipients": recipients}
    cuerpo = json.dumps(documento, sort_keys=True, separators=(",", ":"),
                        ensure_ascii=True, allow_nan=False)
    return AAD_DOMINIO + cuerpo.encode("ascii")


def aad_from_container(container):
    """Validates the container and rebuilds its AAD (decryption side)."""
    validate_container(container)
    return build_aad(container["metadata"], container["recipients"])


def signer_id_from_ed25519_public_key(public_key_raw: bytes) -> str:
    """
    Calculates the signer_id (fingerprint) from the raw Ed25519 public key.
    The Ed25519 public key must be 32 bytes long.
    """
    if not isinstance(public_key_raw, (bytes, bytearray)) or len(public_key_raw) != 32:
        raise ContainerFormatError("Ed25519 public key must be 32 bytes long")
    return hashlib.sha256(bytes(public_key_raw)).hexdigest()


def build_signing_payload(metadata, recipients, nonce_hex, ciphertext_hex,
                          tag_hex, signer_id):
    """
    Canonical bytes to be signed with Ed25519.
    Includes: metadata, recipients, nonce, ciphertext, tag, and signer_id.
    Does NOT include the signature.
    """
    validate_metadata(metadata)
    validate_recipients(recipients)
    validate_signer_id(signer_id)

    leer_hex(nonce_hex, "nonce", NONCE_SIZE)
    leer_hex(ciphertext_hex, "ciphertext")
    leer_hex(tag_hex, "tag", TAG_SIZE)

    documento = {
        "metadata": metadata,
        "recipients": recipients,
        "nonce": nonce_hex,
        "ciphertext": ciphertext_hex,
        "tag": tag_hex,
        "signer_id": signer_id,
    }

    cuerpo = json.dumps(documento, sort_keys=True, separators=(",", ":"),
                        ensure_ascii=True, allow_nan=False)
    return SIGNATURE_DOMINIO + cuerpo.encode("ascii")


def signing_payload_from_container(container):
    """Rebuilds the signed payload from an already validated container."""
    validate_container(container)
    return build_signing_payload(
        container["metadata"],
        container["recipients"],
        container["nonce"],
        container["ciphertext"],
        container["tag"],
        container["signer_id"],
    )


def build_container(metadata, recipients, nonce, ciphertext, tag, signature, signer_id):
    """Builds the final D5 container (nonce, ciphertext, tag, and signature are bytes)."""
    for nombre, valor in (
        ("nonce", nonce),
        ("ciphertext", ciphertext),
        ("tag", tag),
        ("signature", signature),
    ):
        if not isinstance(valor, (bytes, bytearray)):
            raise ContainerFormatError(f"{nombre}: must be bytes")

    # deepcopy to avoid sharing objects with the caller
    container = {
        "metadata": copy.deepcopy(metadata),
        "recipients": copy.deepcopy(recipients),
        "nonce": a_hex(bytes(nonce)),
        "ciphertext": a_hex(bytes(ciphertext)),
        "tag": a_hex(bytes(tag)),
        "signature": a_hex(bytes(signature)),
        "signer_id": signer_id,
    }
    validate_container(container)
    return container


def load_container(text):
    """Reads a container from JSON text and validates it."""
    try:
        container = json.loads(text)
    except (TypeError, ValueError):
        raise ContainerFormatError("container: invalid JSON") from None
    validate_container(container)
    return container