import hashlib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from src.crypto.aad_builder import (
    SIGNATURE_SIZE,
    ContainerFormatError,
    a_hex,
    build_container,
    build_signing_payload,
    leer_hex,
    signer_id_from_ed25519_public_key,
    signing_payload_from_container,
    validate_container,
)

KEY_SIZE = 32  # llaves Ed25519 crudas: 32 bytes


class SignatureVerificationError(ValueError):
    """La firma no es valida (o no corresponde a la llave publica dada)."""


# Llaves

def generate_key_pair():
    """Genera un par Ed25519. Todo sale en hex (llaves crudas de 32 bytes)."""
    privada = Ed25519PrivateKey.generate()
    privada_raw = privada.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    publica_raw = privada.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return {
        "private_key": a_hex(privada_raw),
        "public_key": a_hex(publica_raw),
        "signer_id": signer_id_from_ed25519_public_key(publica_raw),
    }


def load_private_key(private_key_hex):
    """Hex de 32 bytes -> objeto de llave privada Ed25519."""
    crudo = leer_hex(private_key_hex, "private_key", KEY_SIZE)
    return Ed25519PrivateKey.from_private_bytes(crudo)


def load_public_key(public_key_hex):
    """Hex de 32 bytes -> objeto de llave publica Ed25519."""
    crudo = leer_hex(public_key_hex, "public_key", KEY_SIZE)
    return Ed25519PublicKey.from_public_bytes(crudo)


def public_key_from_private(private_key_hex):
    """Saca la llave publica (hex) a partir de la privada (hex)."""
    publica = load_private_key(private_key_hex).public_key()
    return a_hex(publica.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))


# Hash + firma

def hash_payload(payload):
    """SHA-256 del payload (esto es lo que realmente se firma)."""
    if not isinstance(payload, (bytes, bytearray)):
        raise ContainerFormatError("payload: debe ser bytes")
    return hashlib.sha256(bytes(payload)).digest()


def sign_payload(private_key_hex, payload):
    """Hash -> Sign: firma el SHA-256 del payload. Regresa 64 bytes."""
    firma = load_private_key(private_key_hex).sign(hash_payload(payload))
    assert len(firma) == SIGNATURE_SIZE
    return firma


def verify_payload(public_key_hex, payload, signature):
    """Hash -> Verify. Lanza SignatureVerificationError si algo no cuadra (falla cerrado)."""
    if not isinstance(signature, (bytes, bytearray)) or len(signature) != SIGNATURE_SIZE:
        raise SignatureVerificationError("firma invalida")
    try:
        load_public_key(public_key_hex).verify(bytes(signature), hash_payload(payload))
    except InvalidSignature:
        raise SignatureVerificationError("firma invalida") from None


# Contenedor

def sign_container(metadata, recipients, nonce, ciphertext, tag, private_key_hex):
    """Firma lo ya cifrado y arma el contenedor final (nonce, ciphertext y tag como bytes)."""
    public_hex = public_key_from_private(private_key_hex)
    signer_id = signer_id_from_ed25519_public_key(bytes.fromhex(public_hex))

    payload = build_signing_payload(
        metadata, recipients, a_hex(bytes(nonce)), a_hex(bytes(ciphertext)),
        a_hex(bytes(tag)), signer_id,
    )
    firma = sign_payload(private_key_hex, payload)
    return build_container(metadata, recipients, nonce, ciphertext, tag, firma, signer_id)


def verify_container(container, public_key_hex):
    """Verifica el contenedor ANTES de descifrar. Lanza excepcion si falla, no regresa False."""
    # 1) estructura (incluye que exista signature y signer_id)
    validate_container(container)

    # 2) la llave publica debe ser la del firmante declarado
    publica = leer_hex(public_key_hex, "public_key", KEY_SIZE)
    if signer_id_from_ed25519_public_key(publica) != container["signer_id"]:
        raise SignatureVerificationError("la llave publica no corresponde al signer_id")

    # 3) rearmar el payload desde el contenedor y verificar
    payload = signing_payload_from_container(container)
    firma = leer_hex(container["signature"], "signature", SIGNATURE_SIZE)
    verify_payload(public_key_hex, payload, firma)


def main():
    from src.crypto.aad_builder import build_metadata, build_recipient_entry

    par = generate_key_pair()
    metadata = build_metadata("demo.pdf")
    recipients = [build_recipient_entry("alice", "ab" * 40), build_recipient_entry("bob", "cd" * 40)]
    contenedor = sign_container(metadata, recipients, b"\x01" * 12, b"cifrado", b"\x02" * 16,
                                par["private_key"])
    verify_container(contenedor, par["public_key"])
    print("Firma valida. signer_id:", contenedor["signer_id"])

    contenedor["ciphertext"] = "00" + contenedor["ciphertext"][2:]
    try:
        verify_container(contenedor, par["public_key"])
    except SignatureVerificationError as e:
        print("Contenedor alterado rechazado:", e)


if __name__ == "__main__":
    main()