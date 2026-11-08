import copy

import pytest

from src.crypto.aad_builder import (
    ContainerFormatError,
    build_metadata,
    build_recipient_entry,
)
from src.crypto.signature_manager import (
    SignatureVerificationError,
    generate_key_pair,
    hash_payload,
    sign_container,
    sign_payload,
    verify_container,
    verify_payload,
)


def hacer_contenedor(par):
    metadata = build_metadata("doc.pdf", creation_timestamp="2026-01-01T00:00:00+00:00")
    recipients = [build_recipient_entry("alice", "ab" * 40), build_recipient_entry("bob", "cd" * 40)]
    return sign_container(metadata, recipients, b"\x01" * 12, b"texto cifrado", b"\x02" * 16,
                          par["private_key"])


@pytest.fixture
def par():
    return generate_key_pair()


# Llaves y firma basica

def test_generate_key_pair_formato(par):
    assert len(par["private_key"]) == 64
    assert len(par["public_key"]) == 64
    assert len(par["signer_id"]) == 64


def test_pares_distintos():
    assert generate_key_pair()["private_key"] != generate_key_pair()["private_key"]


def test_hash_payload_es_sha256():
    assert hash_payload(b"abc").hex() == (
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )


def test_sign_verify_payload(par):
    firma = sign_payload(par["private_key"], b"hola")
    assert len(firma) == 64
    verify_payload(par["public_key"], b"hola", firma)


def test_payload_distinto_rechazado(par):
    firma = sign_payload(par["private_key"], b"hola")
    with pytest.raises(SignatureVerificationError):
        verify_payload(par["public_key"], b"hola!", firma)


# Pruebas obligatorias A-E

def test_A_firma_valida_aceptada(par):
    verify_container(hacer_contenedor(par), par["public_key"])


def test_B_ciphertext_modificado_rechazado(par):
    c = hacer_contenedor(par)
    c["ciphertext"] = "00" + c["ciphertext"][2:]
    with pytest.raises(SignatureVerificationError):
        verify_container(c, par["public_key"])


def test_C_metadata_modificada_rechazada(par):
    c = hacer_contenedor(par)
    c["metadata"]["filename"] = "otro.pdf"
    with pytest.raises(SignatureVerificationError):
        verify_container(c, par["public_key"])


def test_C_recipients_modificados_rechazados(par):
    c = hacer_contenedor(par)
    c["recipients"][0]["encrypted_key"] = "ef" * 40
    with pytest.raises(SignatureVerificationError):
        verify_container(c, par["public_key"])


def test_C_nonce_y_tag_modificados_rechazados(par):
    for campo, nuevo in (("nonce", "ff" * 12), ("tag", "ff" * 16)):
        c = hacer_contenedor(par)
        c[campo] = nuevo
        with pytest.raises(SignatureVerificationError):
            verify_container(c, par["public_key"])


def test_D_llave_publica_incorrecta_rechazada(par):
    otro = generate_key_pair()
    with pytest.raises(SignatureVerificationError):
        verify_container(hacer_contenedor(par), otro["public_key"])


def test_D_signer_id_cambiado_rechazado(par):
    # Cambiar el signer_id al de otra llave: la firma ya no cuadra con el payload
    otro = generate_key_pair()
    c = hacer_contenedor(par)
    c["signer_id"] = otro["signer_id"]
    with pytest.raises(SignatureVerificationError):
        verify_container(c, par["public_key"])


def test_E_firma_eliminada_rechazada(par):
    c = hacer_contenedor(par)
    del c["signature"]
    with pytest.raises(ContainerFormatError):
        verify_container(c, par["public_key"])


def test_E_signer_id_eliminado_rechazado(par):
    c = hacer_contenedor(par)
    del c["signer_id"]
    with pytest.raises(ContainerFormatError):
        verify_container(c, par["public_key"])


# Firmas mal formadas

@pytest.mark.parametrize("mala", ["", "00" * 63, "00" * 65, "zz" * 64, "AB" * 64, None, 123])
def test_firma_mal_formada_rechazada(par, mala):
    c = hacer_contenedor(par)
    c["signature"] = mala
    with pytest.raises(ValueError):
        verify_container(c, par["public_key"])


def test_firma_de_otro_contenedor_rechazada(par):
    c1 = hacer_contenedor(par)
    c2 = hacer_contenedor(par)
    c2["ciphertext"] = "aa" * 8
    c2["signature"] = c1["signature"]
    with pytest.raises(SignatureVerificationError):
        verify_container(c2, par["public_key"])


def test_sign_container_no_modifica_entradas(par):
    metadata = build_metadata("x.pdf")
    recipients = [build_recipient_entry("alice", "ab" * 40)]
    antes = copy.deepcopy((metadata, recipients))
    sign_container(metadata, recipients, b"\x01" * 12, b"c", b"\x02" * 16, par["private_key"])
    assert (metadata, recipients) == antes