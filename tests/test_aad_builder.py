import copy
import json

import pytest

from src.crypto.aad_builder import (
    ContainerFormatError,
    aad_from_container,
    build_aad,
    build_container,
    build_metadata,
    build_recipient_entry,
    load_container,
    validate_container,
)


# Datos de apoyo

def lista_destinatarios():
    return [
        build_recipient_entry("alice", "aa11", key_id="k-alice"),
        build_recipient_entry("bob", "bb22", key_id="k-bob"),
    ]


def contenedor_base():
    return build_container(
        build_metadata("doc.pdf"), lista_destinatarios(),
        nonce=b"\x01" * 12, ciphertext=b"cifrado", tag=b"\x02" * 16,
    )


def mutar(cambio):
    """Copia del contenedor valido con un cambio aplicado."""
    contenedor = copy.deepcopy(contenedor_base())
    cambio(contenedor)
    return contenedor


# AAD

def test_aad_es_determinista_y_no_depende_del_orden_de_llaves():
    meta = build_metadata("doc.pdf", creation_timestamp="2026-10-25T10:00:00+00:00")
    reordenada = dict(reversed(list(meta.items())))
    assert build_aad(meta, lista_destinatarios()) == build_aad(reordenada, lista_destinatarios())


def test_aad_lleva_prefijo_de_dominio():
    meta = build_metadata("doc.pdf")
    assert build_aad(meta, lista_destinatarios()).startswith(b"vault-d3-aad/v1\x00")


def test_el_orden_de_destinatarios_cambia_el_aad():
    meta = build_metadata("doc.pdf")
    lista = lista_destinatarios()
    assert build_aad(meta, lista) != build_aad(meta, list(reversed(lista)))


@pytest.mark.parametrize("campo,nuevo", [
    ("filename", "otro.pdf"),
    ("creation_timestamp", "1999-01-01T00:00:00+00:00"),
])
def test_cambiar_metadata_cambia_el_aad(campo, nuevo):
    meta = build_metadata("doc.pdf", creation_timestamp="2026-10-25T10:00:00+00:00")
    cambiada = dict(meta, **{campo: nuevo})
    assert build_aad(meta, lista_destinatarios()) != build_aad(cambiada, lista_destinatarios())


@pytest.mark.parametrize("campo,nuevo", [
    ("id", "mallory"),
    ("encrypted_key", "ff00"),
    ("key_id", "k-otro"),
])
def test_cambiar_un_campo_de_destinatario_cambia_el_aad(campo, nuevo):
    meta = build_metadata("doc.pdf")
    lista = lista_destinatarios()
    lista_alterada = copy.deepcopy(lista)
    lista_alterada[1][campo] = nuevo
    assert build_aad(meta, lista) != build_aad(meta, lista_alterada)


def test_quitar_o_agregar_destinatario_cambia_el_aad():
    meta = build_metadata("doc.pdf")
    lista = lista_destinatarios()
    assert build_aad(meta, lista) != build_aad(meta, lista[:1])
    assert build_aad(meta, lista) != build_aad(meta, lista + [build_recipient_entry("carol", "cc33")])


# Validacion estructural

def test_contenedor_valido_pasa_y_viaja_por_json():
    contenedor = contenedor_base()
    validate_container(contenedor)
    assert load_container(json.dumps(contenedor)) == contenedor
    assert aad_from_container(contenedor) == build_aad(contenedor["metadata"], contenedor["recipients"])


@pytest.mark.parametrize("cambio", [
    lambda c: c.update(extra=1),                                   # campo extra
    lambda c: c.pop("tag"),                                        # campo faltante
    lambda c: c["metadata"].update(admin=True),                    # extra en metadata
    lambda c: c["metadata"].update(version=2),                     # version desconocida
    lambda c: c["metadata"].update(version=True),                  # bool no es int
    lambda c: c["metadata"].update(aead_algorithm="DES"),          # algoritmo no permitido
    lambda c: c["metadata"].update(key_wrap_algorithm="RSA-PKCS1"),
    lambda c: c["metadata"].update(creation_timestamp="ayer"),
    lambda c: c["metadata"].update(creation_timestamp="2026-10-25T10:00:00"),  # sin zona
    lambda c: c.update(recipients=[]),                             # sin destinatarios
    lambda c: c.update(recipients="alice"),                        # tipo incorrecto
    lambda c: c["recipients"][0].update(extra="x"),                # extra en destinatario
    lambda c: c["recipients"][0].pop("encrypted_key"),
    lambda c: c["recipients"][0].update(id="../etc"),              # id con caracteres invalidos
    lambda c: c["recipients"][1].update(id="alice"),               # id duplicado
    lambda c: c.update(nonce="aaaa"),                              # nonce de tamano incorrecto
    lambda c: c.update(tag="aaaa"),                                # tag de tamano incorrecto
    lambda c: c.update(ciphertext="zz-no-es-hex"),
    lambda c: c.update(ciphertext="abc"),                          # longitud impar
])
def test_contenedor_malformado_se_rechaza(cambio):
    with pytest.raises(ContainerFormatError):
        validate_container(mutar(cambio))


def test_hex_no_canonico_se_rechaza():
    contenedor = contenedor_base()
    # mismo contenido en mayusculas: decodifica igual pero no es canonico
    contenedor["ciphertext"] = contenedor["ciphertext"].upper()
    with pytest.raises(ContainerFormatError):
        validate_container(contenedor)


@pytest.mark.parametrize("basura", [None, 5, "texto", [], [1, 2]])
def test_contenedor_que_no_es_objeto_se_rechaza(basura):
    with pytest.raises(ContainerFormatError):
        validate_container(basura)


def test_load_container_rechaza_json_invalido():
    with pytest.raises(ContainerFormatError):
        load_container("{no es json")


# Demo manual:  python -m tests.test_aad_builder   (desde la raiz del repo)
def main():
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    print("Pruebas AAD del contenedor hibrido")

    # 1. Armamos metadata y destinatarios (las llaves envueltas son de mentira)
    meta = build_metadata("contrato.pdf")
    destinatarios = lista_destinatarios()
    aad = build_aad(meta, destinatarios)
    print("\nAAD generado")
    print(aad)

    # 2. Ciframos con AES-GCM usando ese AAD
    dek = AESGCM.generate_key(bit_length=256)
    nonce = b"\x07" * 12
    sellado = AESGCM(dek).encrypt(nonce, b"contenido secreto", aad)
    contenedor = build_container(meta, destinatarios, nonce, sellado[:-16], sellado[-16:])
    print("\nContenedor generado")
    print(json.dumps(contenedor, indent=4))

    def descifrar(cont):
        # mismo flujo del descifrado: validar, reconstruir AAD y abrir
        aad_nuevo = aad_from_container(cont)
        crudo = bytes.fromhex(cont["ciphertext"]) + bytes.fromhex(cont["tag"])
        return AESGCM(dek).decrypt(bytes.fromhex(cont["nonce"]), crudo, aad_nuevo)

    # 3. Descifrado normal
    print("\nDescifrado con contenedor intacto")
    print("Resultado:", descifrar(contenedor))

    # 4. Ataques a la lista de destinatarios
    ataques = {
        "cambia el id de bob a 'mallory'": lambda c: c["recipients"][1].update(id="mallory"),
        "cambia la llave envuelta de bob": lambda c: c["recipients"][1].update(encrypted_key="ff00"),
        "reordena los destinatarios": lambda c: c["recipients"].reverse(),
        "elimina a bob": lambda c: c["recipients"].pop(1),
        "agrega a un intruso": lambda c: c["recipients"].append(build_recipient_entry("mallory", "cc33")),
        "cambia el filename": lambda c: c["metadata"].update(filename="virus.exe"),
    }
    for descripcion, ataque in ataques.items():
        print(f"\n--- Atacante {descripcion} ---")
        hackeado = copy.deepcopy(contenedor)
        ataque(hackeado)
        try:
            descifrar(hackeado)
            print("Fallo de seguridad, se acepto el contenedor alterado")
        except (InvalidTag, ContainerFormatError) as e:
            print(f"Rechazado: {type(e).__name__}")

    # 5. Contenedor mal formado (se rechaza antes de descifrar)
    print("\nContenedor con un campo de mas")
    malformado = copy.deepcopy(contenedor)
    malformado["admin"] = True
    try:
        validate_container(malformado)
        print("Fallo de seguridad, se acepto el contenedor malformado")
    except ContainerFormatError as e:
        print(f"Rechazado: {e}")


if __name__ == "__main__":
    main()