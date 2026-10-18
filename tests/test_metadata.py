import copy
import json
import os

import pytest

from metadata import (
    comprobar_contenido,
    comprobar_llaves,
    guardar_json,
    leer_json,
    registrar_estado,
)
from SecureVaultEncryption import SecureVaultEncryption, DecryptionError

vault = SecureVaultEncryption()
PLAINTEXT = b"contenido secreto del documento legal"


@pytest.fixture
def metadatos_originales():
    return {
        "filename": "documento_legal.pdf",
        "algorithm_version": "AES-256-GCM",
        "encryption_parameters": "nonce_123",
        "creation_timestamp": "2026-10-17T10:00:00Z",
    }


@pytest.fixture
def cifrado():
    container, key = vault.encrypt(PLAINTEXT, filename="documento_legal.pdf")
    return container, key



# Bitacora de metadata (metadata.py)

def test_1_metadatos_intactos(metadatos_originales):
    metadatos_nuevos = metadatos_originales.copy()
    assert comprobar_contenido(metadatos_originales, metadatos_nuevos) == "Contenido intacto."
    assert comprobar_llaves(metadatos_originales, metadatos_nuevos) == "Estructura de llaves intacta."


def test_2_metadatos_modificados_fallan(metadatos_originales):
    metadatos_hackeados = metadatos_originales.copy()
    metadatos_hackeados["filename"] = "../../etc/passwd"
    resultado = comprobar_contenido(metadatos_originales, metadatos_hackeados)
    assert "Alerta" in resultado
    assert "filename" in resultado


def test_3_llaves_borradas_fallan(metadatos_originales):
    metadatos_hackeados = metadatos_originales.copy()
    del metadatos_hackeados["algorithm_version"]
    resultado = comprobar_llaves(metadatos_originales, metadatos_hackeados)
    assert "Alerta" in resultado


def test_4_registrar_estado_extrae_los_3_campos(metadatos_originales):
    estado = registrar_estado(metadatos_originales, "cifrar", "OK", "OK", True)
    registro = estado["historial"][0]

    assert registro["filename"] == "documento_legal.pdf"
    assert registro["algorithm_version"] == "AES-256-GCM"
    assert registro["encryption_parameters"] == "nonce_123"


# AAD: cualquier cambio en la metadata del contenedor debe ser rechazado
def test_roundtrip(cifrado):
    container, key = cifrado
    assert vault.decrypt(container, key) == PLAINTEXT


def test_cambiar_filename_es_rechazado(cifrado):
    container, key = cifrado
    malo = copy.deepcopy(container)
    malo["header"]["filename"] = "../../etc/passwd"
    with pytest.raises(DecryptionError):
        vault.decrypt(malo, key)


def test_cambiar_version_es_rechazado(cifrado):
    container, key = cifrado
    malo = copy.deepcopy(container)
    malo["header"]["algorithm_version"] = "AES-128-GCM/v0"
    with pytest.raises(DecryptionError):
        vault.decrypt(malo, key)


def test_cambiar_parametros_es_rechazado(cifrado):
    container, key = cifrado
    malo = copy.deepcopy(container)
    malo["header"]["encryption_parameters"]["tag_bytes"] = 4
    with pytest.raises(DecryptionError):
        vault.decrypt(malo, key)


def test_cambiar_timestamp_es_rechazado(cifrado):
    container, key = cifrado
    malo = copy.deepcopy(container)
    malo["header"]["creation_timestamp"] = "1999-01-01T00:00:00+00:00"
    with pytest.raises(DecryptionError):
        vault.decrypt(malo, key)


def test_agregar_campo_a_metadata_es_rechazado(cifrado):
    container, key = cifrado
    malo = copy.deepcopy(container)
    malo["header"]["admin"] = True
    with pytest.raises(DecryptionError):
        vault.decrypt(malo, key)


def test_metadata_intacta_se_acepta(cifrado):
    container, key = cifrado
    igual = json.loads(json.dumps(container))  # copia por serializacion
    assert vault.decrypt(igual, key) == PLAINTEXT



# Ciphertext, tag, llave y nonce

def _flip_first_byte(b64text):
    import base64
    raw = bytearray(base64.b64decode(b64text))
    raw[0] ^= 0x01
    return base64.b64encode(bytes(raw)).decode()


def test_ciphertext_modificado_falla(cifrado):
    container, key = cifrado
    malo = copy.deepcopy(container)
    malo["ciphertext"] = _flip_first_byte(malo["ciphertext"])
    with pytest.raises(DecryptionError):
        vault.decrypt(malo, key)


def test_tag_modificado_falla(cifrado):
    container, key = cifrado
    malo = copy.deepcopy(container)
    malo["authentication_tag"] = _flip_first_byte(malo["authentication_tag"])
    with pytest.raises(DecryptionError):
        vault.decrypt(malo, key)


def test_llave_incorrecta_falla(cifrado):
    container, _ = cifrado
    _, otra_key = vault.encrypt(b"otra cosa")
    with pytest.raises(DecryptionError):
        vault.decrypt(container, otra_key)


def test_cifrados_multiples_son_distintos():
    c1, k1 = vault.encrypt(PLAINTEXT)
    c2, k2 = vault.encrypt(PLAINTEXT)
    assert c1["nonce"] != c2["nonce"]
    assert c1["ciphertext"] != c2["ciphertext"]
    assert k1 != k2  # llave nueva por archivo



# Archivos
def test_archivo_roundtrip_identico(tmp_path):
    src = tmp_path / "foto.bin"
    src.write_bytes(bytes(range(256)) * 10)
    enc, out = tmp_path / "foto.vault", tmp_path / "foto_out.bin"
    key = vault.encrypt_file(str(src), str(enc))
    vault.decrypt_file(str(enc), key, str(out))
    assert out.read_bytes() == src.read_bytes()


def test_archivo_con_metadata_alterada_no_se_descifra(tmp_path):
    src = tmp_path / "doc.txt"
    src.write_bytes(b"hola")
    enc, out = tmp_path / "doc.vault", tmp_path / "doc_out.txt"
    key = vault.encrypt_file(str(src), str(enc))

    data = json.loads(enc.read_text(encoding="utf-8"))
    data["header"]["filename"] = "virus.exe"
    enc.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(DecryptionError):
        vault.decrypt_file(str(enc), key, str(out))
    assert not out.exists()  # fallo seguro: no se escribe salida



# Demo manual
if __name__ == "__main__":
    print("Pruebas AAD")

    # 1. Ciframos
    contenedor, llave = vault.encrypt(b"foto privada", filename="foto_privada.jpg")
    print("\n--- Contenedor generado ---")
    print(json.dumps(contenedor, indent=4))

    # 2. Descifrado normal
    print("\n--- Descifrado con metadata intacta ---")
    print("Resultado:", vault.decrypt(contenedor, llave))

    # 3. Atacante cambia el filename
    print("\n--- Atacante cambia filename a 'virus.exe' ---")
    hackeado = copy.deepcopy(contenedor)
    hackeado["header"]["filename"] = "virus.exe"
    try:
        vault.decrypt(hackeado, llave)
        print("Fallo de seguridad, se aceptó metadata alterada")
    except DecryptionError as e:
        print(f"Rechazado: {e}")

    # 4. Atacante cambia la version del algoritmo
    print("\n--- Atacante cambia algorithm_version ---")
    hackeado = copy.deepcopy(contenedor)
    hackeado["header"]["algorithm_version"] = "AES-128-GCM/v0"
    try:
        vault.decrypt(hackeado, llave)
        print("Fallo de seguridad, se aceptó metadata alterada")
    except DecryptionError as e:
        print(f"Rechazado: {e}")

    # 5. Un solo JSON: bitacora + contenedor (la llave NO se guarda)
    header_ok = contenedor["header"]
    header_malo = copy.deepcopy(header_ok)
    header_malo["filename"] = "virus.exe"

    estado = registrar_estado(
        datos_json=header_ok,
        accion="intento_descifrado_con_metadata_alterada",
        res_contenido=comprobar_contenido(header_ok, header_malo),
        res_llaves=comprobar_llaves(header_ok, header_malo),
        res_password="no aplica",
    )
    estado["historial"][-1]["container"] = contenedor

    print("\n--- Guardando en metadata.json ---")
    print(guardar_json(estado))

    print("\n¡Archivo generado exitosamente! Contenido:")
    print(json.dumps(leer_json("metadata.json"), indent=4))