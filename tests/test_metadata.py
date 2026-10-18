import copy
import json
import os

import pytest

from src.metadata import (
    comprobar_contenido,
    comprobar_llaves,
    guardar_json,
    leer_json,
    registrar_estado,
)
from src.SecureVaultEncryption import SecureVaultEncryption, DecryptionError

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


# Bitácora de metadata (metadata.py)

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
    igual = json.loads(json.dumps(container))
    assert vault.decrypt(igual, key) == PLAINTEXT


# Vault y bitácora

def test_bitacora_se_guarda_al_rechazar_metadata_alterada(cifrado, tmp_path):
    container, key = cifrado
    ruta = str(tmp_path / "metadata.json")

    header_ok = container["header"]
    header_malo = copy.deepcopy(header_ok)
    header_malo["filename"] = "virus.exe"
    hackeado = copy.deepcopy(container)
    hackeado["header"] = header_malo
    with pytest.raises(DecryptionError):
        vault.decrypt(hackeado, key)

    estado = registrar_estado(
        datos_json=header_ok,
        accion="intento_descifrado_con_metadata_alterada",
        res_contenido=comprobar_contenido(header_ok, header_malo),
        res_llaves=comprobar_llaves(header_ok, header_malo),
        res_password="no aplica",
    )
    estado["historial"][-1]["container"] = container
    assert guardar_json(estado, ruta) == "Guardado exitoso (historial actualizado)"

    assert os.path.exists(ruta)
    registro = leer_json(ruta)["historial"][0]
    assert registro["filename"] == "documento_legal.pdf"
    assert registro["accion"] == "intento_descifrado_con_metadata_alterada"
    assert "filename" in registro["resultado_contenido"]
    assert registro["container"] == container

    assert vault.decrypt(registro["container"], key) == PLAINTEXT

    editado = copy.deepcopy(registro["container"])
    editado["header"]["filename"] = "virus.exe"
    with pytest.raises(DecryptionError):
        vault.decrypt(editado, key)


def test_historial_se_concatena_entre_guardados(cifrado, tmp_path):
    container, _ = cifrado
    ruta = str(tmp_path / "metadata.json")
    header = container["header"]

    for i in range(3):
        estado = registrar_estado(header, f"intento_{i}", "OK", "OK", "no aplica")
        guardar_json(estado, ruta)

    historial = leer_json(ruta)["historial"]
    assert [r["accion"] for r in historial] == ["intento_0", "intento_1", "intento_2"]