import pytest
import os
import json
from metadata import (
    comprobar_contenido, 
    comprobar_llaves, 
    guardar_json, 
    leer_json, 
    registrar_estado
)

# =====================================================================
# PRUEBAS (Para 'pytest')
# =====================================================================
@pytest.fixture
def metadatos_originales():
    return {
        "filename": "documento_legal.pdf",
        "algorithm_version": "AES-256-GCM",
        "encryption_parameters": "nonce_123",
        "creation_timestamp": "2026-10-17T10:00:00Z"
    }

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


# =====================================================================
# MAIN (Para probar manualmente)
# =====================================================================
if __name__ == "__main__":
    print("=== 🧪 GENERANDO JSON CON NOMBRE FORZADO ===")
    
    # 1. Simulamos los datos
    datos_originales = {
        "filename": "foto_privada.jpg",
        "algorithm_version": "AES-256-GCM",
        "encryption_parameters": "nonce=1234, tag=abcd",
        "contraseña": "123"
    }
    
    datos_hackeados = datos_originales.copy()
    datos_hackeados["filename"] = "virus.exe"
    
    # 2. Comprobamos
    res_cont = comprobar_contenido(datos_originales, datos_hackeados)
    res_llav = comprobar_llaves(datos_originales, datos_hackeados)
    
    # 3. Armamos el estado
    estado = registrar_estado(
        datos_json=datos_originales, 
        accion="intento_de_descifrado", 
        res_contenido=res_cont, 
        res_llaves=res_llav, 
        res_password=True
    )
    
    # 4. Guardamos (¡Ya no le pasamos la ruta, se guarda solo en metadata.json!)
    print("\n--- Guardando en JSON ---")
    if os.path.exists("metadata.json"):
        os.remove("metadata.json") # Limpiamos por si ya existía
        
    print(guardar_json(estado))
    
    # 5. Mostramos el resultado
    print("\n¡Archivo generado exitosamente! Contenido:")
    print(json.dumps(leer_json("metadata.json"), indent=4))