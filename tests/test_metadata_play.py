import copy
import json

from metadata import (
    comprobar_contenido,
    comprobar_llaves,
    guardar_json,
    leer_json,
    registrar_estado,
)
from SecureVaultEncryption import SecureVaultEncryption, DecryptionError

vault = SecureVaultEncryption()


def main():
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


if __name__ == "__main__":
    main()