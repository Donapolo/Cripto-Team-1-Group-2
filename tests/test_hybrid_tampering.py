import copy
import json

import pytest

pytest.importorskip("ecies")
from ecies.utils import generate_eth_key
from cryptography.exceptions import InvalidTag

from src.crypto.aad_builder import ContainerFormatError
from src.crypto.hybrid_vault import decrypt_hybrid, encrypt_hybrid


PLAINTEXT = b"contenido confidencial compartido entre varios usuarios"
FILENAME = "contrato.pdf"
FALLO_CERRADO = (InvalidTag, ContainerFormatError, ValueError, KeyError)  # agregar la excepcion de decrypt_hybrid si Jesus define una propia


# Datos de apoyo

def nuevo_usuario():
    """Devuelve (llave_publica_hex, llave_privada_hex)."""
    llave = generate_eth_key()
    return llave.public_key.to_hex(), llave.to_hex()


@pytest.fixture
def escenario():
    # alice, bob y carol tienen llaves, pero el archivo solo se comparte con alice y bob
    usuarios = {uid: nuevo_usuario() for uid in ("alice", "bob", "carol")}
    recipients = {uid: usuarios[uid][0] for uid in ("alice", "bob")}
    container = encrypt_hybrid(PLAINTEXT, FILENAME, recipients)
    return container, usuarios


def clonar(container):
    """Copia por JSON, como si viajara por disco o red."""
    return json.loads(json.dumps(container))


def descifrar(container, usuarios, uid):
    return decrypt_hybrid(container, uid, usuarios[uid][1])


def alterar_texto(valor):
    """Cambia el ultimo caracter."""
    return valor[:-1] + ("0" if valor[-1] != "0" else "1")


def todos_fallan(container, usuarios):
    """Con el contenedor alterado, ni alice ni bob deben poder descifrar."""
    for uid in ("alice", "bob"):
        with pytest.raises(FALLO_CERRADO):
            descifrar(container, usuarios, uid)


# 1. Archivo compartido con 2 o mas usuarios

def test_archivo_compartido_lo_descifran_ambos(escenario):
    container, usuarios = escenario
    assert len(container["recipients"]) >= 2
    assert descifrar(clonar(container), usuarios, "alice") == PLAINTEXT
    assert descifrar(clonar(container), usuarios, "bob") == PLAINTEXT


def test_usuario_no_destinatario_no_descifra(escenario):
    container, usuarios = escenario
    with pytest.raises(FALLO_CERRADO):
        descifrar(clonar(container), usuarios, "carol")


# 2. Modificar la lista de destinatarios hace fallar el descifrado (AAD)

def test_modificar_cualquier_campo_de_un_destinatario_falla(escenario):
    container, usuarios = escenario
    cambios = {
        "id": lambda v: "mallory",
        "encrypted_key": alterar_texto,
        "key_id": lambda v: "otro-key-id",
    }
    probados = 0
    for i, entrada in enumerate(container["recipients"]):
        for campo, cambio in cambios.items():
            if campo not in entrada:
                continue
            malo = clonar(container)
            malo["recipients"][i][campo] = cambio(entrada[campo])
            # incluso el destinatario que NO fue alterado debe fallar
            todos_fallan(malo, usuarios)
            probados += 1
    assert probados >= 4  # al menos id y encrypted_key de las 2 entradas


def test_reordenar_destinatarios_falla(escenario):
    container, usuarios = escenario
    malo = clonar(container)
    malo["recipients"].reverse()
    todos_fallan(malo, usuarios)


def test_agregar_destinatario_falla(escenario):
    container, usuarios = escenario
    malo = clonar(container)
    intruso = copy.deepcopy(malo["recipients"][0])
    intruso["id"] = "mallory"
    malo["recipients"].append(intruso)
    todos_fallan(malo, usuarios)


# 3. Eliminar una entrada rompe el acceso y la verificacion de integridad

def test_eliminar_entrada_de_destinatario_rompe_acceso_e_integridad(escenario):
    container, usuarios = escenario

    # sin alice: alice pierde el acceso y bob falla por AAD
    sin_alice = clonar(container)
    sin_alice["recipients"] = [r for r in sin_alice["recipients"] if r["id"] != "alice"]
    todos_fallan(sin_alice, usuarios)

    # sin bob: bob pierde el acceso y alice falla por AAD
    sin_bob = clonar(container)
    sin_bob["recipients"] = [r for r in sin_bob["recipients"] if r["id"] != "bob"]
    todos_fallan(sin_bob, usuarios)


# Metadata y datos cifrados

def test_modificar_metadata_falla(escenario):
    container, usuarios = escenario

    malo = clonar(container)
    malo["metadata"]["filename"] = "../../etc/passwd"
    todos_fallan(malo, usuarios)

    malo = clonar(container)
    malo["metadata"]["creation_timestamp"] = "1999-01-01T00:00:00+00:00"
    todos_fallan(malo, usuarios)


def test_modificar_ciphertext_o_tag_falla(escenario):
    container, usuarios = escenario
    for campo in ("ciphertext", "tag", "nonce"):
        malo = clonar(container)
        malo[campo] = alterar_texto(malo[campo])
        todos_fallan(malo, usuarios)


# Validacion estructural previa

def test_contenedor_malformado_se_rechaza(escenario):
    container, usuarios = escenario

    # sin la lista de destinatarios
    sin_recipients = clonar(container)
    del sin_recipients["recipients"]
    todos_fallan(sin_recipients, usuarios)

    # con un campo que no existe en el esquema
    con_extra = clonar(container)
    con_extra["admin"] = True
    todos_fallan(con_extra, usuarios)

    # lista de destinatarios vacia
    sin_destinatarios = clonar(container)
    sin_destinatarios["recipients"] = []
    todos_fallan(sin_destinatarios, usuarios)


# Demo manual:  python -m tests.test_hybrid_tampering   (desde la raiz del repo)
def main():
    print("Pruebas de integridad del cifrado hibrido")

    # 1. Alice y bob son destinatarios, carol no
    usuarios = {uid: nuevo_usuario() for uid in ("alice", "bob", "carol")}
    recipients = {uid: usuarios[uid][0] for uid in ("alice", "bob")}
    container = encrypt_hybrid(PLAINTEXT, FILENAME, recipients)
    print("\n--- Contenedor generado ---")
    print(json.dumps(container, indent=4))

    def intentar(titulo, cont, uid):
        try:
            resultado = descifrar(cont, usuarios, uid)
            print(f"{titulo} ({uid}): descifro -> {resultado[:20]}...")
        except Exception as e:
            print(f"{titulo} ({uid}): Rechazado ({type(e).__name__})")

    # 2. Descifrado normal
    print("\nDescifrado con el contenedor intacto")
    for uid in ("alice", "bob", "carol"):
        intentar("Intacto", clonar(container), uid)

    # 3. Ataques a la lista de destinatarios
    print("\nAtacante cambia el id de bob a 'mallory'")
    malo = clonar(container)
    malo["recipients"][1]["id"] = "mallory"
    for uid in ("alice", "bob"):
        intentar("Id cambiado", malo, uid)

    print("\nAtacante reordena los destinatarios")
    malo = clonar(container)
    malo["recipients"].reverse()
    for uid in ("alice", "bob"):
        intentar("Reordenado", malo, uid)

    print("\nAtacante elimina la entrada de bob")
    malo = clonar(container)
    malo["recipients"] = [r for r in malo["recipients"] if r["id"] != "bob"]
    for uid in ("alice", "bob"):
        intentar("Sin bob", malo, uid)

    print("\nAtacante cambia el filename")
    malo = clonar(container)
    malo["metadata"]["filename"] = "virus.exe"
    for uid in ("alice", "bob"):
        intentar("Filename cambiado", malo, uid)


if __name__ == "__main__":
    main()