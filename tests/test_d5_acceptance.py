"""
tests/test_d5_acceptance.py
Acceptance Test Suite for Deliverable D5 (Signatures & Authentication).
Verifies end-to-end integration of encrypt_hybrid and decrypt_hybrid,
covering scenarios A through E, serialization roundtrips, and fail-closed policies.
"""

import copy
import json
import pytest

from src.crypto.key_manager import ECIESKeyManager
from src.crypto.signature_manager import generate_key_pair as generate_signing_key_pair
from src.crypto.hybrid_vault import encrypt_hybrid, decrypt_hybrid, IntegrityError


@pytest.fixture
def crypto_environment():
    """Configura identidades secp256k1 (cifrado) y Ed25519 (firma) junto con el registro confiable."""
    # Llaves de intercambio/cifrado (secp256k1)
    alice_enc = ECIESKeyManager.generate_key_pair()
    bob_enc = ECIESKeyManager.generate_key_pair()

    # Llaves de firma digital (Ed25519)
    signer_alice = generate_signing_key_pair()
    signer_eve = generate_signing_key_pair()

    # Registro fuera de banda de firmantes de confianza
    trusted_signers = {
        signer_alice["signer_id"]: signer_alice["public_key"]
    }

    recipients_map = {
        "alice": alice_enc["public_key"],
        "bob": bob_enc["public_key"],
    }

    payload = b"DOCUMENTO DE PRUEBA D5: Evaluacion de no repudio y autenticacion UNAM FI."
    filename = "contrato_d5.pdf"

    return {
        "alice_enc": alice_enc,
        "bob_enc": bob_enc,
        "signer_alice": signer_alice,
        "signer_eve": signer_eve,
        "trusted_signers": trusted_signers,
        "recipients_map": recipients_map,
        "payload": payload,
        "filename": filename,
    }


# ==============================================================================
# ESCENARIOS PRINCIPALES REQUERIDOS (A - E)
# ==============================================================================

def test_scenario_a_valid_signature_accepted(crypto_environment):
    """
    Escenario A: Firma valida -> Archivo aceptado y descifrado correctamente.
    Verifica que tanto Alice como Bob puedan descifrar tras una firma autentica.
    """
    env = crypto_environment
    container = encrypt_hybrid(
        file_bytes=env["payload"],
        filename=env["filename"],
        recipients=env["recipients_map"],
        signing_private_key=env["signer_alice"]["private_key"],
    )

    # Bob descifra validando contra el registro de firmantes confiables
    recovered_bob = decrypt_hybrid(
        container=container,
        user_id="bob",
        private_key=env["bob_enc"]["private_key"],
        trusted_signers=env["trusted_signers"],
    )
    assert recovered_bob == env["payload"], "El texto plano recuperado por Bob no coincide."

    # Alice descifra validando contra el mismo registro
    recovered_alice = decrypt_hybrid(
        container=container,
        user_id="alice",
        private_key=env["alice_enc"]["private_key"],
        trusted_signers=env["trusted_signers"],
    )
    assert recovered_alice == env["payload"], "El texto plano recuperado por Alice no coincide."


def test_scenario_b_modified_ciphertext_rejected(crypto_environment):
    """
    Escenario B: Texto cifrado modificado -> Rechazado antes de descifrar.
    Cualquier alteracion en ciphertext debe invalidar la firma y lanzar IntegrityError.
    """
    env = crypto_environment
    container = encrypt_hybrid(
        file_bytes=env["payload"],
        filename=env["filename"],
        recipients=env["recipients_map"],
        signing_private_key=env["signer_alice"]["private_key"],
    )

    # Manipular 1 caracter hex del ciphertext
    ct_list = list(container["ciphertext"])
    ct_list[0] = "f" if ct_list[0] != "f" else "0"
    container["ciphertext"] = "".join(ct_list)

    with pytest.raises(IntegrityError, match="Signature verification failed"):
        decrypt_hybrid(
            container=container,
            user_id="bob",
            private_key=env["bob_enc"]["private_key"],
            trusted_signers=env["trusted_signers"],
        )


def test_scenario_c_modified_metadata_rejected(crypto_environment):
    """
    Escenario C: Metadata modificada -> Rechazado antes de descifrar.
    Alterar campos informativos (e.g. filename o timestamp) invalida el payload firmado.
    """
    env = crypto_environment
    container = encrypt_hybrid(
        file_bytes=env["payload"],
        filename=env["filename"],
        recipients=env["recipients_map"],
        signing_private_key=env["signer_alice"]["private_key"],
    )

    # Alterar metadatos cubiertos por la firma
    container["metadata"]["filename"] = "archivo_falsificado.pdf"

    with pytest.raises(IntegrityError, match="Signature verification failed"):
        decrypt_hybrid(
            container=container,
            user_id="bob",
            private_key=env["bob_enc"]["private_key"],
            trusted_signers=env["trusted_signers"],
        )


def test_scenario_d_wrong_public_key_rejected(crypto_environment):
    """
    Escenario D: Llave publica incorrecta / no confiable -> Rechazado.
    1. Firma valida evaluada con una llave publica incorrecta (wrong public key).
    2. Documento firmado por un emisor ausente en el registro trusted_signers.
    """
    env = crypto_environment

    # Caso 1: Firma legitima de Alice evaluada con una llave publica erronea (la de Eve)
    container_alice = encrypt_hybrid(
        file_bytes=env["payload"],
        filename=env["filename"],
        recipients=env["recipients_map"],
        signing_private_key=env["signer_alice"]["private_key"],
    )

    wrong_key_registry = {
        env["signer_alice"]["signer_id"]: env["signer_eve"]["public_key"]
    }

    with pytest.raises(IntegrityError, match="Signature verification failed"):
        decrypt_hybrid(
            container=container_alice,
            user_id="bob",
            private_key=env["bob_enc"]["private_key"],
            trusted_signers=wrong_key_registry,
        )

    # Caso 2: Contenedor firmado por emisor fuera del registro de confianza
    container_eve = encrypt_hybrid(
        file_bytes=env["payload"],
        filename=env["filename"],
        recipients=env["recipients_map"],
        signing_private_key=env["signer_eve"]["private_key"],
    )

    with pytest.raises(IntegrityError, match="Unknown or untrusted document signer"):
        decrypt_hybrid(
            container=container_eve,
            user_id="bob",
            private_key=env["bob_enc"]["private_key"],
            trusted_signers=env["trusted_signers"],
        )


def test_scenario_e_signature_removed_rejected(crypto_environment):
    """
    Escenario E: Firma removida -> Rechazado.
    Un contenedor que omita el campo 'signature' o 'signer_id' debe ser rechazado inmediatamente.
    """
    env = crypto_environment
    container = encrypt_hybrid(
        file_bytes=env["payload"],
        filename=env["filename"],
        recipients=env["recipients_map"],
        signing_private_key=env["signer_alice"]["private_key"],
    )

    # Remover firma (simulando degradacion a contenedor D3 sin firmar)
    container_sin_firma = copy.deepcopy(container)
    del container_sin_firma["signature"]

    with pytest.raises(IntegrityError, match="Invalid or unsigned D5 container"):
        decrypt_hybrid(
            container=container_sin_firma,
            user_id="bob",
            private_key=env["bob_enc"]["private_key"],
            trusted_signers=env["trusted_signers"],
        )

    # Remover signer_id
    container_sin_signer = copy.deepcopy(container)
    del container_sin_signer["signer_id"]

    with pytest.raises(IntegrityError, match="Invalid or unsigned D5 container"):
        decrypt_hybrid(
            container=container_sin_signer,
            user_id="bob",
            private_key=env["bob_enc"]["private_key"],
            trusted_signers=env["trusted_signers"],
        )


# ==============================================================================
# PRUEBAS DE PERSISTENCIA Y NO-DESCIFRADO
# ==============================================================================

def test_json_serialization_roundtrip(crypto_environment):
    """Verifica que el contenedor firmado resista la serializacion y deserializacion JSON real."""
    env = crypto_environment
    container = encrypt_hybrid(
        file_bytes=env["payload"],
        filename=env["filename"],
        recipients=env["recipients_map"],
        signing_private_key=env["signer_alice"]["private_key"],
    )

    # Simular persistencia a disco (JSON dump/load)
    json_str = json.dumps(container)
    loaded_container = json.loads(json_str)

    recovered = decrypt_hybrid(
        container=loaded_container,
        user_id="alice",
        private_key=env["alice_enc"]["private_key"],
        trusted_signers=env["trusted_signers"],
    )
    assert recovered == env["payload"], "Fallo de descifrado tras ciclo JSON dump/load."


def test_invalid_signature_bytes_fails_closed(crypto_environment):
    """Verifica que una firma corrupta aborte la ejecucion antes de intentar descifrar el DEK."""
    env = crypto_environment
    container = encrypt_hybrid(
        file_bytes=env["payload"],
        filename=env["filename"],
        recipients=env["recipients_map"],
        signing_private_key=env["signer_alice"]["private_key"],
    )

    # Alterar un caracter hex de la firma manteniendo el tamano intacto
    sig_list = list(container["signature"])
    sig_list[0] = "0" if sig_list[0] != "0" else "1"
    container["signature"] = "".join(sig_list)

    with pytest.raises(IntegrityError, match="Signature verification failed"):
        decrypt_hybrid(
            container=container,
            user_id="bob",
            private_key=env["bob_enc"]["private_key"],
            trusted_signers=env["trusted_signers"],
        )