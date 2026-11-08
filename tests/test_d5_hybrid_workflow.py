"""D5 end-to-end checks for Armando's fail-closed integration.

These tests use real ECIES/secp256k1 and AES-GCM in the project environment.
They complement, rather than replace, Jonathan's acceptance/QA suite.
"""
import copy

import pytest

pytest.importorskip("ecies")
pytest.importorskip("coincurve")

from src.crypto.hybrid_vault import IntegrityError, decrypt_hybrid, encrypt_hybrid
from src.crypto.key_manager import ECIESKeyManager
from src.crypto.signature_manager import generate_key_pair


@pytest.fixture
def signed_document():
    alice = ECIESKeyManager.generate_key_pair()
    bob = ECIESKeyManager.generate_key_pair()
    sender = generate_key_pair()
    recipients = {"alice": alice["public_key"], "bob": bob["public_key"]}
    trusted = {sender["signer_id"]: sender["public_key"]}

    plaintext = b"Documento firmado D5 - prueba de integracion"
    container = encrypt_hybrid(
        plaintext, "contrato.pdf", recipients,
        signing_private_key=sender["private_key"],
    )
    return container, plaintext, alice, bob, sender, trusted


def test_A_valid_signature_and_both_recipients(signed_document):
    container, plaintext, alice, bob, sender, trusted = signed_document
    assert container["signer_id"] == sender["signer_id"]
    assert len(bytes.fromhex(container["signature"])) == 64
    assert decrypt_hybrid(container, "alice", alice["private_key"], trusted_signers=trusted) == plaintext
    assert decrypt_hybrid(container, "bob", bob["private_key"], trusted_signers=trusted) == plaintext


@pytest.mark.parametrize("field", ["ciphertext", "nonce", "tag"])
def test_B_ciphertext_nonce_tag_tampering_rejected(signed_document, field):
    container, _, alice, _, _, trusted = signed_document
    modified = copy.deepcopy(container)
    raw = modified[field]
    modified[field] = ("f" if raw[0] != "f" else "e") + raw[1:]
    with pytest.raises(IntegrityError, match="Signature verification failed"):
        decrypt_hybrid(modified, "alice", alice["private_key"], trusted_signers=trusted)


@pytest.mark.parametrize("kind", ["filename", "timestamp", "recipients", "reorder"])
def test_C_modified_metadata_or_recipients_rejected(signed_document, kind):
    container, _, alice, _, _, trusted = signed_document
    modified = copy.deepcopy(container)
    if kind == "filename":
        modified["metadata"]["filename"] = "falso.pdf"
    elif kind == "timestamp":
        modified["metadata"]["creation_timestamp"] = "2026-01-01T00:00:00+00:00"
    elif kind == "recipients":
        modified["recipients"][0]["encrypted_key"] = "aa"
    else:
        modified["recipients"].reverse()
    with pytest.raises(IntegrityError, match="Signature verification failed"):
        decrypt_hybrid(modified, "alice", alice["private_key"], trusted_signers=trusted)


def test_D_wrong_public_key_rejected(signed_document):
    container, _, alice, _, sender, trusted = signed_document
    other = generate_key_pair()
    false_registry = {sender["signer_id"]: other["public_key"]}
    with pytest.raises(IntegrityError, match="Signature verification failed"):
        decrypt_hybrid(container, "alice", alice["private_key"], trusted_signers=false_registry)


def test_D_untrusted_signer_rejected(signed_document):
    container, _, alice, _, _, trusted = signed_document
    attacker = generate_key_pair()
    unrelated_registry = {attacker["signer_id"]: attacker["public_key"]}
    with pytest.raises(IntegrityError, match="Unknown or untrusted"):
        decrypt_hybrid(container, "alice", alice["private_key"], trusted_signers=unrelated_registry)


def test_E_removed_signature_rejected(signed_document):
    container, _, alice, _, _, trusted = signed_document
    modified = copy.deepcopy(container)
    del modified["signature"]
    with pytest.raises(IntegrityError, match="Invalid or unsigned"):
        decrypt_hybrid(modified, "alice", alice["private_key"], trusted_signers=trusted)


def test_required_signing_key_and_registry(signed_document):
    container, _, alice, _, _, _ = signed_document
    with pytest.raises(TypeError, match="signing_private_key"):
        encrypt_hybrid(b"x", "file.txt", {"alice": alice["public_key"]})
    with pytest.raises(TypeError, match="trusted_signers"):
        decrypt_hybrid(container, "alice", alice["private_key"])
    with pytest.raises(IntegrityError, match="trusted signer registry"):
        decrypt_hybrid(container, "alice", alice["private_key"], trusted_signers={})


def test_invalid_signature_stops_before_dek_unwrap(signed_document, monkeypatch):
    # Fail-closed proof: tampering never invokes the ECIES DEK-unwrapping step.
    from src.crypto import hybrid_vault

    container, _, alice, _, _, trusted = signed_document
    modified = copy.deepcopy(container)
    modified["metadata"]["filename"] = "tampered.pdf"
    calls = []

    def forbidden_decrypt(*args, **kwargs):
        calls.append((args, kwargs))
        raise AssertionError("ECIES decryption must not be called for invalid signatures")

    monkeypatch.setattr(hybrid_vault, "ecies_decrypt", forbidden_decrypt)
    with pytest.raises(IntegrityError, match="Signature verification failed"):
        decrypt_hybrid(modified, "alice", alice["private_key"], trusted_signers=trusted)
    assert calls == []


def test_valid_signature_then_authorization_is_enforced(signed_document):
    container, _, _, _, _, trusted = signed_document
    outsider = ECIESKeyManager.generate_key_pair()
    with pytest.raises(ValueError, match="not authorized"):
        decrypt_hybrid(container, "mallory", outsider["private_key"], trusted_signers=trusted)


def test_self_signed_attacker_not_trusted(signed_document):
    container, _, alice, _, sender, _ = signed_document
    # Possessing an Ed25519 key is not proof of the claimed trusted identity.
    attacker = generate_key_pair()
    fake = encrypt_hybrid(
        b"fake", "invoice.pdf",
        {"alice": alice["public_key"], "bob": ECIESKeyManager.generate_key_pair()["public_key"]},
        signing_private_key=attacker["private_key"],
    )
    with pytest.raises(IntegrityError, match="Unknown or untrusted"):
        decrypt_hybrid(fake, "alice", alice["private_key"],
                       trusted_signers={sender["signer_id"]: sender["public_key"]})
