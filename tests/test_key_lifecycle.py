"""Tests de src/crypto/key_lifecycle.py (D6: ciclo de vida de llaves)."""

import json
from datetime import datetime, timedelta, timezone

import pytest

from src.crypto.secure_keystore import decrypt_private_key, load_keystore
from src.crypto.key_lifecycle import (
    KeyLifecycleError,
    build_trusted_signers,
    check_key_usable,
    generate_key,
    get_active_key,
    handle_compromise,
    load_registry,
    revoke_key,
    rotate_key,
)

PASSWORD = "StrongPass!2026"
RAPIDO = {"scrypt_n": 16384}  # para que los tests no tarden
T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)


@pytest.fixture
def env(tmp_path):
    return tmp_path / "registry.json", tmp_path / "keystores"


def gen(env, user="alice", algo="secp256k1", **kw):
    return generate_key(env[0], user, algo, PASSWORD, env[1], now=T0, **RAPIDO, **kw)


def rot(env, days=30, algo="secp256k1"):
    return rotate_key(env[0], "alice", algo, PASSWORD, env[1], now=T0 + timedelta(days=days), **RAPIDO)


def test_generate_registers_key_and_stores_no_secrets(env):
    entry = gen(env)
    assert entry["status"] == "active"
    private_hex = decrypt_private_key(
        load_keystore(env[1] / entry["keystore_file"]), PASSWORD, expected_key_id=entry["key_id"]
    )
    texto = env[0].read_text(encoding="utf-8")
    assert private_hex not in texto and PASSWORD not in texto
    assert load_registry(env[0])["keys"][entry["key_id"]] == entry


def test_only_one_active_key_per_user_and_algorithm(env):
    gen(env)
    with pytest.raises(KeyLifecycleError, match="rotate_key"):
        gen(env)
    gen(env, algo="Ed25519")
    gen(env, user="bob")


def test_rotation_retires_old_key_but_it_still_decrypts(env):
    old = gen(env)
    new = rot(env)
    registry = load_registry(env[0])
    assert registry["keys"][old["key_id"]]["status"] == "retired"
    assert get_active_key(registry, "alice", "secp256k1", now=T0)["key_id"] == new["key_id"]
    assert check_key_usable(registry, old["key_id"], "decrypt", now=T0)
    with pytest.raises(KeyLifecycleError, match="retired"):
        check_key_usable(registry, old["key_id"], "encrypt_to", now=T0)
    with pytest.raises(KeyLifecycleError, match="generate_key"):
        rotate_key(env[0], "bob", "secp256k1", PASSWORD, env[1], **RAPIDO)


def test_expired_key_cannot_encrypt_but_can_decrypt(env):
    entry = gen(env, validity_days=10)
    registry = load_registry(env[0])
    tarde = T0 + timedelta(days=11)
    with pytest.raises(KeyLifecycleError, match="expired"):
        check_key_usable(registry, entry["key_id"], "encrypt_to", now=tarde)
    with pytest.raises(KeyLifecycleError, match="expired"):
        get_active_key(registry, "alice", "secp256k1", now=tarde)
    assert check_key_usable(registry, entry["key_id"], "decrypt", now=tarde)


def test_revoked_key_is_denied_except_recovery_decrypt(env):
    entry = gen(env)
    revoke_key(env[0], entry["key_id"], "laptop stolen", now=T0)
    registry = load_registry(env[0])
    for purpose in ("encrypt_to", "decrypt"):
        with pytest.raises(KeyLifecycleError, match="revoked"):
            check_key_usable(registry, entry["key_id"], purpose, now=T0)
    assert check_key_usable(registry, entry["key_id"], "decrypt", now=T0, recovery=True)
    with pytest.raises(KeyLifecycleError, match="already revoked"):
        revoke_key(env[0], entry["key_id"], "again")


def test_revocation_requires_a_reason(env):
    entry = gen(env)
    with pytest.raises(KeyLifecycleError, match="reason"):
        revoke_key(env[0], entry["key_id"], "  ")


def test_purpose_must_match_algorithm(env):
    enc, sig = gen(env), gen(env, algo="Ed25519")
    registry = load_registry(env[0])
    with pytest.raises(KeyLifecycleError, match="not valid"):
        check_key_usable(registry, enc["key_id"], "sign", now=T0)
    with pytest.raises(KeyLifecycleError, match="not valid"):
        check_key_usable(registry, sig["key_id"], "encrypt_to", now=T0)


def test_compromise_revokes_and_replaces_active_key(env):
    old = gen(env)
    result = handle_compromise(env[0], old["key_id"], "malware", PASSWORD, env[1], now=T0, **RAPIDO)
    registry = load_registry(env[0])
    assert result["revoked"]["status"] == "revoked"
    assert result["replacement"]["status"] == "active"
    assert get_active_key(registry, "alice", "secp256k1", now=T0)["key_id"] == result["replacement"]["key_id"]
    assert result["actions_required"]


def test_trusted_signers_have_active_and_retired_but_not_revoked(env):
    first = gen(env, algo="Ed25519")
    second = rot(env, algo="Ed25519")
    bob = gen(env, user="bob", algo="Ed25519")
    gen(env)  # secp256k1 nunca firma
    revoke_key(env[0], bob["key_id"], "left the team", now=T0)
    trusted = build_trusted_signers(load_registry(env[0]), now=T0)
    assert trusted == {first["key_id"]: first["public_key"], second["key_id"]: second["public_key"]}


def test_tampered_registry_is_rejected(env):
    entry = gen(env)
    registro = json.loads(env[0].read_text(encoding="utf-8"))
    originales = env[0].read_text(encoding="utf-8")
    cambios = [("status", "zombie"), ("keystore_file", "../evil.json"), ("public_key", "02" + "11" * 32)]
    for campo, valor in cambios:
        malo = json.loads(originales)
        malo["keys"][entry["key_id"]][campo] = valor
        env[0].write_text(json.dumps(malo), encoding="utf-8")
        with pytest.raises(KeyLifecycleError):
            load_registry(env[0])
    env[0].write_text("{oops", encoding="utf-8")
    with pytest.raises(KeyLifecycleError, match="parse"):
        gen(env, user="bob")  # no arranca un registro nuevo encima de uno corrupto


def test_invalid_inputs_leave_no_files(env):
    for user, algo, dias in (("bad user!", "secp256k1", 365), ("alice", "RSA", 365), ("alice", "secp256k1", 0)):
        with pytest.raises(KeyLifecycleError):
            generate_key(env[0], user, algo, PASSWORD, env[1], validity_days=dias, **RAPIDO)
    assert not env[0].exists()
    assert not env[1].exists() or not list(env[1].iterdir())
