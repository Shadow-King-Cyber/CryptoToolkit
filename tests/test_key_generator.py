"""Tests para key_generator."""

from crypto_toolkit.analysis.key_generator import (
    generate_aes_key, generate_fernet_key, generate_rsa_keypair, generate_random_bytes
)


def test_aes_key():
    result = generate_aes_key(256)
    assert result.key_type == "AES"
    assert result.bits == 256
    assert len(result.key_value) > 0


def test_fernet_key():
    result = generate_fernet_key()
    assert result.key_type == "Fernet"


def test_rsa_keypair():
    priv, pub = generate_rsa_keypair(2048)
    assert priv.key_type == "RSA-Private"
    assert pub.key_type == "RSA-Public"


def test_random_bytes():
    result = generate_random_bytes(32)
    assert result.key_type == "Random"
    assert result.bits == 256
