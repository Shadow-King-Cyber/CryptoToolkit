"""Tests para asymmetric cipher."""

from crypto_toolkit.cipher.asymmetric import (
    generate_rsa_keypair, rsa_encrypt, rsa_decrypt, generate_ecc_keypair
)


def test_rsa_encrypt_decrypt():
    kp = generate_rsa_keypair(2048)
    data = b"mensaje RSA"
    encrypted = rsa_encrypt(data, kp.public_key_pem)
    decrypted = rsa_decrypt(encrypted, kp.private_key_pem)
    assert decrypted == data


def test_rsa_keypair_sizes():
    kp = generate_rsa_keypair(2048)
    assert kp.key_size == 2048
    assert len(kp.private_key_pem) > 0
    assert len(kp.public_key_pem) > 0


def test_ecc_keypair():
    priv, pub = generate_ecc_keypair()
    assert len(priv) > 0
    assert len(pub) > 0
    assert "PRIVATE" in priv.decode()
    assert "PUBLIC" in pub.decode()
