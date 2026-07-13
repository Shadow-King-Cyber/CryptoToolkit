"""Tests para symmetric cipher."""

from crypto_toolkit.cipher.symmetric import (
    encrypt_aes, decrypt_aes, encrypt_chacha20, decrypt_chacha20
)


def test_aes_encrypt_decrypt():
    data = b"mensaje secreto AES"
    encrypted = encrypt_aes(data)
    decrypted = decrypt_aes(encrypted)
    assert decrypted == data


def test_aes_custom_key():
    import os
    key = os.urandom(32)
    data = b"con clave personalizada"
    encrypted = encrypt_aes(data, key)
    assert encrypted.key == key
    decrypted = decrypt_aes(encrypted)
    assert decrypted == data


def test_chacha20_encrypt_decrypt():
    data = b"mensaje secreto ChaCha20"
    encrypted = encrypt_chacha20(data)
    decrypted = decrypt_chacha20(encrypted)
    assert decrypted == data
