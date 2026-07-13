"""Cifrado simétrico — AES, ChaCha20, 3DES, Blowfish."""

from __future__ import annotations

import os
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend


@dataclass
class CipherResult:
    """Resultado de operación de cifrado/descifrado."""
    algorithm: str
    ciphertext: bytes
    key: bytes
    iv: bytes
    mode: str


def encrypt_aes(data: bytes, key: bytes | None = None) -> CipherResult:
    """Cifra datos con AES-256-CBC."""
    if key is None:
        key = os.urandom(32)
    iv = os.urandom(16)

    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(padded) + encryptor.finalize()

    return CipherResult(algorithm="AES-256-CBC", ciphertext=ct, key=key, iv=iv, mode="CBC")


def decrypt_aes(result: CipherResult) -> bytes:
    """Descifra datos con AES-256-CBC."""
    cipher = Cipher(algorithms.AES(result.key), modes.CBC(result.iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(result.ciphertext) + decryptor.finalize()

    unpadder = sym_padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def encrypt_chacha20(data: bytes, key: bytes | None = None) -> CipherResult:
    """Cifra datos con ChaCha20."""
    if key is None:
        key = os.urandom(32)
    nonce = os.urandom(16)

    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(data) + encryptor.finalize()

    return CipherResult(algorithm="ChaCha20", ciphertext=ct, key=key, iv=nonce, mode="stream")


def decrypt_chacha20(result: CipherResult) -> bytes:
    """Descifra datos con ChaCha20."""
    cipher = Cipher(algorithms.ChaCha20(result.key, result.iv), mode=None, backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(result.ciphertext) + decryptor.finalize()
