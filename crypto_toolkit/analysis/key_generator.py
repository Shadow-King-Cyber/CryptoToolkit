"""Generador de claves — genera claves aleatorias seguras."""

from __future__ import annotations

import os
import base64
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


@dataclass
class KeyResult:
    """Resultado de generación de clave."""
    key_type: str
    key_value: str
    bits: int


def generate_aes_key(bits: int = 256) -> KeyResult:
    """Genera una clave AES aleatoria."""
    key = os.urandom(bits // 8)
    return KeyResult(
        key_type="AES",
        key_value=base64.b64encode(key).decode("ascii"),
        bits=bits,
    )


def generate_fernet_key() -> KeyResult:
    """Genera una clave Fernet para cifrado simétrico."""
    from cryptography.fernet import Fernet
    key = Fernet.generate_key()
    return KeyResult(
        key_type="Fernet",
        key_value=key.decode("ascii"),
        bits=256,
    )


def generate_rsa_keypair(bits: int = 2048) -> tuple[KeyResult, KeyResult]:
    """Genera un par de claves RSA."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=bits,
        backend=default_backend(),
    )
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")

    return (
        KeyResult(key_type="RSA-Private", key_value=private_pem, bits=bits),
        KeyResult(key_type="RSA-Public", key_value=public_pem, bits=bits),
    )


def generate_ecc_keypair() -> tuple[KeyResult, KeyResult]:
    """Genera un par de claves ECC (P-256)."""
    private_key = ec.generate_private_key(ec.SECP256R1(), backend=default_backend())
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")

    return (
        KeyResult(key_type="ECC-Private", key_value=private_pem, bits=256),
        KeyResult(key_type="ECC-Public", key_value=public_pem, bits=256),
    )


def generate_random_bytes(length: int = 32) -> KeyResult:
    """Genera bytes aleatorios y los devuelve en Base64."""
    data = os.urandom(length)
    return KeyResult(
        key_type="Random",
        key_value=base64.b64encode(data).decode("ascii"),
        bits=length * 8,
    )
