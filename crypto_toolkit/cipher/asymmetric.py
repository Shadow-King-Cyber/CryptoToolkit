"""Cifrado asimétrico — RSA, ECC."""

from __future__ import annotations

from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding as asym_padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend


@dataclass
class RSAKeyPair:
    """Par de claves RSA."""
    private_key_pem: bytes
    public_key_pem: bytes
    key_size: int


@dataclass
class RSAEncryptResult:
    """Resultado de cifrado RSA."""
    ciphertext: bytes
    key_size: int


def generate_rsa_keypair(key_size: int = 2048) -> RSAKeyPair:
    """Genera un par de claves RSA."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend(),
    )
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    return RSAKeyPair(
        private_key_pem=private_pem,
        public_key_pem=public_pem,
        key_size=key_size,
    )


def rsa_encrypt(data: bytes, public_key_pem: bytes) -> RSAEncryptResult:
    """Cifra datos con RSA-OAEP."""
    public_key = serialization.load_pem_public_key(public_key_pem, backend=default_backend())
    ciphertext = public_key.encrypt(
        data,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return RSAEncryptResult(ciphertext=ciphertext, key_size=public_key.key_size)


def rsa_decrypt(result: RSAEncryptResult, private_key_pem: bytes) -> bytes:
    """Descifra datos con RSA-OAEP."""
    private_key = serialization.load_pem_private_key(
        private_key_pem, password=None, backend=default_backend()
    )
    return private_key.decrypt(
        result.ciphertext,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def generate_ecc_keypair() -> tuple[bytes, bytes]:
    """Genera un par de claves ECC (ECDSA P-256)."""
    private_key = ec.generate_private_key(ec.SECP256R1(), backend=default_backend())
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    return private_pem, public_pem
