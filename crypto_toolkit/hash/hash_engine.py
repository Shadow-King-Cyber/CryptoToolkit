"""Motor de hashing — genera hashes con múltiples algoritmos."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass


SUPPORTED_ALGORITHMS = ["md5", "sha1", "sha256", "sha512"]


@dataclass
class HashResult:
    """Resultado de una operación de hashing."""
    algorithm: str
    hash_value: str
    input_size: int


def compute_hash(data: str | bytes, algorithm: str = "sha256") -> HashResult:
    """Calcula el hash de datos usando el algoritmo especificado."""
    if isinstance(data, str):
        data = data.encode("utf-8")

    algorithm = algorithm.lower()
    if algorithm not in SUPPORTED_ALGORITHMS:
        raise ValueError(f"Algoritmo no soportado: {algorithm}. Use: {SUPPORTED_ALGORITHMS}")

    h = hashlib.new(algorithm)
    h.update(data)

    return HashResult(
        algorithm=algorithm,
        hash_value=h.hexdigest(),
        input_size=len(data),
    )


def compute_file_hash(file_path: str, algorithm: str = "sha256") -> HashResult:
    """Calcula el hash de un archivo."""
    h = hashlib.new(algorithm)
    size = 0
    with open(file_path, "rb") as fh:
        for chunk in iter(lambda: fh.read(8192), b""):
            h.update(chunk)
            size += len(chunk)

    return HashResult(
        algorithm=algorithm,
        hash_value=h.hexdigest(),
        input_size=size,
    )


def compute_all_hashes(data: str | bytes) -> list[HashResult]:
    """Calcula hashes con todos los algoritmos soportados."""
    return [compute_hash(data, algo) for algo in SUPPORTED_ALGORITHMS]
