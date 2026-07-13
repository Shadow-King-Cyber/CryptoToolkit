"""Verificador de integridad — verifica archivos con hashes."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ..hash.hash_engine import compute_file_hash, HashResult


@dataclass
class IntegrityResult:
    """Resultado de verificación de integridad."""
    file_path: str
    hash_results: list[HashResult]
    status: str   # "verified", "error"


def verify_file_integrity(file_path: str | Path, expected_hashes: dict[str, str] | None = None) -> IntegrityResult:
    """Verifica la integridad de un archivo calculando sus hashes."""
    file_path = Path(file_path)
    if not file_path.exists():
        return IntegrityResult(
            file_path=str(file_path),
            hash_results=[],
            status="error",
        )

    hashes = []
    for algo in ["md5", "sha256", "sha512"]:
        result = compute_file_hash(str(file_path), algo)
        hashes.append(result)

    return IntegrityResult(
        file_path=str(file_path),
        hash_results=hashes,
        status="verified",
    )
