"""Cracker de hashes — fuerza bruta / diccionario contra hashes."""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass


@dataclass
class CrackResult:
    """Resultado de un intento de cracking."""
    found: bool
    original_hash: str
    cracked_value: str | None
    algorithm: str
    attempts: int
    elapsed_seconds: float


def crack_hash(
    target_hash: str,
    algorithm: str,
    wordlist: list[str],
) -> CrackResult:
    """Intenta crackear un hash usando fuerza bruta con wordlist."""
    target_hash = target_hash.lower()
    start = time.monotonic()
    attempts = 0

    for word in wordlist:
        attempts += 1
        h = hashlib.new(algorithm)
        h.update(word.encode("utf-8"))
        if h.hexdigest().lower() == target_hash:
            elapsed = time.monotonic() - start
            return CrackResult(
                found=True,
                original_hash=target_hash,
                cracked_value=word,
                algorithm=algorithm,
                attempts=attempts,
                elapsed_seconds=elapsed,
            )

    elapsed = time.monotonic() - start
    return CrackResult(
        found=False,
        original_hash=target_hash,
        cracked_value=None,
        algorithm=algorithm,
        attempts=attempts,
        elapsed_seconds=elapsed,
    )


def crack_with_charset(
    target_hash: str,
    algorithm: str,
    charset: str = "abcdefghijklmnopqrstuvwxyz0123456789",
    max_length: int = 4,
) -> CrackResult:
    """Intenta crackear un hash con fuerza bruta de charset."""
    import itertools
    target_hash = target_hash.lower()
    start = time.monotonic()
    attempts = 0

    for length in range(1, max_length + 1):
        for combo in itertools.product(charset, repeat=length):
            attempts += 1
            candidate = "".join(combo)
            h = hashlib.new(algorithm)
            h.update(candidate.encode("utf-8"))
            if h.hexdigest().lower() == target_hash:
                elapsed = time.monotonic() - start
                return CrackResult(
                    found=True,
                    original_hash=target_hash,
                    cracked_value=candidate,
                    algorithm=algorithm,
                    attempts=attempts,
                    elapsed_seconds=elapsed,
                )

    elapsed = time.monotonic() - start
    return CrackResult(
        found=False,
        original_hash=target_hash,
        cracked_value=None,
        algorithm=algorithm,
        attempts=attempts,
        elapsed_seconds=elapsed,
    )
