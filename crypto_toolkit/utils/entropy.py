"""Calculadora de entropía de Shannon."""

from __future__ import annotations

import math
from collections import Counter


def calculate_entropy(data: str | bytes) -> float:
    """Calcula la entropía de Shannon de los datos.

    Returns:
        Entropía en bits por símbolo (0.0 a 8.0 para bytes).
    """
    if not data:
        return 0.0

    if isinstance(data, str):
        data = data.encode("utf-8")

    counts = Counter(data)
    length = len(data)
    entropy = 0.0

    for count in counts.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)

    return entropy


def calculate_string_entropy(data: str) -> float:
    """Calcula entropía de un string (caracteres ASCII)."""
    return calculate_entropy(data.encode("utf-8"))


def entropy_rating(entropy: float) -> str:
    """Clasifica el nivel de entropía."""
    if entropy < 2.0:
        return "Muy baja"
    elif entropy < 4.0:
        return "Baja"
    elif entropy < 6.0:
        return "Media"
    elif entropy < 7.5:
        return "Alta"
    else:
        return "Muy alta"
