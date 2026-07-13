"""Analizador de fortaleza de contraseñas."""

from __future__ import annotations

import math
import re
from dataclasses import dataclass


@dataclass
class PasswordAnalysis:
    """Resultado del análisis de una contraseña."""
    password_length: int
    entropy_bits: float
    strength: str           # "Muy débil", "Débil", "Media", "Fuerte", "Muy fuerte"
    has_lowercase: bool
    has_uppercase: bool
    has_digits: bool
    has_special: bool
    estimated_crack_time: str


# Diccionario de caracteres por categoría
LOWERCASE = "abcdefghijklmnopqrstuvwxyz"
UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
DIGITS = "0123456789"
SPECIAL = "!@#$%^&*()_+-=[]{}|;:',.<>?/"


def analyze_password(password: str) -> PasswordAnalysis:
    """Analiza la fortaleza de una contraseña."""
    has_lower = any(c in LOWERCASE for c in password)
    has_upper = any(c in UPPERCASE for c in password)
    has_digit = any(c in DIGITS for c in password)
    has_special = any(c in SPECIAL for c in password)

    # Calcular pool de caracteres
    pool_size = 0
    if has_lower:
        pool_size += 26
    if has_upper:
        pool_size += 26
    if has_digit:
        pool_size += 10
    if has_special:
        pool_size += len(SPECIAL)

    if pool_size == 0:
        pool_size = 1  # Evitar log(0)

    entropy = len(password) * math.log2(pool_size)

    # Clasificar fortaleza
    if entropy < 28:
        strength = "Muy débil"
    elif entropy < 36:
        strength = "Débil"
    elif entropy < 60:
        strength = "Media"
    elif entropy < 80:
        strength = "Fuerte"
    else:
        strength = "Muy fuerte"

    # Estimar tiempo de crack (asumiendo 10Billones de intentos/segundo)
    combinations = pool_size ** len(password)
    seconds = combinations / 10_000_000_000_000
    crack_time = _format_time(seconds)

    return PasswordAnalysis(
        password_length=len(password),
        entropy_bits=round(entropy, 2),
        strength=strength,
        has_lowercase=has_lower,
        has_uppercase=has_upper,
        has_digits=has_digit,
        has_special=has_special,
        estimated_crack_time=crack_time,
    )


def _format_time(seconds: float) -> str:
    """Formatea segundos a tiempo legible."""
    if seconds < 0.001:
        return "instantáneo"
    elif seconds < 60:
        return f"{seconds:.1f} segundos"
    elif seconds < 3600:
        return f"{seconds / 60:.1f} minutos"
    elif seconds < 86400:
        return f"{seconds / 3600:.1f} horas"
    elif seconds < 86400 * 365:
        return f"{seconds / 86400:.1f} días"
    elif seconds < 86400 * 365 * 1000:
        return f"{seconds / (86400 * 365):.1f} años"
    elif seconds < 86400 * 365 * 1_000_000:
        return f"{seconds / (86400 * 365 * 1000):.1f} mil años"
    else:
        return f"{seconds / (86400 * 365 * 1_000_000):.1f} millones de años"
