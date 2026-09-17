"""Encodings — Base64, Hex, URL encoding, ROT13."""

from __future__ import annotations

import base64
import binascii
import codecs
from urllib.parse import quote, unquote


def base64_encode(data: str | bytes) -> str:
    """Codifica datos en Base64."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return base64.b64encode(data).decode("ascii")


def base64_decode(encoded: str) -> str:
    """Decodifica datos de Base64."""
    try:
        return base64.b64decode(encoded).decode("utf-8")
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"Entrada no es Base64 válido: {exc}") from exc


def hex_encode(data: str | bytes) -> str:
    """Codifica datos en hexadecimal."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return data.hex()


def hex_decode(encoded: str) -> str:
    """Decodifica datos de hexadecimal."""
    try:
        return bytes.fromhex(encoded).decode("utf-8")
    except ValueError as exc:
        raise ValueError(f"Entrada no es hexadecimal válido: {exc}") from exc


def url_encode(data: str) -> str:
    """Codifica datos para URL."""
    return quote(data, safe="")


def url_decode(encoded: str) -> str:
    """Decodifica datos de URL."""
    return unquote(encoded)


def rot13(data: str) -> str:
    """Aplica ROT13 a un string."""
    return codecs.encode(data, "rot_13")


def rot47(data: str) -> str:
    """Aplica ROT47 a un string."""
    result = []
    for c in data:
        code = ord(c)
        if 33 <= code <= 126:
            result.append(chr(33 + ((code - 33 + 47) % 94)))
        else:
            result.append(c)
    return "".join(result)
