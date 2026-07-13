"""Encodings — Base64, Hex, URL encoding, ROT13."""

from __future__ import annotations

import base64
import codecs
from urllib.parse import quote, unquote


def base64_encode(data: str | bytes) -> str:
    """Codifica datos en Base64."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return base64.b64encode(data).decode("ascii")


def base64_decode(encoded: str) -> str:
    """Decodifica datos de Base64."""
    return base64.b64decode(encoded).decode("utf-8")


def hex_encode(data: str | bytes) -> str:
    """Codifica datos en hexadecimal."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return data.hex()


def hex_decode(encoded: str) -> str:
    """Decodifica datos de hexadecimal."""
    return bytes.fromhex(encoded).decode("utf-8")


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
