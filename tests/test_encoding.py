"""Tests para encoding."""

from crypto_toolkit.cipher.encoding import (
    base64_encode, base64_decode, hex_encode, hex_decode,
    url_encode, url_decode, rot13, rot47,
)


def test_base64_roundtrip():
    encoded = base64_encode("hola mundo")
    decoded = base64_decode(encoded)
    assert decoded == "hola mundo"


def test_hex_roundtrip():
    encoded = hex_encode("test")
    decoded = hex_decode(encoded)
    assert decoded == "test"


def test_url_roundtrip():
    encoded = url_encode("param=valor&key=123")
    decoded = url_decode(encoded)
    assert decoded == "param=valor&key=123"


def test_rot13():
    result = rot13("hello")
    assert rot13(result) == "hello"


def test_rot47():
    result = rot47("Hello!")
    assert rot47(result) == "Hello!"
