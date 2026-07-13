"""Tests para entropy."""

from crypto_toolkit.utils.entropy import calculate_entropy, entropy_rating


def test_entropy_vacia():
    assert calculate_entropy("") == 0.0


def test_entropy_repetida():
    assert calculate_entropy("aaaa") == 0.0


def test_entropy_alta():
    e = calculate_entropy("abcdefghij12345!@#$%")
    assert e > 3.0


def test_entropy_rating():
    assert entropy_rating(1.0) == "Muy baja"
    assert entropy_rating(7.0) == "Alta"
    assert entropy_rating(8.0) == "Muy alta"
