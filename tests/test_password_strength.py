"""Tests para password_strength."""

from crypto_toolkit.analysis.password_strength import analyze_password


def test_password_debil():
    result = analyze_password("123")
    assert result.strength in ("Muy débil", "Débil")
    assert result.entropy_bits < 30


def test_password_fuerte():
    result = analyze_password("MyStr0ng!P@ssw0rd#2026")
    assert result.strength in ("Fuerte", "Muy fuerte")
    assert result.entropy_bits > 60


def test_password_features():
    result = analyze_password("Abc123!")
    assert result.has_lowercase is True
    assert result.has_uppercase is True
    assert result.has_digits is True
    assert result.has_special is True


def test_crack_time():
    result = analyze_password("a")
    assert result.estimated_crack_time != ""
