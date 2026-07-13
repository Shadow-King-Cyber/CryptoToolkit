"""Tests para hash_cracker."""

from crypto_toolkit.hash.hash_cracker import crack_hash, crack_with_charset


def test_crack_hash_found():
    wordlist = ["password", "admin", "123456", "hello"]
    result = crack_hash("5d41402abc4b2a76b9719d911017c592", "md5", wordlist)
    assert result.found is True
    assert result.cracked_value == "hello"


def test_crack_hash_not_found():
    wordlist = ["a", "b", "c"]
    result = crack_hash("5d41402abc4b2a76b9719d911017c592", "md5", wordlist)
    assert result.found is False


def test_crack_with_charset():
    result = crack_with_charset("5d41402abc4b2a76b9719d911017c592", "md5", "helo", max_length=5)
    assert result.found is True
    assert result.cracked_value == "hello"
