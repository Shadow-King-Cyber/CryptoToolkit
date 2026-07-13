"""Tests para integrity_checker."""

from crypto_toolkit.analysis.integrity_checker import verify_file_integrity


def test_verify_file(tmp_path):
    f = tmp_path / "test.txt"
    f.write_text("data to verify")
    result = verify_file_integrity(str(f))
    assert result.status == "verified"
    assert len(result.hash_results) == 3


def test_verify_nonexistent():
    result = verify_file_integrity("/no/existe.txt")
    assert result.status == "error"
