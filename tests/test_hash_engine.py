"""Tests para hash_engine."""

from crypto_toolkit.hash.hash_engine import compute_hash, compute_file_hash, compute_all_hashes


def test_compute_hash_sha256():
    result = compute_hash("hello", "sha256")
    assert result.algorithm == "sha256"
    assert len(result.hash_value) == 64


def test_compute_hash_md5():
    result = compute_hash("hello", "md5")
    assert result.algorithm == "md5"
    assert len(result.hash_value) == 32


def test_compute_hash_invalid():
    try:
        compute_hash("data", "invalid_algo")
        assert False, "Debería lanzar ValueError"
    except ValueError:
        pass


def test_compute_file_hash(tmp_path):
    f = tmp_path / "test.txt"
    f.write_text("hello")
    result = compute_file_hash(str(f), "sha256")
    assert len(result.hash_value) == 64
    assert result.input_size == 5


def test_compute_all_hashes():
    results = compute_all_hashes("test")
    assert len(results) == 4
    assert [r.algorithm for r in results] == ["md5", "sha1", "sha256", "sha512"]


def test_hash_consistency():
    r1 = compute_hash("test", "sha256")
    r2 = compute_hash("test", "sha256")
    assert r1.hash_value == r2.hash_value
