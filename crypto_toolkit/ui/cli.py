"""CLI para CryptoToolkit usando Click."""

from __future__ import annotations

import click

from ..hash.hash_engine import compute_hash, compute_all_hashes
from ..hash.hash_cracker import crack_hash
from ..cipher.symmetric import encrypt_aes, decrypt_aes, encrypt_chacha20, decrypt_chacha20
from ..cipher.asymmetric import generate_rsa_keypair, rsa_encrypt, rsa_decrypt
from ..cipher.encoding import (
    base64_encode, base64_decode, hex_encode, hex_decode,
    url_encode, url_decode, rot13, rot47,
)
from ..analysis.password_strength import analyze_password
from ..analysis.key_generator import generate_aes_key, generate_fernet_key, generate_rsa_keypair as gen_rsa
from ..utils.entropy import calculate_entropy, entropy_rating


@click.group()
def cli() -> None:
    """CryptoToolkit — Toolkit de criptografía."""
    pass


@cli.command()
@click.option("--data", required=True, help="Datos a hashear")
@click.option("--algorithm", default="sha256", help="Algoritmo (md5, sha1, sha256, sha512)")
def hash(data: str, algorithm: str) -> None:
    """Genera hash de datos."""
    result = compute_hash(data, algorithm)
    click.echo(f"[+] {result.algorithm}: {result.hash_value}")


@cli.command()
@click.option("--data", required=True, help="Datos a hashear")
def hash_all(data: str) -> None:
    """Genera hashes con todos los algoritmos."""
    results = compute_all_hashes(data)
    for r in results:
        click.echo(f"  {r.algorithm}: {r.hash_value}")


@cli.command()
@click.option("--hash-value", required=True, help="Hash a crackear")
@click.option("--algorithm", default="sha256", help="Algoritmo del hash")
@click.option("--wordlist", required=True, help="Ruta al wordlist")
def crack(hash_value: str, algorithm: str, wordlist: str) -> None:
    """Crackea un hash con un wordlist."""
    from pathlib import Path
    words = Path(wordlist).read_text().splitlines()
    click.echo(f"[*] Probando {len(words)} palabras...")
    result = crack_hash(hash_value, algorithm, words)
    if result.found:
        click.echo(f"[+] Encontrado: {result.cracked_value}")
    else:
        click.echo("[-] No encontrado")
    click.echo(f"  Intentos: {result.attempts}, Tiempo: {result.elapsed_seconds:.2f}s")


@cli.command()
@click.option("--data", required=True, help="Texto a codificar")
@click.option("--encoding", type=click.Choice(["base64", "hex", "url", "rot13", "rot47"]))
def encode(data: str, encoding: str) -> None:
    """Codifica datos."""
    encoders = {
        "base64": base64_encode,
        "hex": hex_encode,
        "url": url_encode,
        "rot13": rot13,
        "rot47": rot47,
    }
    result = encoders[encoding](data)
    click.echo(f"[+] {encoding}: {result}")


@cli.command()
@click.option("--data", required=True, help="Texto a decodificar")
@click.option("--encoding", type=click.Choice(["base64", "hex", "url"]))
def decode(data: str, encoding: str) -> None:
    """Decodifica datos."""
    decoders = {
        "base64": base64_decode,
        "hex": hex_decode,
        "url": url_decode,
    }
    result = decoders[encoding](data)
    click.echo(f"[+] {result}")


@cli.command()
@click.option("--password", required=True, help="Contraseña a analizar")
def check_password(password: str) -> None:
    """Analiza la fortaleza de una contraseña."""
    result = analyze_password(password)
    click.echo(f"[+] Longitud: {result.password_length}")
    click.echo(f"  Entropía: {result.entropy_bits} bits")
    click.echo(f"  Fortaleza: {result.strength}")
    click.echo(f"  Tiempo estimado de crack: {result.estimated_crack_time}")
    click.echo(f"  Minúsculas: {result.has_lowercase}")
    click.echo(f"  Mayúsculas: {result.has_uppercase}")
    click.echo(f"  Dígitos: {result.has_digits}")
    click.echo(f"  Especiales: {result.has_special}")


@cli.command()
@click.option("--type", "key_type", type=click.Choice(["aes", "fernet", "rsa", "random"]), default="aes")
@click.option("--bits", default=256, help="Tamaño de clave")
def keygen(key_type: str, bits: int) -> None:
    """Genera claves criptográficas."""
    if key_type == "aes":
        result = generate_aes_key(bits)
        click.echo(f"[+] AES: {result.key_value}")
    elif key_type == "fernet":
        result = generate_fernet_key()
        click.echo(f"[+] Fernet: {result.key_value}")
    elif key_type == "rsa":
        priv, pub = gen_rsa(bits)
        click.echo(f"[+] RSA Private:\n{priv.key_value}")
        click.echo(f"[+] RSA Public:\n{pub.key_value}")
    elif key_type == "random":
        from ..analysis.key_generator import generate_random_bytes
        result = generate_random_bytes(bits // 8)
        click.echo(f"[+] Random ({bits} bits): {result.key_value}")


@cli.command()
@click.option("--data", required=True, help="Datos para calcular entropía")
def entropia(data: str) -> None:
    """Calcula la entropía de Shannon."""
    e = calculate_entropy(data)
    rating = entropy_rating(e)
    click.echo(f"[+] Entropía: {e:.2f} bits — {rating}")


def main() -> None:
    """Punto de entrada principal."""
    cli()
