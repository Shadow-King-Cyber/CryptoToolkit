# CryptoToolkit

Toolkit de criptografía para uso educativo — cifrado, hashing, análisis de contraseñas y generación de claves.

> **ADVERTENCIA**: Esta herramienta es **únicamente para uso educativo**. No usar para cifrar datos reales sin comprender las implicaciones de seguridad.

## Características

- **Hashing**: MD5, SHA1, SHA256, SHA512 con cracking de hashes
- **Cifrado simétrico**: AES-256-CBC, ChaCha20
- **Cifrado asimétrico**: RSA-2048/4096, ECC (P-256)
- **Encodings**: Base64, Hex, URL, ROT13, ROT47
- **Análisis de contraseñas**: Entropía, fortaleza, tiempo estimado de crack
- **Generación de claves**: AES, Fernet, RSA, ECC, random bytes
- **Entropía de Shannon**: Análisis de aleatoriedad
- **Verificación de integridad** de archivos
- **CLI Click** con comandos intuitivos

## Instalación

```bash
git clone https://github.com/Shadow-King-Cyber/CryptoToolkit.git
cd CryptoToolkit
pip install -r requirements.txt
```

## Uso

```bash
# Generar hash
crypto-toolkit hash --data "hello" --algorithm sha256

# Crackear hash
crypto-toolkit crack --hash-value abc123 --algorithm md5 --wordlist wordlist.txt

# Cifrar/descifrar AES
crypto-toolkit encrypt --data "secreto"

# Analizar contraseña
crypto-toolkit check-password --password "MiContraseña123!"

# Generar claves
crypto-toolkit keygen --type rsa --bits 2048

# Calcular entropía
crypto-toolkit entropia --data "datos a analizar"
```

## Licencia

MIT License — Shadow-King-Cyber
