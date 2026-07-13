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
- **Verificación de integridad** de archivos con hashes esperados
- **CLI Click** con comandos intuitivos

## Aviso Legal

Esta herramienta se proporciona únicamente con fines educativos. El usuario asume toda la responsabilidad de garantizar el uso adecuado de las técnicas criptográficas implementadas.

**Al usar este software, aceptas que:**
- Solo lo usarás con fines de aprendizaje y demostración
- No usarás las técnicas implementadas para dañar sistemas ajenos
- Los autores no asumen responsabilidad por uso indebido

## Requisitos

- Python 3.11+

```bash
git clone https://github.com/Shadow-King-Cyber/CryptoToolkit.git
cd CryptoToolkit
pip install -r requirements.txt
```

## Inicio Rápido

```bash
# Generar hash SHA256
crypto-toolkit hash --data "hello" --algorithm sha256

# Generar hashes con todos los algoritmos
crypto-toolkit hash-all --data "hello"

# Crackear hash con wordlist
crypto-toolkit crack --hash-value <hash> --algorithm md5 --wordlist wordlist.txt

# Analizar fortaleza de contraseña
crypto-toolkit check-password --password "MiContraseña123!"

# Generar claves criptográficas
crypto-toolkit keygen --type rsa --bits 2048

# Calcular entropía de Shannon
crypto-toolkit entropia --data "datos a analizar"
```

## Comandos del CLI

```bash
# Hashing
crypto-toolkit hash --data "texto" --algorithm sha256
crypto-toolkit hash-all --data "texto"

# Cracking de hashes
crypto-toolkit crack --hash-value <hash> --algorithm sha256 --wordlist wordlist.txt

# Encodings
crypto-toolkit encode --data "texto" --encoding base64
crypto-toolkit decode --data <encoded> --encoding base64

# Análisis de contraseñas
crypto-toolkit check-password --password "contraseña"

# Generación de claves
crypto-toolkit keygen --type aes --bits 256
crypto-toolkit keygen --type fernet
crypto-toolkit keygen --type rsa --bits 4096

# Entropía
crypto-toolkit entropia --data "texto a analizar"
```

## Estructura del Proyecto

```
CryptoToolkit/
├── crypto_toolkit/
│   ├── hash/           # HashEngine, HashCracker
│   ├── cipher/         # Simétrico (AES, ChaCha), Asimétrico (RSA, ECC), Encoding
│   ├── analysis/       # PasswordStrength, KeyGenerator, IntegrityChecker
│   ├── utils/          # Entropía de Shannon
│   └── ui/             # CLI Click
├── tests/              # Suite de tests con pytest
├── requirements.txt    # Dependencias de Python
├── pyproject.toml      # Configuración del proyecto
└── LICENSE             # Licencia MIT
```

## Ejecutar Tests

```bash
pytest -v
```

## Licencia

MIT License — ver [LICENSE](LICENSE)
