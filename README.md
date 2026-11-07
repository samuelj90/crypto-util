# Crypto Util

> A lightweight CLI utility for symmetric encryption, asymmetric keypair operations, and deterministic hashing.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/samuelj90/crypto-util/actions/workflows/ci.yml/badge.svg)](https://github.com/samuelj90/crypto-util/actions/workflows/ci.yml)

---

## Architecture Overview

```mermaid
graph LR
    Input[Plaintext / File] --> CLI[crypto-cli]
    CLI --> AES[AES-256-CBC Module]
    CLI --> PBE[PBE-HMAC-SHA512 Module]
    CLI --> RSA[RSA Asymmetric Module]
    CLI --> HASH[SHA-256 / SHA-512 Stream]
    AES --> Output[Encrypted Ciphertext / Hash]
    PBE --> Output
    RSA --> Output
    HASH --> Output
```

---

## Features

- **AES-256-CBC**: Symmetric encryption and decryption with initialization vectors.
- **PBEWithHMACSHA512AndAES_128**: Password-based key derivation encryption.
- **RSA**: Public key encryption and private key decryption.
- **Hashing**: Deterministic cryptographic digests using SHA-256 and SHA-512.

---

## Installation & Setup

```bash
# Clone the repository
git clone https://github.com/samuelj90/crypto-util.git
cd crypto-util

# Install dependencies
npm install
```

---

## Verification & Testing

Run the deterministic test suite:

```bash
npm test
```

---

## Security

Please report vulnerabilities following our [Security Policy](SECURITY.md).

---

## License

[MIT License](LICENSE)
