# crypto-util

A Utility to execute cryptographic operations such as encryption, decryption, and hashing using various algorithms.

## Features

- AES Encryption and Decryption (AES-256-CBC)
- PBEWITHHMACSHA512ANDAES_128 Encryption and Decrytion
- RSA Encryption and Decryption
- Hashing (SHA-256, SHA-512, etc.)

## Installation

To install the dependencies, run:

```sh
npm install
```

## Supported Algorithms

### Encryption Algorithms
- AES-256-CBC
- RSA
- PBE

### Hashing Algorithms
- SHA-256
- SHA-512

### Encrypt a message

```sh
npm  start encrypt -- -p <password> -m <message> -a <algorithm> -k <key>
```

### Decrypt a message

```sh
npm start decrypt -- -p <password> -d <data> -a <algorithm> -k <key>
```

### Generate a hash

```sh
npm  start hash -- -s <string> -a <algorithm>
```

## Build


To build the project, run:

```sh
npm run build
```

This will create a standalone executable in the [dist](./dist/) folder

## Release


To release the [dist](./dist/)folder using CI, push a new tag that matches the pattern `v*.*.*` (e.g., `v1.0.0`). The GitHub Actions workflow will automatically create a release and upload the [dist](./dist/) folder as an artifact.

## License


This project is licensed under the ISC License.
