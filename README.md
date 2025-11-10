# Secure File Transfer System

A Python language program using end-to-end encryption (E2EE) for secure file transfer over untrusted networks with a zero trust architecture (ZTA).

## Features

### Implemented

- Confidentiality: Encryption with Transport Layer Security (TLS)
- Availability: Asymmetric key generation using client initiated Certificate Signing Requests (CSR)

### Pending implementation

- Integrity: 
    - Digitial signing and verification of files
    - SHA-256 checksums
- Authentication: User registration and password hash management
- Authorisation: Role-based access control (RBAC) with r|w|x enforcement
- Accounting: Tamper evident audit logs

## Architecture

- Client: ____
- Server: ____

## Implementation stack

- Python 3.12
- Docker Engine v28.5.1

## Setup

git clone https://github.com/dbtyrrell/secure-file-transfer-system-python.git

## Usage

___

## Configuration

___

## Security

- Confidentiality through asymmetric E2EE
- Integrity through hash verification
- Non-repudiation through digital signatures

## Licence

MIT