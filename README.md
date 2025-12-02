# Secure File Transfer System

A Python language client–server application for secure file transfer over untrusted networks, using 
mutually authenticated Transport Layer Security (TLS), Public Key Infrastructure (PKI) and 
Role-Based Access Control (RBAC).

This project is intended to demonstrate the implementation secure design principles and is not 
intended for production use.

## Architecture

The program architecture is composed of two concurrently running services:

### CSR Service (`tcp/8444`)

- Clients generate Certificate Signing Requests (CSR) and receive the host server's certificate.
- HMAC authentication of clients.

### SFTS Service (`tcp/8443`)

- Clients access the secure file transfer API of the host server to upload, download, list and 
delete files with Role Based Access Controls (RBAC).
- Mutually authenticated TLS of host server and clients.

### Commands

- Delete: Delete a file from the server.
- Download: Download a file from the server.
- Exit: Close the connection and exit the program.
- Help: Display available commands.
- LS: List files on the server.
- Update: Update user details and password.
- Upload: Upload a file to the server

## Security Features

### Confidentiality

**Mutual TLS 1.2**:
- Disabled compressions and restriction of ciphers to only those that enable 
both Elliptic Curve Diffie-Hellman Ephemeral (ECDHE) and Advanced Encryption Standard in 
Galois/Counter Mode (AES-GCM).

**Replay protection**:
- Inclusion of ISO 8601 timestamps.
- Server-side evaluation of delay tolerance.
- Replay protection with ISO 8601 timestamps validated against a global delay tolerance.

**Password handling**:
- Rainbow table protection with SHA256 hash of 'username|password' stored.
- Shoulder surfing protection with hidden password input fields.
- Password requirements set in compliance with NIST SP 800-63B.

### Integrity

- Digital signatures for uploads and downloads with the Rivest, Shamir and Adleman Probabilist 
Signature Scheme (RSA-PSS).
- SHA256 hash integrity checks for uploads and downloads with failing files dropped.

### Availability

- IP based rate-limiting for potentially abusive traffic.
- Resource limits with strict controls on socket timeouts, header size and message buffers to 
prevent exhaustion of server resources.

**IP-based rate limiting / blocking**:
- Authentication failures are tracked per IP.
- Exceeding a threshold within a sliding window results in temporary IP blocks.

**Resource-safety controls**:
  - Socket timeouts.
  - Strict limits on:
    - Header sizes.
    - Total message sizes.
  - Mitigates resource exhaustion attacks.

### Authentication

**TLS client authentication**:
- X.509 certificates.

**Application-layer authentication**:
- HMAC-based challenge-response using a pre-shared host code for CSR service access and stored 
password hashes for SFTS server login.

### Authorisation

**Role-Based Access Control (RBAC)**:
- Roles and permissions defined in `roles.json`.
- Server verification of user role permissions prior to SFTS command execution. 

**Directory traversal protection**:
- File operations restricted to the configured server directory.
- Filename normalisation and validation, incorpating absolute path rejection.

### Accounting

**Logging**:
- Timestamped log entries for connections, commands, authentication events, errors and warnings.
- Separate logs for client and server components.

## Implementation stack

- Python 3.12
- Docker Engine v28.5.1
- Cryptography 46.0.0

## Project structure

```text
project_root/
├─ .devcontainer/
│  └─ devcontainer.json         # Container configuration
├─ certificates/                # CA, server, and client keys/certificates
│  └─ README.md
├─ directory/                   # Server-side file storage
├─ src/
│  ├─ server.py                 # Server entry point (CSR + SFTS services)
│  ├─ client.py                 # Client entry point
│  ├─ roles.json                # Role-based permissions
│  ├─ users.json                # User metadata (created at runtime)
│  ├─ auth_failures.json        # IP failure tracking (runtime)
│  ├─ blocked_ip.json           # Blocked IPs (runtime)
│  └─ blocked_passwords.json    # Disallowed passwords
├─ requirements.txt 
└─ README.md
```

## Setup

### Clone

git clone https://github.com/dbtyrrell/secure-file-transfer-system-python.git
cd secure-file-transfer-system-python

### Dependencies

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

### Run

- python3 server.py
- python3 client.py

## Licence

MIT