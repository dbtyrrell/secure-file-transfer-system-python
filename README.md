# Secure File Transfer System

A Python language program using mutually authenticated Transport Layer Security (TLS) for secure 
file transfer over untrusted networks.

## Architecture

The program architecture is composed of two concurrently running services:

### CSR Service
- TCP Port 8444
- Clients generate Certificate Signing Requests (CSR) and receive the host server's certificate.
- HMAC authentication of clients.

### SFTS Service
- TCP Port 8443
- Clients access the secure file transfer API of the host server to upload, download, list and 
delete files with Role Based Access Controls (RBAC).
- Mutually authenticated TLS of host server and clients.

## Security Features

### Confidentiality
- TLS 1.2 or higher with disabled compressions and restriction of ciphers to only those that enable 
both Elliptic Curve Diffie-Hellman Ephemeral (ECDHE) and Advanced Encryption Standard in 
Galois/Counter Mode (AES-GCM).
- Replay protection with command timestamp validation against a pre-set delay tolerance.
- Brute-force protection with IP blocks applied to repeated authentication failures.
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

### Authentication
- Application layer authentication with HMAC challenge and response.

### Authorisation
- RBAC enforced at the server level prior to execution of SFTS service commands.
- Directory traversal protection with type controls applied to all user inputs and validation of 
filenames prior to execution of SFTS service commands.

### Accounting
- Timestamped logging of info, errors and warnings for both clients and the host server.

## Implementation stack

- Python 3.12
- Docker Engine v28.5.1
- Cryptography 46.0.0

## Setup

git clone https://github.com/dbtyrrell/secure-file-transfer-system-python.git

## Usage

Run: 
- python3 server.py
- python3 client.py

## Commands
- Delete: Delete a file from the server.
- Download: Download a file from the server.
- Exit: Close the connection and exit the program.
- Help: Display available commands.
- LS: List files on the server.
- Update: Update user details and password.
- Upload: Upload a file to the server

## Licence

MIT