import base64
from cryptography import x509
from cryptography.exceptions import InvalidKey
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.x509.oid import NameOID
from datetime import datetime, timezone
import getpass
import hashlib
import hmac
import ipaddress
import json
import logging
import os
from pathlib import Path
import socket
import ssl
import sys
import threading

# Global variables
SFTS_PORT: int = 8443
CSR_PORT: int = 8444
TERMINATOR: bytes = b"!_end_!"

SFTS_ROOT = str(Path(__file__).resolve().parent.parent)
CERTIFICATES: str = os.path.join(SFTS_ROOT, "certificates")
DIRECTORY: str = os.path.join(SFTS_ROOT, "directory")
BLOCKED_PASSWORDS: str = os.path.join(SFTS_ROOT, "src/blocked_passwords.json")
ROLES: str = os.path.join(SFTS_ROOT, "src/roles.json")

# Configure logging protocol
logging.basicConfig(
    level = logging.INFO,
    format = "[%(asctime)s] [%(levelname)s] %(message)s",
    datefmt = "%y-%m-%d %H:%M:%S"
)
log = logging.getLogger("SFTS_client")

# Create filepaths if required
os.makedirs(CERTIFICATES, exist_ok = True)
os.makedirs(DIRECTORY, exist_ok = True)
if not os.path.exists(BLOCKED_PASSWORDS):
    with open(BLOCKED_PASSWORDS, 'w') as file:
        json.dump([], file)
if not os.path.exists(ROLES):
    with open(ROLES, 'w') as file:
        json.dump({}, file)

# Serialise read/write operations on json files to mitigate race conditions
blocked_passwords_file_lock = threading.Lock()
roles_file_lock = threading.Lock()

# Initialise user role permissions
roles = {}
with roles_file_lock:
    try:        
        with open(ROLES, "r") as file:
            roles = json.load(file)

    except Exception as e:
        log.error(f"Roles file error: Failed to read from file. {e}.")

def credentials_certificate_initialise(
        host_certificate_filepath: str, user_private_key: rsa.RSAPrivateKey, 
        username: str, host_address: str, host_hash: str) -> None:
    """
    This function initialises the certificate for the host server using the user's private key.
    
    Args:
        host_certificate_filepath: A string containing the filepath to the CA and server 
        certificates for the specified host server.

        user_private_key: An object containing the RSA private key for the client user.

        username: A string containing the username input by the client user.

        host_address: A string containing the host server's IP address.

        host_hash: A string containing a SHA-256 hex hash of the host code.
    """

    try:
        # Generate and send a Certificate Signing Request (CSR) if required
        if not os.path.exists(host_certificate_filepath):
            csr_path = csr_generate(username, user_private_key)      
            csr_send(csr_path, username, host_address, host_hash)

        # Check whether an existing certificate is current and replace if required
        else:
            with open(host_certificate_filepath, "rb") as file:
                certificate = x509.load_pem_x509_certificate(file.read())

            # Delete expire host certificate if required
            if datetime.now(timezone.utc) > certificate.not_valid_after_utc:
                os.remove(host_certificate_filepath)
                log.info(f"Expired client {username} CSR and {host_address} certificate deleted.")

                # Obtain new host certificate
                csr_path = csr_generate(username, user_private_key)      
                csr_send(csr_path, username, host_address, host_hash)

        log.info(f"Valid certificate for host server {host_address} confirmed")

    except Exception as e:
        log.error(f"Credential error: Failed to obtain certificate for {host_address}. {e}.")

def credentials_key_initialise(
        user_private_key_filepath: str, username: str, user_password: str) -> rsa.RSAPrivateKey:
    """
    The function initialises a RSA private key for the client user, either by decrypting an existing
    key or by calling the credentials_key_generate function.
    
    Args:
        user_private_key_filepath: A string containing the filepath to the private key for the 
        client user
    
        username: A string containing the username input by the client user.

        user_password: A string containing the password input by the client user.

    Returns:
        An object containing the RSA private key for the client user.
    """

    # Generate a user specific private key if one doesn't already exist
    if not os.path.exists(os.path.join(CERTIFICATES, f"{username}_key.pem")):
        credentials_key_generate(user_private_key_filepath, username, user_password)

    try:
        with open(user_private_key_filepath, "rb") as file:
            user_private_key = serialization.load_pem_private_key(
                file.read(),
                password = user_password.encode() if user_password else None
            )

    except InvalidKey:
        log.error(f"Credential error: Incorrect password for private key.")
        sys.exit(1)

    log.info(f"Client {username} private key initialised.")

    return user_private_key


def credentials_input_host() -> tuple[str, str]:
    """
    This function obtains user input to initialise the host server's IPv4 or IPv6 adddress, using 
    the ipaddress module to validate input formatting, and host code. 
    
    This host code is a well-known word specific to the server and is only used to enable access to 
    the server's Client Signing Request (CSR) service. The host code is independant of user 
    passwords and does not enable access to SFTS functionality. 
            
    Returns:
        A tuple contining the IPv4 or IPv6 host address input by the client as a string and a 
        SHA-265 hash of the host code input by the client as a string.
    """

    while True:
        host_address = str(input("Enter host server IPv4 or IPv6 address: ").strip())
        try:
            ipaddress.ip_address(host_address)
            break
        except ValueError as e:
            log.error(f"Credential error: Invalid host server IP address. {e}.")
            print("Please enter either:\n"
                  "- An IPv4 address using the format 255.255.255.255, or\n"
                  "- An IPv6 address using the format ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
                  )
        
    host_code = getpass.getpass(prompt = "Enter host server code: ")
    host_hash = hashlib.sha256(host_code.encode()).hexdigest()

    return host_address, host_hash

def credentials_input_user() -> tuple[str, str, str]:
    """
    This function obtains user input to initialise their username and password.
                
    Returns:
        A list contining the username input by the user as a string, the password input by the user 
        as a string and a SHA-265 hash of the password input by the user.
    """

    while True:
        username = str(input("Enter username: ").replace(" ", ""))
        if 4 <= len(username) <= 20:
            break
        else:
            print("Username must be between 4 to 20 characters in length")
    
    with open(BLOCKED_PASSWORDS, "r") as file:
        blocked_passwords = json.load(file)

    while True:
        user_password_prelim = getpass.getpass(prompt = "Enter user password: ")   

        if not 15 <= len(user_password_prelim) <= 64:
            print("Password error: Password length must be between 15 and 64 characters")
            continue

        if user_password_prelim.lower() in blocked_passwords:
            print("Password error: Password must not be easily predictable")
            continue

        user_password = getpass.getpass(prompt = "Confirm user password: ")  

        if user_password_prelim == user_password:
            break

        log.error(f"Credential error: Client {username} passwords don't match")

    salt = username + "|" + user_password

    password_hash = hashlib.sha256(salt.encode()).hexdigest()

    return username, user_password, password_hash

def credentials_key_generate(
        user_private_key_filepath: str, username: str, user_password: str) -> None:
    """
    This function generates a private key for the client using Rivest Shamir Adleman (RSA) 
    encryption.
    
    Args:
        user_private_key_filepath: A string containing the filepath to the private key for the 
        client user
    
        username: A string containing the username input by the client user.

        user_password: A string containing the password input by the client user.
    """
    
    # Generate a RSA private key
    user_private_key = rsa.generate_private_key(public_exponent = 65537, key_size = 2048)

    try:
        # Write the private key file
        with open(user_private_key_filepath, "wb") as file:
            file.write(
                user_private_key.private_bytes(
                    encoding = serialization.Encoding.PEM, 
                    format = serialization.PrivateFormat.TraditionalOpenSSL, 
                    encryption_algorithm = serialization.BestAvailableEncryption(
                        user_password.encode()
                        )
                )
            )

    except Exception as e:
        log.error(f"Credential error: Failed to write private key. {e}.")
        sys.exit(1)

    log.info(f"Client {username} private key saved to {user_private_key_filepath}")

def csr_generate(username: str, user_private_key: rsa.RSAPrivateKey) -> str:
    """
    This function defines the logic for generating a Certificate Signing Request (CSR), enabling 
    asymmetrically encrypted communication between the client and host server.
    
    Args:
        username: A string containing the username input by the client user.
    
        user_private_key: An object containing the RSA private key for the client user.

    Returns:
        A string containing the file path for the generated csr.
    """
    
    # Define the CSR subject variables and digitally sign
    csr = x509.CertificateSigningRequestBuilder().subject_name(
                x509.Name([
                    x509.NameAttribute(NameOID.COUNTRY_NAME, "AU"),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Secure File Transfer System"),
                    x509.NameAttribute(NameOID.COMMON_NAME, username)
                ])
            ).sign(user_private_key, hashes.SHA256())

    # Define the CSR filepath
    csr_path = os.path.join(CERTIFICATES, f"{username}_csr.pem")

    # Write the CSR file
    with open(csr_path, "wb") as file:
        file.write(csr.public_bytes(serialization.Encoding.PEM))

    log.info(f"CSR saved to {csr_path}")

    return csr_path

def csr_send(csr_path: str, username: str, host_address: str, host_hash: str) -> None:
    """
    This function defines the logic for sending an unencrypted Certificate Signing Request (CSR) to 
    a host server for the purpose of enabling subsequent asymmetric communication.
    
    Args:
        csr_path: A string containing the file path for the generated CSR.
        
        username: A string containing the username input by the client user.
    
        host_address: A string containing the host server's IP address.

        host_hash: A string containing a SHA-256 hex hash of the host code.
    """  
    
    signed_certificate_path = os.path.join(CERTIFICATES, f"{username}_certificate.pem")

    with socket.create_connection((host_address, CSR_PORT)) as csr_sock:
        
        # Receive 256 bit nonce from host server
        nonce_line = b""
        while b"\n" not in nonce_line:
            chunk = csr_sock.recv(1024)
            if not chunk:
                break
            nonce_line += chunk

            if len(nonce_line) > 4096:
                log.error(f"CSR error: Invalid nonce received from {host_address}.")
                raise ValueError

        if b"\n" not in nonce_line:
            log.error(f"CSR error: Incomplete nonce received from {host_address}.")
            return

        header_line, remainder = nonce_line.split(b"\n",1)
        nonce = bytes.fromhex(header_line.decode().strip())

        # Authenticate to host server using hmac
        client_hmac = hmac.new(
            key = host_hash.encode(),
            msg = nonce,
            digestmod = hashlib.sha256
        ).hexdigest().encode() + b"\n"

        csr_sock.sendall(client_hmac)

        # Send CSR to host server
        with open(csr_path, "rb") as file:
            csr_sock.sendall(file.read())
        
        # Notify server of completed CSR send
        csr_sock.shutdown(socket.SHUT_WR)
        
        # Notify user of completed CSR send
        log.info(f"CSR sent to host server {host_address}:{CSR_PORT}.")

        # Receive signed server certificate
        signed_certificate = b""
        while True:
            chunk = csr_sock.recv(4096)
            if not chunk:
                break
            signed_certificate += chunk

    # Save signed server certificate
    with open(signed_certificate_path, "wb") as file:
        file.write(signed_certificate)

    # Notify user of completed CSR send
    log.info(f"Signed certificate recieved from host server {host_address}.")

    # Delete now redundant CSR
    try:
        os.remove(csr_path)
        log.info(f"CSR deletion successful.")
    
    except Exception as e:
        log.error(f"Credential error: CSR deletion failure. {csr_path}")

def sfts_authenticate(
        ssl_conn: ssl.SSLSocket, username: str, password_hash: str, 
        host_address: str) -> tuple[str, str]:              
    """
    This function receives a nonce from the host server and in response authenticates with a HMAC.

    Args:
        ssl_conn: A SSL-wrapped socket connection object enabling binary transfer.

        username: A string containing the username input by the client user.

        password_hash: A string containing a SHA256 hash of the concatenation of the client user's
        username, | character and password.

        host_address: A string containing the host server's IP address.

    Returns:
        A tuple containing a bool that is True if the client users passed authentication, else 
        False, and the user role provided by the host server as a string. 
    """
    
    # Receive 256 bit nonce from host server
    nonce_line = b""
    while b"\n" not in nonce_line:
        chunk = ssl_conn.recv(1024)
        if not chunk:
            break

        nonce_line += chunk

        if len(nonce_line) > 4096:
            log.error(f"SFTS error: Invalid nonce size received from {host_address}.")
            raise ValueError

    if b"\n" not in nonce_line:
        log.error(f"SFTS error: Incomplete nonce received from {host_address}.")
        return False, "unregistered"

    header_line, remainder = nonce_line.split(b"\n",1)
    nonce = bytes.fromhex(header_line.decode().strip())

    # Authenticate to host server using hmac
    client_hmac = hmac.new(
        key = password_hash.encode(),
        msg = nonce,
        digestmod = hashlib.sha256
    ).hexdigest().encode() + b"\n"

    ssl_conn.sendall(client_hmac)

    # Send username and password hash to host server
    credentials_bytes = f"{username}|{password_hash}\n".encode()
    ssl_conn.sendall(credentials_bytes)

    # Receive authentication result and user role from host server 
    results_bytes = b""
    while b"\n" not in results_bytes:
        chunk = ssl_conn.recv(1024)
        if not chunk:
            break
        results_bytes += chunk

        if len(results_bytes) > 4096:
            log.error(
                f"SFTS error: Incorrect results header sent by host server {host_address}.")
            raise ValueError("Results header error")

    if b"\n" not in results_bytes:
        log.error(f"SFTS error: Incomplete results header sent by host server {host_address}.")
        return False, "unregistered"

    header_line, remainder = results_bytes.split(b"\n",1)
    result_string, user_role = header_line.decode().split("|",1)

    if result_string.lower() == "true":
        result = True
    else:
        result = False

    return result, user_role

def sfts_cmd_delete(ssl_conn: ssl.SSLSocket, host_address: str) -> None:
    """
    This function deletes a file from the host server directory.
    
    Args:
        ssl_conn: A SSL-wrapped socket connection object enabling binary transfer.

        host_address: A string containing the host server's IP address.
    """

    log.info(f"Initiated the delete command.")
    
    filename = str(input("File to be deleted: ").strip())

    # Send command to host server
    timestamp = datetime.now(timezone.utc).isoformat()
    msg = (f"delete|{filename}|{timestamp}\n").encode()
    ssl_conn.sendall(msg)

    try:
        # Receive response from host server
        buffer = sfts_response(ssl_conn, host_address)

    except (ConnectionError, ValueError) as e:
        log.error(f"Command error: Failed to receive response from host server {host_address}")
        return

    # Remove post-buffer data from host server response
    response, _ = buffer.split(TERMINATOR,1)

    # Decompose host server response
    response_lines = response.split(b"\n")
    header = response_lines[0].decode(errors = "replace").strip()
    body = [line.decode(errors = "replace") for line in response_lines[1:] if line]

    # Print host server response
    print(header)
    if body:
        print("\n".join(body))
    
    else:
        print("")

def sfts_cmd_download(ssl_conn: ssl.SSLSocket, host_address: str) -> None:
    """
    This function downloads a file from the host server directory to the client directory.
    
    Args:
        ssl_conn: A SSL-wrapped socket connection object enabling binary transfer.

        host_address: A string containing the host server's IP address.
    """

    log.info(f"Initiated the download command.")

    while True:
        filename = str(input("File to be downloaded: ").strip())
        if filename:
            break
        print("Invalid filename")

    filepath = os.path.join(DIRECTORY, filename)

    # Prevent accidental overwrites caused by name conflicts
    if os.path.exists(filepath):
        log.info(f"A file named {filename} already exists in {DIRECTORY}.\n")

        # Obtain user permission to overwrite or cancel download request
        user_choice = str(input(
            "Type 'Yes' to overwrite the existing file or type any other key to cancel: ").strip())
        
        if user_choice.lower() != "yes":
            log.info(f"Download cancelled to prevent overwrite of {filepath}")
            return
        
        log.info(f"Overwrite of {filepath} approved by user")

    # Send command to host server
    timestamp = datetime.now(timezone.utc).isoformat()
    msg = (f"download|{filename}|{timestamp}\n").encode()
    ssl_conn.sendall(msg)

    # Receive filesize information from host server
    try:
        buffer = sfts_response(ssl_conn, host_address)

    except (ConnectionError, ValueError) as e:
        log.error(f"Command error: Failed to receive response from host server {host_address}")
        return

    # Isolate JSON header in host server response
    header_bytes, _ = buffer.split(TERMINATOR,1)

    # Decode JSON header
    try:
        header = json.loads(header_bytes.decode("utf-8"))

    except json.JSONDecodeError:
        log.error(f"Command error: Unable to decode JSON header")
        return

    # Print error messages if required
    if "Error" in header:
        print(header["Error"])
        return

    # Initialise JSON header contents
    try:
        filename = header["filename"]
        filesize = int(header["filesize"])
        hash_alg = header["hash_algorith"]
        file_hash = header["file_hash"]
        timestamp = header["timestamp"]
        signature = header["signature"]

    except KeyError as e:
        log.error(f"Command error: Missing download cmd header contents. {e}")
        return

    # Validate JSON header hash algorithm
    if hash_alg.upper() != "SHA256":
        log.error(f"Command error: Unrecognised hash algorithm. {hash_alg}")

    # Extract and initilaise the server public key from the server certificate
    try:
        der_certificate = ssl_conn.getpeercert(binary_form = True)
        if not der_certificate:
            raise ValueError("Server certificate couldn't be initialised")
        server_certificate = x509.load_der_x509_certificate(der_certificate)
        server_public_key = server_certificate.public_key()

    except Exception as e:
        log.error(f"Signature error: Server public key couldn't be initialised. {e}.")
        return

    # Validate signature
    header_data = f"{filename}|{filesize}|{hash_alg}|{timestamp}".encode("utf-8")
    try:
        signature = base64.b64decode(signature)
        server_public_key.verify(
            signature,
            header_data,
            padding.PSS(
                mgf = padding.MGF1(hashes.SHA256()),
                salt_length = padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        log.info(f"Signature validated for {filename} from host server {host_address}.")

    except Exception as e:
        log.error(f"Signature error: Unable to validate signature for {filename} from host server"
                  f"{host_address}.")

        # Discard excess data in the event on an error processing header
        remaining = filesize
        try:
            while remaining > 0:
                chunk = ssl_conn.recv(min(4096, remaining))
                if not chunk:
                    break
                remaining -= len(chunk)

        except Exception:
            pass

        return

    # Receive file from host server while incrementally 
    client_hash = hashlib.sha256()
    remaining = filesize

    try:
        with open(filepath, "wb") as file:
            while remaining > 0:
                chunk = ssl_conn.recv(min(4096, remaining))
                if not chunk:
                    log.error(f"Command error: Connection with {host_address} lost during download")
                    raise ConnectionError(f"Connection lost during download")
                file.write(chunk)
                client_hash.update(chunk)
                remaining -= len(chunk)

    except Exception as e:
        log.error(f"Command error: {filename} download failed. {e}.")

        # Attempt to remove failed downloads
        try:
            os.remove(filepath)

        except Exception:
            pass

        return

    # Verify download file integrity using host server provided hash and client generated hash
    client_hash.hexdigest()
    if client_hash.hexdigest() != file_hash:
        log.error(f"Command error: {filename} failed hash verification.")

        # Attempt to remove unverified downloads
        try:
            os.remove(filepath)

        except Exception:
            pass

        return

    log.info(f"{filename} download and integrity verification successful.")

def sfts_cmd_exit(ssl_conn: ssl.SSLSocket, host_address: str) -> None:
    """
    This function exits the program.
    
    Args:
        ssl_conn: A SSL-wrapped socket connection object enabling binary transfer.

        host_address: A string containing the host server's IP address.
    """

    log.info("Initiated the exit command.")

    # Send command to host server
    timestamp = datetime.now(timezone.utc).isoformat()
    msg = (f"exit|None|{timestamp}\n").encode()
    ssl_conn.sendall(msg)

    # Close the server-client connection
    log.info(f"Closing connection with host server {host_address}.")
    ssl_conn.close()
    sys.exit(1)

def sfts_cmd_help(user_role: str) -> None:
    """
    This function provides the client user with information on the commands available based on their
    user role.
    
    Args:
        user_role: A string containing the client user's role as advised by the host server.
    """

    role_check = roles.get(user_role, {})

    print("\nThe following commands are available to you:\n")

    if role_check.get("delete", False):
        print("DELETE      Delete a file from the server directory")

    if role_check.get("download", False):
        print("DOWNLOAD    Download a file from the server directory")

    print("EXIT        Exit program")
    print("HELP        View available commands")

    if role_check.get("ls", False):
        print("LS          List all files within the server directory")

    print("UPDATE      Update your personal user details")

    if role_check.get("upload", False):
        print("UPLOAD      Upload a file to the server directory")

def sfts_cmd_ls(ssl_conn: ssl.SSLSocket, host_address: str) -> None:
    """
    This function lists all directories and files contained in the host server directory.
    
    Args:
        ssl_conn: A SSL-wrapped socket connection object enabling binary transfer.

        host_address: A string containing the host server's IP address.
    """

    log.info(f"Initiated the list command.")

    # Send command to to host server
    timestamp = datetime.now(timezone.utc).isoformat()
    msg = (f"ls|None|{timestamp}\n").encode()
    ssl_conn.sendall(msg)

    try:
        # Receive response from host server
        buffer = sfts_response(ssl_conn, host_address)

    except (ConnectionError, ValueError) as e:
        log.error(f"Command error: Failed to receive response from host server {host_address}")
        return

    # Remove post-buffer data from host server response
    response, _ = buffer.split(TERMINATOR,1)

    # Decompose host server response
    response_lines = response.split(b"\n")
    header = response_lines[0].decode(errors = "replace").strip()
    body = [line.decode(errors = "replace") for line in response_lines[1:] if line]

    # Print host server response
    print(header)
    if body:
        print("\n".join(body))
    
    else:
        print("")

def sfts_cmd_update(ssl_conn: ssl.SSLSocket, username: str) -> None:
    """
    This function enables a client user to update the password used to authenticate with the SFTS 
    service but confirming their existing password hash and registering a new password has with
    the host server.
    
    Args:
        ssl_conn: A SSL-wrapped socket connection object enabling binary transfer.

        username: A string containing the username input by the client user.
    """

    log.info(f"Initiated the update command.")

def sfts_cmd_upload(ssl_conn: ssl.SSLSocket, user_private_key: rsa.RSAPrivateKey, username: str, 
                    host_address: str) -> None:
    """
    This function uploads a file from the client directory to the host server director.
    
    Args:
        ssl_conn: A SSL-wrapped socket connection object enabling binary transfer.

        user_private_key: An object containing the RSA private key for the client user.

        username: A string containing the username input by the client user.

        host_address: A string containing the host server's IP address.
    """

    log.info(f"Initiated the upload command.")

    while True:
        filename = str(input("File to be uploaded: ").strip())
        if filename:
            break
        print("Invalid filename")
    
  # Validate filename
    if not filename:
        log.error(f"Command error: Invalid filename.")
        return

    filepath = os.path.join(DIRECTORY, filename)

    # Validate filepath
    filepath = os.path.join(DIRECTORY, filename)
    if not os.path.exists(filepath):
        log.error(f"Command error: Requested file doesn't exist.")
        return

    # Validate user's private key
    if not user_private_key:
        log.error(f"Signing error: User's private key failed to initialise.")
        return

    try:
        # Calculate filesize
        filesize = os.path.getsize(filepath)

        # Generate a SHA256 hash of the file for integrity verification
        client_hash = hashlib.sha256()       
        with open(filepath, "rb") as file:
            for chunk in iter(lambda: file.read(4096), b""):
                client_hash.update(chunk)
        file_hash = client_hash.hexdigest()

    except Exception as e:
        log.error(f"Command error: Unable to read {filepath}. {e}.")

    # Generate digitial signature
    try:
        timestamp = datetime.now(timezone.utc).isoformat()
        msg = f"{filename}|{filesize}|{file_hash}|{timestamp}".encode("utf-8")
        signature = user_private_key.sign(
            msg,
            padding.PSS(
                mgf = padding.MGF1(hashes.SHA256()),
                salt_length = padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        ) 

    except Exception as e:
        log.error(f"Signing error: Unable to sign upload cmd message. {e}.") 
        return       

    # Generate JSON header
    header = {
        "filename": filename,
        "filesize": filesize,
        "hash_algorith": "SHA256",
        "file_hash": file_hash,
        "timestamp": timestamp,
        "signature": base64.b64encode(signature).decode("ascii")
    }
    header_bytes = json.dumps(header, separators = (",", ":")).encode("utf-8") + TERMINATOR

    # Send command to host server
    timestamp = datetime.now(timezone.utc).isoformat()
    msg = (f"upload|{filename}|{timestamp}\n").encode()
    ssl_conn.sendall(msg)

    # Send JSON header to host server
    ssl_conn.sendall(header_bytes)

    # Send file to client
    try:
        with open(filepath, "rb") as file:
            while True:
                chunk = file.read(4096)
                if not chunk:
                    break
                ssl_conn.sendall(chunk)

    except Exception as e:
        log.error(f"Command error: Upload failure for {filepath}. {e}.")

    log.info(f"{filepath} uploaded to host server {host_address}.")

    try:
        # Receive response from host server
        buffer = sfts_response(ssl_conn, host_address)

    except (ConnectionError, ValueError) as e:
        log.error(f"Command error: Failed to receive response from host server {host_address}")
        return

    # Remove post-buffer data from host server response
    response_bytes, _ = buffer.split(TERMINATOR,1)

    # Decompose host server response
    try:
        response = json.loads(response_bytes.decode("utf-8"))
    
    except json.JSONDecodeError as e:
        log.error(f"Command error: Unable to decode JSON header")
        return
    
    header = response.get("status", "error")
    body = response.get("message", "Unknown response from host server")

    if header == "success":
        log.info(f"{filename} upload successful.")

    else:
        log.info(f"{filename} upload failed.")

def sfts_connection(
        host_certificate_filepath: str, user_private_key: rsa.RSAPrivateKey, 
        user_private_key_filepath: str, username: str, user_password: str, password_hash: str, 
        host_address: str) -> None:
    """
    This function establishes a mutually authenticated TLS connection with the host server and 
    then calls authentication, authorisation and SFTS operation functions.

    Args:
        host_certificate_filepath: A string containing the filepath to the CA and server 
        certificates for the specified host server.

        user_private_key: An object containing the RSA private key for the client user.

        user_private_key_filepath: A string containing the filepath to the private key for the 
        client user.

        username: A string containing the username input by the client user.

        user_password: A string containing the password input by the client user.

        password_hash: A string containing a SHA256 hash of the concatenation of the client user's
        username, | character and password.
        
        host_address: A string containing the host server's IP address.
    """
    
    # Configure SSL context
    context = ssl.create_default_context(
        ssl.Purpose.SERVER_AUTH, 
        cafile = f"{CERTIFICATES}ca_certificate.pem"
    )
    
    # Initialise SSL certificates and keys as local variables
    context.load_cert_chain(
        certfile = host_certificate_filepath, 
        keyfile = user_private_key_filepath,
        password = user_password
    )

    # Establish SFTS connections
    with socket.create_connection((host_address, SFTS_PORT)) as sock:
        with context.wrap_socket(sock, server_hostname = host_address) as ssl_conn:

            try:
                # Authenticate client
                authentication, user_role = sfts_authenticate(
                    ssl_conn, username, password_hash, host_address)

                if not authentication:
                    log.warning("User credentials failed host server authentication")
                    sys.exit(1)

                # Recieve commands from client
                sfts_operations(ssl_conn, user_private_key, host_address, username, user_role)

            # Display common error notifications
            except ssl.SSLError as e:
                log.error(f"SSL connection error: {e}.")
                sys.exit(1)

            except ConnectionResetError as e:
                log.error(f"Connection error: Connection with {host_address} lost. {e}.")
                sys.exit(1)
 
            finally:
                log.info("Connection closed")

def sfts_operations(ssl_conn: ssl.SSLSocket, user_private_key: rsa.RSAPrivateKey, host_address: str,
                    username: str, user_role: str) -> None:
    """
    This function manages SSL connections with the host server, incorporating function calls for 
    client initiated commands.
    
    Args:
        ssl_conn: A SSL-wrapped socket connection object enabling binary transfer.

        user_private_key: An object containing the RSA private key for the client user.

        host_address: A string containing the host server's IP address.

        username: A string containing the username input by the client user.

        user_role: A string containing the client user's role as advised by the host server.
    """

    log.info(f"Client {username} commenced SFTS operations.")

    while True:
        # Display user interface
        cmd = str(input("\nEnter SFTS command:\n\n")).strip().lower()

        # Skip unauthorised commands
        if not roles.get(user_role, {}).get(cmd, False):
            log.error(f"Command error: {username} called {cmd} without role permissions.")
            continue

        # Process commands
        match cmd:
            case "delete":
                sfts_cmd_delete(ssl_conn, host_address)

            case "download":
                sfts_cmd_download(ssl_conn, host_address)

            case "exit":
                sfts_cmd_exit(ssl_conn, host_address)

            case "help":
                sfts_cmd_help(user_role)                 

            case "ls":
                sfts_cmd_ls(ssl_conn, host_address)

            case "update":
                sfts_cmd_update(ssl_conn, username)

            case "upload":
                sfts_cmd_upload(ssl_conn, user_private_key, username, host_address)

            case _:
                log.error(f"Command error: {username} input an invalid command. {cmd}")

def sfts_response(
        ssl_conn: ssl.SSLSocket, host_address: str, max_bytes: int = 1024 * 1024) -> bytes:
    """
    The function reads from the SSL-wrapped socket connection until the TERMINATOR global variable
    is found in the received data.

    Args:
        ssl_conn: A SSL-wrapped socket connection object enabling binary transfer.

        host_address: A string containing the host server's IP address.

        max_bytes [optional]: The maximum data size in bytes that will be processed by the function 
        before a Value Error is raised, with a default value of 1 MB.

    Return:
        All bytes received up to the end of the TERMINATOR global variable.
    """

    buffer = b""

    while TERMINATOR not in buffer:
        chunk = ssl_conn.recv(4096)
        if not chunk:
            log.error(f"Command error: Host server {host_address} closed connection prematurely.")
            raise ConnectionError("Connection closed before completion of sfts_reciever function")
        buffer += chunk

        if len(buffer) > max_bytes:
            log.error(f"Command error: Invalid msg size received from host server {host_address}.")
            raise ValueError("sfts_reciever function argument exceeded allowed messsage size.")
    
    return buffer

def main() -> None:
    print("---------------------------------------------------------------------------------\n")
    print("                       Secure File Transfer System: Client                       \n")
    print("---------------------------------------------------------------------------------\n")
    
    # Input host server credentials
    host_address, host_hash = credentials_input_host()

    # Input user credentials
    username, user_password, password_hash = credentials_input_user()

    # Initialise host certificate and private key filepaths
    user_private_key_filepath = os.path.join(CERTIFICATES, f"{username}_key.pem")
    host_certificate_filepath = os.path.join(CERTIFICATES, f"{username}_certificate.pem")

    # Initialise private key
    user_private_key = credentials_key_initialise(
        user_private_key_filepath, username, user_password)

    # Initialise host certificate
    credentials_certificate_initialise(
        host_certificate_filepath, user_private_key, username, host_address, host_hash)

    # Connect to the SFTS service
    sfts_connection(
        host_certificate_filepath, user_private_key, user_private_key_filepath, username, 
        user_password, password_hash, host_address)

if __name__ == "__main__":
    try:
        main()

    except KeyboardInterrupt:
        log.info("Client shutdown by keyboard interrupt.")

    except Exception as e:
        log.critical(f"Fatal error: {e}.")