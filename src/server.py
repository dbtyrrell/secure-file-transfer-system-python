import base64
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509.oid import NameOID
from datetime import datetime, timezone, timedelta
import getpass
import hashlib
import hmac
import json
import logging
import os
import socket
import ssl
import sys
import threading

# Global variables
HOST: str = "127.0.0.1"                                                                     #"10.16.10.247"
HOST_CODE: str = "9d695442d1ccee8313ff7f7eaa1566cbe6b32fa4c9e80f7ebd68a36d8df83f5a"
SFTS_PORT: int = 8443
CSR_PORT: int = 8444
BLOCK_WINDOW: timedelta = timedelta(hours=24)
BLOCK_DURATION: timedelta = timedelta(hours=24)
DELAY_TOLERANCE: timedelta = timedelta(seconds=30)
TERMINATOR: bytes = b"!_end_!"

CERTIFICATES: str = "/workspaces/secure-file-transfer-system-python/certificates/"
DIRECTORY: str = "/workspaces/secure-file-transfer-system-python/directory/"
AUTH_FAILURES: str = "/workspaces/secure-file-transfer-system-python/src/auth_failures.json"
BLOCKED_IP: str = "/workspaces/secure-file-transfer-system-python/src/blocked_ip.json"
BLOCKED_PASSWORDS: str = "/workspaces/secure-file-transfer-system-python/src/blocked_passwords.json"
ROLES: str = "/workspaces/secure-file-transfer-system-python/src/roles.json"
USERS: str = "/workspaces/secure-file-transfer-system-python/src/users.json"

# Configure logging protocol
logging.basicConfig(
    level = logging.INFO,
    format = "[%(asctime)s] [%(levelname)s] %(message)s",
    datefmt = "%y-%m-%d %H:%M:%S"
)
log = logging.getLogger("SFTS_server")

# Create required filepaths if they don't already exist
os.makedirs(CERTIFICATES, exist_ok = True)
os.makedirs(DIRECTORY, exist_ok = True)
if not os.path.exists(AUTH_FAILURES):
    with open(AUTH_FAILURES, 'w') as file:
        json.dump({}, file)
if not os.path.exists(BLOCKED_IP):
    with open(BLOCKED_IP, 'w') as file:
        json.dump({}, file)
if not os.path.exists(BLOCKED_PASSWORDS):
    with open(BLOCKED_PASSWORDS, 'w') as file:
        json.dump({}, file)
if not os.path.exists(ROLES):
    with open(ROLES, 'w') as file:
        json.dump({}, file)
if not os.path.exists(USERS):
    with open(USERS, 'w') as file:
        json.dump({}, file)

# Serialise read/write operations on json files to mitigate race conditions
auth_failures_file_lock = threading.Lock()
blocked_ip_file_lock = threading.Lock()
blocked_passwords_file_lock = threading.Lock()
roles_file_lock = threading.Lock()
users_file_lock = threading.Lock()

# Initialise user role permissions
with roles_file_lock:
    try:        
        with open(ROLES, "r") as file:
            roles = json.load(file)

    except Exception as e:
        log.error(f"Roles file error: Failed to read from file. {e}.")

def csr_connection(
        conn: socket.socket, client_addr: tuple[str, int], ca_key: object) -> None:
    """
    This function receives CSR connections with clients and returns a certificate valid for 365 
    days.
    
    Args:        
        conn: A socket connection object enabling binary transfer.
    
        client_addr: A tuple containing the client's IP address as a string and port as an int.

        ca_key: A private key object containing the CA key.
    """

    # Initialise the csr path variable to mitigate exception errors
    csr_path = None
    client_ip = client_addr[0]

    try:
        if evaluate_ip(client_ip):
            log.warning(f"Authentication rejection: Client {client_addr} blocked.")
            return
         
        # Send 256 bit nonce to client
        nonce = os.urandom(32)        
        nonce_hex = nonce.hex().encode() + b"\n"
        conn.sendall(nonce_hex)
        
        # Receive HMAC from client
        authentication = b""
        while b"\n" not in authentication:
            chunk = conn.recv(1024)
            if not chunk:
                break
            authentication += chunk

            if len(authentication) > 4096:
                log.error(f"CSR error: Incorrect authentication header received from {client_addr}.")
                raise ValueError("CSR authentication header error")

        if b"\n" not in authentication:
            log.error(f"CSR error: Incomplete authentication header received from {client_addr}.")
            return

        header_line, remainder = authentication.split(b"\n",1)
        client_hmac = header_line.decode().strip()

        # Authenticate HMAC received from client
        server_hmac = hmac.new(
            key = HOST_CODE.encode(),
            msg = nonce,
            digestmod = hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(client_hmac, server_hmac):
            log.warning(f"CSR error: Incorrect host code received from {client_addr}.")
            
            # Record authentication failure
            client_ip = client_addr[0]
            register_auth_failure(client_ip)
            
            return

        log.info(f"Client {client_addr} CSR authenctication successful.")

        # Receive CSR data from client
        chunks = []
        if remainder:
            chunks.append(remainder)

        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)

        if not chunks:
            log.error(f"CSR error: No data received from client {client_addr}.")

        # Compile CSR data
        csr_data = b"".join(chunks)

        # Initialise the client IP address as a variable that can be used for file naming
        client_ip = client_addr[0].replace(".","")

        csr_path = os.path.join(CERTIFICATES, f"{client_ip}_csr.pem")
        
        with open(csr_path, "wb") as file:
            file.write(csr_data)

        # Sign CSR
        signed_certificate_path, username = csr_sign(csr_path, client_addr, ca_key)

        # Send certificate to client
        with open(signed_certificate_path, "rb") as file:
            conn.sendall(file.read())
        
        log.info(f"Client {username} {client_addr} certificate sent.")

    except Exception as e:
        log.error(f"CSR error: CSR failure for {client_addr}. {e}.")

    finally:
        try:
            conn.close()
        
        except Exception:
            pass

        if csr_path and os.path.exists(csr_path):
            try:
                os.remove(csr_path)

            except Exception:
                pass

def csr_decryption(attempts: int = 3) -> tuple[str, object, object]:
    """
    This function obtains the PKI password from the server user, and verifies that this password 
    correctly decrypts the CA and server keys.
    
    Args:
        attempts: An int containing the number of attempts a server user has to provide the correct
        decryption password before the program will exit.

    Returns:
        A tuple containing the password used to decrypt the CA and server keys input by the server 
        user as a string, the CA key as a private key object and the server key as a private key 
        object.
    """
    
    ca_key_path = os.path.join(CERTIFICATES, "ca_key.pem")
    server_key_path = os.path.join(CERTIFICATES,"server_key.pem")

    # Initialise CA key data
    try:
        with open(ca_key_path, "rb") as file:
            ca_key_data = file.read()

    except OSError as e:
        log.error(f"CSR error: Unable to read {ca_key_path}. {e}.")
        sys.exit(1)

    # Initialise server key data
    try:
        with open(server_key_path, "rb") as file:
            server_key_data = file.read()

    except OSError as e:
        log.error(f"CSR error: Unable to read {server_key_path}. {e}.")
        sys.exit(1)

    # Obtain user input
    for _ in range(attempts, 0, -1):
        password = getpass.getpass(prompt = "Enter PKI decryption password: ")

        # Attempt decryption of the CA and server keys
        try:
            ca_key = serialization.load_pem_private_key(
                ca_key_data,
                password = password.encode() if password else None
            )

            server_key = serialization.load_pem_private_key(
                server_key_data,
                password = password.encode() if password else None
            )
            
            return password, ca_key, server_key
        
        except (ValueError, TypeError):
            log.error("Credential error: Incorrect PKI decryption password.")


    log.error("Credential error: Too many failed authentication attempts.")   
    sys.exit(1)

def csr_listen(ca_key: object) -> None:
    """
    This function listens for Certificate Signing Request (CSR) connections sent by clients, using 
    the threading module for parallel processing of handler threads.
    
    Args:
        ca_key: A private key object containing the CA key.
    """

    # Configure socket connections
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        # Account for server crash/resart by enabling reuse of socket addresses 
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            sock.bind((HOST, CSR_PORT))
            sock.listen(5)
            # Log initiation of CSR listening service
            log.info(f"CSR service listening on {HOST}:{CSR_PORT}.")

        except Exception as e:
            log.critical(f"CSR error: Port {CSR_PORT} binding failure. {e}.")

        # Initialise placeholder client address to prevent exception reporting errors
        client_addr = ("unknown",0)

        while True:
            try:
                conn, client_addr = sock.accept()
            
            except Exception as e:
                log.error(f"CSR error: Connection with failure with client {client_addr}. {e}.")
                continue
            
            log.info(f"CSR service connection success with client {client_addr}.")

            conn.settimeout(120)

            threading.Thread(
                target = csr_connection,
                args = (conn, client_addr, ca_key),
                daemon = True
            ).start()

def csr_sign(csr_path: str, client_addr: tuple[str, int], ca_key: object) -> tuple[str,str]:
    """
    This function signs a CSR using the Certificate Authority (CA) certificate and Private Key, and 
    returns the new certificate filepath.
        
    Args:
        csr_path: A string containing the file path for the client's CSR.
    
        client_addr: A tuple containing the client's IP address as a string and port as an int.

        ca_key: A private key object containing the CA key.

    Returns:
        A tuple containing the file path for the signed client certificate as a string and the 
        username input by the client user as a string.
    """
    
    # Define the CA key and certificate filepaths
    ca_certificate_path = os.path.join(CERTIFICATES, "ca_certificate.pem")

    try:
        # Initialise the CA certificate as a local variable
        with open(ca_certificate_path, "rb") as file:
            ca_certificate = x509.load_pem_x509_certificate(file.read())

    except Exception as e:
        log.error(f"Credential error: Failed to initialise CA certificate. {e}.")
        sys.exit(1)

    log.info("CA certificate initialised.")

    try:
        # Initialise the client's CSR as a local variable
        with open(csr_path, "rb") as file:
            csr = x509.load_pem_x509_csr(file.read())

        username = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value

    except Exception as e:
        log.error(f"Credential error: Failed to initialise client {client_addr} CSR. {e}.")
        return "csr_failure", "csr_failure"

    log.info(f"Client {username} {client_addr} CSR initialised.")

    try:
        # Generate the client's certificate
        client_certificate = (
            x509.CertificateBuilder()
            .subject_name(csr.subject)
            .issuer_name(ca_certificate.subject)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days = 365))
            .add_extension(
                x509.BasicConstraints(
                    ca = False,
                    path_length = None
                ),
                critical = True
            )
            .sign(private_key = ca_key, algorithm = hashes.SHA256())
        )

    except Exception as e:
        log.error(f"CSR error: Failed to generate client {username} {client_addr} certificate. "
                  f"{e}.")

    # Initialise the client IP address as a variable that can be used for file naming
    client_ip = client_addr[0].replace(".","")

    try:
        # Write the client's certificate
        client_certificate_path = os.path.join(
            CERTIFICATES, 
            f"{username}_{client_ip}_certificate.pem"
            )

        with open(client_certificate_path, "wb") as file:
            file.write(client_certificate.public_bytes(serialization.Encoding.PEM))

        return client_certificate_path, username

    except Exception as e:
        log.error(f"CSR error: Failed to write client {username} {client_addr} certificate. {e}.")

def evaluate_ip(ip: str) -> bool:
    """
    This function evaluates whether a connecting client IP address is currently blocked.

    Args:
        ip: A string containing the IP address of a connecting client.

    Returns:
        A bool containing False if the client IP address is not currently blocked, else True.
    """

    timestamp = datetime.now(timezone.utc).timestamp()
    blocked = read_blocked_ip()

    blocked_expiry = blocked.get(ip)
    
    # Return False for IP addresses not in the blocked dictionary
    if blocked_expiry is None:
        return False

    # Return True for IP addresses in the blocked dictionary with active blocks
    if blocked_expiry > timestamp:
        return True

    # Return False and delete entries for IP addresses in the block dictionary with expired blocks.
    del blocked[ip]
    write_blocked_ip(blocked)
    log.info(f"Client {ip} block expired and removed from blocked_ip.json")
    return False

def read_auth_failures() -> dict:
    """
    This function initialises the content of the auth_failures.json file as a dictionary, mapping 
    client IP addresses to a list of failed authentication timestamps.
        
    Returns:
        A dictionary containing the details of all client users.
    """

    with auth_failures_file_lock:
        try:
            if not os.path.exists(AUTH_FAILURES):
                return {}
            
            with open(AUTH_FAILURES, "r") as file:
                return json.load(file)

        except Exception as e:
            log.error(f"Authorisation failures file error: Failed to read from file. {e}.")
            return {}

def read_blocked_ip() -> dict:
    """
    This function initialises the content of the blocked_ip.json file as a dictionary, mapping 
    client IP addresses to a timestamp of when the IP block will expire.
        
    Returns:
        A dictionary containing the details of all client users.
    """

    with blocked_ip_file_lock:
        try:
            if not os.path.exists(BLOCKED_IP):
                return {}
            
            with open(BLOCKED_IP, "r") as file:
                return json.load(file)

        except Exception as e:
            log.error(f"Blocked IP file error: Failed to read from file. {e}.")
            return {}

def read_blocked_passwords() -> list:
    """
    This function initialises the content of the blocked_ip.json file as a dictionary, mapping 
    client IP addresses to a timestamp of when the IP block will expire.
        
    Returns:
        A dictionary containing the details of all client users.
    """

    with blocked_passwords_file_lock:
        try:
            if not os.path.exists(BLOCKED_PASSWORDS):
                return []
            
            with open(BLOCKED_PASSWORDS, "r") as file:
                return json.load(file)

        except Exception as e:
            log.error(f"Blocked passwords file error: Failed to read from file. {e}.")
            return []

def read_users() -> dict:
    """
    This function initialises the content of the users.json file as a dictionary, mapping client 
    usernames to user metadata.
        
    Returns:
        A dictionary containing the details of all client users.
    """

    with users_file_lock:
        try:
            if not os.path.exists(USERS):
                return {}
            
            with open(USERS, "r") as file:
                return json.load(file)

        except Exception as e:
            log.error(f"Users file error: Failed to read from file. {e}.")
            return {}

def register_auth_failure(ip: str) -> None:
    """
    This function registers the IP address of a client that failed an authentication. If the 
    quantitiy authentication failures exceeds three within the BLOCK_WINDOW global variable, the 
    client IP address is added to the blocked_ip.json for the BLOCK_DURATION global variable.

    Args:
        ip: A string containing a client IP address that failed an authentication.
    """

    timestamp = datetime.now(timezone.utc).timestamp()

    failures = read_auth_failures()
    ip_failures = failures.get(ip, [])

    # Calculate the quantity of authentication failures within the BLOCK_WINDOW
    assessed_period = timestamp - BLOCK_WINDOW.total_seconds()
    ip_failures = [ts for ts in ip_failures if ts >= assessed_period]
    ip_failures.append(timestamp)
    failures[ip] = ip_failures
    write_auth_failures(failures)

    # Block client IPs with more than 3 authentication failures within the BLOCK_WINDOW
    if len(ip_failures) >= 3:
        blocked = read_blocked_ip()
        blocked_expiry = timestamp + BLOCK_DURATION.total_seconds()
        blocked[ip] = blocked_expiry
        write_blocked_ip(blocked)
        log.warning(
            f"Authentication error: Client {ip} has {len(ip_failures)} and has been blocked for"
            f"{BLOCK_DURATION}"
        )

    # Reset authentication failure tracking
    failures[ip] = []
    write_auth_failures(failures)

def sfts_authenticate(
        ssl_conn: ssl.SSLSocket, client_addr: tuple[str, int]) -> tuple[bool, str, str]:
    """
    This function authenticates the received client user credentials against the values stored in 
    the server's users.json file.
    
    Args:
        ssl_conn: A SSL-wrapped socket connection object enabling binary transfer.

        client_addr: A tuple containing the client's IP address as a string and port as an int.

    Returns:
        A tuple containing a bool defining whether the user passed SFTS authentication, a string 
        containing the username submitted by the client and a string _____________________________________________
        ______This function returns the role assigned to the user in the users.json file. Users not listed in the users.json file are assigned the default 'unregistered' role title.

    """

    try:
        # Send 256 bit nonce to client
        nonce = os.urandom(32)        
        nonce_hex = nonce.hex().encode() + b"\n"
        ssl_conn.sendall(nonce_hex)
        
        # Receive HMAC from client
        authentication = b""
        while b"\n" not in authentication:
            chunk = ssl_conn.recv(1024)
            if not chunk:
                break
            authentication += chunk

            if len(authentication) > 4096:
                log.error(
                    f"SFTS error: Incorrect authentication header received from {client_addr}.")
                raise ValueError("SFTS authentication header error")

        if b"\n" not in authentication:
            log.error(f"SFTS error: Incomplete authentication header received from {client_addr}.")
            return False, "unknown", "unregistered"

        header_line, remainder = authentication.split(b"\n",1)
        client_hmac = header_line.decode().strip()

        # Receive username from client
        username_bytes = b""
        while b"\n" not in username_bytes:
            chunk = ssl_conn.recv(1024)
            if not chunk:
                break
            username_bytes += chunk

            if len(username_bytes) > 4096:
                log.error(f"SFTS error: Incorrect username header sent by client {client_addr}.")
                raise ValueError("Username header error")

        if b"\n" not in username_bytes:
            log.error(f"SFTS error: Incomplete username header sent by client {client_addr}.")
            return False, "unknown", "unregistered"

        header_line, remainder = username_bytes.split(b"\n",1)
        username = header_line.decode().strip()

        # Initialise client variables
        users = read_users()
        timestamp = datetime.now(timezone.utc).timestamp()

        if username not in users:
            # Register first time users
            user_role = "registered"
            users[username] = {
                "hash":client_hmac, 
                "role":user_role, 
                "created":timestamp,
                "modified":timestamp
                }
            write_users(users)
            log.info(f"New user registration: Client {username} {client_addr}.")

        else:
            # Initialise credentials for returning client users
            password_hash = users[username]["hash"]
            user_role = users[username]["role"]

            # Authenticate HMAC received from returning client users
            server_hmac = hmac.new(
                key = password_hash.encode(),
                msg = nonce,
                digestmod = hashlib.sha256
            ).hexdigest()

            if not hmac.compare_digest(client_hmac, server_hmac):
                log.warning(
                    f"SFTS error: Incorrect password sent by client {username} {client_addr}.")
                
                # Record authentication failure
                client_ip = client_addr[0]
                register_auth_failure(client_ip)

                # Notify client of authentication failure
                result_bytes = b"False|denied\n"
                ssl_conn.sendall(result_bytes)
                
                return False, username, user_role

        log.info(f"Client {username} {client_addr} SFTS authenctication successful.")

        # Notify client of authentication success
        result_bytes = b"True|" + user_role.encode() + b"\n"
        ssl_conn.sendall(result_bytes)

        # Update last_access variable in users.json
        users[username]["last_access"] = timestamp
        write_users(users)

        return True, username, user_role

    except Exception as e:
        log.error(f"SFTS error: Authentication failure for {client_addr}. {e}.")
        return False, "unknown", "unregistered"

def sfts_cmd_delete(
        ssl_conn: ssl.SSLSocket, client_addr: tuple[str, int], username: str, 
        filename: str) -> None:
    """
    This function deletes a file from the host server directory.
    
    Args:    
        ssl_conn: A SSL-wrapped socket connection object enabling binary transfer.
        
        client_addr: A tuple containing the client's IP address as a string and port as an int.

        username: A string containing the username received from the client user.

        filename: A string containing the filename specified by the client user.
    """

    log.info(f"Client {username} {client_addr} initiated the delete command.")

    # Validate filename
    if not filename:
        log.error(f"Command error: Client {username} {client_addr} delete failed."
                  "Filename not received.")
        msg = b"Error: Filename not specified." + TERMINATOR
        ssl_conn.sendall(msg)
        return

    # Validate filepath
    filepath = os.path.join(DIRECTORY, filename)
    if not os.path.exists(filepath):
        log.error(f"Command error: Client {username} {client_addr} download failed."
                  "Filename doesn't exist.")
        msg = b"Error: Invalid filename." + TERMINATOR
        ssl_conn.sendall(msg)
        return

    # Delete file
    try:
        os.remove(filepath)
        log.info(f"Client {username} {client_addr} deleted {filepath}.")
        msg = (f"{filename} deleted.{TERMINATOR}").encode()
        ssl_conn.sendall(msg)

    except Exception as e:
        log.error(f"Command error: Client {username} {client_addr} delete failure {filepath}. {e}.")
        msg = b"Error: Unable to delete {filename}." + TERMINATOR
        ssl_conn.sendall(msg)

def sfts_cmd_download(
        ssl_conn: ssl.SSLSocket, client_addr: tuple[str, int], server_key: object, username: str, 
        filename: str) -> None:
    """
    This function downloads a file from the host server directory to the client directory.
    
    Args:
        ssl_conn: A SSL-wrapped socket connection object enabling binary transfer.
    
        client_addr: A tuple containing the client's IP address as a string and port as an int.

        server_key: A private key object containing the server's private key.

        username: A string containing the username received from the client user.

        filename: A string containing the filename specified by the client user.
    """

    log.info(f"Client {username} {client_addr} initiated the download command.")

    # Validate filename
    if not filename:
        log.error(f"Command error: Client {username} {client_addr} download failed."
                  "Filename not received.")
        msg = {"Error": "Filename not specified"}
        ssl_conn.sendall(json.dumps(msg).encode() + TERMINATOR)
        return

    # Validate filepath
    filepath = os.path.join(DIRECTORY, filename)
    if not os.path.exists(filepath):
        log.error(f"Command error: Client {username} {client_addr} download failed."
                  "Filename doesn't exist.")
        msg = {"Error": "Invalid filename"}
        ssl_conn.sendall(json.dumps(msg).encode() + TERMINATOR)
        return

    # Validate server key
    if not server_key:
        log.error(f"Signing error: Server key failed to initialise.")
        msg = {"Error": "Server key failed to initialise"}
        ssl_conn.sendall(json.dumps(msg).encode() + TERMINATOR)
        return

    try:
        # Calculate filesize
        filesize = os.path.getsize(filepath)

        # Generate a SHA256 hash of the file for integrity verification
        server_hash = hashlib.sha256()        
        with open(filepath, "rb") as file:
            for chunk in iter(lambda: file.read(4096), b""):
                server_hash.update(chunk)
        file_hash = server_hash.hexdigest()
        timestamp = datetime.now(timezone.utc).isoformat()

        # Generate digitial signature
        msg = f"{filename}|{filesize}|{file_hash}|{timestamp}".encode("utf-8")
        signature = server_key.sign(
            msg,
            padding.PSS(
                mgf = padding.MGF1(hashes.SHA256()),
                salt_length = padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        ) 

        # Generate JSON header
        header = {
            "filename": filename,
            "filesize": filesize,
            "hash_algorith": "SHA256",
            "file_hash": file_hash,
            "signed": timestamp,
            "signature": base64.b64encode(signature).decode("ascii")
        }
        header_bytes = json.dumps(header, seperators = (",", ":")).encode("utf-8") + TERMINATOR

        # Send JSON header to client
        ssl_conn.sendall(header_bytes)

        # Send file to client
        with open(filepath, "rb") as file:
            while True:
                chunk = file.read(4096)
                if not chunk:
                    break
                ssl_conn.sendall(chunk)

        log.info(f"Client {username} {client_addr} downloaded {filepath}.")

    except Exception as e:
        log.error(f"Command error: Client {username} {client_addr} download failure for"
                  f"{filepath}. {e}.")
        msg = {"Error": f"Unable to delete {filename}."}
        
        try:
            ssl_conn.sendall(json.dumps(msg).encode() + TERMINATOR)

        except Exception:
            pass

def sfts_cmd_ls(ssl_conn: ssl.SSLSocket, client_addr: tuple[str, int], username: str) -> None:
    """
    This function lists file in the host server directory.
    
    Args:
        ssl_conn: A SSL-wrapped socket connection object enabling binary transfer.
    
        client_addr: A tuple containing the client's IP address as a string and port as an int.

        username: A string containing the username received from the client user.
    """

    log.info(f"Client {username} {client_addr} initiated the list command.")

    try:
        files = os.listdir(DIRECTORY)
        file_list = "\n".join(files) if files else "Directory empty"

        msg = (f"Directory contents:\n{file_list}\n").encode() + TERMINATOR
        ssl_conn.sendall(msg)

        log.info(f"Client {username} {client_addr} listing success {file_list}.")

    except Exception as e:
        error_msg = b"Uable to list host server directory\n" + TERMINATOR
        try:
            ssl_conn.sendall(error_msg)

        except Exception:
            pass

        log.error(f"Command error: Client {username} {client_addr} list failure {file_list}. {e}.")

def sfts_cmd_update(ssl_conn: ssl.SSLSocket, client_addr: tuple[str, int], username: str) -> None:
    """
    This function uploads a file from the client directory to the host server directory.
    
    Args:
        ssl_conn: A SSL-wrapped socket connection object enabling binary transfer.
    
        client_addr: A tuple containing the client's IP address as a string and port as an int.

        username: A string containing the username received from the client user.
    """

    log.info(f"Client {username} {client_addr} initiated the update command.")

###################################################################################################
######################################## NOT YET DEVELOPED ########################################
###################################################################################################

def sfts_cmd_upload(
        ssl_conn: ssl.SSLSocket, client_addr: tuple[str, int], server_key: object, username: str, 
        filename: str) -> None:
    """
    This function uploads a file from the client directory to the host server directory.
    
    Args:
        ssl_conn: A SSL-wrapped socket connection object enabling binary transfer.
    
        client_addr: A tuple containing the client's IP address as a string and port as an int.

        server_key: A private key object containing the server's private key.

        username: A string containing the username received from the client user.

        filename: A string containing the filename specified by the client user.
    """

    log.info(f"Client {username} {client_addr} initiated the upload command.")






















    # while True:
    #     filename = str(input("File to be downloaded:").strip())
    #     if filename:
    #         break
    #     print("Invalid filename")

    # filepath = os.path.join(DIRECTORY, filename)

    # # Prevent accidental overwrites caused by name conflicts
    # if os.path.exists(filepath):
    #     log.info(f"A file named {filename} already exists in {DIRECTORY}.\n")

    #     # Obtain user permission to overwrite or cancel download request
    #     user_choice = str(input(
    #         "Type 'Yes' to overwrite the existing file or type any other key to cancel: ").strip())
        
    #     if user_choice.lower() != "yes":
    #         log.info(f"Client {username} cancelled download to prevent overwrite of {filepath}")
    #         return
        
    #     log.info(f"Client {username} elected to overwrite {filepath}")

    # # Send command to host server
    # timestamp = datetime.now(timezone.utc).isoformat()
    # msg = (f"download|{filename}|{timestamp}\n").encode()
    # ssl_conn.sendall(msg)

    # # Receive filesize information from host server
    # try:
    #     buffer = sfts_response(ssl_conn, host_address)

    # except (ConnectionError, ValueError) as e:
    #     log.error(f"Command error: Failed to receive response from host server {host_address}")
    #     return

    # # Isolate JSON header in host server response
    # header_bytes, _ = buffer.split(TERMINATOR,1)

    # # Decode JSON header
    # try:
    #     header = json.loads(header_bytes.decode("utf-8"))

    # except json.JSONDecodeError as e:
    #     log.error(f"")
    #     return

    # # Print error messages if required
    # if "Error" in header:
    #     print(header["Error"])
    #     return

    # # Initialise JSON header contents
    # try:
    #     filename = header["filename"],
    #     filesize = int(header["hash_algorith"]),
    #     hash_alg = header["file_hash"],
    #     signed = header["signed"],
    #     signature = header["signature"],

    # except KeyError as e:
    #     log.error(f"Command error: Missing download cmd header contents. {e}")
    #     return

    # # Print error messages if SHA256 wasn't used to generate the hash.
    # if hash_alg.upper() != "SHA256":
    #     log.error(f"Command error: Unrecognised hash algorithm. {hash_alg}")

    # # Extract and initilaise the server public key from the server certificate
    # try:
    #     der_certificate = ssl_conn.getpeercert(binary_form = True)
    #     if not der_certificate:
    #         raise ValueError("Server certificate couldn't be initialised")
    #     server_certificate = x509.load_der_x509_certificate(der_certificate)
    #     server_public_key = server_certificate.public_key()

    # except Exception as e:
    #     log.error(f"Signature error: Server private key couldn't be initialised. {e}.")

    # header_data = f"{filename}|{filesize}|{hash_alg}|{signed}"

    # # Validate signature
    # try:
    #     signature = base64.b64decode(signature)
    #     server_public_key.verify(
    #         signature,
    #         header_data,
    #         padding.PSS(
    #             mgf = padding.MGF1(hashes.SHA256()),
    #             salt_length = padding.PSS.MAX_LENGTH
    #         ),
    #         hashes.SHA256
    #     )

    #     log.info(f"Signature validated for {filename} from host server {host_address}.")

    # # Discard excess data in the event on an error processing header
    # except Exception as e:
    #     log.error(f"Signature error: Unable to validate signature for {filename} from host server"
    #               f"{host_address}.")

    #     remaining = filesize
    #     try:
    #         while remaining > 0:
    #             chunk = ssl_conn.recv(min(4096, remaining))
    #             if not chunk:
    #                 break
    #             remaining -= len(chunk)

    #     except Exception:
    #         pass

    # # Receive file from host server while incrementally 
    # received_hash = hashlib.sha256()
    # remaining = filesize

    # try:
    #     with open(filepath) as file:
    #         while remaining > 0:
    #             chunk = ssl_conn.recv(min(4096, remaining))
    #             if not chunk:
    #                 log.error(f"Command error: Connection with {host_address} lost during download")
    #                 raise ConnectionError(f"Connection lost during download")
    #             file.write(chunk)
    #             received_hash.update(chunk)
    #             remaining -= len(chunk)

    # except Exception as e:
    #     log.error(f"Command error: {filename} download failed. {e}.")

    #     # Attempt to remove fail downloads
    #     try:
    #         os.remove(filepath)

    #     except Exception:
    #         pass

    #     return

    # # Verify download file integrity using host server provided hash and client generated hash
    # client_hash = received_hash.hexdigest()
    # if received_hash != client_hash:
    #     log.error(f"Command error: {filename} failed hash verification.")

    #     # Attempt to remove unverified downloads
    #     try:
    #         os.remove(filepath)

    #     except Exception:
    #         pass

    #     return

    # log.info(f"{filename} download and integrity verification successful.")













def sfts_connection(
        conn: socket.socket, client_addr: tuple[str, int], password: str, 
        server_key: object) -> None:
    """
    This function establishes SSL connections with clients and initiates authentication,
    authorisation and SFTS operation functions.
    
    Args:
        conn: A socket connection object enabling binary transfer.

        client_addr: A tuple containing the client's IP address as a string and port as an int.

        password: A string containing the password used to decrypt the CA and server keys as input 
        by the server user.

        server_key: A private key object containing the server's private key.
    """
    
    # Initialise placeholder client address to prevent exception reporting errors
    username = "unknown"
    client_ip = client_addr[0]

    try:
        # Evaluate whether the client IP is currently blocked and terminate connection if True
        if evaluate_ip(client_ip):
            log.warning(f"Authentication rejection: Client {client_addr} blocked.")
            return
        
        context = sfts_context(password)
        with context.wrap_socket(conn, server_side = True) as ssl_conn:
            log.info(f"SFTS service connection success with client {client_addr}.")

            # Authenticate client
            user_authentication, username, user_role = sfts_authenticate(ssl_conn, client_addr)
            
            # Disconnect from clients that failed authentication
            if not user_authentication:
                log.warning(f"Authentication error: Client {username} {client_addr} failure.")
                return

            # Recieve commands from client
            sfts_operations(ssl_conn, client_addr, server_key, username, user_role)

    # Common error handling
    except ssl.SSLError as _:
        log.error(f"SFTS error: Client {client_addr} SSL/TLS error. {_}.")

    except Exception as e:
        log.error(f"SFTS error: Client {client_addr} connection failure. {e}.")

    finally:
        try:
            conn.close()
        
        except Exception as e:
            log.error(f"SFTS error: Client {username} {client_addr} connection error. {e}.")
            pass
        
        log.info(f"Connection with client {username} {client_addr} closed")

def sfts_context(password: str) -> ssl.SSLContext:
    """
    This function creates a hardened SSL context using TLS 1.2 and Public Key Infrastructure 
    (PKI).
    
    Args:
        password: A string containing the password used to decrypt the CA and server keys as input 
        by the server user.

    Returns:
        A SSL object containing the CA, server certificate and private key.
    """

    try:
        # Default to newest TLS version
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

        # Security configuration
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.options |= ssl.OP_NO_COMPRESSION
        context.set_ciphers("ECDHE+AESGCM")

        # Initilaise SSL certificates and keys as variables
        context.load_cert_chain(
            certfile = f"{CERTIFICATES}server_certificate.pem", 
            keyfile = f"{CERTIFICATES}server_key.pem",
            password = password
        )

        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations(f"{CERTIFICATES}ca_certificate.pem")

        log.info("SSL context initialisation success.")
        return context

    except Exception as e:
        log.critical(f"Fatal error: SSL context initialisation failure. {e}.")
        sys.exit(1)

def sfts_listen(password: str, server_key: object) -> None:
    """
    This function listens for Transport Layer Security (TLS) connections sent by clients, using the 
    threading module for parallel processing of handler threads.
    
    Args:
        password: A string containing the password used to decrypt the CA and server keys as input 
        by the server user.

        server_key: A private key object containing the server's private key.
    """

    # Configure socket connections
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        # Mitigate server crashes and restarts by enabling reuse of socket addresses 
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            sock.bind((HOST, SFTS_PORT))
            sock.listen(5)
            log.info(f"SFTS service bound to {HOST}:{SFTS_PORT}.")

        except Exception as e:
            log.critical(f"SFTS error: Failed to bind SFTS service to port {SFTS_PORT}. {e}.")

        # Initialise placeholder client address to prevent variable errors in exception reporting
        client_addr = ("unknown",0)

        while True:
            try:
                conn, client_addr = sock.accept()
            
            except Exception as e:
                log.error(f"SFTS error: Connection with failure with client {client_addr}. {e}.")
                continue
            
            log.info(f"SFTS service connection success with client {client_addr}.")

            conn.settimeout(120)

            threading.Thread(
                target = sfts_connection,
                args = [conn, client_addr, password, server_key],
                daemon = True
            ).start()

def sfts_operations(
        ssl_conn: ssl.SSLSocket, client_addr: tuple[str, int], server_key: object, username: str, 
        user_role: str) -> None:

    """
    This function manages SSL connections with clients, incorporating function calls for client 
    initiated commands.

    Args:
        ssl_conn: A SSL-wrapped socket connection object enabling binary transfer.
    
        client_addr: A tuple containing the client's IP address as a string and port as an int.
        
        server_key: A private key object containing the server's private key.

        username: A string containing the username received from the client user.
        
        user_role: A string containing the client user's role as listed in the users.json file.
    """

    log.info(f"Client {username} {client_addr} initiated SFTS operations.")

    while True:

        # Receive command from client
        cmd_bytes = b""
        while b"\n" not in cmd_bytes:
            chunk = ssl_conn.recv(1024)
            if not chunk:
                break
            cmd_bytes += chunk

            if len(cmd_bytes) > 4096:
                log.error(f"Cmd error: Incorrect command header sent by client {client_addr}.")
                raise ValueError("Cmd header error")

        if b"\n" not in cmd_bytes:
            log.error(f"Cmd error: Incomplete command header sent by client {client_addr}.")
            return

        # Initialise command variables
        header_line, remainder = cmd_bytes.split(b"\n",1)
        cmd, filename, timestamp = header_line.decode().strip().split("|",maxsplit = 2)   


# Initialise command variables
        try:
            cmd = cmd.lower().strip()
            filename = filename.lower().strip()
            timestamp = datetime.fromisoformat(timestamp)

        except Exception as e:
            log.error(f"Command error: Client {username} {client_addr} sent incorrect command data"
                      f" type. {e}.")
            continue

        # Validate client command timestamp
        if not timestamp_validation(timestamp, client_addr, username):
            log.error(f"Command error: Client {username} {client_addr} exceeded delay threshold.")
            continue

        # Validate client role permissions
        if not roles.get(user_role, {}).get(cmd, False):
            log.error(f"Command error: Client {username} {client_addr} called {cmd} without role"
                      " permissions.")
            continue

        # Action client command
        if cmd == "delete":
            sfts_cmd_delete(ssl_conn, client_addr, username, filename)

        elif cmd == "download":
            sfts_cmd_download(ssl_conn, client_addr, server_key, username, filename)

        elif cmd == "exit":
            log.info(f"Client {username} {client_addr} terminated session")
            break

        elif cmd == "ls":
            sfts_cmd_ls(ssl_conn, client_addr, username)

        elif cmd == "update":
            sfts_cmd_update(ssl_conn, client_addr, username)

        elif cmd == "upload":
            sfts_cmd_upload(ssl_conn, client_addr, server_key, username, filename)

        else:
            log.error(
                f"Command error: Client {username} {client_addr} sent unrecognised command {cmd}.")

def timestamp_validation(timestamp: object, client_addr: tuple[str, int], username: str) -> bool:
    """
    This function mitigates against replay attacks by calculating the difference between timestamps 
    embedded in client communication and timestamps generated by the server.
    
    Args:
        timestamp: An object containing the date and time in UTC +0:00, identifying when the 
        received message was sent by the client.

        client_addr: A tuple containing the client's IP address as a string and port as an int.

        username: A string containing the username received from the client user.

    Returns:
        A Bool containing True if the age of the recieved timestamp is less than the DELAY_TOLERANCE 
        global variable, else False.
    """
    
    try:
        delay = datetime.now(timezone.utc) - timestamp
    
        if delay < DELAY_TOLERANCE:
            return True

        log.error(
            f"Timestamp error: Client {username} {client_addr} timestamp exceeds delay tolerance.")
        return False   
    
    except Exception as e:
        log.error(f"Timestamp error: Client {username} {client_addr} validation failure. {e}.")
        return False

def write_auth_failures(auth_failures: dict) -> None:
    """
    This function writes a dictionary to the auth_failures.json file.
        
    Args:
        auth_failures: A dictionary containing the timestamps of client authentication failures.
    """

    with auth_failures_file_lock:
        try:
            with open(AUTH_FAILURES, "w") as file:
                json.dump(auth_failures, file, indent = 4)

        except Exception as e:
            log.error(f"Authorisation failures file error: Failed to write file. {e}.")
            return

def write_blocked_ip(blocked_ip: dict) -> None:
    """
    This function writes a dictionary to the users.json file.
        
    Args:
        blocked_ip: A dictionary containing the timestamp of when the blocks on client IP 
        addresses will expire.
    """

    with blocked_ip_file_lock:
        try:
            with open(BLOCKED_IP, "w") as file:
                json.dump(blocked_ip, file, indent = 4)

        except Exception as e:
            log.error(f"Blocked IP file error: Failed to write file. {e}.")
            return

def write_users(users: dict) -> None:
    """
    This function writes a dictionary to the users.json file.
        
    Args:
        users: A dictionary containing the details of all client users.
    """

    with users_file_lock:
        try:
            with open(USERS, "w") as file:
                json.dump(users, file, indent = 4)

        except Exception as e:
            log.error(f"Users file error: Failed to write file. {e}.")
            return

def main() -> None:
    print("---------------------------------------------------------------------------------\n")
    print("                       Secure File Transfer System: Server                       \n")
    print("---------------------------------------------------------------------------------\n")

    # Input the CA and server decryption password
    password, ca_key, server_key = csr_decryption()

    # Start the CSR service
    log.info(f"CSR service starting on {HOST}:{CSR_PORT}")
    threading.Thread(
        target = csr_listen,
        args = [ca_key],
        daemon = True
    ).start()

    # Start the SFTS service
    log.info(f"SFTS service starting on {HOST}:{SFTS_PORT}")
    sfts_listen(password, server_key)

if __name__ == "__main__":
    try:
        main()

    except KeyboardInterrupt:
        log.info("Server shutdown by keyboard interrupt.")

    except Exception as e:
        log.critical(f"Fatal error: {e}.")