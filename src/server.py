from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from datetime import datetime, timezone, timedelta
import json
import logging
import os
import socket
import ssl
import threading
from typing import TextIO

# Initialise global variables
HOST: str = "127.0.0.1"       #"10.16.10.247"
HOST_CODE: str = "9d695442d1ccee8313ff7f7eaa1566cbe6b32fa4c9e80f7ebd68a36d8df83f5a"
SFTS_PORT: int = 8443
CSR_PORT: int = 8444
DELAY_TOLERANCE: timedelta = timedelta(seconds=5)
CERTIFICATES: str = "/workspaces/secure-file-transfer-system-python/certificates/"
DIRECTORY: str = "/workspaces/secure-file-transfer-system-python/directory/"
USERS: str = "/workspaces/secure-file-transfer-system-python/src/users.json"

# Create required filepaths if they don't already exist
os.makedirs(CERTIFICATES, exist_ok = True)
os.makedirs(DIRECTORY, exist_ok = True)

if not os.path.exists(USERS):
    with open(USERS, 'w') as file:
        json.dump({}, file)

# Initialise user role permissions
ROLES: dict[str, dict[str, bool]] = {
    "admin": {
        "administer" : True,
        "delete" : True,
        "download" : True,        
        "ls" : True,
        "update" : True,
        "upload" : True
    },
    "user": {
        "administer" : False,
        "delete" : False,
        "download" : True,        
        "ls" : True,
        "update" : True,
        "upload" : True
    },
    "registered": {
        "administer" : False,
        "delete" : False,
        "download" : False,        
        "ls" : True,
        "update" : True,
        "upload" : False
    },
    "unregistered": {
        "administer" : False,
        "delete" : False,
        "download" : False,        
        "ls" : False,
        "update" : True,
        "upload" : False
    },   
}

# Configure logging protocol
logging.basicConfig(
    level = logging.INFO,
    format = "[%(asctime)s] [%(levelname)s] %(message)s",
    datefmt = "%y-%m-%d %H:%M:%S"
)

log = logging.getLogger("SFTS_server")

def csr_connection(client_sock: socket.socket, client_addr: tuple[str, int]) -> None:
    """
    This function receives CSR connections with clients and returns a certificate valid for 365 days.
    
    Args:        
        client_sock: A socket object connected to the client.
    
        client_addr: A tuple containing the client's ip address as a string and port as an int.
    """

    # Initialise the csr path variable to mitigate exception errors
    csr_path = None

    try:
        # Receive CSR data from client
        chunks = []
        while True:
            chunk = client_sock.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)

        if not chunks:
            log.error(f"CSR error: No data received from client {client_addr}.")

        # Compile CSR data
        csr_data = b"".join(chunks)

        # Initialise the client ip address as a variable that can be used for file naming
        client_ip = client_addr[0].replace(".","")

        csr_path = os.path.join(CERTIFICATES, f"{client_ip}_csr.pem")
        
        with open(csr_path, "wb") as file:
            file.write(csr_data)

        # Sign CSR
        signed_certificate_path = csr_sign(csr_path, client_addr)

        # Send certificate to client
        with open(signed_certificate_path, "rb") as file:
            client_sock.sendall(file.read())
        
        log.info(f"CSR {csr_path} signed and sent to {client_addr}.")

    except Exception as e:
        log.error(f"CSR error: CSR failure for {client_addr}. {e}.")

    finally:
        try:
            client_sock.close()
        
        except Exception:
            pass

        if csr_path and os.path.exists(csr_path):
            try:
                os.remove(csr_path)

            except Exception:
                pass

def csr_listen() -> None:
    """
    This function listens for Certificate Signing Request (CSR) connections sent by 
    clients, using the threading module for parallel processing of handler threads.
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
                client_sock, client_addr = sock.accept()
            
            except Exception as e:
                log.error(f"CSR error: Connection with failure with client {client_addr}. {e}.")
                continue
            
            log.info(f"CSR service connection success with client {client_addr}.")

            client_sock.settimeout(10)

            threading.Thread(
                target = csr_connection,
                args = (client_sock, client_addr),
                daemon = True
            ).start()

def csr_sign(csr_path: str, client_addr: tuple[str, int]) -> str:
    """
    This function signs a CSR using the Certificate Authority (CA) certificate and Private Key, 
    and returns the new certificate filepath.
        
    Args:
        csr_path: A string containing the file path for the client's CSR.
    
        client_addr: A tuple containing the client's ip address as a string and port as an int.

    Returns:
        A string containing the file path for the signed client certificate.
    """
    
    # Define the CA key and certificate filepaths
    ca_key_path = os.path.join(CERTIFICATES, "ca_key.pem")
    ca_certificate_path = os.path.join(CERTIFICATES, "ca_certificate.pem")

    try:
        # Initialise the CA key as a local variable
        with open(ca_key_path, "rb") as file:
            ca_key = serialization.load_pem_private_key(
                file.read(),
                password = None             ############## Data at rest encryption to be added once all other functionality is fully tested ##############
            )

        # Initialise the CA certificate as a local variable
        with open(ca_certificate_path, "rb") as file:
            ca_certificate = x509.load_pem_x509_certificate(file.read())

        # Initialise the client's CSR as a local variable
        with open(csr_path, "rb") as file:
            csr = x509.load_pem_x509_csr(file.read())

    except Exception as e:
        log.error(f"CSR error: Failed to initialise CA certificate, CA key or CSR. {e}.")
        raise

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
        log.error(f"CSR error: Failed to initialise client certificate. {e}.")
        raise

    # Initialise the client ip address as a variable that can be used for file naming
    client_ip = client_addr[0].replace(".","")

    try:
        # Write the client's certificate
        client_certificate_path = os.path.join(CERTIFICATES, f"{client_ip}_certificate.pem")

        with open(client_certificate_path, "wb") as file:
            file.write(client_certificate.public_bytes(serialization.Encoding.PEM))

        return client_certificate_path

    except Exception as e:
        log.error(f"CSR error: Failed to write client certificate. {e}.")
        raise

def sfts_authenticate(client_addr: tuple[str, int]) -> tuple[bool, str]:
    """
    This function authenticates received user credentials against the values stored in the 
    users.json file.
    
    Args:
        client_addr: A tuple containing the client's ip address as a string and port as an int.

    Returns:
        A tuple containing a bool defining whether the user passed SFTS authentication and
        a string containing the username submitted by the client.
    """
    
    #####
    #####
    #####
    #####
    #####
    #####
    #####
    
    username = "dban0016"                                                           ######################## Placeholder only, update when building this function ########################
    password = "162a1dd44f30c97998f750a500a19ba5992c451f71e1bc9702503a24c3f1b217"   ######################## Placeholder only, update when building this function ########################

    users = users_read()

    if username in users and users[username]["hash"] == password:
        log.info(f"Client {username} {client_addr} authentication success.")
        return True, username

    log.error(f"Client {username} {client_addr} authentication failure.")
    return False, username

def sfts_authorise(username: str) -> str:
    """
    This function returns the role assigned to the user in the users.json file. Users not 
    listed in the users.json file are assigned the default 'unregistered' role title.
    
    Args:
        username: A string containing the client's username.    
    
    Returns:
        A string containing the user's role title.
    """
    users = users_read()

    if username in users:
        role = users[username]["role"]
        return role

    return "unregistered"

def sfts_cmd_delete(reader: TextIO, writer: TextIO, client_addr: tuple[str, int], username: str ) -> None:
    """
    This function deletes a file from the host server directory.
    
    Args:
        reader: A TextIO object that enables reading from the SSL-wrapped socket connection.
    
        writer: A TextIO object that enables writing to the SSL-wrapped socket connection.
    
        client_addr: A tuple containing the client's ip address as a string and port as an int.

        username: A string containing the client's username.
    """

    log.info(f"Client {username} {client_addr} delete initiated.")
    
    filename = reader.readline().strip()

    if not filename:
        log.error(f"Command error: Client {username} {client_addr} delete failed. Filename not received.")
        writer.write(f"Error: Filename not received\n!reset!\n")
        writer.flush()
        return

    filepath = os.path.join(DIRECTORY, filename)

    if not os.path.exists(filepath):
        log.error(f"Command error: Client {username} {client_addr} delete failed. Invalid filename.")
        writer.write(f"Error: Invalid filename\n!reset!\n")
        writer.flush()
        return

    try:
        os.remove(filepath)
        log.info(f"Client {username} {client_addr} deleted {filepath}.")
        writer.write(f"{filename} deleted\n")
        writer.flush()

    except Exception as e:
        log.error(f"Command error: Client {username} {client_addr} delete failure {filepath}. {e}.")
        writer.write(f"Error: Unable to delete {filename}\n!reset!\n")
        writer.flush()

def sfts_cmd_download(ssl_conn: ssl.SSLSocket, reader: TextIO, writer: TextIO, client_addr: tuple[str, int], username: str) -> None:
    """
    This function downloads a file from the host server directory to the client directory.
    
    Args:
        ssl_conn: The SSL-wrapped socket connection enabling binary transfer.
        
        reader: A TextIO object that enables reading from the SSL-wrapped socket connection.
    
        writer: A TextIO object that enables writing to the SSL-wrapped socket connection.
    
        client_addr: A tuple containing the client's ip address as a string and port as an int.

        username: A string containing the client's username.
    """

    log.info(f"Client {username} {client_addr} download initiated.")

    filename = reader.readline().strip()

    if not filename:
        log.error(f"Command error: Client {username} {client_addr} download failed. Filename not received.")
        writer.write(f"Error: Filename not received\n!reset!\n")
        writer.flush()
        return

    filepath = os.path.join(DIRECTORY, filename)

    if not os.path.exists(filepath):
        log.error(f"Command error: Client {username} {client_addr} download failed. Invalid filename.")
        writer.write(f"Error: Invalid filename\n!reset!\n")
        writer.flush()
        return

    try:
        filesize = os.path.getsize(filepath)
        writer.write(f"{filesize}\n")
        writer.flush()

        with open(filepath, "rb") as file:
            while True:
                chunk = file.read(4096)
                if not chunk:
                    break
                ssl_conn.sendall(chunk)
        
        log.info(f"Client {username} {client_addr} downloaded {filepath}.")
        writer.write(f"{filename} download successful\n")
        writer.flush()

    except Exception as e:
        log.error(f"Command error: Client {username} {client_addr} download failure {filepath}. {e}.")
        writer.write(f"Error: Unable to download {filename}\n!reset!\n")
        writer.flush()

def sfts_cmd_ls(writer: TextIO, client_addr: tuple[str, int], username: str) -> None:
    """
    This function lists file in the host server directory.
    
    Args:
        writer: A TextIO object that enables writing to the SSL-wrapped socket connection.
    
        client_addr: A tuple containing the client's ip address as a string and port as an int.

        username: A string containing the client's username.
    """

    log.info(f"Client {username} {client_addr} ls initiated.")

    try:
        # files = sorted(file.name for file in DIRECTORY.iterdir() if file.is_file())                   ######################## Need to evaluate whether this is a more optimal solution
        files = os.listdir(DIRECTORY)
        file_list = "\n".join(files) if files else "Directory empty"
        
        log.info(f"Client {username} {client_addr} listing success {file_list}.")
        
        writer.write(f"Directory contents:\n{file_list}\n")
        writer.flush()

    except Exception as e:
        log.error(f"Command error: Client {username} {client_addr} listing failure {file_list}. {e}.")
        writer.write("Error: Unable to list directory\n!reset!\n")
        writer.flush()

def sfts_cmd_upload(ssl_conn: ssl.SSLSocket, reader: TextIO, writer: TextIO, client_addr: tuple[str, int], username: str) -> None:
    """
    This function uploads a file from the client directory to the host server directory.
    
    Args:
        ssl_conn: The SSL-wrapped socket connection enabling binary transfer.
        
        reader: A TextIO object that enables reading from the SSL-wrapped socket connection.
    
        writer: A TextIO object that enables writing to the SSL-wrapped socket connection.
    
        client_addr: A tuple containing the client's ip address as a string and port as an int.

        username: A string containing the client's username.
    """

    log.info(f"Client {username} {client_addr} upload initiated.")

    filename = reader.readline().strip()

    if not filename:
        log.error(f"Command error: Client {username} {client_addr} upload failed. Filename not received.")
        writer.write(f"Error: Filename not received\n!reset!\n")
        writer.flush()
        return

    filepath = os.path.join(DIRECTORY, filename)

    if filepath is None:
        log.error(f"Command error: Client {username} {client_addr} upload failed. Invalid filename.")
        writer.write(f"Error: Invalid filename\n!reset!\n")
        writer.flush()
        return

    filesize_line = reader.readline().strip()
    if not filesize_line:
        log.error(f"Command error: Client {username} {client_addr} upload failed. Filesize not received.")
        writer.write("Error: Filesize not provided\n!reset!\n")
        writer.flush()
        return

    try:
        filesize = int(filesize_line.strip())
        if filesize < 0:
            log.error(f"Command error: Client {username} {client_addr} upload failed. Filesize {filesize} invalid.")
            raise ValueError

    except Exception as e:
        log.error(f"Command error: Client {username} {client_addr} upload failed. {e}.")
        writer.write(f"Error: Invalid filesize {filesize}\n!reset!\n")
        writer.flush()
        return

    # Write upload file to disk
    remaining = filesize
    try:
        with open(filepath, "wb") as file:
            while remaining > 0:
                chunk = ssl_conn.recv(min(4096, remaining))
                if not chunk:
                    break
                file.write(chunk)
                remaining -= len(chunk)

        if remaining != 0:
            log.error(f"Command error: Client {username} {client_addr} upload failed. Disconnection with {remaining} bytes remaining.")
            writer.write(f"Error: Upload incomplete\n!reset!\n")
            writer.flush()
            raise IOError

        # Completion notification
        log.info(f"Client {username} {client_addr} uploaded {filepath}.")
        writer.write(f"{filename} upload successful\n")
        writer.flush()

    except Exception as e:
        log.error(f"Command error: Client {username} {client_addr} upload failure {filepath}. {e}")
        writer.write(f"Error: Unable to upload {filename}\n!reset!\n")
        writer.flush()

def sfts_operations(ssl_conn: ssl.SSLSocket, reader: TextIO, writer: TextIO, client_addr: tuple[str, int], username: str, user_role: str) -> None:

    """
    This function manages SSL connections with clients, incorporating function calls for client 
    initiated commands.

    Args:
        ssl_conn: The SSL-wrapped socket connection enabling binary transfer.
        
        reader: A TextIO object that enables reading from the SSL-wrapped socket connection.
    
        writer: A TextIO object that enables writing to the SSL-wrapped socket connection.
    
        client_addr: A tuple containing the client's ip address as a string and port as an int.
        
        username: A string containing the user name input by the client.
        
        user_role: A string containing the user's role as listed in the users.json file.
    """

    log.info(f"Client {username} {client_addr} initiated SFTS operations.")

    while True:               
        
        # Receive client command
        line = reader.readline()
        if not line:
            log.info(f"Client {username} {client_addr} terminated SFTS operations.")
            break

        # Decompose client command into cmd|timestamp
        args = line.strip().split("|",maxsplit = 1)   
        if len(args) != 2:
            log.error(f"Command error: Client {username} {client_addr} msg length incorrect.")          
            writer.write("Error: Incorrect message length\n!reset!\n")
            writer.flush()
            continue
        
        # Initialise command variables
        try:
            cmd = args[0].lower() 
            timestamp = datetime.fromisoformat(args[1])

        except Exception as e:
            log.error(f"Command error: Client {username} {client_addr} sent incorrect command data type. {e}.")
            writer.write("Error: Incorrect command data type\n!reset!\n")
            writer.flush
            continue

        # Validate client command timestamp
        if not timestamp_validation(timestamp, client_addr, username):
            log.error(f"Command error: Client {username} {client_addr} exceeded delay threshold.")
            writer.write("Error: Message delay threshold exceeded\n!reset!\n")
            writer.flush()
            continue

        # Validate client role permissions
        if not ROLES[user_role][cmd]:
            log.error(f"Command error: Client {username} {client_addr} called {cmd} without role permissions")
            writer.write(f"Error: You don't have sufficient permissions to {cmd}\n!reset!\n")
            writer.flush()
            continue

        # Action client command
        if cmd == "administer":
            users_administer()
        
        elif cmd == "download":
            sfts_cmd_download(ssl_conn, reader, writer, client_addr, username)

        elif cmd == "delete":
            sfts_cmd_delete(reader, writer, client_addr, username)

        elif cmd == "exit":
            log.info(f"Client {username} {client_addr} terminated session")
            break

        elif cmd == "ls":
            sfts_cmd_ls(writer, client_addr, username)

        elif cmd == "update":
            users_update()

        elif cmd == "upload":
            sfts_cmd_upload(ssl_conn, reader, writer, client_addr, username)

        else:
            log.error(f"Command error: Client {username} {client_addr} sent unrecognised command {cmd}.")
            writer.write(f"Error: {cmd} not recognised\n")
            writer.flush()

def sfts_connection(client_sock: socket.socket, client_addr: tuple[str, int]) -> None:
    """
    This function establishes SSL connections with clients and initiates authentication,
    authorisation and SFTS operation functions.
    
    Args:
        client_sock: A socket object connected to the client.

        client_addr: A tuple containing the client's ip address as a string and port as an int.
    """
    
    # Initialise placeholder client address to prevent exception reporting errors
    username = "unknown"

    try:
        context = sfts_context()
        with context.wrap_socket(client_sock, server_side = True) as ssl_conn:
            log.info(f"SFTS service connection success with client {client_addr}.")

            # Define server-client communication protocol
            reader = ssl_conn.makefile("r", encoding = "utf-8")
            writer = ssl_conn.makefile("w", encoding = "utf-8", buffering = 1)
    
            # Authenticate client
            user_authentication, username = sfts_authenticate(client_addr)
            
            # Disconnect from clients that failed authentication
            if not user_authentication:
                return

            # Authorise client
            user_role = sfts_authorise(username)
            log.info(f"Client {username} {client_addr} authorisation success: {user_role} permissions")

            # Recieve commands from client
            sfts_operations(ssl_conn, reader, writer, client_addr, username, user_role)

    # Common error handling
    except ssl.SSLError as _:
        log.error(f"SFTS error: Client {client_addr} SSL/TLS error. {_}.")

    except Exception as e:
        log.error(f"SFTS error: Client {client_addr} connection failure. {e}.")

    finally:
        try:
            client_sock.close()
        
        except Exception as e:
            log.error(f"SFTS error: Connection with client {username} {client_addr} failed to close gracefully. {e}.")
            pass
        
        log.info(f"Connection with client {username} {client_addr} closed")

def sfts_context() -> ssl.SSLContext:
    """
    This function creates a hardened SSL context using TLS 1.2 and Public Key Infrastructure 
    (PKI).
    
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
            keyfile = f"{CERTIFICATES}server_key.pem"
        )

        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations(f"{CERTIFICATES}ca_certificate.pem")

        log.info("SSL context initialisation success.")
        return context

    except Exception as e:
        log.critical(f"Fatal error: SSL context initialisation failure. {e}")

def sfts_listen() -> None:
    """
    This function listens for Transport Layer Security (TLS) connections sent by 
    clients, using the threading module for parallel processing of handler threads.
    """

    # Configure socket connections
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        # Account for server crash/resart by enabling reuse of socket addresses 
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            sock.bind((HOST, SFTS_PORT))
            sock.listen(5)
            # Log initiation of SFTS listening service
            log.info(f"SFTS service listening on {HOST}:{SFTS_PORT}.")

        except Exception as e:
            log.critical(f"SFTS error: Port {SFTS_PORT} binding failure. {e}.")

        # Initialise placeholder client address to prevent exception reporting errors
        client_addr = ("unknown",0)

        while True:
            try:
                client_sock, client_addr = sock.accept()
            
            except Exception as e:
                log.error(f"SFTS error: Connection with failure with client {client_addr}. {e}.")
                continue
            
            log.info(f"SFTS service connection success with client {client_addr}.")

            client_sock.settimeout(10)

            threading.Thread(
                target = sfts_connection,
                args = (client_sock, client_addr),
                daemon = True
            ).start()

def timestamp_validation(timestamp: object, client_addr: tuple[str, int], username: str) -> bool:
    """
    This function mitigates against replay attacks by calculating the difference between
    timestamps embedded in client communication and timestamps generated by the server.
    
    Args:
        timestamp: An object containing the date and time in UTC +0:00, identifying when 
        the received message was sent by the client.

        client_addr: A tuple containing the client's ip address as a string and port as an int.

        username: A string containing the user name input by the client.

    Returns:
        A Bool containing True if the age of the recieved timestamp is less than the 
        DELAY_TOLERANCE global variable, else False.
    """
    
    try:
        delay = datetime.now(timezone.utc)  - timestamp
    
        if delay < DELAY_TOLERANCE:
            return True

        log.error(f"Timestamp error: Client {username} {client_addr} timestamp exceeds delay tolerance.")
        return False   
    
    except Exception as e:
        log.error(f"Timestamp error: Client {username} {client_addr} validation failure. {e}.")
        return False

def users_administer() -> None:
    """
    _________________________________________
    """
    pass

# Serialise read/write operations on the users.json file to mitigate race conditions
users_file_lock = threading.Lock()

def users_read() -> dict:
    """
    This function initialises the content of the users.json file as a dictionary.
        
    Returns:
        A dictionary containing the details of all STFS users.
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

def users_update() -> None:
    """
    _______________________
    """
    pass

def users_write(users: dict) -> None:
    """
    This function writes a dictionary to the users.json file.
        
    Args:
        users: A dictionary containing the details for STFS users.
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

    # Start the CSR service
    log.info(f"CSR service starting on {HOST}:{CSR_PORT}")
    threading.Thread(target = csr_listen, daemon = True).start()

    # Start the SFTS service
    log.info(f"SFTS service starting on {HOST}:{SFTS_PORT}")
    sfts_listen()

if __name__ == "__main__":
    try:
        main()

    except KeyboardInterrupt:
        log.info("Server shutdown by keyboard interrupt.")

    except Exception as e:
        log.critical(f"Fatal error: {e}.")