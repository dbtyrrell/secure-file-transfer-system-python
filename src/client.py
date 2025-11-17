from cryptography import x509
from cryptography.exceptions import InvalidKey
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from datetime import datetime, timezone
import getpass
import hashlib
import ipaddress
import logging
import os
import socket
import ssl
import sys
import threading
from typing import TextIO

# Global variable configuration
SFTS_PORT = 8443
CSR_PORT = 8444
CERTIFICATES = "/workspaces/secure-file-transfer-system-python/certificates/"
DIRECTORY = "/workspaces/secure-file-transfer-system-python/directory/"

# Create filepaths if required
os.makedirs(CERTIFICATES, exist_ok = True)
os.makedirs(DIRECTORY, exist_ok = True)

# Configure logging protocol
logging.basicConfig(
    level = logging.INFO,
    format = "[%(asctime)s] [%(levelname)s] %(message)s",
    datefmt = "%y-%m-%d %H:%M:%S"
)

log = logging.getLogger("SFTS_client")


def credentials_certificate_initialise(host_certificate_filepath: str, user_private_key: rsa.RSAPrivateKey, username: str, host_address: str) -> None:
    """
    ________________________________________
    """

    try:
        # Generate and send a Certificate Signing Request (CSR) if a host certificate doesn't already exists
        if not os.path.exists(host_certificate_filepath):
            csr_path = csr_generate(username, user_private_key)      
            csr_send(csr_path, username, host_address)

        # Check whether an existing certificate is current and replace if required
        else:
            with open(host_certificate_filepath, "rb") as file:
                certificate = x509.load_pem_x509_certificate(file.read())

                if datetime.now() > certificate.not_valid_after_utc:
                    
                    # Delete host certificate
                    os.remove(host_certificate_filepath)
                    log.info(f"Expired client {username} CSR and {host_address} certificate deleted.")

                    # Obtain new host certificate
                    csr_path = csr_generate(username, user_private_key)      
                    csr_send(csr_path, username, host_address)

    except Exception as e:
        log.error(f"Credential error: Failed to obtain certificate for {host_address}. {e}")

    log.info(f"Valid certificate for {host_address} confirmed")

def credentials_input_host() -> tuple[str, str]:
    """
    This function obtains user input to initialise the host server's IPv4 or IPv6 adddress, 
    using the ipaddress module to validate input formatting, and host code. 
    
    This host code is a well-known word specific to the server and is only used to enable access
    to the server's Client Signing Request (CSR) service. The host code is independant of user 
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
            log.error(f"Credential error: Invalid host server ip address. {e}")
            print("Please enter either:\n"
                  "- An IPv4 address using the format 255.255.255.255, or\n"
                  "- An IPv6 address using the format ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
                  )
        
    host_code = getpass.getpass(prompt = "Enter host server code: ")
    host_hash = hashlib.sha256(host_code.encode()).hexdigest()

    return host_address, host_hash

def credentials_input_user() -> list[str, str, str]:
    """
    This function obtains user input to initialise their username and password.
                
    Returns:
        A list contining the username input by the user as a string, the password input 
        by the user as a string and a SHA-265 hash of the password input by the user.
    """

    while True:
        username = str(input("Enter username: ").replace(" ", ""))
        if 4 <= len(username) <= 20:
            break
        else:
            print("Username must be between 4 to 20 characters in length")
    
    while True:
        user_password_prelim = getpass.getpass(prompt = "Enter user password: ")
        user_password = getpass.getpass(prompt = "Confirm user password: ")    

        if user_password_prelim == user_password:
            break

        log.error(f"Credential error: Client {username} passwords don't match")

    password_hash = hashlib.sha256(user_password.encode()).hexdigest()

    return username, user_password, password_hash

def credentials_key_initialise(user_private_key_filepath: str, username: str, user_password: str) -> rsa.RSAPrivateKey:
    """
    The function ________________
    
    Args:
        user_private_key_filepath: ____________________________________
    
        username: A string containing the username input by the user.

        user_password: A string containing the password input by the client.

    Returns:
        An object ____________________________________
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
        log.error(f"Credential error: Incorrect password (private key).")
        sys.exit(1)

    log.info(f"Client {username} private key initialised.")

    return user_private_key

def credentials_key_generate(user_private_key_filepath: str, username: str, user_password: str) -> None:
    """
    This function generates a private key for the client using Rivest Shamir Adleman (RSA) 
    encryption.
    
    Args:
        user_private_key_filepath: ____________________________________
    
        username: A string containing the username input by the user.

        user_password: A string containing the password input by the client.
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
                    encryption_algorithm = serialization.BestAvailableEncryption(user_password.encode())
                )
            )

    except Exception as e:
        log.error(f"Credential error: Failed to write private key. {e}")
        sys.exit(1)

    log.info(f"Client {username} private key saved to {user_private_key_filepath}")

def csr_generate(username: str, user_private_key: rsa.RSAPrivateKey) -> str:
    """
    This function defines the logic for generating a Certificate Signing Request (CSR), 
    enabling asymmetrically encrypted communication between the client and host server.
    
    Args:
        username: A string containing the username input by the user.
    
        user_private_key: An object _______________________________________________

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

def csr_send(csr_path: str, username: str, host_address: str) -> None:
    """
    This function defines the logic for sending an unencrypted Certificate Signing Request
    (CSR) to a host server for the purpose of enabling subsequent asymmetric communication.
    
    Args:
        csr_path: ___________________________________________
        
        username: A string containing the username input by the user.
    
        host_address: A string containing the host server's ip address.
    """  
    
    signed_certificate_path = os.path.join(CERTIFICATES, f"{username}_certificate.pem")

    with socket.create_connection((host_address, CSR_PORT)) as csr_sock:
        
        # Send CSR to server
        with open(csr_path, "rb") as file:
            csr_sock.sendall(file.read())
        
        # Notify server of completed CSR send
        csr_sock.shutdown(socket.SHUT_WR)
        
        # Notify user of completed CSR send
        log.info(f"CSR sent to {host_address}:{CSR_PORT}.")

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
    log.info(f"Signed certificate recieved from {host_address}.")

    # Delete now redundant CSR
    try:
        os.remove(csr_path)
        log.info(f"CSR deletion successful.")
    
    except Exception as e:
        log.error(f"Credential error: CSR deletion failure. {csr_path}")

def hash(input: str, timestamp: float) -> str:
    """
    This function applies a SHA-256 hash to an input password and timestamp.

    Args:
        input: A string containing the input to be hashed.
    
        time: A float containing a timestamp.
    
    Returns:
        hexdigest: A string containing a hex-encoded SHA-256 hash.
    """

    return hashlib.sha256(f"{input}{timestamp}".encode()).hexdigest()

def sfts_authenticate(ssl_conn: ssl.SSLSocket, writer: TextIO, username: str, password_hash) -> None:              
    """
    This function ___________________________.

    Args:
        ssl_conn: The SSL-wrapped socket connection enabling binary transfer.
    
        writer: A TextIO object that enables writing to the SSL-wrapped socket connection.

    Returns:
        A string containing the username input by the user.
    """
    
    timestamp = datetime.now(timezone.utc).timestamp()
    authentication = hash(password_hash, timestamp)

    # Send authentication credentials to host server
    writer.write(f"{username}|{timestamp}|{authentication}\n")
    writer.flush()

    server_response = ssl_conn.recv(1024).decode().strip()
    if server_response != "authentication success":
        log.error(f"Authentication error: Unexpected response from server. {server_response}")
        sys.exit(1)

    log.info(f"Client {username} authentication success")

def sfts_cmd_delete(writer: TextIO, username: str) -> None:
    """
    This function deletes a file from the host server directory.
    
    Args: 
        writer: A TextIO object that enables writing to the SSL-wrapped socket connection.

        username: A string containing the username input by the user.
    """
    
    log.info(f"Client {username} selected the delete command.")
    
    filename = str(input("File to be deleted:").strip())

    timestamp = datetime.now(timezone.utc).isoformat()
    writer.write(f"delete|{timestamp}\n")
    writer.flush()

    writer.write(f"{filename}\n")
    writer.flush()

    log.info(f"Delete command sent to server.")

def sfts_cmd_download(ssl_conn: ssl.SSLSocket, reader: TextIO, writer: TextIO, username: str) -> None:
    """
    This function downloads a file from the host server directory to the client directory.
    
    Args:
        ssl_conn: The SSL-wrapped socket connection enabling binary transfer.
        
        reader: A TextIO object that enables reading from the SSL-wrapped socket connection.
    
        writer: A TextIO object that enables writing to the SSL-wrapped socket connection.

        username: A string containing the username input by the user.
    """
    
    log.info(f"Client {username} selected the download command.")

    filename = str(input("File to be downloaded:").strip())
    filepath = os.path.join(DIRECTORY, filename)

    # Prevent accidental overwrites caused by name conflicts
    if os.path.exists(filepath):
        log.info(f"A file named {filename} already exists in {DIRECTORY}.\n")

        # Obtain user permission to overwrite or cancel download request
        user_choice = str(input("Type 'Yes' to overwrite the existing file or type any other key to cancel: ").strip())
        if user_choice.lower() != "yes":
            return
        log.info(f"Client {username} elected to overwrite {filepath}")

    timestamp = datetime.now(timezone.utc).isoformat()
    writer.write(f"download|{timestamp}\n")
    writer.flush()

    # Receive expected filesize data from server
    filesize_line = reader.readline().strip()
    if not filesize_line:
        log.error("Command error: Filesize not received from server.")
        return
    try:
        filesize = int(filesize_line)
    except ValueError as e:
        print(f"Filesize error: {filesize_line.strip()}.", e)
        return

    # Receive download from server
    remaining = filesize
    with open(filepath, "wb") as file:
        while remaining > 0:
            chunk = ssl_conn.recv(min(4096, remaining))
            if not chunk:
                break

            file.write(chunk)
            remaining -= len(chunk)

    # Successful download notification
    log.info(f"{filename} downloaded from server.")

def sfts_cmd_ls(writer: TextIO, username: str) -> None:
    """
    This function lists file in the host server directory.
    
    Args:
        writer: A TextIO object that enables writing to the SSL-wrapped socket connection.

        username: A string containing the username input by the user.
    """
    
    log.info(f"Client {username} selected the ls command.")

    timestamp = datetime.now(timezone.utc).isoformat()
    writer.write(f"ls|{timestamp}\n")
    writer.flush()

    log.info(f"ls command sent to server.")

def sfts_cmd_upload(ssl_conn: ssl.SSLSocket, writer: TextIO, username: str) -> None:
    """
    This function uploads a file from the client directory to the host server directory.
    
    Args:
        ssl_conn: The SSL-wrapped socket connection enabling binary transfer.
    
        writer: A TextIO object that enables writing to the SSL-wrapped socket connection.

        username: A string containing the username input by the user.
    """

    log.info(f"Client {username} selected the upload command.")

    filename = str(input("File to be uploaded:").strip())
    filepath = os.path.join(DIRECTORY, filename)
    
    # Prevent requests for non-existant files
    if not os.path.exists(filepath):
        print("Error: Requested file doesn't exist")
        return

    # Request upload to server
    timestamp = datetime.now(timezone.utc).isoformat()
    writer.write(f"upload|{timestamp}\n")
    writer.flush()

    writer.write(f"{filename}\n")
    writer.flush()

    filesize = os.path.getsize(filepath)
    writer.write(f"{filesize}\n")
    writer.flush()

    # Send upload to server
    with open(filepath, "rb") as file:
        while True:
            chunk = file.read(4096)
            if not chunk:
                break
            ssl_conn.sendall(chunk)

    # Successful upload notification
    log.info(f"{filename} uploaded to server.")

def sfts_connection(host_certificate_filepath, user_private_key_filepath, username, user_password, password_hash, host_address: str):
    """
    _________________________________________________________
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
                # Define server|client communication protocol
                reader = ssl_conn.makefile("r", encoding="utf-8")
                writer = ssl_conn.makefile("w", encoding="utf-8", buffering=1)

                #
                #
                ## Authenticate client
                # sfts_authenticate(ssl_conn, writer, username, password_hash)
                #
                #
                #
                ## Receive client's role from server 
                # user_role = reader.readline().strip()
                #
                # if not user_role:
                #     log.warning(f"Client {username} user role not received from server.")
                #
                # else:
                #     log.info(f"Client {username} user role is {user_role}.")
                #

                # # Continuously listen for communication from the host server
                # sfts_listen(ssl_conn, reader, writer)

                # Recieve commands from client
                sfts_operations(ssl_conn, reader, writer, username)

            # Display common error notifications
            except ssl.SSLError as e:
                log.error(f"SSL connection error: {e}.")
                sys.exit(1)

            except ConnectionResetError as e:
                log.error(f"Connection error: Connection with {host_address} lost. {e}.")
                sys.exit(1)
 
            finally:
                log.info("Connection closed")


# def sfts_listen(ssl_conn, reader, writer, username):
#     """
#     ____________________ # Continuously listen for communication from the server _____________________________
#     """
    
#     while True:
#         threading.Thread(target = sfts_receive, args = (ssl_conn, reader, writer, username,), daemon = True).start()

def sfts_operations(ssl_conn: ssl.SSLSocket, reader: TextIO, writer: TextIO, username: str) -> None:
    """
    This function manages SSL connections with the host server, incorporating function calls for 
    client initiated commands.
    
    Args:
        ssl_conn: The SSL-wrapped socket connection enabling binary transfer.
        
        reader: A TextIO object that enables reading from the SSL-wrapped socket connection.
    
        writer: A TextIO object that enables writing to the SSL-wrapped socket connection.

        username: A string containing the username input by the user.
    """

    while True:

        # Display available user commands
        cmd = str(input(
            "\nSelect SFTS mode:\n\n"
            "UPLOAD      Upload a file to the server directory [Users and Administrators only]\n"
            "DOWNLOAD    Download a file from the server directory [Users and Administrators only]\n"
            "LS          List all files within the the server directory [Regisered, Users and Administrators only]\n"
            "DELETE      Delete a file from the server directory [Administrators only]\n"
            "EXIT        Exit program\n"
            )).strip().lower()

        # Action user mode selection
        match cmd:
            case "delete":
                sfts_cmd_delete(writer, username)

            case "download":
                sfts_cmd_download(ssl_conn, reader, writer, username)           

            case "exit":
                log.info(f"Client {username} selected the exit command.")
                timestamp = datetime.now(timezone.utc).isoformat()
                writer.write(f"exit|{timestamp}\n")
                writer.flush()
                log.info("Closing connection.")
                sys.exit(1)

            case "ls":
                sfts_cmd_ls(writer, username)

            case "upload":
                sfts_cmd_upload(ssl_conn, writer, username)

            case _:
                log.error(f"Command error: Client {username} input an invalid command. {cmd}")
                continue

def sfts_receive(ssl_conn: ssl.SSLSocket, reader: TextIO, writer: TextIO, username: str) -> None:
    """
    This function displays incoming messages from the host server and resets the corrects synchronisation
    errors by calling the sfts_operations() function if directed by the server.
    
    Args:
        ssl_conn: The SSL-wrapped socket connection enabling binary transfer.
        
        reader: A TextIO object that enables reading from the SSL-wrapped socket connection.
    
        writer: A TextIO object that enables writing to the SSL-wrapped socket connection.

        username: A string containing the username input by the user.
    """
    
    while True:        
        incoming_msg = reader.readline().strip().lower()
        if incoming_msg == "!reset!":
            sfts_operations(ssl_conn, reader, writer, username)
        
        elif incoming_msg:
            print(incoming_msg)

def users_administer() -> None:
    """
    _________________________________________
    """
    pass

def users_update() -> None:
    """
    _______________________
    """
    pass

def main() -> None:
    print("---------------------------------------------------------------------------------\n")
    print("                       Secure File Transfer System: Client                       \n")
    print("---------------------------------------------------------------------------------\n")
    
    # Input host server credentials
    host_address, host_code = credentials_input_host()

    # Input user credentials
    username, user_password, password_hash = credentials_input_user()

    # Initialise host certificate and private key filepaths
    user_private_key_filepath = os.path.join(CERTIFICATES, f"{username}_key.pem")
    host_certificate_filepath = os.path.join(CERTIFICATES, f"{username}_certificate.pem")

    # Initialise private key
    user_private_key = credentials_key_initialise(user_private_key_filepath, username, user_password)

    # Initialise host certificate
    credentials_certificate_initialise(host_certificate_filepath, user_private_key, username, host_address)

    # Connect to the SFTS service
    sfts_connection(host_certificate_filepath, user_private_key_filepath, username, user_password, password_hash, host_address)

if __name__ == "__main__":
    try:
        main()

    except KeyboardInterrupt:
        log.info("Client shutdown by keyboard interrupt.")

    except Exception as e:
        log.critical(f"Fatal error: {e}.")