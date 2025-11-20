from cryptography import x509
from cryptography.exceptions import InvalidKey
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from datetime import datetime, timezone
import getpass
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import socket
import ssl
import sys
import threading
from typing import TextIO

# Global variables
SFTS_PORT: int = 8443
CSR_PORT: int = 8444

CERTIFICATES: str = "/workspaces/secure-file-transfer-system-python/certificates/"
DIRECTORY: str = "/workspaces/secure-file-transfer-system-python/directory/"
BLOCKED_PASSWORDS: str = "/workspaces/secure-file-transfer-system-python/src/blocked_passwords.json"
ROLES_DIR: str = "/workspaces/secure-file-transfer-system-python/src/roles.json"

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
        json.dump({}, file)

if not os.path.exists(ROLES_DIR):
    with open(ROLES_DIR, 'w') as file:
        json.dump({}, file)

# Serialise read/write operations on the users.json file to mitigate race conditions
roles_file_lock = threading.Lock()

# Initialise user role permissions
with roles_file_lock:
    try:        
        with open(ROLES_DIR, "r") as file:
            ROLES = json.load(file)

    except Exception as e:
        log.error(f"Roles file error: Failed to read from file. {e}.")

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
            log.error(f"Credential error: Invalid host server ip address. {e}.")
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

        # if not 15 <= len(user_password_prelim) <= 64:                                         ############ COMMENTED OUT FOR TESTING PURPOSES ONLY
        #     print("Password error: Password length must be between 15 and 64 characters")
        #     continue

        # if user_password_prelim.lower() in blocked_list:
        #     print("Password error: Password must not be easily predictable")
        #     continue

        user_password = getpass.getpass(prompt = "Confirm user password: ")  

        if user_password_prelim == user_password:
            break

        log.error(f"Credential error: Client {username} passwords don't match")

    password_hash = hashlib.sha256(user_password.encode()).hexdigest()

    return username, user_password, password_hash

def credentials_key_initialise(
        user_private_key_filepath: str, username: str, user_password: str) -> rsa.RSAPrivateKey:
    """
    The function ________________
    
    Args:
        user_private_key_filepath: ____________________________________
    
        username: A string containing the username input by the client user.

        user_password: A string containing the password input by the client user.

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

def credentials_key_generate(
        user_private_key_filepath: str, username: str, user_password: str) -> None:
    """
    This function generates a private key for the client using Rivest Shamir Adleman (RSA) 
    encryption.
    
    Args:
        user_private_key_filepath: ____________________________________
    
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

def credentials_certificate_initialise(
        host_certificate_filepath: str, user_private_key: rsa.RSAPrivateKey, 
        username: str, host_address: str, host_hash: str) -> None:
    """
    This function initialises the certificate for the host server using the user's private key.
    
    Args:
        host_certificate_filepath: ________________________________________

        user_private_key: ________________________________________

        username: A string containing the username input by the client user.

        host_address: A string containing the host server's ip address.

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

def csr_generate(username: str, user_private_key: rsa.RSAPrivateKey) -> str:
    """
    This function defines the logic for generating a Certificate Signing Request (CSR), enabling 
    asymmetrically encrypted communication between the client and host server.
    
    Args:
        username: A string containing the username input by the client user.
    
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

def csr_send(csr_path: str, username: str, host_address: str, host_hash: str) -> None:
    """
    This function defines the logic for sending an unencrypted Certificate Signing Request (CSR) to 
    a host server for the purpose of enabling subsequent asymmetric communication.
    
    Args:
        csr_path: A string containing the file path for the generated CSR.
        
        username: A string containing the username input by the client user.
    
        host_address: A string containing the host server's ip address.

        host_hash: A string containing a SHA-256 hex hash of the host code.
    """  
    
    signed_certificate_path = os.path.join(CERTIFICATES, f"{username}_certificate.pem")

    with socket.create_connection((host_address, CSR_PORT)) as csr_sock:
        
        # Receive 256 bit nonce from server
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

        # Authenticate to server using hmac
        client_hmac = hmac.new(
            key = host_hash.encode(),
            msg = nonce,
            digestmod = hashlib.sha256
        ).hexdigest().encode() + b"\n"

        csr_sock.sendall(client_hmac)

        # Send CSR to server
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
        ssl_conn: ssl.SSLSocket, username: str, password_hash: str, host_address: str) -> str:              
    """
    This function ___________________________.

    Args:
        ssl_conn: A SSL-wrapped socket connection object enabling binary transfer.

        username: A string containing the username input by the client user.

        password_hash: _____________________

        host_address: A string containing the host server's ip address.

    Returns:
        A string containing the user role provided by the host server. 
    """
    
    # Receive 256 bit nonce from server
    nonce_line = b""
    while b"\n" not in nonce_line:
        chunk = ssl_conn.recv(1024)
        if not chunk:
            break

        nonce_line += chunk

        if len(nonce_line) > 4096:
            log.error(f"SFTS error: Invalid nonce received from {host_address}.")
            raise ValueError

    if b"\n" not in nonce_line:
        log.error(f"SFTS error: Incomplete nonce received from {host_address}.")
        return

    header_line, remainder = nonce_line.split(b"\n",1)
    nonce = bytes.fromhex(header_line.decode().strip())

    # Authenticate to server using hmac
    client_hmac = hmac.new(
        key = password_hash.encode(),
        msg = nonce,
        digestmod = hashlib.sha256
    ).hexdigest().encode() + b"\n"

    ssl_conn.sendall(client_hmac)

    # Send username to server
    username_bytes = username.encode() + b"\n"
    ssl_conn.sendall(username_bytes)

    # Receive authentication result and user role from server 
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
        return

    header_line, remainder = results_bytes.split(b"\n",1)
    result, user_role = header_line.decode().split("|",1)

    return result, user_role

def sfts_connection(
        host_certificate_filepath: str, user_private_key_filepath: str, username: str, 
        user_password: str, password_hash: str, host_address: str) -> None:
    """
    This function _________________________________________________________

    Args:
        host_certificate_filepath: ___________

        user_private_key_filepath: ___________

        username: A string containing the username input by the client user.

        user_password: A string containing the password input by the client user.

        password_hash: ____________
        
        host_address: A string containing the host server's ip address.
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
                
###################################################################################################
######################################### TO BE EVALUATED #########################################
###################################################################################################
                
                # # Define server|client communication protocol
                # reader = ssl_conn.makefile("r", encoding="utf-8")
                # writer = ssl_conn.makefile("w", encoding="utf-8", buffering=1)

###################################################################################################
######################################### TO BE EVALUATED #########################################
###################################################################################################

                # Authenticate client
                authentication, user_role = sfts_authenticate(
                    ssl_conn, username, password_hash, host_address)

                if not authentication:
                    log.warning("User credentials failed host server authentication")
                    sys.exit(1)

                # Recieve commands from client
                sfts_operations(ssl_conn, username, user_role)

            # Display common error notifications
            except ssl.SSLError as e:
                log.error(f"SSL connection error: {e}.")
                sys.exit(1)

            except ConnectionResetError as e:
                log.error(f"Connection error: Connection with {host_address} lost. {e}.")
                sys.exit(1)
 
            finally:
                log.info("Connection closed")

def sfts_operations(ssl_conn: ssl.SSLSocket, username: str, user_role: str) -> None:
    """
    This function manages SSL connections with the host server, incorporating function calls for 
    client initiated commands.
    
    Args:
        ssl_conn: A SSL-wrapped socket connection object enabling binary transfer.

        username: A string containing the username input by the client user.

        user_role: A string containing the client user's role as advised by the host server.
    """

    log.info(f"Client {username} commenced SFTS operations.")

    while True:
        # Display user interface
        cmd = str(input("\nEnter SFTS command:\n\n")).strip().lower()

        # Prevent the user from input commands outside of their role permissions.

###################################################################################################
######################################## NOT YET DEVELOPED ########################################
###################################################################################################

        # Action user mode selection
        match cmd:
            case "admin":
                sfts_cmd_administer(ssl_conn, username)
            
            case "delete":
                sfts_cmd_delete(ssl_conn, username)

            case "download":
                sfts_cmd_download(ssl_conn, username)

            case "exit":
                sfts_cmd_exit(ssl_conn, username)

            case "help":
                sfts_cmd_help(user_role)                 

            case "ls":
                sfts_cmd_ls(ssl_conn, username)

            case "update":
                sfts_cmd_update(ssl_conn, username)

            case "upload":
                sfts_cmd_upload(ssl_conn, username)

            case _:
                log.error(f"Command error: Client {username} input an invalid command. {cmd}")
                continue

def sfts_cmd_administer(ssl_conn, user_role: str) -> None:
    """
    This function ________________________________.
    
    Args:
        ssl_conn: A SSL-wrapped socket connection object enabling binary transfer.

        user_role: A string containing the client user's role as advised by the host server.
    """

    log.info(f"Initiated the administer command.")

###################################################################################################
######################################## NOT YET DEVELOPED ########################################
###################################################################################################

def sfts_cmd_delete(ssl_conn, user_role: str) -> None:
    """
    This function deletes a file from the host server directory.
    
    Args:
        ssl_conn: A SSL-wrapped socket connection object enabling binary transfer.

        user_role: A string containing the client user's role as advised by the host server.
    """

    log.info(f"Initiated the delete command.")
    
    # filename = str(input("File to be deleted:").strip())

    # timestamp = datetime.now(timezone.utc).isoformat()
    # writer.write(f"delete|{timestamp}\n")
    # writer.flush()

    # writer.write(f"{filename}\n")
    # writer.flush()

def sfts_cmd_download(ssl_conn, user_role: str) -> None:
    """
    This function downloads a file from the host server directory to the client directory.
    
    Args:
        ssl_conn: A SSL-wrapped socket connection object enabling binary transfer.

        user_role: A string containing the client user's role as advised by the host server.
    """

    log.info(f"Initiated the download command.")

    # filename = str(input("File to be downloaded:").strip())
    # filepath = os.path.join(DIRECTORY, filename)

    # # Prevent accidental overwrites caused by name conflicts
    # if os.path.exists(filepath):
    #     log.info(f"A file named {filename} already exists in {DIRECTORY}.\n")

    #     # Obtain user permission to overwrite or cancel download request
    #     user_choice = str(input("Type 'Yes' to overwrite the existing file or type any other key to cancel: ").strip())
    #     if user_choice.lower() != "yes":
    #         return
    #     log.info(f"Client {username} elected to overwrite {filepath}")

    # timestamp = datetime.now(timezone.utc).isoformat()
    # writer.write(f"download|{timestamp}\n")
    # writer.flush()

    # writer.write(f"{filename}\n")
    # writer.flush()

    # # Receive expected filesize data from server
    # filesize_line = reader.readline().strip()
    # if not filesize_line:
    #     log.error("Command error: Filesize not received from server.")
    #     return
    # try:
    #     filesize = int(filesize_line)
    # except ValueError as e:
    #     print(f"Filesize error: {filesize_line.strip()}.", e)
    #     return

    # # Receive download from server
    # remaining = filesize
    # with open(filepath, "wb") as file:
    #     while remaining > 0:
    #         chunk = ssl_conn.recv(min(4096, remaining))
    #         if not chunk:
    #             break

    #         file.write(chunk)
    #         remaining -= len(chunk)

    # # Successful download notification
    # log.info(f"{filename} written to {DIRECTORY}.")

def sfts_cmd_exit(ssl_conn, user_role: str) -> None:
    """
    This function ________________________________.
    
    Args:
        ssl_conn: A SSL-wrapped socket connection object enabling binary transfer.

        user_role: A string containing the client user's role as advised by the host server.
    """

    log.info(f"Initiated the exit command.")

    # timestamp = datetime.now(timezone.utc).isoformat()
    # writer.write(f"exit|{timestamp}\n")
    # writer.flush()
    # log.info("Closing connection.")
    # sys.exit(1)

def sfts_cmd_help(user_role: str) -> None:
    """
    This function ________________________________.
    
    Args:
        user_role: A string containing the client user's role as advised by the host server.
    """

    print("\nThe following commands are available to you:\n")

    if ROLES[user_role]["admin"]:
        print("ADMIN       Administer the role profiles assigned to non-admin users")

    if ROLES[user_role]["delete"]:
        print("DELETE      Delete a file from the server directory")

    if ROLES[user_role]["download"]:
        print("DOWNLOAD    Download a file from the server directory")

    print("EXIT        Exit program")
    print("HELP        View available commands")

    if ROLES[user_role]["ls"]:
        print("LS          List all files within the server directory")

    print("UPDATE      Update your personal user details")

    if ROLES[user_role]["upload"]:
        print("UPLOAD      Upload a file to the server directory")

def sfts_cmd_ls(ssl_conn, user_role: str) -> None:
    """
    This function lists file in the host server directory.
    
    Args:
        ssl_conn: A SSL-wrapped socket connection object enabling binary transfer.

        user_role: A string containing the client user's role as advised by the host server.
    """

    log.info(f"Initiated the list command.")

    # timestamp = datetime.now(timezone.utc).isoformat()
    # writer.write(f"ls|{timestamp}\n")
    # writer.flush()

def sfts_cmd_update(ssl_conn, user_role: str) -> None:
    """
    This function ________________________________.
    
    Args:
        ssl_conn: A SSL-wrapped socket connection object enabling binary transfer.

        user_role: A string containing the client user's role as advised by the host server.
    """

    log.info(f"Initiated the update command.")

###################################################################################################
######################################## NOT YET DEVELOPED ########################################
###################################################################################################

def sfts_cmd_upload(ssl_conn, user_role: str) -> None:
    """
    This function uploads a file from the client directory to the host server director.
    
    Args:
        ssl_conn: A SSL-wrapped socket connection object enabling binary transfer.

        user_role: A string containing the client user's role as advised by the host server.
    """

    log.info(f"Initiated the upload command.")

    # filename = str(input("File to be uploaded:").strip())
    # filepath = os.path.join(DIRECTORY, filename)
    
    # # Prevent requests for non-existant files
    # if not os.path.exists(filepath):
    #     print("Error: Requested file doesn't exist")
    #     return

    # # Request upload to server
    # timestamp = datetime.now(timezone.utc).isoformat()
    # writer.write(f"upload|{timestamp}\n")
    # writer.flush()

    # writer.write(f"{filename}\n")
    # writer.flush()

    # filesize = os.path.getsize(filepath)
    # writer.write(f"{filesize}\n")
    # writer.flush()

    # # Send upload to server
    # with open(filepath, "rb") as file:
    #     while True:
    #         chunk = file.read(4096)
    #         if not chunk:
    #             break
    #         ssl_conn.sendall(chunk)

    # # Successful upload notification
    # log.info(f"{filename} sent to server.")

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
        host_certificate_filepath, user_private_key_filepath, username, 
        user_password, password_hash, host_address)

if __name__ == "__main__":
    try:
        main()

    except KeyboardInterrupt:
        log.info("Client shutdown by keyboard interrupt.")

    except Exception as e:
        log.critical(f"Fatal error: {e}.")