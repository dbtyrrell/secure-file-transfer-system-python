import bcrypt
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta
import json
import os
import socket
import ssl
import threading

# Global variables
HOST = "10.16.10.247"
SFTS_PORT = 8443
CSR_PORT = 8444
CERTIFICATES = "/workspaces/secure-file-transfer-system-python/certificates/"
DIRECTORY = "/workspaces/secure-file-transfer-system-python/directory/"
USERS = "/workspaces/secure-file-transfer-system-python/src/users.json"
ROLES = {
    "admin": {
        "download" : True,
        "upload" : True,
        "delete" : True,
        "ls" : True
    },
    "user": {
        "download" : True,
        "upload" : True,
        "delete" : False,
        "ls" : True
    },
    "registered": {
        "download" : False,
        "upload" : False,
        "delete" : False,
        "ls" : True
    },
    "unregistered": {
        "download" : False,
        "upload" : False,
        "delete" : False,
        "ls" : False
    },   
}

# Create required filepaths if they don't already exist
os.makedirs(CERTIFICATES, exist_ok=True)
os.makedirs(DIRECTORY, exist_ok=True)
if not os.path.exists(USERS):
    with open(USERS, 'w') as file:
        json.dump({}, file)

# Configure SSL context
context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.verify_mode = ssl.CERT_REQUIRED
context.load_cert_chain(
    certfile = f"{CERTIFICATES}server_certificate.pem", 
    keyfile = f"{CERTIFICATES}server_key.pem"
)
context.load_verify_locations(f"{CERTIFICATES}ca_certificate.pem")

def manage_client(ssl_conn, reader, writer):
    """
    This function defines the logic for how the server will manage SSL connections with client 
    devices, incorporating response logic for client initiated Upload, Download, ls and Quit 
    commands.
    """

    print("Client connection initiated:", ssl_conn.getpeercert())    
    writer.write(f"Connected to Secure File Transfer System server {HOST}\n".encode())

    # Authenticate user
    writer.write("Enter username: \n")
    writer.flush()
    username = reader.readline().strip()
    
    writer.write("Enter password: \n")
    writer.flush()
    password = reader.readline().strip()

    role = authenticate_user(username, password)

    # Notify client of unsuccessful authentication and close connection
    if not role:
        writer.write("Invalid credentials\n")
        ssl_conn.close()
        return
    
    # Notify client by providing user role
    writer.write(f"{role}\n".encode())

    # Initialise user role permissions as a local variable
    user_permissions = ROLES[role]

    try:
        while True:
            line = reader.readline()
            if not line:
                break
            
            # Decomposion of client commands
            args = line.strip().split(maxsplit=1)    
            cmd = args[0].lower()
            filename = args[1] if len(args) > 1 else None
            # time_sent = args[2] if len(args) > 2 else None      ### PLACEHOLDER ONLY, Replay Attack mitigiation mechanism yet to be added

            # Download command logic for ssl transfer
            if cmd == "download":
                
                if not user_permissions["download"]:
                    writer.write("Insufficient permissions\n")
                    continue
                
                if not filename:
                    writer.write("Error: Filename not provided\n")
                    continue                    

                filepath = os.path.join(DIRECTORY, filename)
                
                if not os.path.exists(filepath):
                    writer.write("Error: Specified file doesn't exist\n")
                    continue

                filesize = os.path.getsize(filepath)
                writer.write(f"{filesize}\n".encode())
                writer.flush()

                with open(filepath, "rb") as file:
                    while True:
                        chunk = file.read(4096)
                        if not chunk:
                            break
                        ssl_conn.sendall(chunk)
            
                writer.write(f"{filename} download successful\n".encode())
                writer.flush()

            # Upload command logics for ssl transfer
            elif cmd == "upload":
                
                if not user_permissions["upload"]:
                    writer.write("Insufficient permissions\n")
                    continue
                
                if not filename:
                    writer.write("Error: Filename not provided\n")
                    continue   

                filepath = os.path.join(DIRECTORY, filename)

                writer.write("Ready\n")
                writer.flush()

                filesize_line = reader.readline()
                if not filesize_line:
                    writer.write("Error: Filesize not provided\n")
                    continue

                try:
                    filesize = int(filesize_line.strip())
                except ValueError:
                    writer.write("Error: Invalid filesize\n")
                    continue

                remaining = filesize
                with open(filepath, "wb") as file:
                    while remaining > 0:
                        chunk = ssl_conn.recv(min(4096, remaining))
                        if not chunk:
                            break
                        file.write(chunk)
                        remaining -= len(chunk)

                writer.write(f"{filename} upload successful\n".encode())
                writer.flush()

            # Delete command logic
            elif cmd == "delete":
                
                if not user_permissions["delete"]:
                    writer.write("Insufficient permissions\n")
                    continue
                
                if not filename:
                    writer.write("Error: Filename not provided\n")
                    continue   

                filepath = os.path.join(DIRECTORY, filename)

                if os.path.exists(filepath):
                    os.remove(filepath)
                    writer.write(f"{filename} deletion successful\n".encode())
                    writer.flush()

                else:
                    writer.write("Error: Specified file doesn't exist\n")
                    writer.flush()

            # ls command logic
            elif cmd == "ls":
                
                if not user_permissions["ls"]:
                    writer.write("Insufficient permissions\n")
                    continue

                files = os.listdir(DIRECTORY)
                file_list = "\n".join(files) if files else "No files currently stored"
                writer.write(f"{DIRECTORY}:\n{file_list}\n")

            # Quit command logic
            elif cmd.lower() == "quit":
                writer.write("Session terminated\n")
                writer.flush()
                break

            # Invalid command logic
            else:
                writer.write("Invalid command. Please enter either:\nUpload <filename>\nDownload <filename>\nls\nQuit\n")

    # Display error messages
    except ssl.SSLError as e:
        print(f"SSL error: {e}")
    
    except Exception as e:
        print(f"Client handling error: {e}")

    finally:
        ssl_conn.close()
        print("Client connection terminated:", ssl_conn.getpeercert())

def listen_for_csr():
    """
    This function defines the logic for how the server listens for Certificate Signing Requests
    (CSR) sent by clients.
    """ 

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((HOST, CSR_PORT))
        sock.listen(5)
        print(f"CSR service listening on {HOST}:{CSR_PORT}")

        while True:
            client_sock, client_addr = sock.accept()
            client_sock.settimeout(10)
            print(f"CSR service connection with {client_addr}")

            threading.Thread(
                target=receive_csr,
                args=(client_sock, client_addr),
                daemon=True
            ).start()

def receive_csr(sock, client_addr):
    """
    This function defines the logic for how the server receives CSR sent by clients.
    """    
    
    try:
        csr_data = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            csr_data += chunk

        csr_path = os.path.join(CERTIFICATES, f"{client_addr.replace(".","|")}_csr.pem")
        with open(csr_path, "wb") as file:
            file.write(csr_data)
        
        signed_certificate_path = sign_csr(csr_path, client_addr)

        with open(signed_certificate_path, "rb") as file:
            sock.sendall(file.read())
        print(f"CSR signed and sent to {client_addr}")

    except Exception as e:
        print(f"CSR receipt error from {client_addr}: {e}")

    finally:
        sock.close()
        if os.path.exists(csr_path):
            os.remove(csr_path)

def sign_csr(csr_path, client_addr):
    """
    This function defines the logic for how the server signs a CSR using the CA certificate
    and Private Key, and returns the new certificate filepath.
    """
    
    # Define the CA key and certificate filepaths
    ca_key_path = os.path.join(CERTIFICATES, "ca_key.pem")
    ca_certificate_path = os.path.join(CERTIFICATES, "ca_certificate.pem")

    # Initialise the CA key as a local variable
    with open(ca_key_path, "rb") as file:
        ca_key = serialization.load_pem_private_key(
            file.read(),
            password = None             # Encryption to be added once initial functionality is fully tested
        )

    # Initialise the CA certificate as a local variable
    with open(ca_certificate_path, "rb") as file:
        ca_certificate = x509.load_pem_x509_certificate(file.read())

    # Initialise the client's CSR as a local variable
    with open(csr_path, "rb") as file:
        csr = x509.load_pem_x509_csr(file.read())

    # Generate the client's certificate
    client_certificate = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_certificate.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now())
        .not_valid_after(datetime.now() + timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(
                ca = False,
                path_length = None
            ),
            critical = True
        )
        .sign(private_key = ca_key, algorithm = hashes.SHA256())
    )

    # Write the client's certificate
    client_certificate_path = os.path.join(CERTIFICATES, f"{client_addr.replace(".","|")}_certificate.pem")

    with open(client_certificate_path, "wb") as file:
        file.write(client_certificate.public_bytes(serialization.Encoding.PEM))

    return client_certificate_path

def read_users():
    """
    This function initialises the content of the users.json file as a dictionary.
    """

    if not os.path.exists(USERS):
        return {}
    
    with open(USERS, "r") as file:
        return json.load(file)

def write_users(users):
    """
    This function writes a dictionary to the users.json file.
    """

    with open(USERS, "w") as file:
        json.dump(users, file, indent=4)

def authenticate_user(username, password):
    """
    This function authenticates received user credentials against the values stored in the 
    users.json file.
    """
    
    # Prevent server from authenticating users if users.json can't be found 
    if not os.path.exists(USERS):
        return None

    # Prevent server from authenticating if the user is not in the user permission file
    with open(USERS, "r") as file:
        users = json.load(file)
        if username not in users:
            return None

    # Approved user submitted hashes that match the stored hash
    hash = users[username]["hash"]
    if not hash:
        return None
    if bcrypt.checkpw(password.encode(), hash):                     ##### SALTING FUNCTIONALITY STILL TO BE ADDED
        return users[username]["role"]

    # Reject ser submitted hashes that don't match the stored hash
    return None

def main():
    print("---------------------------------------------------------------------------------\n")
    print("                       Secure File Transfer System: Server                       \n")
    print("---------------------------------------------------------------------------------\n")
    
    # Start the Certificate Signing Request (CSR) service
    threading.Thread(target = listen_for_csr, daemon = True).start()

    # Manage Secure File Transfer System (SFTS) service
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
        sock.bind((HOST, SFTS_PORT))
        sock.listen(5)
        print(f"SFTS service listening on {HOST}:{SFTS_PORT}")

        while True:
            client_sock, client_addr = sock.accept()
            print(f"SFTS service connection with {client_addr}")

            try:
                with context.wrap_socket(client_sock, server_side=True) as ssl_conn:
                    
                    # Define network communication protocol
                    reader = ssl_conn.makefile("r", encoding="utf-8")
                    writer = ssl_conn.makefile("w", encoding="utf-8", buffering=1)

                    # Execute SFTS client-facing functions
                    manage_client(ssl_conn, reader, writer)
            
            except ssl.SSLError as e:
                print(f"{client_addr} SSL error: {e}")

if __name__ == "__main__":
    main()