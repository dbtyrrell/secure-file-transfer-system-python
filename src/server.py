from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from datetime import datetime, timedelta
import os
import socket
import ssl
import threading

# Global variables
HOST = "10.16.10.247"
PORT = 8443
CERTIFICATES = "/workspaces/secure-file-transfer-system-python/certificates/"
DIRECTORY = "/workspaces/secure-file-transfer-system-python/directory/"

# Create filepaths if required
os.makedirs(CERTIFICATES, exist_ok=True)
os.makedirs(DIRECTORY, exist_ok=True)

# Configure SSL context
context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.verify_mode = ssl.CERT_REQUIRED
context.load_cert_chain(
    certfile = f"{CERTIFICATES}server_certificate.pem", 
    keyfile = f"{CERTIFICATES}server_key.pem"
)
context.load_verify_locations("/workspaces/secure-file-transfer-system-python/certificates/ca_certificate.pem")

def manage_client(conn):
    """
    This function defines the logic for how the server will manage SSL connections with client 
    devices, incorporating client initiated Upload, Download, ls and Quit commands.
    """

    print("Client connected:", conn.getpeercert())
    writer = conn.makefile("rwb", buffering=0)
    writer.write(b"Authentication successful\n")

    try:
        while True:
            line = conn.makefile("r").readline()
            if not line:
                break
            args = line.strip().split(maxsplit=1)    
            cmd = args[0].lower()
            filename = args[1] if len(args) > 1 else None

            # Download command ssl transfer logic
            if cmd == "download":
                if not filename:
                    writer.write(b"Error: Filename not provided\n")
                    continue
                filepath = os.path.join(DIRECTORY, filename)
                if not os.path.exists(filepath):
                    writer.write(b"Error: Requested file doesn't exist\n")
                    continue                
                with open(filepath, "rb") as file:
                    for chunk in iter(lambda: file.read(4096), b""):
                        conn.send(chunk)
                conn.send(b"EOF")
                writer.write(f"{filename} download successful\n".encode())

            # Upload command ssl transfer logic
            elif cmd == "upload":
                if not filename:
                    writer.write(b"Error: Filename not provided\n")
                    continue
                writer.write(b"Ready\n")
                filepath = os.path.join(DIRECTORY, filename)
                with open(filepath, "wb") as file:
                    while True:
                        chunk = conn.recv(4096)
                        if chunk == b"EOF":
                            break
                        file.write(chunk)
                writer.write(f"{filename} upload successful\n".encode())
        
            # ls command logic
            elif cmd.lower() == "ls":
                files = os.listdir(DIRECTORY)
                file_list = "\n".join(files) if files else "No files currently available"
                writer.write(f"{DIRECTORY}:\n{file_list}\n".encode())

            # Quit command logic
            elif cmd.lower() == "quit":
                conn.send(b"Session terminated\n")
                break

            # Invalid command logic
            else:
                writer.write(
                    b"Invalid command. Please enter either:\nUpload <filename>\nDownload <filename>\nls\nQuit\n"
                )

    # Display client handling errors
    except Exception as e:
        print(f"Client handling error: {e}")

    finally:
        conn.close()
        print("Connection closed")

def listen_for_csr():
    """
    This function ____________________________________________
    """ 
    csr_port = 8444

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((HOST, csr_port))
        sock.listen(5)
        print(f"CSR service listening on {HOST}:{csr_port}")

        while True:
            client_sock, client_addr = sock.accept()
            print(f"CSR service connection with {client_addr}")
            receive_csr(client_sock)

def receive_csr(sock):
    """
    This function ____________________________________________
    """    
    csr_data = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        csr_data += chunk

    csr_path = os.path.join(CERTIFICATES, "client_csr.pem")
    with open(csr_path, "wb") as file:
        file.write(csr_data)
    
    client_certificate_path = sign_csr(csr_path)

    with open(client_certificate_path, "rb") as file:
        sock.sendall(file.read())

    sock.close()
    os.remove(csr_path)

def sign_csr(csr_path):
    """
    This function ____________________________________________
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
    client_username = csr.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    client_certificate_path = os.path.join(CERTIFICATES, f"{client_username}_certificate.pem")

    with open(client_certificate_path, "wb") as file:
        file.write(client_certificate.public_bytes(serialization.Encoding.PEM))

    return client_certificate_path

def main():
    print("---------------------------------------------------------------------------------\n")
    print("                       Secure File Transfer System: Server                       \n")
    print("---------------------------------------------------------------------------------\n")
    
    # Manage Certificate Signing Request (CSR) service
    threading.Thread(target = listen_for_csr, daemon = True).start()

    # Manage Secure File Transfer System (SFTS) service
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
        sock.bind((HOST, PORT))
        sock.listen(5)
        print(f"SFTS service listening on {HOST}:{PORT}")

        while True:
            client_sock, client_addr = sock.accept()
            print(f"SFTS service onnection with {client_addr}")
            
            try:
                with context.wrap_socket(client_sock, server_side=True) as ssl_conn:
                    manage_client(ssl_conn)
            
            except ssl.SSLError as e:
                print(f"{client_addr} SSL error: {e}")

if __name__ == "__main__":
    main()