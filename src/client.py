from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import ipaddress
import os
import socket
import ssl

# Global variables
SFTS_PORT = 8443
CSR_PORT = 8444
CERTIFICATES = "/workspaces/secure-file-transfer-system-python/certificates/"
DIRECTORY = "/workspaces/secure-file-transfer-system-python/directory/"

# Create filepaths if required
os.makedirs(CERTIFICATES, exist_ok=True)
os.makedirs(DIRECTORY, exist_ok=True)

def download(conn, writer, filename):
    """
    This function defines the logic for how the client will initate downloads from the server 
    using a SSL connection.
    """

    # Prevent accidental overwrites caused by name conflicts
    filepath = os.path.join(DIRECTORY, filename)
    if os.path.exists(filepath):
        print(f"A file named {filename} already exists in {DIRECTORY}.\n")

        # Obtain user permission to overwrite or cancel download request
        while True:
            user_choice = str(input("Type 'Yes' to continue and overwrite the existing file or 'No' to cancel: ").strip())
            if user_choice.lower() in ["yes", "y"]:
                break
            elif user_choice.lower() in ["no", "n"]:
                print("Download cancelled")
                return
            else:
                print("Invalid input")

    # Request download from server
    writer.write(f"download {filename}\n".encode())
    
    # Download command ssl transfer logic
    with open(filepath, "wb") as file:
        while True:
            chunk = conn.recv(4096)
            if chunk == b"EOF":
                break
            file.write(chunk)
    
    # Successful transfer notification
    print(f"Downloaded {filename} to {filepath}")

def upload(conn, writer, filename):
    """
    This function defines the logic for how the client initates uploads to the server 
    using a SSL connection.
    """

    # Prevent requests for non-existant files
    filepath = os.path.join(DIRECTORY, filename)
    if not os.path.exists(filepath):
        print("Error: Requested file doesn't exist")
        return
    
    # Request upload to server
    writer.write(f"upload {os.path.basename(filename)}\n".encode())
    server_response = conn.makefile('r').readline().strip()
    if server_response != "Ready":
        print(f"Server not ready: {server_response}")
        return
    
    # Upload command ssl transfer logic
    with open(filepath, "rb") as file:
        for chunk in iter(lambda: file.read(4096), b""):
            conn.send(chunk)
        conn.send(b"EOF")
        print(conn.makefile('r').readline().strip())

def hostAddress():
    """
    This function obtains user input to determine the host server's IPv4 or IPv6 adddress, and 
    uses the ipaddress module to validate input formatting.
    """
    
    while True:
        host = str(input("Enter host server IPv4 or IPv6 address: ").strip())
        ip_addr = ipaddress.ip_address(host)

        if isinstance(ip_addr, ipaddress.IPv4Address) or isinstance(ip_addr, ipaddress.IPv6Address):
            return host

        else:
            print("Invalid host server address. Please enter either:")
            print("- An IPv4 address using the format 255.255.255.255, or")
            print("- An IPv6 address using the format ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")

def generate_private_key(username):
    """
    This function defines the logic for generating a private key for the client using Rivest 
    Shamir Adleman (RSA) encryption.
    """
    
    # Generate a RSA private key
    user_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    
    # Define the private key filepath
    user_private_key_path = os.path.join(CERTIFICATES, f"{username}_key.pem")

    # Write the private key file
    with open(user_private_key_path, "wb") as file:
        file.write(user_private_key.private_bytes(
            encoding = serialization.Encoding.PEM, 
            format = serialization.PrivateFormat.TraditionalOpenSSL, 
            encryption_algorithm = serialization.NoEncryption()))       # Encryption to be added once initial functionality is verified
            # encryption_algorithm = serialization.BestAvailableEncryption(b"password")))

    return user_private_key

def generate_csr(username, email, user_private_key):
    """
    This function defines the logic for generating a Certificate Signing Request (CSR), 
    enabling asymmetrically encrypted communication between the client and host server.
    """
    
    # Define the CSR Subject variables and Subject Alternative Name (SAN)
    csr_variables = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "AUS"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Secure File Transfer System"),
        x509.NameAttribute(NameOID.COMMON_NAME, username)
    ])
    
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(csr_variables)
        #.add_extension(
        #    x509.SubjectAlternativeName([
        #        x509.DNSName(email),         # Need to validate whether this is required
        #        x509.RFC822Name(email)       # Need to validate whether this is required
        #    ])
        #)
    )

    # Digitally sign the CSR
    csr = csr.sign(user_private_key, hashes.SHA256())

    # Define the CSR filepath
    csr_path = os.path.join(CERTIFICATES, f"{username}_certificate.pem")

    # Write the CSR file
    with open(csr_path, "wb") as file:
        file.write(csr.public_bytes(serialization.Encoding.PEM))

def send_csr(username, host):
    """
    This function ____________________________________________
    """  
    csr_path = os.path.join(CERTIFICATES, f"{username}_certificate.pem")

    with socket.create_connection((host, CSR_PORT)) as csr_sock:
        
        # Send CSR to server
        with open(csr_path, "rb") as file:
            csr_sock.sendall(file.read())
        
        # Notify server of completed CSR send
        csr_sock.shutdown(socket.SHUT_WR)
        
        # Notify user of completed CSR send
        print(f"CSR sent to {host}:{CSR_PORT}")

        # Receive signed server certificate
        signed_certificate = b""
        while True:
            chunk = csr_sock.recv(4096)
            if not chunk:
                break
            signed_certificate += chunk

    # Save signed server certificate
    with open(csr_path, "wb") as file:
        file.write(signed_certificate)

    # Notify user of completed CSR send
    print(f"Signed certificate recieved from {host}")

def main():
    print("---------------------------------------------------------------------------------\n")
    print("                       Secure File Transfer System: Client                       \n")
    print("---------------------------------------------------------------------------------\n")
    
    username = "user1" # Hardcoded temporarily - to be updated when RADIUS authentication feature is added
    email = "user1@gmail.com" # Hardcoded temporarily - to be updated when RADIUS authentication feature is added
    host = hostAddress()

    # Generate a Private Key for the user if one doesn't already exist
    if not os.path.exists(os.path.join(CERTIFICATES, f"{username}_key.pem")):
        generate_private_key(username)

    # Generate a Certificate Signing Request (CSR) if a host certificate doesn't already exists
    if not os.path.exists(os.path.join(CERTIFICATES, f"{host}_certificate.pem")):
        with open(os.path.join(CERTIFICATES, f"{username}_key.pem"), "rb") as file:
            user_private_key = serialization.load_pem_private_key(
                file.read(),
                password = None             # Encryption to be added once initial functionality is fully tested
            )
        generate_csr(username, email, user_private_key)

        # Send CSR to host server       
        send_csr(username, host)

    # Configure SSL context
    context = ssl.create_default_context(
        ssl.Purpose.SERVER_AUTH, 
        cafile = f"{CERTIFICATES}ca_certificate.pem"
    )
    context.load_cert_chain(
        certfile = f"{CERTIFICATES}{username}_certificate.pem", 
        keyfile = f"{CERTIFICATES}{username}_key.pem"
    )

    # Establish SSL connection
    with socket.create_connection((host, SFTS_PORT)) as sock:
        with context.wrap_socket(sock, server_hostname="ubuntu-sfts") as ssock:
            reader = ssock.makefile("r")
            writer = ssock.makefile("w", buffering=1)
            print(reader.readline().strip())
            
            # Send client initiated commands to server
            while True:
                cmd = str(input("Please select either:\nUpload <filename>\nDownload <filename>\nls\nQuit\n")).strip()
                
                if not cmd:
                    continue

                if cmd.lower().startswith("download"):
                    _, filename = cmd.split(maxsplit=1)
                    download(ssock, writer, filename)

                elif cmd.lower().startswith("upload"):
                    _, filename = cmd.split(maxsplit=1)
                    upload(ssock, writer, filename)
                
                elif cmd.lower() == "ls":
                    writer.write("ls\n")
                    print(reader.readline().strip())
                
                elif cmd.lower() == "quit":
                    writer.write("quit\n")
                    print(reader.readline().strip())
                    break            

                else:
                    print("Invalid command. Please enter either:\nUpload <filename>\nDownload <filename>\nls\nQuit\n")

    ###
    ### Need to check whether I need to add a clean disconnect mechanic for the client
    ###

if __name__ == "__main__":
    main()