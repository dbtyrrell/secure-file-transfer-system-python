from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import getpass
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

def download(conn, reader, writer, filename):
    """
    This function defines the logic for how the client will initate downloads from the server 
    using a SSL connection.
    """

    filepath = os.path.join(DIRECTORY, filename)

    # Prevent accidental overwrites caused by name conflicts
    if os.path.exists(filepath):
        print(f"A file named {filename} already exists in {DIRECTORY}.\n")

        # Obtain user permission to overwrite or cancel download request
        user_choice = str(input("Type 'Yes' to overwrite the existing file or type any other key to cancel: ").strip())
        if user_choice.lower() != "yes":
            return

    # Request download from server
    writer.write(f"download {filename}\n")
    writer.flush()
    
    # Receive expected filesize data from server
    filesize_line = reader.readline()
    if not filesize_line:
        print("Connection error: No response from server")
        return
    try:
        filesize = int(filesize_line.strip())
    except ValueError as e:
        print(f"Filesize error: {filesize_line.strip()}. ", e)
        return

    # Download command ssl transfer logic
    remaining = filesize
    with open(filepath, "wb") as file:
        while remaining > 0:
            chunk = conn.recv(min(4096, remaining))
            if not chunk:
                break

            file.write(chunk)
            remaining -= len(chunk)
        
    # Successful download notification
    print(reader.readline().strip())

def upload(conn, reader, writer, filename):
    """
    This function defines the logic for how the client initates uploads to the server 
    using a SSL connection.
    """

    filepath = os.path.join(DIRECTORY, filename)

    # Prevent requests for non-existant files
    if not os.path.exists(filepath):
        print("Error: Requested file doesn't exist")
        return
    
    # Request upload to server
    writer.write(f"upload {filename}\n")
    writer.flush()

    server_response = reader.readline().strip()
    if server_response != "Ready":
        print(f"Server not ready: {server_response}")
        return
    
    filesize = os.path.getsize(filepath)
    writer.write(f"{filesize}\n")

    # Upload command ssl transfer logic
    with open(filepath, "rb") as file:
        while True:
            chunk = file.read(4096)
            if not chunk:
                break
            conn.sendall(chunk)

    # Successful upload notification
    print(reader.readline().strip())

def delete(reader, writer, filename):
    """
    This function defines the logic for how the client initates deletion of files
    on the server.
    """

    # Request delete from server
    writer.write(f"delete {filename}\n")
    writer.flush()
            
    # Successful download notification
    print(reader.readline().strip())

def host_credentials():
    """
    This function obtains user input to initialise the host server's IPv4 or IPv6 adddress, using
    the ipaddress module to validate input formatting, and password.
    """

    while True:
        host_address = str(input("Enter host server IPv4 or IPv6 address: ").strip())
        
        try:
            ipaddress.ip_address(host_address)
            break

        except ValueError as e:
            print(f"Value Error: {e}.\nPlease enter either:")
            print("- An IPv4 address using the format 255.255.255.255, or")
            print("- An IPv6 address using the format ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")

    host_password = getpass.getpass(prompt="Enter host server password: ")

    # 
    #
    # Functionality still to be implemented
    # Host password is not currently used for anything
    #
    #

    return host_address, host_password

def user_credentials():
    """
    This function obtains user input to initialise their username and password.
    """

    while True:
        username = str(input("Enter username: ").replace(" ", ""))
        if 4<= len(username) <= 20:
            break
        else:
            print("Username must be between 4 to 20 characters in length")
    
    user_password = getpass.getpass(prompt="Enter user password: ")

    return username, user_password

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
        file.write(
            user_private_key.private_bytes(
                encoding = serialization.Encoding.PEM, 
                format = serialization.PrivateFormat.TraditionalOpenSSL, 
                encryption_algorithm = serialization.NoEncryption()             # Encryption to be added once initial functionality is verified
                # encryption_algorithm = serialization.BestAvailableEncryption(b"password")
            )
        )

    return user_private_key

def generate_csr(username, user_private_key):
    """
    This function defines the logic for generating a Certificate Signing Request (CSR), 
    enabling asymmetrically encrypted communication between the client and host server.
    """
    
    # Define the CSR subject variables and digitally sign
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COUNTRY_NAME, "AUS"),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Secure File Transfer System"),
                    x509.NameAttribute(NameOID.COMMON_NAME, username)
                ]
            )
        )
        #.add_extension(
        #    x509.SubjectAlternativeName([
        #        x509.DNSName(email),         # Need to validate whether this is required
        #        x509.RFC822Name(email)       # Need to validate whether this is required
        #    ])
        #)
        .sign(user_private_key, hashes.SHA256())
    )

    # Define the CSR filepath
    csr_path = os.path.join(CERTIFICATES, f"{username}_csr.pem")

    # Write the CSR file
    with open(csr_path, "wb") as file:
        file.write(csr.public_bytes(serialization.Encoding.PEM))

    return csr_path

def send_csr(username, host_address):
    """
    This function defines the logic for sending an unencrypted Certificate Signing Request
    (CSR) to a host server for the purpose of enabling subsequent asymmetric communication.
    """  
    
    csr_path = os.path.join(CERTIFICATES, f"{username}_csr.pem")
    signed_certificate_path = os.path.join(CERTIFICATES, f"{username}_certificate.pem")

    with socket.create_connection((host_address, CSR_PORT)) as csr_sock:
        
        # Send CSR to server
        with open(csr_path, "rb") as file:
            csr_sock.sendall(file.read())
        
        # Notify server of completed CSR send
        csr_sock.shutdown(socket.SHUT_WR)
        
        # Notify user of completed CSR send
        print(f"CSR sent to {host_address}:{CSR_PORT}")

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
    print(f"Signed certificate recieved from {host_address}")

def main():
    print("---------------------------------------------------------------------------------\n")
    print("                       Secure File Transfer System: Client                       \n")
    print("---------------------------------------------------------------------------------\n")
    
    # Input host server credentials
    host_address, host_password = host_credentials()

    # Input user credentials
    username, user_password = user_credentials()

    # Initialise certificate and key filepaths
    user_certificate_filepath = os.path.join(CERTIFICATES, f"{username}_certificate.pem")
    user_private_key_filepath = os.path.join(CERTIFICATES, f"{username}_key.pem")

    # Generate a Private Key for the user if one doesn't already exist
    if not os.path.exists(os.path.join(CERTIFICATES, f"{username}_key.pem")):
        user_private_key = generate_private_key(username)

    else:
        with open(user_private_key_filepath, "rb") as file:
            user_private_key = serialization.load_pem_private_key(
                file.read(),
                password = None             # Encryption to be added once initial functionality is fully tested
            )

    # Generate and send a Certificate Signing Request (CSR) if a host certificate doesn't already exists
    if not os.path.exists(user_certificate_filepath):
        generate_csr(username, user_private_key)      
        send_csr(username, host_address)
        
    # Configure SSL context
    context = ssl.create_default_context(
        ssl.Purpose.SERVER_AUTH, 
        cafile = f"{CERTIFICATES}ca_certificate.pem"
    )
    context.load_cert_chain(
        certfile = user_certificate_filepath, 
        keyfile = user_private_key_filepath
    )

    # Establish SSL connection
    with socket.create_connection((host_address, SFTS_PORT)) as sock:
        with context.wrap_socket(sock, server_hostname=host_address) as ssock:
            reader = ssock.makefile("r")
            writer = ssock.makefile("wb", buffering=1)
            
            # _____________________________ Display server message      # Need to cross-check that all server messages are correctly read and displayed
            print(reader.readline().strip())
            
            # Send client initiated commands to server
            while True:
                cmdline = str(input("Please select either:\nUpload <filename>\nDownload <filename>\nls\nQuit\n")).strip()
                
                if not cmdline:
                    continue

                # Decomposion of client commands
                args = cmdline.split(maxsplit=1)    
                cmd = args[0].lower()
                filename = args[1] if len(args) > 1 else None
                # time_sent = args[2] if len(args) > 2 else None      ### PLACEHOLDER ONLY, Replay Attack mitigiation mechanism yet to be added

                if cmd == "download" and filename:
                    download(ssock, reader, writer, filename)

                elif cmd == "upload" and filename:
                    upload(ssock, reader, writer, filename)
                
                elif cmd == "delete":
                    delete(reader, writer, filename)

                elif cmd == "ls":
                    writer.write(b"ls\n")
                    writer.flush()
                    print(reader.readline().strip())
                
                elif cmd == "quit":
                    writer.write(b"quit\n")
                    writer.flush()
                    print(reader.readline().strip())
                    break            

                else:
                    print("Invalid command or missing filename. Please enter either:\nUpload <filename>\nDownload <filename>\nls\nQuit\n")

    ###
    ### Need to check whether I need to add a clean disconnect mechanic for the client
    ###

if __name__ == "__main__":
    main()