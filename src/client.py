import os
import socket
import ssl

# Global variables
HOST = "10.16.10.247"
PORT = 8443
CERTIFICATES = "/workspaces/secure-file-transfer-system-python/certificates/"
DIRECTORY = "/workspaces/secure-file-transfer-system-python/directory/"

# SSL context configuration
context = ssl.create_default_context(
    ssl.Purpose.SERVER_AUTH, 
    cafile = f"{CERTIFICATES}ca_certificate.pem"
)
context.load_cert_chain(
    certfile = f"{CERTIFICATES}client_certificate.pem", 
    keyfile = f"{CERTIFICATES}client_key.pem"
)

# Create the Directory filepath if it doesn't already exist
os.makedirs(DIRECTORY, exist_ok=True)

def download(conn, writer, filename):
    """
    This function defines the logics for how the client will initate downloads from the server 
    using a SSL connection.
    """

    # Prevent accidental overwrites caused by name conflicts
    filepath = os.path.join(DIRECTORY, filename)
    if os.path.exists(filepath):
        print(f"A file named {filename} already exists in {DIRECTORY}.\n")

    ###
    ### LOGIC YET TO BE ADDED FOR DUPLICATE FILE NAMES
    ###

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
    This function defines the logics for how the client will initate uploads to the server 
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
    if server_response != b"Ready":
        print(f"Server not ready: {server_response}")
        return
    
    # Upload command ssl transfer logic
    with open(filepath, "rb") as file:
        for chunk in iter(lambda: file.read(4096), b""):
            conn.send(chunk)
    conn.send(b"EOF")
    print(conn.makefile('r').readline().strip())

def main():
    print("---------------------------------------------------------------------------------\n")
    print("                       Secure File Transfer System: Client                       \n")
    print("---------------------------------------------------------------------------------\n")
    
    with socket.create_connection((HOST, PORT)) as sock:
        with context.wrap_socket(sock, server_hostname="ubuntu-sfts") as ssock:
            reader = ssock.makefile("r")
            writer = ssock.makefile("w", buffering=1)
            print(reader.readline().strip())
            
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

if __name__ == "__main__":
    main()