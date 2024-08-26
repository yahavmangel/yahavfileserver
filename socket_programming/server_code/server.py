import socket
import os 

def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('0.0.0.0', 65432))  # Bind to all interfaces on port 65432
    server_socket.listen(1)
    print("Server is listening...")

    conn, addr = server_socket.accept() #addr will contain tuple with (ip addr, port)
    print(f"Connected by {addr}")

    hostname, alias, ip_addresses = socket.gethostbyaddr(addr[0]) #reverse DNS lookup on ip address to get hostname
    
    client_dir = hostname.replace('.yahavfileserver.home', '', 1) #make new directory in file server with hostname as name  
    os.makedirs(client_dir, exist_ok=True)
    with open(os.path.join(client_dir, "received_file.txt"), 'wb') as file: #join file name with newly made directory 
        while True:
            data = conn.recv(1024)
            if not data:
                break
            file.write(data)
    print("File received successfully")

    conn.close()

if __name__ == "__main__":
    start_server()