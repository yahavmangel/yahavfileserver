import socket
import os 
import sys

def start_server():
    cancel_flag = 0
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(('0.0.0.0', 12346))  # Bind to all interfaces on port
    server_socket.listen(1)
    print("Server is listening...")

    conn, addr = server_socket.accept() # addr will contain tuple with (ip addr, port)
    print(f"Connected by {addr}")

    hostname, alias, ip_addresses = socket.gethostbyaddr(addr[0]) # reverse DNS lookup on ip address to get hostname
    client_msg = conn.recv(1024).decode('utf-8') # receive and parse initial client message
    command, filename = client_msg.split('|', 1)
    client_dir = hostname.replace('.yahavfileserver.home', '', 1) #make new directory in file server with hostname as name  
    if os.path.exists(os.path.join(client_dir, os.path.basename(filename))) and command == 'STORE': # detect case of overwrite
        conn.sendall(b'OVERWRITE') # notify client of potential overwrite
        client_msg = conn.recv(1024).decode('utf-8') # receive client response to overwrite
        print(client_msg)
        while True: 
            if ((client_msg == 'ACK') or (client_msg == 'QUIT')): # wait for client response to process
                break
    if client_msg == 'QUIT': # client decided to abort to avoid overwrite
        cancel_flag = 1
        print("Request cancelled.")
        conn.close()
        server_socket.close()
    if not cancel_flag: 
        conn.sendall(b'READY') # eventually, do some authentication before this. But for now, always indicate ready. 
        if command == 'STORE':
            os.makedirs(client_dir, exist_ok=True)
            with open(os.path.join(client_dir, os.path.basename(filename)), 'wb') as file: # join file name with newly made directory 
                data_flag = 0
                while True:
                    data = conn.recv(1024)
                    if not data:
                        if not data_flag:
                            os.remove(os.path.join(client_dir, os.path.basename(filename))) # if file is empty, don't actually create anything
                            print("Error: file contained no data")   
                        break
                    file.write(data)
                    data_flag = 1
                if data_flag: 
                    print("File stored successfully")
                    
        elif command == 'REQUEST':
            print("Server requests not implemented yet")

    conn.close()
    server_socket.close()

def test_dir_scan(dir_name):
    for root, dirs, files in os.walk(dir_name):
        print(f"root: {root}")
        print(f"dirs: {dirs}")
        print(f"files: {files}")
if __name__ == "__main__":
    start_server()
    # test_dir_scan(sys.argv[1])