import socket
import os 

def start_server():
    cancel_flag = 0
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('0.0.0.0', 12347))  # Bind to all interfaces on port
    server_socket.listen(1)
    print("Server is listening...")

    conn, addr = server_socket.accept() # addr will contain tuple with (ip addr, port)
    print(f"Connected by {addr}")

    hostname, alias, ip_addresses = socket.gethostbyaddr(addr[0]) # reverse DNS lookup on ip address to get hostname
    client_msg = conn.recv(1024).decode('utf-8') # receive and parse initial client message
    command, filename = client_msg.split('|', 1)
    client_dir = hostname.replace('.yahavfileserver.home', '', 1) #make new directory in file server with hostname as name  
    if os.path.exists(os.path.join(client_dir, filename)) and command == 'STORE': # detect case of overwrite
        conn.sendall(b'OVERWRITE') # notify client of potential overwrite
        client_msg = conn.recv(1024).decode('utf-8') # receive client response to overwrite
        while True: 
            if ((client_msg == 'ACK') or (client_msg == 'QUIT')): # wait for client response to process
                break
    if client_msg == 'QUIT': # client decided to abort to avoid overwrite
        cancel_flag = 1
        print("Request cancelled.")
        conn.close()
    if not cancel_flag: 
        conn.sendall(b'READY') # eventually, do some authentication before this. But for now, always indicate ready. 
        if command == 'STORE':
            os.makedirs(client_dir, exist_ok=True)
            with open(os.path.join(client_dir, filename), 'wb') as file: # join file name with newly made directory 
                data_flag = 0
                while True:
                    data = conn.recv(1024)
                    if not data:
                        if not data_flag:
                            os.remove(os.path.join(client_dir, filename)) # if file is empty, don't actually create anything
                            print("Error: file contained no data")   
                        break
                    file.write(data)
                    data_flag = 1
                if data_flag: print("File stored successfully")
        elif command == 'REQUEST':
            print("Server requests not implemented yet")

    conn.close()

if __name__ == "__main__":
    start_server()