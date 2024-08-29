import socket
import os 
import sys
import json

from difflib import get_close_matches

def start_server():

    # connection setup

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(('0.0.0.0', 12346))  # Bind to all interfaces on port
    server_socket.listen(1)
    print("Server is listening...")
    conn, addr = server_socket.accept() # addr will contain tuple with (ip addr, port)
    print(f"Connected by {addr}")

    # collect connection information

    hostname, alias, ip_addresses = socket.gethostbyaddr(addr[0]) # reverse DNS lookup on ip address to get hostname
    client_msg = conn.recv(1024).decode('utf-8') # receive and parse initial client message
    command, filename = client_msg.split('|', 1)
    client_dir = hostname.replace('.yahavfileserver.home', '', 1) # get client's directory name in fileserver 

    # check and handle file overwrite case

    if os.path.exists(os.path.join(client_dir, os.path.basename(filename))) and command == 'STORE': # detect case of overwrite
        conn.sendall(b'OVERWRITE') # notify client of potential overwrite
        client_msg = conn.recv(1024).decode('utf-8') # receive client response to overwrite
        while True: 
            if ((client_msg == 'ACK') or (client_msg == 'QUIT')): # wait for client response to overwrite
                break
    cancel_flag = 0
    if client_msg == 'QUIT': # client decided to abort to avoid overwrite
        cancel_flag = 1
        print("Request canceled.")
        conn.close()
        server_socket.close()
    
    # handle main requests

    if not cancel_flag: 
        
        if command == 'STORE':
            conn.sendall(b'READY') # eventually, do some authentication before this. But for now, always indicate ready. 
            os.makedirs(client_dir, exist_ok=True) # make directory for new host (or just don't do anything if already exists)
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
            conn.sendall(b'READY')
            json_list = json.dumps(similarity_search("../server-code", filename)) # call search algorithm and send result to client
            if not json.loads(json_list): 
                print("Error: search unsuccessful. Closing.")
            else:     
                conn.sendall(json_list.encode('utf-8'))

                client_msg = conn.recv(1024).decode('utf-8')
                options = json.loads(json_list) 
                if int(client_msg) > len(options):
                    print("Error: search unsuccessful. Closing.")
                else: 
                    target_file = options[int(client_msg)-1]
                    with open(target_file, 'rb') as file: 
                        data = file.read()
                        conn.sendall(data)
                        print("File sent successfully")
                



            # check if file exists in fileserver 
            # if it doesn't, return an error status to client (SERVFAIL?)
            # if it does, gather bookkeeping info about file (and later, check if client is authorized to access it, if they are not return SERVFAIL)
            # if all is well, send READY signal to client
            # receive ACK signal from client
            # send file to client

    # close connection

    conn.close()
    server_socket.close()

def test_dir_scan(dir_name):
    for root, dirs, files in os.walk(dir_name):
        print(f"root: {root}")
        print(f"dirs: {dirs}")
        print(f"files: {files}")

def similarity_search(dir_name, keyword):
    file_dict = {}
    for root, dirs, files in os.walk(dir_name):
        for file in files: 
            filepath = os.path.join(root.replace('../server-code/', '', 1), file)
            file_dict.update({filepath:os.path.basename(filepath)})
    matches = get_close_matches(keyword, list(file_dict.values()), n=10, cutoff=0.5)
    return [match for match, base_name in file_dict.items() if base_name in matches]
        
if __name__ == "__main__":
    start_server()
    # test_dir_scan(sys.argv[1])
    # similarity_search('../server-code', 'receive')