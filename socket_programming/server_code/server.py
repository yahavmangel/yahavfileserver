import socket
import os 
import json
import threading
from difflib import get_close_matches

# global resources

file_lock_dict = {}
global_dict_lock = threading.Lock()                                                         # lock for locking the file lock dictionary (make it threading safe as well)

# main code 

def client_handler(conn):

    try: 

        # collect connection information

        try: 
            hostname, alias, ip_addresses = socket.gethostbyaddr(addr[0])                   # reverse DNS lookup on ip address to get hostname
        except socket.herror: 
            print("DNS server offline. Quitting.")
            conn.close()
            return 

        client_msg = conn.recv(1024).decode('utf-8')                                        # receive and parse initial client message
        command, filename = client_msg.split('|', 1)
        client_dir = os.path.join('../files', hostname.split('.')[0])                       # get client's directory name in fileserver 

        # check and handle file overwrite case

        if os.path.exists(os.path.join(client_dir, os.path.basename(filename))) and command == 'STORE': 
            conn.sendall(b'OVERWRITE')                                                      # notify client of potential overwrite
            client_msg = conn.recv(1024).decode('utf-8')                                    # receive client response to overwrite
            while True: 
                if ((client_msg == 'ACK') or (client_msg == 'QUIT')):                       # wait for client response to overwrite
                    break

        if client_msg == 'QUIT':                                                            # client decided to abort to avoid overwrite
            print("Request canceled.")
            conn.close()
            return 
        
        # handle main requests

        if command == 'STORE':

            file_lock = get_file_lock(filename)                                             # synchronization: prevent w/w conflicts to same file 
            file_lock.acquire()

            conn.sendall(b'READY')                                                          # eventually, do some authentication before this. But for now, always indicate ready. 
            os.makedirs(client_dir, exist_ok=True)                                          # make directory for new host (or just don't do anything if already exists)
            with open(os.path.join(client_dir, os.path.basename(filename)), 'wb') as file:  # join file name with newly made directory 
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

                file_lock.release()
                    
        elif command == 'REQUEST':
            conn.sendall(b'READY')
            json_list = json.dumps(similarity_search("../files/", filename))                # call search algorithm and send result to client
            if not json.loads(json_list):                                                   # list is empty
                print("Error: search unsuccessful. Closing.")
            else: 
                conn.sendall(b'OPTIONS')    
                conn.sendall(json_list.encode('utf-8'))
                client_msg = conn.recv(1024).decode('utf-8')                                # receive back client's number choice, which is index into list
                options = json.loads(json_list) 
                if int(client_msg) > len(options):                                          # client chose N/A option
                    print("Error: search unsuccessful. Closing.")
                else: 
                    target_file = options[int(client_msg)-1]
                    file_lock = get_file_lock(target_file)                                  # synchronization: prevent r/w conflicts on the same file
                    file_lock.acquire()
                    with open(os.path.join('../files', target_file), 'rb') as file: 
                        data = file.read()                                                  # send target file to client
                        conn.sendall(data)
                        print("File sent successfully")

                    file_lock.release()

        # close connection

        conn.close()

    except ConnectionError: 
        print("Connection Error. Exiting.")

# helper functions

def similarity_search(dir_name, keyword):
    file_dict = {}
    for root, dirs, files in os.walk(dir_name):
        for file in files: 
            filepath = os.path.join(root.replace(dir_name, '', 1), file)
            file_dict.update({filepath:os.path.basename(filepath)})
    matches = get_close_matches(keyword, list(file_dict.values()), n=10, cutoff=0.5)
    return [match for match, base_name in file_dict.items() if base_name in matches]
        
def get_file_lock(filename):
    with global_dict_lock:
        if filename not in file_lock_dict:
            file_lock_dict[filename] = threading.Lock()
        return file_lock_dict[filename]

# main loop 

if __name__ == "__main__":

    # connection setup

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(('0.0.0.0', 12345))                                                  
    server_socket.listen(5)

    print("Server is listening...")

    while True:
        conn, addr = server_socket.accept()                                                 # every time a connection is accepted by server, make a new thread
        print(f"Connected by {addr}")
        client_thread = threading.Thread(target=client_handler, args=(conn,))
        client_thread.start()