import socket
import os 
import json
import threading
import zipfile
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

        if command == 'STORE' and os.path.exists(os.path.join(client_dir, filename.split('/')[-1])): 
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

            conn.sendall(b'READY')                                                                  # eventually, do some authentication before this. But for now, always indicate ready. 

            while True: 
                client_msg = conn.recv(1024).decode('utf-8')
                if (client_msg == 'STOREDIR' or client_msg == 'STOREFILE'):
                    break
            
            if client_msg == 'STOREFILE':
                file_lock = get_file_lock(os.path.join(hostname.split('.')[0], os.path.basename(filename)))                                                # synchronization: prevent w/w conflicts to same file 
                print(f'{os.path.join(hostname.split('.')[0], os.path.basename(filename))} lock acquired')

                with file_lock:                                                    
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
            elif client_msg == 'STOREDIR':                                          
                dir_lock = get_file_lock(os.path.join(hostname.split('.')[0], filename[:-1].split('/')[-1])) # don't even ask what this is
                print(f'{os.path.join(hostname.split('.')[0], filename[:-1].split('/')[-1])} lock acquired')
                with dir_lock:                                                                      # synchronization: prevent w/w conflicts to same directory 
                    extraction_dir = client_dir
                    os.makedirs(extraction_dir, exist_ok=True)
                    with open(filename[:-1].replace('/', '_', 1) + '_temp.zip', 'wb') as temp_zip:               # receive zip file binary. This opens a temp zip file.
                        while True: 
                            zip_data = conn.recv(4096)
                            if not zip_data:
                                break
                            temp_zip.write(zip_data)
                        temp_zip.flush()                                            # weird solution that fixed 'not a zip file' error for me
                        os.fsync(temp_zip.fileno())
                        with zipfile.ZipFile(filename[:-1].replace('/', '_', 1) + '_temp.zip', 'r') as zip_file: # use zipfile API to unzip requested directory 
                            zip_file.extractall(path=extraction_dir)
                            print("Directory unzipped successfully")
                    os.remove(filename[:-1].replace('/', '_', 1) + '_temp.zip')                                  # remove temp zip file. 

                    
        elif command == 'REQUEST':
            conn.sendall(b'READY')
            json_list = json.dumps(similarity_search("../files/", filename))                    # call search algorithm and send result to client
            conn.sendall(b'OPTIONS')
            if not json.loads(json_list):                                                       # list is empty
                print("Error: search unsuccessful. Closing.")
            else:     
                conn.sendall(json_list.encode('utf-8'))
                client_msg = conn.recv(1024).decode('utf-8')                                    # receive back client's number choice, which is index into list
                options = json.loads(json_list) 
                if int(client_msg) > len(options):                                              # client chose N/A option
                    print("Error: search unsuccessful. Closing.")
                else: 

                    target_file = options[int(client_msg)-1]
                    
                    # file request 

                    if os.path.isfile(os.path.join('../files', target_file)):
                        file_lock = get_file_lock(target_file)                                  # synchronization: prevent r/w conflicts on the same file
                        print(f'{target_file} lock acquired')
                        with file_lock: 
                            with open(os.path.join('../files', target_file), 'rb') as file: 
                                data = file.read()                                              # send target file to client
                                conn.sendall(data)
                                print("File sent successfully")
                    
                    # directory request 
                    
                    elif os.path.isdir(os.path.join('../files', target_file[:-1])):     
                        dir_lock = get_file_lock(target_file[:-1])
                        print(f'{target_file[:-1]} lock acquired')
                        with dir_lock:                                                                                          # synchronization: prevent r/w conflicts on the same file
                            with zipfile.ZipFile(os.path.join('../files', target_file[:-1] + '.zip'), 'w') as zip:              # use zipfile API to zip requested directory. This opens a temp zip file
                                for root, dirs, files in os.walk(os.path.join('../files', target_file[:-1])):
                                    for file in files:                                                                          # add every file to zip archive
                                        filepath = os.path.join(root, file)
                                        arcname = os.path.relpath(filepath, start=os.path.join('../files', target_file[:-1]))   # use relative path to maintain correct directory structure
                                        zip.write(filepath, arcname=arcname)
                                    for dir in dirs:                                                                            # add every subdirectory to zip archive
                                        dirpath = os.path.join(root, dir)
                                        arcname = os.path.relpath(dirpath, start=os.path.join('../files', target_file[:-1]))    # use relative path to maintain correct directory structure
                                        zip.write(dirpath, arcname=arcname)
                            with open(os.path.join('../files', target_file[:-1] + '.zip'), 'rb') as zip_file:                   # open file in binary mode to send it over socket
                                data = zip_file.read()
                                conn.sendall(data)
                                print("Zipped directory sent successfully")
                            os.remove(os.path.join('../files', target_file[:-1] + '.zip'))                                      # remove temporary file

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
        for dir in dirs: 
            dirpath = os.path.join(root.replace(dir_name, '', 1), dir)
            file_dict.update({dirpath + '/':os.path.basename(dirpath)})                         # add '/' to signify it is a directory
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
        conn, addr = server_socket.accept()                                                     # every time a connection is accepted by server, make a new thread
        print(f"Connected by {addr}")
        client_thread = threading.Thread(target=client_handler, args=(conn,))
        client_thread.start()