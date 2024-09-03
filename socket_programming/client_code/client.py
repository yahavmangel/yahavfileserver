import socket
import sys
import json
import os
import zipfile

def server_request(server_ip, command, filename, target_dir):

    # input validation
    
    if not (command == 'STORE' or command == 'REQUEST'):
        print("Error: invalid command")
        return 
    
    # connection setup
    
    try: 

        try:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            client_socket.connect((server_ip, 12345))
            server_msg = f"{command}|{filename}"
            client_socket.sendall(server_msg.encode())                                      # send server message 
        except socket.gaierror:
            print("Error: Invalid server IP. Exiting.")                                     # invalid format case 
            return

        # handle initial server response
        
        if command == 'STORE':

            while True: 
                server_resp = client_socket.recv(1024).decode('utf-8')                      # collect initial response from server 
                if (server_resp == 'OVERWRITE') or (server_resp == 'READY'): 
                    break
            
            # handle file overwriting case

            if server_resp == 'OVERWRITE':                                                  # detect overwriting
                print("hi")
                while True:
                    user_input = input("File already exists. Overwrite? [y/n] ")            # prompt user on action
                    if user_input == 'n' or user_input == 'y':
                        break
                    else:
                        print ("Invalid input, try again\n")
                if user_input == 'n':
                    print("Request canceled.")
                    server_msg = "QUIT"                                                     # notify server that you quit
                    client_socket.sendall(server_msg.encode()) 
                    client_socket.close()                                                   
                    return 
                elif user_input == 'y':
                    server_msg = "ACK"                                                      # notify server that you acknowledge overwrite
                    client_socket.sendall(server_msg.encode())
                    wait_for_server_resp(client_socket, "READY")                            # check that server is ready AFTER overwrite

        # handle server response to request 

        if command == 'STORE':
            if os.path.isfile(filename):
                server_msg = 'STOREFILE'
                client_socket.sendall(server_msg.encode()) 
                with open(filename, 'rb') as file:
                    data = file.read()                                                      # Read the whole file
                    client_socket.sendall(data)                                             # Send all the data
                    print("File sent successfully")
            elif os.path.isdir(filename):
                server_msg = 'STOREDIR'
                client_socket.sendall(server_msg.encode()) 
                with zipfile.ZipFile(filename + '.zip', 'w') as temp_zip:
                    for root, dirs, files in os.walk(filename):
                        for file in files:                                                                                  # add every file to zip archive
                            filepath = os.path.join(root, file)
                            arcname = os.path.relpath(filepath, start=os.path.join(os.path.join(target_dir, filename)))     # use relative path to maintain correct directory structure
                            temp_zip.write(filepath, arcname=arcname)
                        for dir in dirs:                                                                                    # add every subdirectory to zip archive
                            dirpath = os.path.join(root, dir)
                            arcname = os.path.relpath(dirpath, start=os.path.join(os.path.join(target_dir, filename)))      # use relative path to maintain correct directory structure
                            temp_zip.write(dirpath, arcname=arcname)
                with open(filename + '.zip', 'rb') as zip: 
                    data = zip.read()
                    client_socket.sendall(data)
                    print("Zipped directory sent successfully")
                os.remove(filename + '.zip')  
            else: 
                print("Error: the file you requested to store does not exist. Exiting.")    # case of invalid file name
                

        elif command == 'REQUEST':
            wait_for_server_resp(client_socket, "READY")                                    # check that server is ready for request
            try: 
                wait_for_server_resp(client_socket, "OPTIONS")                              # wait for server to return search options
                json_list = client_socket.recv(4096).decode('utf-8')
                options = json.loads(json_list)                                             # decode sent options into local array 
                if (len(options) > 0):                                                      
                    print("Server returned multiple results: \n")
                    i = 0
                    for option in options: 
                        i += 1
                        print (str(i) + ': ' + option)
                    print (str(i + 1) + ": N/A \n")
                    while True:
                        user_input = input("Which one? ")
                        try: 
                            if(int(user_input) > 0 and int(user_input) < len(options) + 2): 
                                break
                            else: 
                                print("Invalid choice, try again\n")
                        except ValueError: 
                            print("Please choose one of the numbers above.")                # case of non-int input

                    server_msg = user_input                                                 # send chosen number as server message
                    client_socket.sendall(server_msg.encode())                              # send server message 
                    if int(user_input) > len(options):                                      # chose N/A option    
                        print("Sorry we couldn't find your file :(")
                    else: 

                        # handle file request response

                        if not options[int(user_input)-1][-1] == '/':                       # use '/' character appended by server to distinguish between files and dirs. If there is a '/', it is a dir. 
                            new_filepath = os.path.join(target_dir, (os.path.basename(options[int(user_input)-1])))
                            if os.path.exists(new_filepath):                                # check for potential overwrite. If so, add (1), (2), etc. to indicate copy number.
                                for i in range(1, 1000000):                                 # bad implementation, but ain't nobody gonna make more than 1 million copies of a file.. right?????
                                    if os.path.exists(new_filepath.split('.')[0] + f' ({i})' + '.' + new_filepath.split('.')[1]):
                                        continue
                                    new_filepath = new_filepath.split('.')[0] + f' ({i})' + '.' + new_filepath.split('.')[1]
                                    break
                            with open(new_filepath, 'wb') as file:                          # receive requested file data 
                                while True: 
                                    data = client_socket.recv(1024)
                                    if not data:
                                        break
                                    file.write(data)
                                print("File received successfully")

                        # handle directory request response 

                        else: 
                            extraction_dir = os.path.join(target_dir, os.path.basename(options[int(user_input)-1][:-1]))
                            if os.path.exists(extraction_dir):                              # check for potential overwrite. If so, add (1), (2), etc. to indicate copy number.
                                for i in range(1, 1000000):                                 # bad implementation, but ain't nobody gonna make more than 1 million copies of a file.. right?????
                                    if os.path.exists(extraction_dir + f' ({i})'):
                                        continue
                                    extraction_dir += f' ({i})'
                                    break
                            os.makedirs(extraction_dir, exist_ok=True)
                            with open('temp_zip_file.zip', 'wb') as temp_zip:               # receive zip file binary. This opens a temp zip file.
                                while True: 
                                    zip_data = client_socket.recv(4096)
                                    if not zip_data:
                                        break
                                    temp_zip.write(zip_data)
                                temp_zip.flush()                                            # weird solution that fixed 'not a zip file' error for me
                                os.fsync(temp_zip.fileno())
                                with zipfile.ZipFile('temp_zip_file.zip', 'r') as zip_file: # use zipfile API to unzip requested directory 
                                    zip_file.extractall(path=extraction_dir)
                                    print("Directory unzipped successfully")
                            os.remove('temp_zip_file.zip')                                  # remove temp zip file. 

                else: 
                    print("Error: File not found in server. Exiting.")
            except json.decoder.JSONDecodeError:
                print("No matching results in server. Exiting.")
    
        #close connection

        client_socket.close()
        
    except ConnectionError: 
        print("Connection Error. Exiting.")

def wait_for_server_resp(client_socket, resp):                                              # helper function that polls for specific server response
    resp_len = len(resp)
    while True:
        server_resp = client_socket.recv(resp_len).decode('utf-8')
        if resp in server_resp:
            break

if __name__ == "__main__":
    server_request(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])