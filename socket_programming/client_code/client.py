import socket
import sys
import json
import os
import zipfile
import configparser
import logging

# important metadata

config = configparser.ConfigParser()
config.read('client-code/config.ini')
server_ip = config['client']['server_ip']
port = int(config['client']['port'])
login_name = os.getlogin()

command_table = { 

    # client commands 

    'STORE': 'STORE',
    'REQUEST': 'REQUEST',

    # internal commands

    'OPTIONS': 'OPTIONS',
    'READY': 'READY',
    'OVERWRITE': 'OVERWRITE',
    'QUIT': 'QUIT',
    'ACK': 'ACK',
    'STOREFILE': 'STOREFILE',
    'STOREDIR': 'STOREDIR',
    'AUTHSUCCESS': 'AUTHS',
    'AUTHFAIL': 'AUTHF'
}

# magic numbers

NUM_CLIENT_COMMANDS = 2
NUM_INTERNAL_COMMANDS = 7
AUTH_RESP_LEN = 5
BUF_SIZE_SMALL = 1024
BUF_SIZE_LARGE = 4096
FILE_COPY_LIMIT = 1000000

#logging 

logging.basicConfig(level=logging.DEBUG,
                    format='%(name)s - %(levelname)s - %(message)s',
                    filename=f'{login_name}.log')

logger = logging.getLogger()

# main code 

def server_request(command, filename, target_dir):

    try: 

        # input validation
    
        if not (command == 'STORE' or command == 'REQUEST'):
            logger.error("Invalid command")
            return 
        
        # connection setup

        try:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            client_socket.connect((server_ip, port))
            server_msg = f"{os.getlogin()}|{command}|{filename}"                            # send client username, command, and file name to server for processing
            client_socket.sendall(server_msg.encode())                                      # send server message 
        except socket.gaierror:
            logger.critical("Invalid server IP. Exiting.")                                 # invalid format case 
            return

        # handle client command

        if command == 'STORE':

            while True: 
                server_resp = client_socket.recv(AUTH_RESP_LEN).decode('utf-8')             # wait for server authentication response
                if (server_resp[:-1] == 'AUTH'):                                            # could be either auth success or fail 
                    break
            if server_resp == 'AUTHS':                                                      # auth success: handle request 
                status = handle_overwrite(client_socket)
                if not status: return                                                       # either no overwrite, or chose to proceed
                else: store_handler(client_socket, filename, target_dir)                       
            elif server_resp == 'AUTHF':                                                    # auth fail: reject request
                logger.error("Permission denied. Exiting.")
                return

        elif command == 'REQUEST':

            while True: 
                server_resp = client_socket.recv(AUTH_RESP_LEN).decode('utf-8')             # wait for server authentication response
                if ('AUTH' in server_resp):
                    break
            if server_resp == 'AUTHS':                                                      # auth success: handle request 
                request_handler(client_socket, filename, target_dir)
            elif server_resp == 'AUTHF':                                                    # auth fail: rejct request 
                logger.error("Permission denied. Exiting.")
                return
    
        #close connection

        client_socket.close()
        
    except ConnectionError: 
        logger.critical("Connection Error. Exiting.")

def handle_overwrite(client_socket):

    while True: 
        server_resp = client_socket.recv(BUF_SIZE_SMALL).decode('utf-8')                    # collect initial response from server 
        if (server_resp == 'OVERWRITE') or (server_resp == 'READY'): 
            break
    
    # handle file overwriting case

    if server_resp == 'OVERWRITE':                                                          # detect overwriting
        while True:
            user_input = input("File already exists. Overwrite? [y/n] ")                    # prompt user on action
            if user_input == 'n' or user_input == 'y':
                break
            else:
                print("Invalid input, try again\n")
        if user_input == 'n':
            logger.info("Request canceled.")                                    
            send_client_msg(client_socket, "QUIT")                                          # notify server that you quit
            client_socket.close()                                                   
            return False
        elif user_input == 'y':
            send_client_msg(client_socket, "ACK")                                           # notify server that you acknowledge overwrite
            wait_for_server_resp(client_socket, "READY")                                    # check that server is ready AFTER overwrite
            return True                
    else: return True

def store_handler(client_socket, filename, target_dir):

    if os.path.isfile(filename):
        send_client_msg(client_socket, "STOREFILE")
        with open(filename, 'rb') as file:
            data = file.read()                                                              # Read the whole file
            client_socket.sendall(data)                                                     # Send all the data
            logger.info("File sent successfully") 
    elif os.path.isdir(filename):
        send_client_msg(client_socket, "STOREDIR")
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
            logger.info("Zipped directory sent successfully")
        os.remove(filename + '.zip')  
    else: 
        logger.error("The file or directory you requested to store does not exist. Exiting.")                       # case of invalid file name

def request_handler(client_socket, filename, target_dir):

    wait_for_server_resp(client_socket, "READY")                                    # check that server is ready for request
    try: 
        wait_for_server_resp(client_socket, "OPTIONS")                              # wait for server to return search options
        json_list = client_socket.recv(BUF_SIZE_LARGE).decode('utf-8')
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
                        for i in range(1, FILE_COPY_LIMIT):                         # bad implementation, but ain't nobody gonna make more than 1 million copies of a file.. right?????
                            if os.path.exists(new_filepath.split('.')[0] + f' ({i})' + '.' + new_filepath.split('.')[1]):
                                continue
                            new_filepath = new_filepath.split('.')[0] + f' ({i})' + '.' + new_filepath.split('.')[1]
                            break
                    with open(new_filepath, 'wb') as file:                          # receive requested file data 
                        while True: 
                            data = client_socket.recv(BUF_SIZE_SMALL)
                            if not data:
                                break
                            file.write(data)
                        logger.info("File received successfully")

                # handle directory request response 

                else: 
                    extraction_dir = os.path.join(target_dir, os.path.basename(options[int(user_input)-1][:-1]))
                    dirname = filename[:-1]
                    tempfilename = dirname.replace('/', '_', 1) + '_temp.zip'
                    if os.path.exists(extraction_dir):                              # check for potential overwrite. If so, add (1), (2), etc. to indicate copy number.
                        for i in range(1, FILE_COPY_LIMIT):                         # bad implementation, but ain't nobody gonna make more than 1 million copies of a file.. right?????
                            if os.path.exists(extraction_dir + f' ({i})'):
                                continue
                            extraction_dir += f' ({i})'
                            break
                    os.makedirs(extraction_dir, exist_ok=True)
                    with open(tempfilename, 'wb') as temp_zip:                      # receive zip file binary. This opens a temp zip file.
                        while True: 
                            zip_data = client_socket.recv(BUF_SIZE_LARGE)
                            if not zip_data:
                                break
                            temp_zip.write(zip_data)
                        temp_zip.flush()                                            # weird solution that fixed 'not a zip file' error for me
                        os.fsync(temp_zip.fileno())
                        with zipfile.ZipFile(tempfilename, 'r') as zip_file:        # use zipfile API to unzip requested directory 
                            zip_file.extractall(path=extraction_dir)
                            logger.info("Directory unzipped successfully")
                    os.remove(tempfilename)                                         # remove temp zip file. 
        else: 
            logger.error("File not found in server. Exiting.")
    except json.decoder.JSONDecodeError:
        logger.error("No matching results in server. Exiting.")
        
# helper functions

def wait_for_server_resp(client_socket, resp):                                      # helper function that polls for specific server response
    resp_len = len(resp)
    while True:
        server_resp = client_socket.recv(resp_len).decode('utf-8')
        if resp in server_resp and resp in command_table.values():
            break

def send_client_msg(conn, msg):
    logger.debug("Client " + str(login_name) + " sent message to server: " + msg)                       # log each server message in debug level of logger 
    conn.sendall(command_table[msg].encode())

if __name__ == "__main__":
    server_request(sys.argv[1], sys.argv[2], sys.argv[3])