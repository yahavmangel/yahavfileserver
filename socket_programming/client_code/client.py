import socket
import sys
import json
import os
import zipfile
import configparser
import logging
from loghandler import JSONSocketHandler
import threading

# logging and metadata

script_dir = os.path.dirname(os.path.abspath(__file__))                                     # make script execution dynamic 
login_name = os.getlogin()

logger = logging.getLogger(login_name)
logger.setLevel(logging.DEBUG)

try:                                                                                        # collect config file info 
    config = configparser.ConfigParser()
    config.read(os.path.join(script_dir, 'config.ini'))
    server_ip = config['client']['server_ip']                                               # ip of fileserver
    local_ip = config['client']['local_ip']                                                 # ip of localserver (for logs/user prompts)
    port = int(config['client']['port'])                                                    # port for connection with fileserver
    port2 = int(config['client']['port2'])                                                  # port for connection with localserver (for logs/user prompts)
    target_dir = os.path.join(script_dir, config['client']['target_dir'])                   # target directory of operations 
except KeyError:                                                                            # check for misconfigured config file 
    logger.critical(f"Missing or misconfigured config file")    
    sys.exit(1) 

json_handler = JSONSocketHandler(local_ip, port2)
json_handler.setLevel(logging.DEBUG)
json_handler.setFormatter(logging.Formatter('(%(name)s) %(levelname)s: %(message)s'))
logger.addHandler(json_handler)

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
    'STOREDIRE': 'STOREDIRE',
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

# main code 

def server_request(command, filename):
    """
    Launches the server request.

    Args:
        command: client requested command (STORE, REQUEST, etc.)
        filename: the file name or similar key word that the operation is executed on
    """

    try: 

        # input validation
    
        if not (command == 'STORE' or command == 'REQUEST'):
            logger.error("Invalid command")
            return 
        
        # connection setup

        try:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try: 
                client_socket.settimeout(10)
                client_socket.connect((server_ip, port))
            except socket.timeout:
                logger.critical("Connection timed out. Server unreachable.")
                return
            logger.info("Connected to server: " + server_ip)
            server_msg = f"{os.getlogin()}|{command}|{filename}"                            # send client username, command, and file name to server for processing
            client_socket.sendall(server_msg.encode())                                      # send server message 
        except socket.gaierror:
            logger.critical("Invalid server IP. Exiting.")                                  # invalid format case 
            return

        # handle client command

        if command == 'STORE':

            while True: 
                server_resp = client_socket.recv(AUTH_RESP_LEN).decode('utf-8')             # wait for server authentication response
                if (server_resp[:-1] == 'AUTH'):                                            # could be either auth success or fail 
                    break
            if server_resp == 'AUTHS':                                                      # auth success: handle request 
                logger.debug("Received authorization from server")
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
            if server_resp == 'AUTHS': 
                logger.debug("Received authorization from server")                          # auth success: handle request 
                request_handler(client_socket, target_dir)
            elif server_resp == 'AUTHF':                                                    # auth fail: rejct request 
                logger.error("Permission denied. Exiting.")
                return
        
    except ConnectionError: 
        logger.critical("Connection Error. Exiting.")
    except TimeoutError:
        logger.critical("Connection timed out. Server unreachable.")
    finally: 
        client_socket.close()


def handle_overwrite(client_socket):
    """
    Handles the case of overwrite (occurs when a STORE would overwrite a preexisting file on the server) by asking client whether they want to proceed or not.

    Args:
        client_socket: the socket holding the connection with the server. 
    
    Returns: 
        Bool: outcome of client decision (True = Ok, False = Stop)
    """
    while True: 
        server_resp = client_socket.recv(BUF_SIZE_SMALL).decode('utf-8')                    # collect initial response from server 
        if (server_resp == 'OVERWRITE') or (server_resp == 'READY'): 
            break
    
    # handle file overwriting case

    if server_resp == 'OVERWRITE':                                                          # detect overwriting
        while True:
            user_input = send_prompt("File already exists. Overwrite? [y/n] ", "prompt")                    # prompt user on action
            if user_input == 'n' or user_input == 'y':
                break
            else:
                send_prompt("Invalid input, try again\n", "prompt")
        if user_input == 'n':
            logger.info("Request canceled.")                                    
            send_client_msg(client_socket, "QUIT")                                          # notify server that you quit
            return False
        elif user_input == 'y':
            logger.info("Acknowledged overwrite")
            send_client_msg(client_socket, "ACK")                                           # notify server that you acknowledge overwrite
            wait_for_server_resp(client_socket, "READY")                                    # check that server is ready AFTER overwrite
            return True                
    else: return True

def store_handler(client_socket, filename, target_dir):
    """
    Handles main workflow of STORE command: sends file/directory to server.

    Args:
        client_socket: the socket holding the connection with the server. 
        filename: name of file to store. 
        target_dir: directory to grab file/dir from 
    """

    logger.debug("Checking if " + str(filename) + " is a file or a directory...")
    if os.path.isfile(filename):
        logger.debug("Result: is a file")
        send_client_msg(client_socket, "STOREFILE")
        try: 
            with open(filename, 'rb') as file:
                while chunk := file.read(BUF_SIZE_LARGE):
                    client_socket.sendall(chunk)                                                                    # Send all the data
                logger.info("File " + str(filename) + " sent successfully")
        except IOError as e:
            logger.error("Error reading file " + str(filename) + ": " + str(e))
            return 
    elif os.path.isdir(filename):
        logger.debug("Result: is a directory")
        send_client_msg(client_socket, "STOREDIRE")
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
            while chunk := zip.read(BUF_SIZE_LARGE):
                client_socket.sendall(chunk)
            logger.info("The " + filename + " directory was zipped and sent successfully")
        os.remove(filename + '.zip')  
    else: 
        logger.error("The file or directory you requested to store does not exist. Exiting.")                       # case of invalid file name

def request_handler(client_socket, target_dir):
    """
    Handles main workflow of REQUEST command: wait for server options -> prompt user to choose -> send choice to server -> receive requested file from server 

    Args:
        client_socket: the socket holding the connection with the server. 
        filename: name of file to store. 
        target_dir: directory to grab file/dir from 
    """

    wait_for_server_resp(client_socket, "READY")                                    # check that server is ready for request
    try: 
        logger.debug("Waiting for server search results...")
        wait_for_server_resp(client_socket, "OPTIONS")    
        logger.debug("Results received.")                                           # wait for server to return search options
        json_list = client_socket.recv(BUF_SIZE_LARGE).decode('utf-8')
        options = json.loads(json_list)                                             # decode sent options into local array 
        if (len(options) > 0):                                                      
            send_prompt("Server returned multiple results: \n", "print")
            i = 0
            for option in options: 
                i += 1
                send_prompt(str(i) + ': ' + option, "print")
            send_prompt(str(i + 1) + ": N/A \n", "print")
            logger.debug("Waiting for client choice...")
            while True:
                user_input = send_prompt("Which one? ", "prompt")
                try: 
                    if(int(user_input) > 0 and int(user_input) < len(options) + 2): 
                        logger.debug("Client chose option #" + user_input)
                        break
                    else: 
                        send_prompt("Invalid choice, try again\n", "prompt")
                except ValueError: 
                    send_prompt("Please choose one of the numbers above.", "print")                # case of non-int input

            server_msg = user_input                                                 # send chosen number as server message
            client_socket.sendall(server_msg.encode())                              # send server message 
            if int(user_input) > len(options):                                      # chose N/A option    
                logger.debug("Client chose N/A option")
                send_prompt("Sorry we couldn't find your file :(", "print")
            else: 

                # handle file request response
                logger.debug("Checking if result is a file or directory...")
                if not options[int(user_input)-1][-1] == '/':                       # use '/' character appended by server to distinguish between files and dirs. If there is a '/', it is a dir. 
                    logger.debug("Is a file")
                    new_filepath = os.path.join(target_dir, os.path.basename(options[int(user_input)-1]))
                    if os.path.exists(new_filepath):                                # check for potential overwrite. If so, add (1), (2), etc. to indicate copy number.
                        for i in range(1, FILE_COPY_LIMIT):                         # bad implementation, but ain't nobody gonna make more than 1 million copies of a file.. right?????
                            if os.path.exists(os.path.join(target_dir, os.path.basename(new_filepath).split('.')[0] + f' ({i})' + '.' + os.path.basename(new_filepath).split('.')[1])):
                                continue
                            new_filepath = os.path.join(target_dir, os.path.basename(new_filepath).split('.')[0] + f' ({i})' + '.' + os.path.basename(new_filepath).split('.')[1])
                            break
                    try: 
                        with open(new_filepath, 'wb') as file:                      # receive requested file data 
                            while True: 
                                data = client_socket.recv(BUF_SIZE_SMALL)
                                if not data:
                                    break
                                file.write(data)
                            logger.info("File received successfully")
                    except IOError as e:
                        logger.error("Error reading file " + str(new_filepath) + ": " + str(e))
                        return 

                # handle directory request response 

                else: 
                    logger.debug("Is a directory")
                    extraction_dir = os.path.join(target_dir, os.path.basename(options[int(user_input)-1][:-1]))
                    tempfilename = extraction_dir + '_temp.zip'
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
    """
    Polls for a server response, and breaks once it is received. Logs the received message.

    Args:
        client_socket: the socket holding the connection with the server. 
        resp: desired response from server 
    """
    resp_len = len(resp)
    while True:
        server_resp = client_socket.recv(resp_len).decode('utf-8')
        if resp in server_resp and resp in command_table.values():
            logger.debug("Received message from server: " + resp)
            break

def send_client_msg(client_socket, msg):
    """
    Sends a message to the server and logs it.

    Args:
        client_socket: the socket holding the connection with the server. 
        msg: desired message to server 
    """
    logger.debug(str(login_name) + " -> server: " + msg)                            # log each server message in DEBUG log level
    client_socket.sendall(command_table[msg].encode())

def send_prompt(message, type):
    """
    Sends a prompt (either input() or print()) to local server)

    Args:
        message: message to send
        tye: print or input
    """

    try: 
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((local_ip, port2))

        match type: 
            case "prompt":
                msg = 'USRINPUT' + message + 'END'
                sock.sendall(msg.encode('utf-8'))
                return sock.recv(BUF_SIZE_SMALL).decode('utf-8')                    # wait for prompt response
            case "print":
                msg = 'USRPRINT' + message + 'END'
                sock.sendall(msg.encode('utf-8'))
                return 1
        sock.close()
    except Exception: 
        logger.critical("localserver unreachable. Exiting.")
        sys.exit(1)

if __name__ == "__main__":
    server_request(sys.argv[1], sys.argv[2])