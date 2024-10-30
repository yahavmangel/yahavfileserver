"""
Execute and manage a client request to the fileserver. 

Functions: 
    server_request(command, filename)
    handle_overwrite(client_socket)
    store_handler(client_socket, filename, target_dir)
    request_handler(client_socket, target_dir)
    wait_for_server_resp(client_socket, resp)
    send_client_msg(client_socket, msg)
    send_prompt(message, prompt_type)
"""
import socket
import sys
import json
import os
import zipfile
import configparser
import logging
from loghandler import JSONSocketHandler

# logging and metadata

script_dir = os.path.dirname(os.path.abspath(__file__))         # make script execution dynamic
login_name = os.getlogin()

logger = logging.getLogger(login_name)
logger.setLevel(logging.DEBUG)

try:                                                            # collect config file info
    config = configparser.ConfigParser()
    config.read(os.path.join(script_dir, 'config.ini'))
    server_ip = config['client']['server_ip']                   # ip of fileserver
    local_ip = config['client']['local_ip']                     # ip of localserver
    port = int(config['client']['port'])                        # port for connection w/ fileserver
    port2 = int(config['client']['port2'])                      # port for connection w/ localserver
    target_dir = os.path.join(script_dir,
                              config['client']['target_dir'])   # target dir of operations
except KeyError:                                                # case of misconfigured config file
    logger.critical("Missing or misconfigured config file")
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

        if command not in ['STORE', 'REQUEST']:
            logger.error("Invalid command: %s", command)
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
            logger.info("Connected to server: %s", server_ip)

            # send client username, command, and file name to server for processing
            server_msg = f"{os.getlogin()}|{command}|{filename}"
            client_socket.sendall(server_msg.encode())           # send server message
        except socket.gaierror:
            logger.critical("Invalid server IP. Exiting.")       # invalid format case
            return

        # handle client command

        if command == 'STORE':

            while True:                                         # wait for server auth response
                server_resp = client_socket.recv(AUTH_RESP_LEN).decode('utf-8')
                if server_resp[:-1] == 'AUTH':
                    break
            if server_resp == 'AUTHS':                          # auth success: handle request
                logger.debug("Received authorization from server")
                status = handle_overwrite(client_socket)
                if not status:
                    return                                      # overwrite check passed
                store_handler(client_socket, filename, target_dir)
            elif server_resp == 'AUTHF':                        # auth fail: reject request
                logger.error("Permission denied. Exiting.")
                return

        elif command == 'REQUEST':

            while True:
                # wait for server authentication response
                server_resp = client_socket.recv(AUTH_RESP_LEN).decode('utf-8')
                if 'AUTH' in server_resp:
                    break
            if server_resp == 'AUTHS':                          # auth success: handle request
                logger.debug("Received authorization from server")
                request_handler(client_socket, target_dir)
            elif server_resp == 'AUTHF':                        # auth fail: rejct request
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
    Handles the case of overwrite (occurs when a STORE would overwrite a preexisting file on server) 
    by asking client whether they want to proceed or not.

    Args:
        client_socket: the socket holding the connection with the server. 
    
    Returns: 
        Bool: outcome of client decision (True = Ok, False = Stop)
    """
    while True:
        # collect initial response from server
        server_resp = client_socket.recv(BUF_SIZE_SMALL).decode('utf-8')
        if server_resp in ['OVERWRITE', 'READY']:
            break

    # handle file overwriting case

    if server_resp == 'OVERWRITE':                              # detect overwriting
        while True:                                             # prompt user on action
            user_input = send_prompt("File already exists. Overwrite? [y/n] ", "prompt")
            if user_input in ['n', 'y']:
                break
            send_prompt("Invalid input, try again\n", "print")
        if user_input == 'n':
            logger.info("Request canceled.")
            send_client_msg(client_socket, "QUIT")              # notify server that you quit
            return False
        if user_input == 'y':
            # notify server that you acknowledge overwrite and
            # check that server is ready AFTER overwrite
            logger.info("Acknowledged overwrite")
            send_client_msg(client_socket, "ACK")
            wait_for_server_resp(client_socket, "READY")
            return True
    return True

def store_handler(client_socket, filename, target_dir):
    """
    Handles main workflow of STORE command: sends file/directory to server.

    Args:
        client_socket: the socket holding the connection with the server.
        filename: name of file to store.
        target_dir: directory to grab file/dir from
    """

    logger.debug("Checking if %s is a file or a directory...", filename)
    if os.path.isfile(filename):
        logger.debug("Result: is a file")
        send_client_msg(client_socket, "STOREFILE")
        try:
            with open(filename, 'rb') as file:
                while chunk := file.read(BUF_SIZE_LARGE):
                    client_socket.sendall(chunk)
                logger.info("File %s sent successfully", filename)
        except IOError as e:
            logger.error("Error reading file %s: %s", filename, e)
            return
    elif os.path.isdir(filename):
        logger.debug("Result: is a directory")
        send_client_msg(client_socket, "STOREDIRE")
        with zipfile.ZipFile(filename + '.zip', 'w') as temp_zip:
            for root, dirs, files in os.walk(filename):
                for file in files:                              # add every file to zip archive
                    filepath = os.path.join(root, file)

                    # use relative path for arcname to maintain correct directory structure
                    arcname = os.path.relpath(filepath,
                                              start=os.path.join(
                                                  os.path.join(target_dir, filename)))
                    temp_zip.write(filepath, arcname=arcname)
                for dire in dirs:                               # add every dir to zip archive
                    dirpath = os.path.join(root, dire)

                    # use relative path for arcname maintain correct directory structure
                    arcname = os.path.relpath(dirpath,
                                              start=os.path.join(
                                                  os.path.join(target_dir, filename)))
                    temp_zip.write(dirpath, arcname=arcname)
        with open(filename + '.zip', 'rb') as zip_file:
            while chunk := zip_file.read(BUF_SIZE_LARGE):
                client_socket.sendall(chunk)
            logger.info("The %s directory was zipped and sent successfully", filename)
        os.remove(filename + '.zip')
    else:                                                       # case of invalid file name
        logger.error("The file or directory you requested to store does not exist. Exiting.")

def request_handler(client_socket, target_dir):
    """
    Handles main workflow of REQUEST command: 
    1. wait for server options 
    2. prompt user to choose 
    3. send choice to server 
    4. receive requested file from server 

    Args:
        client_socket: the socket holding the connection with the server. 
        filename: name of file to store. 
        target_dir: directory to grab file/dir from 
    """

    wait_for_server_resp(client_socket, "READY")                # check that server is ready
    try:
        logger.debug("Waiting for server search results...")
        wait_for_server_resp(client_socket, "OPTIONS")          # wait for server to return options
        logger.debug("Results received.")
        json_list = client_socket.recv(BUF_SIZE_LARGE).decode('utf-8')
        options = json.loads(json_list)                         # decode options into local array
        if len(options) > 0:
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
                        logger.debug("Client chose option #%s", user_input)
                        break
                    send_prompt("Invalid choice, try again\n", "prompt")
                except ValueError:                              # case of non-int input
                    send_prompt("Please choose one of the numbers above.", "print")

            server_msg = user_input                             # send choice # as server message
            client_socket.sendall(server_msg.encode())          # send server message
            if int(user_input) > len(options):                  # chose N/A option
                logger.debug("Client chose N/A option")
                send_prompt("Sorry we couldn't find your file :(", "print")
            else:

                # handle file request response
                logger.debug("Checking if result is a file or directory...")

                # use '/' character appended by server to distinguish between files and dirs.
                # If there is a '/', it is a dir.
                if not options[int(user_input)-1][-1] == '/':
                    logger.debug("Is a file")
                    new_filepath = os.path.join(target_dir,
                                                os.path.basename(options[int(user_input)-1]))

                    # check for potential overwrite. If so, add (1), (2), etc. to indicate new copy.
                    if os.path.exists(new_filepath):
                        for i in range(1, FILE_COPY_LIMIT):

                            # disguisting parsing logic
                            file_name, ext = os.path.splitext(os.path.basename(new_filepath))
                            same_filepath = f"{file_name} ({i}){ext}"
                            if os.path.exists(os.path.join(target_dir, same_filepath)):
                                continue
                            new_filepath = os.path.join(target_dir, same_filepath)
                            break
                    try:
                        with open(new_filepath, 'wb') as file:  # receive requested file data
                            while True:
                                data = client_socket.recv(BUF_SIZE_SMALL)
                                if not data:
                                    break
                                file.write(data)
                            logger.info("File received successfully")
                    except IOError as e:
                        logger.error("Error reading file %s: %s", new_filepath, e)
                        return

                # handle directory request response

                else:
                    logger.debug("Is a directory")
                    extraction_dir = os.path.join(target_dir,
                                                  os.path.basename(options[int(user_input)-1][:-1]))
                    tempfilename = extraction_dir + '_temp.zip'

                    # check for potential overwrite. If so, add (1), (2), ... to indicate copy number.
                    if os.path.exists(extraction_dir):
                        for i in range(1, FILE_COPY_LIMIT):
                            if os.path.exists(extraction_dir + f' ({i})'):
                                continue
                            extraction_dir += f' ({i})'
                            break
                    os.makedirs(extraction_dir, exist_ok=True)

                    # receive zip file binary. This opens a temp zip file.
                    with open(tempfilename, 'wb') as temp_zip:
                        while True:
                            zip_data = client_socket.recv(BUF_SIZE_LARGE)
                            if not zip_data:
                                break
                            temp_zip.write(zip_data)

                        # weird solution to 'not a zip file' error
                        temp_zip.flush()
                        os.fsync(temp_zip.fileno())
                        # use zipfile API to unzip requested directory
                        with zipfile.ZipFile(tempfilename, 'r') as zip_file:
                            zip_file.extractall(path=extraction_dir)
                            logger.info("Directory unzipped successfully")
                    os.remove(tempfilename)                     # remove temp zip file.
        else:
            logger.error("File not found in server. Exiting.")
    except json.decoder.JSONDecodeError:
        logger.error("No matching results in server. Exiting.")

# helper functions

def wait_for_server_resp(client_socket, resp):
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
            logger.debug("Received message from server: %s", resp)
            break

def send_client_msg(client_socket, msg):
    """
    Sends a message to the server and logs it.

    Args:
        client_socket: the socket holding the connection with the server. 
        msg: desired message to server 
    """
    logger.debug("%s -> server: %s", login_name, msg)
    client_socket.sendall(command_table[msg].encode())

def send_prompt(message, prompt_type):
    """
    Sends a prompt (either input() or print()) to local server)

    Args:
        message: message to send
        type: print or input
    """

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((local_ip, port2))

        match prompt_type:
            case "prompt":
                msg = 'USRINPUT' + message + 'END'
                sock.sendall(msg.encode('utf-8'))

                # wait for prompt response
                return sock.recv(BUF_SIZE_SMALL).decode('utf-8')
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
