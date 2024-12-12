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
import logging
import threading
import queue
import argparse
from loghandler import JSONSocketHandler
from clientgui import clientGUI
from client_utils import *

class YFSClient: 

    def __init__(self, mode, args): 

        # logging setup 
        self.logger = logging.getLogger(LOGIN_NAME)
        self.logger.setLevel(getattr(logging, LOG_LEVEL))
        self.json_handler = JSONSocketHandler(LOCAL_IP, PORT2)              # instantiate and attach custom handler
        self.json_handler.setLevel(getattr(logging, LOG_LEVEL))
        self.json_handler.setFormatter(logging.Formatter('(%(name)s) %(levelname)s: %(message)s'))
        self.logger.addHandler(self.json_handler)

        # initialize metadata 
        self.command = args.command if args.command else None
        self.filename = args.filename if args.filename else None
        self.params = args.params if args.params else []
        self.prompt_queue = queue.Queue()                                   # make queue for user prompts
        self.resp_queue = queue.Queue()                                     # make queue for user responses
        self.cur_params_idx = 0                                             # index of pre-passed params currently expecting
        self.mode = mode

    def start(self):
        match self.mode: 
            case 2:
                gui = clientGUI(SERVER_IP, self.launch_request, self.prompt_queue, self.resp_queue)
                gui.mainloop()
            case _:
                self.server_request()

    def server_request(self):
        """
        Launches the server request.

        Args:
            command: client requested command (STORE, REQUEST, etc.)
            filename: the file name or similar key word that the operation is executed on
        """

        try:

            # input validation

            if self.command not in ['STORE', 'REQUEST']:
                self.logger.error("Invalid command: %s", self.command)
                return

            # connection setup

            try:
                client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                try:
                    client_socket.settimeout(10)
                    client_socket.connect((SERVER_IP, PORT))
                except socket.timeout:
                    self.logger.critical("Connection timed out. Server unreachable.")
                    return
                self.logger.info("Connected to server: %s", SERVER_IP)

                # send client username, command, and file name to server for processing
                server_msg = f"{os.getlogin()}|{self.command}|{self.filename}"
                client_socket.sendall(server_msg.encode())           # send server message
            except socket.gaierror:
                self.logger.critical("Invalid server IP. Exiting.")       # invalid format case
                return

            # handle client command

            if self.command == 'STORE':

                while True:                                         # wait for server auth response
                    server_resp = client_socket.recv(AUTH_RESP_LEN).decode('utf-8')
                    if server_resp[:-1] == 'AUTH':
                        break
                if server_resp == 'AUTHS':                          # auth success: handle request
                    self.logger.debug("Received authorization from server")
                    status = self.handle_overwrite(client_socket)
                    if not status:
                        return                                      # overwrite check passed
                    self.store_handler(client_socket)
                elif server_resp == 'AUTHF':                        # auth fail: reject request
                    self.logger.error("Permission denied. Exiting.")
                    return

            elif self.command == 'REQUEST':

                while True:
                    # wait for server authentication response
                    server_resp = client_socket.recv(AUTH_RESP_LEN).decode('utf-8')
                    if 'AUTH' in server_resp:
                        break
                if server_resp == 'AUTHS':                          # auth success: handle request
                    self.logger.debug("Received authorization from server")
                    self.request_handler(client_socket)
                elif server_resp == 'AUTHF':                        # auth fail: rejct request
                    self.logger.error("Permission denied. Exiting.")
                    return

        except ConnectionError:
            self.logger.critical("Connection Error. Exiting.")
        except TimeoutError:
            self.logger.critical("Connection timed out. Server unreachable.")
        finally:
            client_socket.close()

    def handle_overwrite(self, client_socket):
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
                user_input = send_prompt("File already exists. Overwrite? [y/n] ", "prompt", self.mode, self.prompt_queue, self.resp_queue, self.logger)
                if user_input in ['n', 'y']:
                    send_prompt("Success!", "print", self.mode, self.prompt_queue, self.resp_queue, self.logger)
                    break
                send_prompt("Invalid input, try again\n", "print", self.mode, self.prompt_queue, self.resp_queue, self.logger)
            if user_input == 'n':
                self.logger.info("Request canceled.")
                send_client_msg(client_socket, "QUIT", self.logger)              # notify server that you quit
                return False
            if user_input == 'y':
                # notify server that you acknowledge overwrite and
                # check that server is ready AFTER overwrite
                self.logger.info("Acknowledged overwrite")
                send_client_msg(client_socket, "ACK", self.logger)
                wait_for_server_resp(client_socket, "READY", self.logger)
                return True
        return True

    def store_handler(self, client_socket):
        """
        Handles main workflow of STORE command: sends file/directory to server.

        Args:
            client_socket: the socket holding the connection with the server.
            filename: name of file to store.
            target_dir: directory to grab file/dir from
        """

        self.logger.debug("Checking if %s is a file or a directory...", self.filename)
        if os.path.isfile(self.filename):
            self.logger.debug("Result: is a file")
            send_client_msg(client_socket, "STOREFILE", self.logger)
            try:
                with open(self.filename, 'rb') as file:
                    while chunk := file.read(BUF_SIZE_LARGE):
                        client_socket.sendall(chunk)
                    self.logger.info("File %s sent successfully", self.filename)
            except IOError as e:
                self.logger.error("Error reading file %s: %s", self.filename, e)
                return
        elif os.path.isdir(self.filename):
            self.logger.debug("Result: is a directory")
            send_client_msg(client_socket, "STOREDIRE", self.logger)
            with zipfile.ZipFile(self.filename + '.zip', 'w') as temp_zip:
                for root, dirs, files in os.walk(self.filename):
                    for file in files:                              # add every file to zip archive
                        filepath = os.path.join(root, file)

                        # use relative path for arcname to maintain correct directory structure
                        arcname = os.path.relpath(filepath,
                                                start=os.path.join(
                                                    os.path.join(TARGET_DIR, self.filename)))
                        temp_zip.write(filepath, arcname=arcname)
                    for dire in dirs:                               # add every dir to zip archive
                        dirpath = os.path.join(root, dire)

                        # use relative path for arcname maintain correct directory structure
                        arcname = os.path.relpath(dirpath,
                                                start=os.path.join(
                                                    os.path.join(TARGET_DIR, self.filename)))
                        temp_zip.write(dirpath, arcname=arcname)
            with open(self.filename + '.zip', 'rb') as zip_file:
                while chunk := zip_file.read(BUF_SIZE_LARGE):
                    client_socket.sendall(chunk)
                self.logger.info("The %s directory was zipped and sent successfully", self.filename)
            os.remove(self.filename + '.zip')
        else:                                                       # case of invalid file name
            self.logger.error("The file or directory you requested to store does not exist. Exiting.")

    def request_handler(self, client_socket):
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

        wait_for_server_resp(client_socket, "READY", self.logger)                # check that server is ready
        try:
            self.logger.debug("Waiting for server search results...")
            wait_for_server_resp(client_socket, "OPTIONS", self.logger)          # wait for server to return options
            self.logger.debug("Results received.")
            json_list = client_socket.recv(BUF_SIZE_LARGE).decode('utf-8')
            options = json.loads(json_list)                         # decode options into local array
            if len(options) > 0:
                send_prompt("Server returned multiple results: \n", "print", self.mode, self.prompt_queue, self.resp_queue, self.logger)
                i = 0
                for option in options:
                    i += 1
                    send_prompt(str(i) + ': ' + option, "print", self.mode, self.prompt_queue, self.resp_queue, self.logger)
                    if i == 9:                                      # stop at 10 options 
                        break
                send_prompt(str(i + 1) + ": N/A \n", "print", self.mode, self.prompt_queue, self.resp_queue, self.logger)
                self.logger.debug("Waiting for client choice...")
                while True:
                    user_input = send_prompt("Which one? ", "prompt", self.mode, self.prompt_queue, self.resp_queue, self.logger)
                    try:
                        if(int(user_input) > 0 and int(user_input) < len(options) + 2 and int(user_input) < 11):
                            self.logger.debug("Client chose option #%s", user_input)
                            send_prompt("Success!", "print", self.mode, self.prompt_queue, self.resp_queue, self.logger)
                            break
                        send_prompt("Invalid choice, try again\n", "prompt", self.mode, self.prompt_queue, self.resp_queue, self.logger)
                    except ValueError:                              # case of non-int input
                        send_prompt("Please choose one of the numbers above.", "print", self.mode, self.prompt_queue, self.resp_queue, self.logger)

                server_msg = user_input                             # send choice # as server message
                client_socket.sendall(server_msg.encode())          # send server message
                if int(user_input) > len(options) or int(user_input) == 10:                  # chose N/A option
                    self.logger.debug("Client chose N/A option")
                    send_prompt("Sorry we couldn't find your file :(", "print", self.mode, self.prompt_queue, self.resp_queue, self.logger)
                else:

                    # handle file request response
                    self.logger.debug("Checking if result is a file or directory...")

                    # use '/' character appended by server to distinguish between files and dirs.
                    # If there is a '/', it is a dir.
                    if not options[int(user_input)-1][-1] == '/':
                        self.logger.debug("Is a file")
                        new_filepath = os.path.join(TARGET_DIR,
                                                    os.path.basename(options[int(user_input)-1]))

                        # check for potential overwrite. If so, add (1), (2), etc. to indicate new copy.
                        if os.path.exists(new_filepath):
                            for i in range(1, FILE_COPY_LIMIT):

                                # disguisting parsing logic
                                file_name, ext = os.path.splitext(os.path.basename(new_filepath))
                                same_filepath = f"{file_name} ({i}){ext}"
                                if os.path.exists(os.path.join(TARGET_DIR, same_filepath)):
                                    continue
                                new_filepath = os.path.join(TARGET_DIR, same_filepath)
                                break
                        try:
                            with open(new_filepath, 'wb') as file:  # receive requested file data
                                while True:
                                    data = client_socket.recv(BUF_SIZE_SMALL)
                                    if not data:
                                        break
                                    file.write(data)
                                self.logger.info("File received successfully")
                        except IOError as e:
                            self.logger.error("Error reading file %s: %s", new_filepath, e)
                            return

                    # handle directory request response

                    else:
                        self.logger.debug("Is a directory")
                        extraction_dir = os.path.join(TARGET_DIR,
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
                                self.logger.info("Directory unzipped successfully")
                        os.remove(tempfilename)                     # remove temp zip file.
            else:
                self.logger.error("File not found in server. Exiting.")
        except json.decoder.JSONDecodeError:
            self.logger.error("No matching results in server. Exiting.")

    def launch_request(self, command, filename):
        self.command = command
        self.filename = filename
        req_thread = threading.Thread(target=self.server_request)
        req_thread.start()

if __name__ == "__main__":
    mode, args = parse_client_args()
    client = YFSClient(mode, args)
    client.start()
