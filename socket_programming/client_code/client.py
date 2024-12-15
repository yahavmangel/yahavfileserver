"""
The class implementation for a client for the YFS server. 
Uses various utilities, config variables, and constants from the client_utils.py file. 

Functions: 
    Main flow: 
        start()
        server_request()
        store_handler(client_socket)
        request_handler(client_socket)
    Helper functions: 
        handle_overwrite(client_socket)
        receive_file(selected_option, client_socket)
        receive_dir(selected_option, client_socket)
        send_file(client_socket)
        send_dir(client_socket)
        send_prompt(message, prompt_type)
        launch_request(command, filename)
"""

import socket
import sys
import json
import os
import zipfile
import logging
import threading
import queue
from loghandler import JSONSocketHandler
from clientgui import ClientGUI
from client_utils import *

class YFSClient: 
    """
    The class implementation for a client for the YFS server. 
    """
    def __init__(self, mode, args): 

        # logging setup 
        self.logger = logging.getLogger(LOGIN_NAME)
        self.logger.setLevel(getattr(logging, LOG_LEVEL))
        self.json_handler = JSONSocketHandler(LOCAL_IP, PORT2)      # instantiate and attach custom handler
        self.json_handler.setLevel(getattr(logging, LOG_LEVEL))
        self.json_handler.setFormatter(logging.Formatter('(%(name)s) %(levelname)s: %(message)s'))
        self.logger.addHandler(self.json_handler)

        # initialize metadata 
        self.command = args.command if args.command else None
        self.filename = args.filename if args.filename else None
        self.params = args.params if args.params else []
        self.prompt_queue = queue.Queue()                           # make queue for user prompts
        self.resp_queue = queue.Queue()                             # make queue for user responses
        self.cur_params_idx = 0                                     # index of pre-passed params currently expecting
        self.mode = mode

    def start(self):
        """
        Launches either GUI or request based on mode.
        """
        match self.mode: 
            case 2:                                                 # user mode only: launch user GUI
                gui = ClientGUI(SERVER_IP, self.launch_request, self.prompt_queue, self.resp_queue)
                gui.mainloop()
            case _:                                                 # all other modes: just launch a request
                self.server_request()

    def server_request(self):
        """
        Launches a server request. All necessary metadata for the request is initialized in the constructor. 
        """

        client_socket = None                                        # to avoid error
        try:
            # input validation
            if self.command not in ['STORE', 'REQUEST']:
                self.logger.error("Invalid command: %s", self.command)
                return

            # connection setup
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            try:
                client_socket.settimeout(10)
                client_socket.connect((SERVER_IP, PORT))
                self.logger.info("Connected to server: %s", SERVER_IP)

                # send client username, command, and file name to server for processing
                server_msg = f"{os.getlogin()}|{self.command}|{self.filename}"
                client_socket.sendall(server_msg.encode())          # send server message

                # handle client command
                if self.command == 'STORE':
                    while True:                                     # wait for server auth response
                        server_resp = client_socket.recv(AUTH_RESP_LEN).decode('utf-8')
                        if server_resp[:-1] == 'AUTH':
                            break
                    if server_resp == 'AUTHS':                      # auth success: handle request
                        self.logger.debug("Received authorization from server")
                        status = self.handle_overwrite(client_socket)
                        if not status:
                            return                                  # overwrite check passed
                        self.store_handler(client_socket)
                    elif server_resp == 'AUTHF':                    # auth fail: reject request
                        self.logger.error("Permission denied. Exiting.")
                        return

                elif self.command == 'REQUEST':
                    while True:                                     # wait for server auth response
                        server_resp = client_socket.recv(AUTH_RESP_LEN).decode('utf-8')
                        if 'AUTH' in server_resp:
                            break
                    if server_resp == 'AUTHS':                      # auth success: handle request
                        self.logger.debug("Received authorization from server")
                        self.request_handler(client_socket)
                    elif server_resp == 'AUTHF':                    # auth fail: rejct request
                        self.logger.error("Permission denied. Exiting.")
                        return

            # error handling
            except socket.gaierror:
                self.logger.critical("Invalid server IP. Exiting.")
            except ConnectionError:
                self.logger.critical("Connection Error. Exiting.")
            except TimeoutError:
                self.logger.critical("Connection timed out. Server unreachable.")

        finally:
            if client_socket: 
                client_socket.close()

    def store_handler(self, client_socket):
        """
        Handles main workflow of STORE command: sends file/directory to server.

        Args:
            client_socket: the socket holding the connection with the server.
        """

        self.logger.debug("Checking if %s is a file or a directory...", self.filename)
        if os.path.isfile(self.filename):
            self.logger.debug("Result: is a file")
            if not self.send_file(client_socket):
                return
        elif os.path.isdir(self.filename):
            self.logger.debug("Result: is a directory")
            if not self.send_dir(client_socket):
                return
        else:                                                       # case of invalid file name
            self.logger.error("The file or directory you requested to store does not exist. Exiting.")

    def request_handler(self, client_socket):
        """
        Handles main workflow of REQUEST command: 
        1. wait for server options 
        2. prompt user to choose b/w options
        3. send user choice to server 
        4. receive requested choice from server 

        Args:
            client_socket: the socket holding the connection with the server. 
        """

        # check that server is ready
        wait_for_server_resp(client_socket, "READY", self.logger)               
        try:
            # wait for server to return options
            self.logger.debug("Waiting for server search results...")
            wait_for_server_resp(client_socket, "OPTIONS", self.logger)
            self.logger.debug("Results received.")

            # receive and decode options 
            json_list = client_socket.recv(BUF_SIZE_LARGE).decode('utf-8')      
            options = json.loads(json_list)

            # check if any results were found
            if len(options) > 0:
                user_input = self.prompt_for_choice(options)        # prompt user to choose b/w options
                client_socket.sendall(user_input.encode())          # send user choice back to server

                if int(user_input) > len(options) or int(user_input) == 10:
                    self.logger.debug("Client chose N/A option")    # user chose N/A
                    self.send_prompt("Sorry we couldn't find your file :(", "print")
                else:                                               # user chose an actual choice 
                    # handle file request response
                    self.logger.debug("Checking if result is a file or directory...")
                    selected_option = options[int(user_input) - 1]

                    # use '/' character appended by server to distinguish between files and dirs.
                    # If there is a '/', it is a dir. If there isn't, it's a file. 
                    if not selected_option.endswith('/') == '/':
                        self.logger.debug("Is a file")
                        self.receive_file(selected_option, client_socket)
                    else:
                        self.logger.debug("Is a directory")
                        self.receive_dir(selected_option, client_socket)
            else:
                self.logger.error("File not found in server. Exiting.")
        except json.decoder.JSONDecodeError:
            self.logger.error("No matching results in server. Exiting.")

    ############ helper functions ############

    def handle_overwrite(self, client_socket):
        """
        Handles the case of overwrite (occurs when a STORE would overwrite a preexisting file on server) 
        by asking client whether they want to proceed or not.

        Args:
            client_socket: the socket holding the connection with the server. 
        
        Returns: 
            Bool: outcome of client decision (True = Acknowledge overwrite, False = Quit)
        """

        while True:
            # collect initial response from server
            server_resp = client_socket.recv(BUF_SIZE_SMALL).decode('utf-8')
            if server_resp in ['OVERWRITE', 'READY']:
                break

        # handle file overwriting case
        if server_resp == 'OVERWRITE':                                  # detect overwriting
            while True:                                                 # prompt user on action
                user_input = self.send_prompt("File already exists. Overwrite? [y/n] ", "prompt")
                if user_input in ['n', 'y']:
                    self.send_prompt("Success!", "print")
                    break
                self.send_prompt("Invalid input, try again\n", "print")
            if user_input == 'n':
                self.logger.info("Request canceled.")
                send_client_msg(client_socket, "QUIT", self.logger)     # notify server that you quit
                return False
            if user_input == 'y':                                       # notify server that you acknowledge
                self.logger.info("Acknowledged overwrite")
                send_client_msg(client_socket, "ACK", self.logger)
                wait_for_server_resp(client_socket, "READY", self.logger)
        return True

    def prompt_for_choice(self, options):
        """
        Helper function that prompts the user to choose between the received options from a REQUEST command.
        The user should return a number between 1 and 10, as only a max of 10 options are received.

        Args: 
            options: list of options returned from server 
        """

        # print out options
        self.send_prompt("Server returned multiple results: \n", "print")   
        max_idx = len(options) if len(options) < 10 else 9
        for i, option in enumerate(options[:max_idx], 1):
            self.send_prompt(f"{i}: {option}", "print")
        self.send_prompt(f"{max_idx + 1}: N/A \n", "print")

        self.logger.debug("Waiting for client choice...")
        while True:
            user_input = self.send_prompt("Which one? ", "prompt")
            try:
                # check if choice # is between valid bounds
                if(int(user_input) > 0 and int(user_input) < len(options) + 2 and int(user_input) < 11):
                    self.logger.debug("Client chose option #%s", user_input)
                    self.send_prompt("Success!", "print")
                    return user_input
                self.send_prompt("Invalid choice, try again\n", "prompt")
            except ValueError:                                                  # case of non-int input
                self.send_prompt("Please choose one of the numbers above.", "print")

    def receive_file(self, selected_option, client_socket):
        """
        Helper function to handle receiving a file during a REQUEST command.
        This function also implements a "copy" mechanism to prevent overwrite.
        
        Args:  
            selected_option: the filename of the user selected option
            client_socket: socket that holds connection to the server
        """
        new_filepath = os.path.join(TARGET_DIR, os.path.basename(selected_option))

        # check for potential overwrite. If so, add (1), (2), etc. to indicate new copy.
        if os.path.exists(new_filepath):
            for i in range(1, FILE_COPY_LIMIT):
                # disguisting parsing logic to make copies
                file_name, ext = os.path.splitext(os.path.basename(new_filepath))
                same_filepath = f"{file_name} ({i}){ext}"
                if os.path.exists(os.path.join(TARGET_DIR, same_filepath)):
                    continue
                new_filepath = os.path.join(TARGET_DIR, same_filepath)
                break
        try:
            with open(new_filepath, 'wb') as file:                              # receive requested file data
                while True:
                    data = client_socket.recv(BUF_SIZE_SMALL)
                    if not data:
                        break
                    file.write(data)
                self.logger.info("File received successfully")
        except IOError as e:
            self.logger.error("Error reading file %s: %s", new_filepath, e)
    
    def receive_dir(self, selected_option, client_socket):
        """
        Helper function to handle receiving a directory during a REQUEST command. 
        This function also implements a "copy" mechanism to prevent overwrite.
        Uses zipfile library: upnzips received zipfile from server. 

        Args:  
            selected_option: the filename of the user selected option
            client_socket: socket that holds connection to the server
        """
        extraction_dir = os.path.join(TARGET_DIR, os.path.basename(selected_option.rstrip('/')))
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
        os.remove(tempfilename)                                                 # remove temp zip file.
        
    def send_file(self, client_socket):
        """
        Helper function to send a file during a STORE command.
        Simply sends binary over socket.

        Args: 
            client_socket: socket that holds connection to the server
        """
        self.logger.debug("Sending file %s...", self.filename)
        send_client_msg(client_socket, "STOREFILE", self.logger)
        try:
            with open(self.filename, 'rb') as file:
                while chunk := file.read(BUF_SIZE_LARGE):
                    client_socket.sendall(chunk)
                self.logger.info("File %s sent successfully", self.filename)
        except IOError as e:
            self.logger.error("Error reading file %s: %s", self.filename, e)
            return False
        return True

    def send_dir(self, client_socket):
        """
        Helper function to send a directory during a STORE command.
        Zips directory into a zipfile, then sends zipfile binary over socket. 

        Args: 
            client_socket: socket that holds connection to the server
        """
        self.logger.debug("Sending directory %s...", self.filename)
        send_client_msg(client_socket, "STOREDIRE", self.logger)
        with zipfile.ZipFile(self.filename + '.zip', 'w') as temp_zip:
            for root, dirs, files in os.walk(self.filename):
                for file in files:                                  # add every file to zip archive
                    filepath = os.path.join(root, file)
                    arcname = os.path.relpath(filepath, start=os.path.join(os.path.join(TARGET_DIR, self.filename)))
                    temp_zip.write(filepath, arcname=arcname)
                for dire in dirs:                                   # add every dir to zip archive
                    dirpath = os.path.join(root, dire)
                    arcname = os.path.relpath(dirpath, start=os.path.join(os.path.join(TARGET_DIR, self.filename)))
                    temp_zip.write(dirpath, arcname=arcname)
        with open(self.filename + '.zip', 'rb') as zip_file:
            while chunk := zip_file.read(BUF_SIZE_LARGE):
                client_socket.sendall(chunk)
            self.logger.info("The %s directory was zipped and sent successfully", self.filename)
        os.remove(self.filename + '.zip')
        return True

    def send_prompt(self, message, prompt_type):
        """
        Sends a prompt (either input() or print()) to local server).
        The way of sending depends on the mode that the script was launched with: 
        - User mode: direct all prompts to the user GUI
        - Developer mode: send all prompts (over socket) to the localserver and await response from there
        - Test mode: pass pre-passed prompt responses to code

        Args:
            message: message to send
            prompt_type: print or input
        """
        match self.mode: 
            case 2:                                                 # user mode 
                self.prompt_queue.put((message, prompt_type))
                if prompt_type == "prompt":
                    while self.resp_queue.empty():                  # wait for user resp
                        pass
                    while not self.resp_queue.empty():
                        return self.resp_queue.get()

            case 1:                                                 # test mode
                match prompt_type: 
                    case "prompt":
                        self.cur_params_idx += 1                    # consume param
                        return self.params[self.cur_params_idx - 1] # use previous index     
                    case "print":
                        pass                                        # in test mode, we don't care about prints

            case 0:                                                 # dev mode
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.connect((LOCAL_IP, PORT2))                 # send to localserver over socket
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
                except ConnectionError:
                    self.logger.critical("localserver unreachable. Exiting.")
                    sys.exit(1)

    def launch_request(self, command, filename):
        """
        Helper function that launches a server_request on the fly. Only used in user mode.
        Passed into and launched by the user GUI.

        Args: 
            Command: command for server request (STORE/REQUEST).
            Filename: the name of the file to either store or search for. 
        """
        self.command = command
        self.filename = filename
        req_thread = threading.Thread(target=self.server_request)
        req_thread.start()

if __name__ == "__main__":
    mode, args = parse_client_args()                                
    client = YFSClient(mode, args)
    client.start()
