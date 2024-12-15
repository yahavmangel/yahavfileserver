"""
This file contains various constants, magic numbers, and utilities used by the client script.
"""

import sys
import configparser
import os
import argparse

# constants

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))         # make script execution dynamic
LOGIN_NAME = os.getlogin()                                      # change to local if using localserver as client

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

# load config file 

try:                                                            # collect config file info
    config = configparser.ConfigParser()
    config.read(os.path.join(SCRIPT_DIR, 'config.ini'))

    SERVER_IP = config['client']['server_ip']                   # ip of fileserver
    LOCAL_IP = config['client']['local_ip']                     # ip of localserver
    PORT = int(config['client']['port'])                        # port for connection w/ fileserver
    PORT2 = int(config['client']['port2'])                      # port for connection w/ localserver
    TARGET_DIR = os.path.join(SCRIPT_DIR,
                              config['client']['target_dir'])   # target dir of operations
    LOG_LEVEL = config['client']['log_level']
except KeyError:                                                # case of misconfigured config file
    print("Error: Missing or misconfigured config file")
    sys.exit(1)

def wait_for_server_resp(client_socket, resp, logger):
    """
    Polls for a server response, and breaks once it is received. Logs the received message.

    Args:
        client_socket: the socket holding the connection with the server.
        resp: desired response from server
        logger: logger to log messages to
    """
    resp_len = len(resp)
    while True:
        server_resp = client_socket.recv(resp_len).decode('utf-8')
        if resp in server_resp and resp in command_table.values():
            logger.debug("Received message from server: %s", resp)
            break

def send_client_msg(client_socket, msg, logger):
    """
    Sends a message to the server and logs it.

    Args:
        client_socket: the socket holding the connection with the server. 
        msg: desired message to server 
        logger: logger to log messages to
    """
            
    logger.debug("%s -> server: %s", LOGIN_NAME, msg)
    client_socket.sendall(command_table[msg].encode())

def parse_client_args():
    """
    Parses the CLI call of the client script into the 3 distinct modes.
    Uses argparse library. 
    """

    mode = None

    # parser setup 
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)

    # define the mode flags
    group.add_argument('-u', '--user', action='store_const', const = 'user',
                        help='Run in user mode: launches user GUI and executes client requests on the fly.')
    group.add_argument('-d', '--dev', action='store_const', const = 'dev',
                        help='Run in dev mode: instantly executes a single client request, and waits for prompt responses from the developer.')
    group.add_argument('-t', '--test', action='store_const', const = 'test',
                        help='Run in test mode: instantly executes a single client with preloaded responses to prompts.')
    
    # define positional arguments
    parser.add_argument('command', nargs='?', help="Command to execute (dev/test modes).")
    parser.add_argument('filename', nargs='?', help="Filename to operate on (dev/test modes).")
    parser.add_argument('params', nargs='*', help="Pre-passed parameters (test mode).")
    
    # parse and validate
    args = parser.parse_args()
    
    if args.dev:
        mode = 0
        if not args.command or not args.filename:
            parser.error("Dev mode requires 'command' and 'filename'.")
        if args.params:
            parser.error("Dev mode does not allow additional parameters.")
    
    elif args.test:
        mode = 1
        if not args.command or not args.filename:
            parser.error("Test mode requires 'command' and 'filename'.")
        if not args.params:
            parser.error("Test mode requires at least one pre-passed parameter.")
    
    elif args.user:
        mode = 2
        if args.command or args.filename or args.params:
            parser.error("No arguments are allowed in user mode.")

    return (mode, args) 
