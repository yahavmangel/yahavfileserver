"""
Run Authentication service: 
- use win32security API to parse incoming clients' security descriptor
- Authenticate against desired permission at the granular permission level.
See reposity README for more information. 

Functions: 
    auth_code(conn)
"""
import socket
import configparser
import threading
import json
import logging
import os
import sys
from loghandler import JSONSocketHandler
import win32security

# logging and metadata

script_dir = os.path.dirname(os.path.abspath(__file__))         # make script execution dynamic

logger = logging.getLogger("DC")
logger.setLevel(logging.DEBUG)

try:
    config = configparser.ConfigParser()
    config.read(os.path.join(script_dir, 'config.ini'))
    port = int(config['dc']['port'])                            # port for connection w/ fileserver
    port2 = int(config['dc']['port2'])                          # port for connection w/ localserver
    local_ip = config['dc']['local_ip']                         # ip of localserver
except KeyError:                                                # case of misconfigured config file
    logger.critical("Missing or misconfigured config file", extra={'conn_counter': "N/A"})
    sys.exit(1)

json_handler = JSONSocketHandler(local_ip, port2)
json_handler.setLevel(logging.DEBUG)
json_handler.setFormatter(logging.Formatter(
    '(%(name)s, ID: %(conn_counter)s) %(levelname)s: %(message)s'))
logger.addHandler(json_handler)

# magic numbers

# permission bitmasks (from windows security manual)
GENERIC_FILE_READ = 0x120089
GENERIC_FILE_WRITE = 0x120116

# main code

def auth_code(conn):
    """
    Main authentication code: 
    1. receives nTSecurityDescriptor + list of SIDs to authenticate from server 
    2. parses SecDesc into individual ACEs/permissions 
    3. authenticates against the requested permission.
    Note that this code must be run on a Windows machine because it uses the win32security api.
    (in my original implementation, I ran it on a Windows Server 2022 Domain Controller)
    
    Args:
        conn: connection of current thread
    
    Returns (to server via socket): 
        Bool: authentication decision (True = Authorized, False = not authorized)
    """

    # receive server authentication request

    delimiter = b'\x1f'                                         # Will not appear in any binary data
    received = b''
    while True:
        data = conn.recv(4096)
        if not data:
            break
        received += data

    # parse server request message

    bin_sd, target_permission_bin, sid_list_bin, conn_counter = received.split(delimiter)
    target_permission = target_permission_bin.decode('utf-8')
    sid_list = json.loads(sid_list_bin.decode('utf-8'))
    conn_counter = conn_counter.decode('utf-8')

    # main authentication logic

    # Fetch DACL out of nTSecurityDescriptor,
    # Iterate through the ACEs within the DACL,
    # then check perms of each ACE that has
    # an SID in the client's sid_list.
    sec_desc = win32security.SECURITY_DESCRIPTOR(bin_sd)
    dacl = sec_desc.GetSecurityDescriptorDacl()
    perm_flag = 0
    for i in range(dacl.GetAceCount()):
        ace = dacl.GetAce(i)
        ace_sid = ace[2]                                        # grab SID of current ACE
        try:
            sid_name, _, _ = win32security.LookupAccountSid(None, ace_sid)
        except TypeError:                                       # this filters out non-SID objects
            continue
        string_sid = win32security.ConvertSidToStringSid(ace_sid)
        if string_sid in sid_list:                              # only check for relevant SIDs
            permissions = ace[1]                                # grab access mask of current ACE
            logger.info("%s has permissions %s. Has read access: %s, has write access: %s.",
                         sid_name, hex(permissions), bool((permissions & GENERIC_FILE_READ)),
                         bool((permissions & GENERIC_FILE_WRITE)),
                         extra={'conn_counter': conn_counter})
            match target_permission:                            # bitwise AND the perm and bit mask
                case 'read':
                    perm_flag = int(bool(permissions & GENERIC_FILE_READ))
                    if not perm_flag:                           # if one of the groups deny
                        break                                   # access, deny access altogether
                case 'write':
                    perm_flag = int(bool(permissions & GENERIC_FILE_WRITE))
                    if not perm_flag:                           # if one of the groups deny
                        break                                   # access, deny access altogether

    logger.info("Authentication concluded. Result: %s",
                perm_flag, extra={'conn_counter': conn_counter})

    # send authentication result and close server connection

    conn.sendall(b'AUTHS')                                      # tell server auth is complete
    conn.sendall(str(perm_flag).encode('utf-8'))                # send auth decision to server
    conn.shutdown(socket.SHUT_WR)                               # force all buffered data to send
    conn.close()

# main loop

if __name__ == "__main__":

    # connection setup

    dc_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    dc_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    dc_socket.bind(('0.0.0.0', port))
    dc_socket.listen(5)

    logger.info("DC is listening...", extra={'conn_counter': "N/A"})

    while True:
        try:
            conn, addr = dc_socket.accept()
            logger.info("Connected by %s", addr, extra={'conn_counter': "N/A"})

            # every time a connection is accepted, make a new thread
            server_thread = threading.Thread(target=auth_code, args=(conn,))
            server_thread.start()
        except KeyboardInterrupt:
            logger.info("Shutting down DC...", extra={'conn_counter': "N/A"})
            dc_socket.close()
            conn.close()
            break
