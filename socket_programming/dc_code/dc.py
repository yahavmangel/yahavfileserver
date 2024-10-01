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

script_dir = os.path.dirname(os.path.abspath(__file__))                             # make script execution dynamic                  

logger = logging.getLogger("DC")
logger.setLevel(logging.DEBUG)

try: 
    config = configparser.ConfigParser()
    config.read(os.path.join(script_dir, 'config.ini'))
    port = int(config['dc']['port'])                                                # port for connection w/ fileserver 
    port2 = int(config['dc']['port2'])                                              # port for connection w/ localserver (for logs)
    local_ip = config['dc']['local_ip']                                             # ip of localserver (for logs)
except KeyError:                                                                    # check for misconfigured config file 
    logger.critical("Missing or misconfigured config file", extra={'conn_counter': "N/A"})
    sys.exit(1)

json_handler = JSONSocketHandler(local_ip, port2)
json_handler.setLevel(logging.DEBUG)
json_handler.setFormatter(logging.Formatter('(%(name)s, ID: %(conn_counter)s) %(levelname)s: %(message)s'))
logger.addHandler(json_handler)

# magic numbers

GENERIC_FILE_READ = 0x120089                                                        # bit mask of generic file read permissions as defined by windows security manual
GENERIC_FILE_WRITE = 0x120116                                                       # bit mask of generic file write permissions as defined by windows security manual

# main code

def auth_code(conn):
    """
    Main authentication code: receives nTSecurityDescriptor + list of SIDs to authenticate from server -> parses SecDesc into individual ACEs/permissions -> authenticates against the requested permission.
    This code must be run on a Windows machine because it uses the win32security api (in my original implementation, I ran it on a Windows Server 2022 Domain Controller)
    
    Args:
        conn: connection of current thread
    
    Returns (to server via socket): 
        Bool: authentication decision (True = Authorized, False = not authorized)
    """

    # receive server authentication request 

    delimiter = b'\x1f'                                                             # separating character of server -> dc message components, will not appear in nTSecurityDescriptor binary data
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
    conn_counter = conn_counter.decode('utf-8')                                     # use for logging 

    # main authentication logic

    dacl = win32security.SECURITY_DESCRIPTOR(bin_sd).GetSecurityDescriptorDacl()    # fetch DACL out of the client's security descriptor 
    perm_flag = 0
    for i in range(dacl.GetAceCount()):                                             # iterate through each ACE in the DACL, checking the permissions of each ACE with the same SID as the target. 
        ace = dacl.GetAce(i)
        ace_sid = ace[2]                                                            # grab SID of current ACE
        try:                                                                        # this filters out non-SID objects 
            sid_name, _, _ = win32security.LookupAccountSid(None, ace_sid)
        except Exception: 
            continue
        if win32security.ConvertSidToStringSid(ace_sid) in sid_list:               # if the current ACE is associated with a SID that we care about
            permissions = ace[1]                                                    # grab access mask of current ACE
            logger.info("%s has permissions %s. Has read access: %s, has write access: %s.", sid_name, hex(permissions), bool((permissions & GENERIC_FILE_READ)), bool((permissions & GENERIC_FILE_WRITE)), extra={'conn_counter': conn_counter})
            match target_permission:                                                
                case 'read':                                                        # check for read perms
                    perm_flag = int(bool(permissions & GENERIC_FILE_READ))          # bitwise AND with generic permission bit mask to get result 
                    if not perm_flag: 
                        break                                         # if even ONE of the groups in the list deny access, deny access altogether
                case 'write':
                    perm_flag = int(bool(permissions & GENERIC_FILE_WRITE))         # bitwise AND with generic permission bit mask to get result
                    if not perm_flag: 
                        break                                         # if even ONE of the groups in the list deny access, deny access altogether

    logger.info("Authentication concluded. Result: %s", perm_flag, extra={'conn_counter': conn_counter})

    # send authentication result and close server connection

    conn.sendall(b'AUTHS')                                                          # indicate to server that authentication is complete                    
    conn.sendall(str(perm_flag).encode('utf-8'))                                    # send authentication decision to server 
    conn.shutdown(socket.SHUT_WR)                                                   # force all buffered data to send (weird bug fix)
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
            conn, addr = dc_socket.accept()                                         # every time a connection is accepted, make a new thread
            logger.info("Connected by %s", addr, extra={'conn_counter': "N/A"})
            server_thread = threading.Thread(target=auth_code, args=(conn,))
            server_thread.start()
        except KeyboardInterrupt:
            logger.info("Shutting down DC...", extra={'conn_counter': "N/A"})
            dc_socket.close()
            conn.close()
            break
