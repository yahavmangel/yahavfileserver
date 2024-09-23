import socket
import win32security
import configparser
import threading
import json
import logging 

# important metadata

config = configparser.ConfigParser()
config.read('config.ini')
port = int(config['dc']['port'])

# magic numbers

GENERIC_FILE_READ = 0x120089                                                        # bit mask of generic file read permissions as defined by windows security manual
GENERIC_FILE_WRITE = 0x120116                                                       # bit mask of generic file write permissions as defined by windows security manual

# logging 

logging.basicConfig(level=logging.DEBUG,
                    format='%(name)s - %(levelname)s - %(message)s',
                    filename=f'dc.log')

logger = logging.getLogger()


# main code

def auth_code(conn):

    # receive server authentication request 

    delimiter = b'\x1f'                                                             # separating character of server -> dc message components, will not appear in nTSecurityDescriptor binary data
    received = b''
    while True:
        data = conn.recv(4096) 
        if not data:
            break
        received += data
    
    # parse server request message 
    
    bin_sd, target_permission_bin, sid_list_bin = received.split(delimiter)         # split server msg by delimiter
    target_permission = target_permission_bin.decode('utf-8')                   
    sid_list = json.loads(sid_list_bin.decode('utf-8'))

    # main authentication logic

    dacl = win32security.SECURITY_DESCRIPTOR(bin_sd).GetSecurityDescriptorDacl()    # fetch DACL out of the client's security descriptor 
    perm_flag = 0
    for i in range(dacl.GetAceCount()):                                             # iterate through each ACE in the DACL, checking the permissions of each ACE with the same SID as the target. 
        ace = dacl.GetAce(i)
        ace_sid = ace[2]                                                            # grab SID of current ACE
        try:                                                                        # this filters out non-SID objects 
            sid_name, domain, _type = win32security.LookupAccountSid(None, ace_sid)
        except: continue
        if(win32security.ConvertSidToStringSid(ace_sid) in sid_list):               # if the current ACE is associated with a SID that we care about
            permissions = ace[1]                                                    # grab access mask of current ACE
            logger.info(str(sid_name) + " has permissions " + str(hex(permissions)) + ". Has read access: " + str(bool((permissions & GENERIC_FILE_READ))) + ", has write access: " + str(bool((permissions & GENERIC_FILE_WRITE))) + ".")
            match target_permission:                                                
                case 'read':                                                        # check for read perms
                    perm_flag = int(bool(permissions & GENERIC_FILE_READ))          # bitwise AND with generic permission bit mask to get result 
                    if not perm_flag: break                                         # if even ONE of the groups in the list deny access, deny access altogether
                case 'write':
                    perm_flag = int(bool(permissions & GENERIC_FILE_WRITE))         # bitwise AND with generic permission bit mask to get result
                    if not perm_flag: break                                         # if even ONE of the groups in the list deny access, deny access altogether

    logger.info("Authentication concluded. Result: " + str(perm_flag))

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

    logger.info("DC is listening...")

    while True:
        try: 
            conn, addr = dc_socket.accept()                                         # every time a connection is accepted, make a new thread
            logger.info("Connected by " + str(addr))
            server_thread = threading.Thread(target=auth_code, args=(conn,))
            server_thread.start()
        except KeyboardInterrupt:
            logger.info("Shutting down DC...")
            dc_socket.close()
            conn.close()
            break