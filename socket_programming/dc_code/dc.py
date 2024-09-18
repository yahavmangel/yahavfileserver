import socket
import win32security
import configparser
import threading
import json

config = configparser.ConfigParser()
config.read('config.ini')
port = int(config['dc']['port'])

def auth_code(conn):
    delimiter = b'\x1f'
    received = b''
    while True:
        data = conn.recv(4096) 
        if not data:
            break
        received += data
    bin_sd, target_permission_bin, sid_list_bin = received.split(delimiter)
    target_permission = target_permission_bin.decode('utf-8')
    sid_list = json.loads(sid_list_bin.decode('utf-8'))
    print(sid_list)
    dacl = win32security.SECURITY_DESCRIPTOR(bin_sd).GetSecurityDescriptorDacl()
    
    perm_flag = 0
    for i in range(dacl.GetAceCount()):
        ace = dacl.GetAce(i)
        ace_sid = ace[2]
        try: 
            sid_name, domain, _type = win32security.LookupAccountSid(None, ace_sid)
        except: continue
        if(win32security.ConvertSidToStringSid(ace_sid) in sid_list): 
            permissions = ace[1]
            print(f'{sid_name} is {i} and has permissions {hex(permissions)}. Read is {str(bool((permissions & 0x120089)))}, and Write is {str(bool((permissions & 0x120116)))}.')
            match target_permission:
                case 'read':
                    perm_flag = int(bool(permissions & 0x120089)) # keep setting it to whatever this is until it's true. 
                    if not perm_flag: break
                case 'write':
                    perm_flag = int(bool(permissions & 0x120116))
                    if not perm_flag: break
    print(str(perm_flag).encode('utf-8'))
    conn.sendall(b'AUTH')            
    conn.sendall(str(perm_flag).encode('utf-8'))   
    conn.shutdown(socket.SHUT_WR)
    conn.close()
    return 

if __name__ == "__main__":
    dc_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    dc_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    dc_socket.bind(('0.0.0.0', port))                                                  
    dc_socket.listen(5)

    print("DC is listening...")

    while True:
        try: 
            conn, addr = dc_socket.accept()                                                     # every time a connection is accepted by server, make a new thread
            print(f"Connected by {addr}")
            server_thread = threading.Thread(target=auth_code, args=(conn,))
            server_thread.start()
        except KeyboardInterrupt:
            print("Shutting down server...")
            dc_socket.close()
            conn.close()
            break