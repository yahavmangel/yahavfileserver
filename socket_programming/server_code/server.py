import socket
import os 
import json
import threading
import zipfile
import configparser
from difflib import get_close_matches
from ldap3 import Server, Connection, ALL, SASL, GSSAPI

# important metadata

config = configparser.ConfigParser()
config.read('config.ini')
port = int(config['server']['port'])
port2 = int(config['server']['port2'])
domain_controller = config['server']['domain_controller']
domain_controller_ip = config['server']['domain_controller_ip']
dc_array = domain_controller.split('.')[1:]

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
BUF_SIZE_SMALL = 1024
BUF_SIZE_LARGE = 4096
SEC_GROUP_BITMASK = 0x80000000

# file search params 

NUM_FILES_RETURNED = 10                                                                     
SIMILARITY_IDX = 0.5

# global resources

file_lock_dict = {}
global_dict_lock = threading.Lock()                                                         # lock for locking the file lock dictionary (make it thread safe as well)

# main code 

def client_handler(conn):

    try: 

        # collect connection information

        try: 
            hostname, alias, ip_addresses = socket.gethostbyaddr(addr[0])                   # reverse DNS lookup on ip address to get hostname
        except socket.herror: 
            print("DNS server offline. Quitting.")
            conn.close()
            return 

        client_msg = conn.recv(BUF_SIZE_SMALL).decode('utf-8')                              # receive and parse initial client message
        command, filename = client_msg.split('|', 1)
        client_name = hostname.split('.')[0]
        client_dir = os.path.join('../files', client_name)                                  # get client's directory name in fileserver 

        # handle main requests

        if command == 'STORE':

            if check_ldap_auth(client_name, 'write'):                                       # check if client has write perms                  
                print("Authorized.")
                conn.sendall(command_table['AUTHSUCCESS'].encode())                         # indicate to client that they are authorized and may proceed
                handle_store(conn, filename, client_dir, client_name)                       # process client request 
            else:                                                                           # client is not authorized
                print("Error: client not authorized to make request. Exiting.")
                conn.sendall(command_table['AUTHFAIL'].encode())                            # indicate to client that they are not authorized
                conn.close()                                                                # stop connection
                return
                    
        elif command == 'REQUEST':

            if check_ldap_auth(client_name, 'read'):                                        # check if client has write perms
                print("Authorized.")
                conn.sendall(command_table['AUTHSUCCESS'].encode())                         # indicate to client that they are authorized and may proceed
                handle_request(conn, filename)                                              # process client request
            else:
                print("Error: client not authorized to make request. Exiting.")
                conn.sendall(command_table['AUTHFAIL'].encode())                            # indicate to client that they are not authorized
                conn.close()                                                                # stop connection
                return

        # close connection

        conn.close()

    except ConnectionError: 
        print("Connection Error. Exiting.")


def handle_store(conn, filename, client_dir, client_name):

    # check for overwrite

    if os.path.exists(os.path.join(client_dir, filename.split('/')[-1])): 
        conn.sendall(command_table['OVERWRITE'].encode())                                   # notify client of potential overwrite
        client_msg = conn.recv(BUF_SIZE_SMALL).decode('utf-8')                              # receive client response to overwrite
        while True: 
            if ((client_msg == 'ACK') or (client_msg == 'QUIT')):                           # wait for client response to overwrite
                break
        if client_msg == 'QUIT':                                                            # client decided to abort to avoid overwrite
            print("Request canceled.")
            conn.close()
            return 

    # initiate request 

    conn.sendall(command_table['READY'].encode())                                           # indicate to client that server is ready 

    while True: 
        client_msg = conn.recv(BUF_SIZE_SMALL).decode('utf-8')                              # wait for client's message of file type to store 
        if (client_msg == 'STOREDIR' or client_msg == 'STOREFILE'):
            break
    
    if client_msg == 'STOREFILE':

        file_lock = get_file_lock(os.path.join(client_name, os.path.basename(filename)))    # synchronization: prevent w/w conflicts to same file 

        with file_lock:                                                    
            os.makedirs(client_dir, exist_ok=True)                                          # make directory for new host (or just don't do anything if already exists)
            with open(os.path.join(client_dir, os.path.basename(filename)), 'wb') as file:  # join file name with newly made directory 
                data_flag = 0
                while True:
                    data = conn.recv(BUF_SIZE_SMALL)
                    if not data:
                        if not data_flag:
                            os.remove(os.path.join(client_dir, os.path.basename(filename))) # if file is empty, don't actually create anything
                            print("Error: file contained no data")   
                        break
                    file.write(data)
                    data_flag = 1
                if data_flag: 
                    print("File stored successfully")
    
    elif client_msg == 'STOREDIR':
                                                  
        dirname = filename[:-1]
        tempfilename = dirname.replace('/', '_', 1) + '_temp.zip'
        dir_lock = get_file_lock(os.path.join(client_name, dirname.split('/')[-1])) 
        with dir_lock:                                                                      # synchronization: prevent w/w conflicts to same directory 
            extraction_dir = client_dir
            os.makedirs(extraction_dir, exist_ok=True)
            with open(tempfilename, 'wb') as temp_zip:                                      # receive zip file binary. This opens a temp zip file.
                while True: 
                    zip_data = conn.recv(BUF_SIZE_LARGE)
                    if not zip_data:
                        break
                    temp_zip.write(zip_data)
                temp_zip.flush()                                                            # weird solution that fixed 'not a zip file' error for me
                os.fsync(temp_zip.fileno())
                with zipfile.ZipFile(tempfilename, 'r') as zip_file:                        # use zipfile API to unzip requested directory 
                    zip_file.extractall(path=extraction_dir)
                    print("Directory unzipped successfully")
            os.remove(tempfilename)                                                         # remove temp zip file. 
    
def handle_request(conn, filename):

    conn.sendall(command_table['READY'].encode())
    json_list = json.dumps(similarity_search("../files/", filename))                        # call search algorithm and send result to client
    conn.sendall(command_table['OPTIONS'].encode())
    if not json.loads(json_list):                                                           # list is empty
        print("Error: search unsuccessful. Closing.")
    else:     
        conn.sendall(json_list.encode('utf-8'))
        client_msg = conn.recv(BUF_SIZE_SMALL).decode('utf-8')                              # receive back client's number choice, which is index into list
        options = json.loads(json_list) 
        if int(client_msg) > len(options):                                                  # client chose N/A option
            print("Error: search unsuccessful. Closing.")
        else: 

            target_file = options[int(client_msg)-1]
            
            # file request 

            if os.path.isfile(os.path.join('../files', target_file)):
                file_lock = get_file_lock(target_file)                                      # synchronization: prevent r/w conflicts on the same file
                with file_lock: 
                    with open(os.path.join('../files', target_file), 'rb') as file: 
                        data = file.read()                                                  # send target file to client
                        conn.sendall(data)
                        print("File sent successfully")
            
            # directory request 
            
            elif os.path.isdir(os.path.join('../files', target_file[:-1])):     
                dirname = target_file[:-1]
                tempfilename = os.path.join('../files', dirname + '.zip')
                dir_lock = get_file_lock(dirname)
                with dir_lock:                                                              # synchronization: prevent r/w conflicts on the same file
                    with zipfile.ZipFile(tempfilename, 'w') as zip:                         # use zipfile API to zip requested directory. This opens a temp zip file
                        for root, dirs, files in os.walk(os.path.join('../files', dirname)):
                            for file in files:                                              # add every file to zip archive
                                filepath = os.path.join(root, file)
                                arcname = os.path.relpath(filepath, start=os.path.join('../files', dirname))   
                                zip.write(filepath, arcname=arcname)                        # use relative path to maintain correct directory structure
                            for dir in dirs:                                                # add every subdirectory to zip archive
                                dirpath = os.path.join(root, dir)
                                arcname = os.path.relpath(dirpath, start=os.path.join('../files', dirname))    
                                zip.write(dirpath, arcname=arcname)                         # use relative path to maintain correct directory structure
                    with open(tempfilename, 'rb') as zip_file:                              # open file in binary mode to send it over socket
                        data = zip_file.read()
                        conn.sendall(data)
                        print("Zipped directory sent successfully")
                    os.remove(tempfilename)                                                 # remove temporary file

# helper functions

def similarity_search(dir_name, keyword):
    file_dict = {}                          
    for root, dirs, files in os.walk(dir_name):                                                                             # walk through all files in server, adding their base names to a dictionary.                                              
        for file in files: 
            filepath = os.path.join(root.replace(dir_name, '', 1), file)
            file_dict.update({filepath:os.path.basename(filepath)})
        for dir in dirs: 
            dirpath = os.path.join(root.replace(dir_name, '', 1), dir)
            file_dict.update({dirpath + '/':os.path.basename(dirpath)})                                                     # add '/' to signify it is a directory
    matches = get_close_matches(keyword, list(file_dict.values()), n=NUM_FILES_RETURNED, cutoff=SIMILARITY_IDX)             # perform search on all file and directory base names
    return [match for match, base_name in file_dict.items() if base_name in matches]                                        # return all matches' full file name in an array
        
def get_file_lock(filename):
    with global_dict_lock:
        if filename not in file_lock_dict:
            file_lock_dict[filename] = threading.Lock()
        return file_lock_dict[filename]
    
def check_ldap_auth(username, perm):

    print(f'verifying {username} permissions...')

    # initiate LDAP server connection

    domain_dn = construct_dn('')                                                                                            # get DN of full domain
    ldap_server = f'ldap://{domain_controller}'                                                                             
    server = Server(ldap_server, get_info=ALL)                                                                              # Connect to the LDAP server using GSSAPI (Kerberos) authentication
    ldap_conn = Connection(server, authentication=SASL, sasl_mechanism=GSSAPI)    
    ldap_conn.bind()

    # query #1: get DN and nTSecurityDescriptor of client 

    ldap_conn.search(search_base=domain_dn, 
                     search_filter=f'(|(&(objectClass=user)(cn={username}))(&(objectClass=computer)(cn={username})))',      # look for either users or computer accounts with the client's name
                     attributes=['distinguishedName', 'nTSecurityDescriptor'])                                              # return both their full DN and their security descriptor
    
    if ldap_conn.entries: 
        user_dn = ldap_conn.entries[0].distinguishedName.value
        bin_sd = ldap_conn.entries[0].ntSecurityDescriptor.raw_values[0]                                                    # get binary data of security descriptor 
        
        # query #2: get all groups that the client is member of

        ldap_conn.search(search_base=domain_dn,                                                                             
                         search_filter=f'(&(objectCategory=group)(member={user_dn}))',                                      # look for groups that the client is a member of, as they will contain the permissions which the user will inherit
                         attributes=['cn', 'groupType', 'objectSid'])                                                       # return important data about each group
        
        if ldap_conn.entries:
            groups_to_check = []                                                                                            # list of SIDs to be sent to the domain controller for permission checking
            for entry in ldap_conn.entries: 
                if((entry.groupType.value & SEC_GROUP_BITMASK) != 0):                                                       # check if the group is a security group (not a distribution group)
                    print(f'{username} is a member of the {entry.cn.value} security group')
                    groups_to_check.append(entry.objectSid.value)                                                           # add SID of security group to the list
            return bool(auth_request(bin_sd, perm, groups_to_check))                                                        # send authentication request to domain controller, and return result to main code
        
        else: return False                                                                                                  # edge case: client is not a member of any group
    
    else: return False                                                                                                      # edge case: client does not exist in domain

def auth_request(security_desc, target_permission, sid_list):

    # set up socket connection with DC
    
    dc_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    dc_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    dc_socket.connect((domain_controller_ip, port2))
                                                                                                    
    # Convert binary data to bytes and combine everything into a single message with the control character delimiter. This delimiter will not show up in any misc binary data.

    delimiter = b'\x1F'  
    server_msg = delimiter.join([
        security_desc,
        target_permission.encode('utf-8'),
        json.dumps(sid_list).encode('utf-8')
    ])

    # send information to the domain controller for processing 
     
    dc_socket.sendall(server_msg)                                               # send server message to DC                                        
    dc_socket.shutdown(socket.SHUT_WR)                                          # force all buffered data to send (weird bug fix)
    wait_for_server_resp(dc_socket, command_table['AUTHSUCCESS'])
    resp = int(dc_socket.recv(1).decode('utf-8'))                               # DC will return a 1 or 0, 1 is authorized, 0 is not. 
    dc_socket.close()
    return resp                                                                 # return DC's authentication result to main code 

def construct_dn(basename):

    for i in range(0, len(dc_array)):
        basename += ('DC=' + dc_array[i])
        if i < len(dc_array) - 1:
            basename += ','
    return basename

def wait_for_server_resp(dc_socket, resp):                                      # helper function that polls for specific server response
    resp_len = len(resp)
    while True:
        server_resp = dc_socket.recv(resp_len).decode('utf-8')
        if resp in server_resp and resp in command_table.values():
            break

# main loop 

if __name__ == "__main__":

    # connection setup

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(('0.0.0.0', port))                                                  
    server_socket.listen(5)

    print("Server is listening...")

    while True:
        conn, addr = server_socket.accept()                                     # every time a connection is accepted by server, make a new thread
        print(f"Connected by {addr}")
        client_thread = threading.Thread(target=client_handler, args=(conn,))
        client_thread.start()