import socket
import os 
import json
import threading
import zipfile
import configparser
from difflib import get_close_matches
from ldap3 import Server, Connection, ALL, SASL, GSSAPI
import logging 
import sys 

# logging and metadata

login_name = os.getlogin()                                                                          # base logging and ID based on login
script_dir = os.path.dirname(os.path.abspath(__file__))                                             # make script execution dynamic
logging.basicConfig(level=logging.DEBUG,
                    format='(%(name)s, ID: %(conn_counter)s) %(levelname)s: %(message)s',
                    filemode = 'w',                                                                 # log overwrites for every new script 
                    filename=os.path.join(script_dir, f'{login_name}.log'))

logger = logging.getLogger(login_name)                                                              

try:                                                                                                # collect config file info
    config = configparser.ConfigParser()                                                                
    config.read(os.path.join(script_dir, 'config.ini'))
    port = int(config['server']['port'])
    port2 = int(config['server']['port2'])
    domain_controller = config['server']['domain_controller']
    domain_controller_ip = config['server']['domain_controller_ip']
    target_dir = os.path.join(script_dir, config['server']['target_dir'])
except KeyError:                                                                                    
    logger.critical(f"Missing or misconfigured config file", extra={'conn_counter': "N/A"})
    sys.exit(1)                                                                                     # stops script execution w/o key info 
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
    'STOREDIRE': 'STOREDIRE',
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
global_dict_lock = threading.Lock()                                                                 # lock for locking the file lock dictionary (make it thread safe as well)                                                                            # counter to keep track of number of connections. Used for logging. 

# main code 

def client_handler(conn, conn_counter):

    try: 

        # collect connection information

        try: 
            hostname, alias, ip_addresses = socket.gethostbyaddr(addr[0])                           # reverse DNS lookup on ip address to get hostname
            logger.info("Client host connected: " + str(hostname), extra={'conn_counter': "N/A"})
        except socket.herror: 
            logger.critical("DNS server offline. Quitting.", extra={'conn_counter': "N/A"})
            conn.close()
            return 

        client_msg = conn.recv(BUF_SIZE_SMALL).decode('utf-8')                                      # receive and parse initial client message
        name, command, filename = client_msg.split('|')
        logger.info("_______________NEW CONNECTION: " + str(name) + "; COMMAND: " + str(command) + " " + str(filename) + "; ID: " + str(conn_counter) + "______________", extra={'conn_counter': conn_counter})
        ldap_conn = initiate_ldap_conn(conn_counter)                                                # initiate LDAP server connection for rest of operation
        logger.debug("Searching for client in LDAP server...", extra={'conn_counter': conn_counter})
        entries = get_ldap_user_info(ldap_conn, name.split('@')[0], ['cn'])                         # verify existence/CN of client 
        if entries: 
            logger.info("Client recognized in LDAP server", extra={'conn_counter': conn_counter})
            client_name = entries[0].cn.value 
        else:
            logger.error("Unrecognized connection. Exiting.", extra={'conn_counter': conn_counter})  
            conn.close()
            return 
        client_dir = os.path.join(target_dir, client_name)                                          # get client's directory name in fileserver 

        # handle main requests

        if command == 'STORE':

            if check_ldap_auth(ldap_conn, client_name, 'write', conn_counter):                      # check if client has write perms                  
                logger.info("Client " + str(client_name) + " is authorized.", extra={'conn_counter': conn_counter})
                send_server_msg(conn, 'AUTHSUCCESS', client_name, conn_counter)                     # indicate to client that they are authorized and may proceed
                handle_store(conn, filename, client_dir, client_name, conn_counter)                 # process client request 
            else:                                                                                   # client is not authorized
                logger.error("Client not authorized to make request. Exiting.", extra={'conn_counter': conn_counter})
                send_server_msg(conn, 'AUTHFAIL', client_name, conn_counter)                        # indicate to client that they are not authorized
                conn.close()                                                                        # stop connection
                return
                    
        elif command == 'REQUEST':

            if check_ldap_auth(ldap_conn, client_name, 'read', conn_counter):                       # check if client has write perms
                logger.info("Client " + str(client_name) + " is authorized.", extra={'conn_counter': conn_counter})
                send_server_msg(conn, 'AUTHSUCCESS', client_name, conn_counter)                     # indicate to client that they are authorized and may proceed
                handle_request(conn, filename, client_name, conn_counter)                           # process client request
            else:
                logger.error("Client not authorized to make request. Exiting.", extra={'conn_counter': conn_counter})
                send_server_msg(conn, 'AUTHFAIL', client_name, conn_counter)                        # indicate to client that they are not authorized
                conn.close()                                                                        # stop connection
                return

        # close connection

        conn.close()

    except ConnectionError: 
        logger.critical("Server connection Failure. Exiting.", extra={'conn_counter': conn_counter})


def handle_store(conn, filename, client_dir, client_name, conn_counter):

    # check for overwrite

    basename = os.path.basename(filename)
    if basename == '': basename = os.path.basename(filename[:-1])

    if os.path.exists(os.path.join(client_dir, basename)): 
        logger.warning("Overwrite detected. Notifying client...", extra={'conn_counter': conn_counter})
        send_server_msg(conn, 'OVERWRITE', client_name, conn_counter)                               # notify client of potential overwrite
        client_msg = conn.recv(BUF_SIZE_SMALL).decode('utf-8')                                      # receive client response to overwrite
        while True: 
            if ((client_msg == 'ACK') or (client_msg == 'QUIT')):                                   # wait for client response to overwrite
                break
        if client_msg == 'QUIT':                                                                    # client decided to abort to avoid overwrite
            logger.info("Client canceled request. Exiting.", extra={'conn_counter': conn_counter})
            conn.close()
            return 
        elif client_msg == 'ACK':
            logger.info("Client acknowledged overwrite. Continuing.", extra={'conn_counter': conn_counter})

    # initiate request 

    send_server_msg(conn, 'READY', client_name, conn_counter)                                       # indicate to client that server is ready 

    logger.debug("Checking if STORE request is for a file or a directory...", extra={'conn_counter': conn_counter})
    while True: 
        client_msg = conn.recv(BUF_SIZE_SMALL).decode('utf-8')                                      # wait for client's message of file type to store 
        if (client_msg == 'STOREDIRE' or client_msg == 'STOREFILE'):
            break
    
    if client_msg == 'STOREFILE':   
        logger.debug("Request is for a file.", extra={'conn_counter': conn_counter})
        file_lock = get_file_lock(os.path.join(client_name, os.path.basename(filename)))            # synchronization: prevent w/w conflicts to same file 

        with file_lock:                                                    
            os.makedirs(client_dir, exist_ok=True)                                                  # make directory for new host (or just don't do anything if already exists)
            try: 
                with open(os.path.join(client_dir, os.path.basename(filename)), 'wb') as file:      # join file name with newly made directory 
                    data_flag = 0
                    while True:
                        data = conn.recv(BUF_SIZE_SMALL)
                        if not data:
                            if not data_flag:
                                os.remove(os.path.join(client_dir, os.path.basename(filename)))     # if file is empty, don't actually create anything
                                logger.warning("File contained no data. No file has been created.", extra={'conn_counter': conn_counter})   
                            break
                        file.write(data)
                        data_flag = 1
                    if data_flag: 
                        logger.info("File " + str(filename) + " stored successfully", extra={'conn_counter': conn_counter})
            except IOError:
                logger.error("Failed to write file during STORE", extra={'conn_counter': conn_counter})
                return
    
    elif client_msg == 'STOREDIRE':
        logger.debug("Request is for a directory.", extra={'conn_counter': conn_counter})                                          
        dirname = os.path.basename(filename[:-1])
        tempfilename = target_dir + dirname + '_temp.zip'
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
                    logger.info("Directory " + str(dirname) + " unzipped and stored successfully", extra={'conn_counter': conn_counter})
            os.remove(tempfilename)                                                         # remove temp zip file. 
    
def handle_request(conn, filename, client_name, conn_counter):

    send_server_msg(conn, 'READY', client_name, conn_counter)
    json_list = json.dumps(similarity_search(target_dir, filename, conn_counter))           # call search algorithm and send result to client
    send_server_msg(conn, 'OPTIONS', client_name, conn_counter)
    if not json.loads(json_list):                                                           # list is empty
        logger.error("Search unsuccessful. Closing.", extra={'conn_counter': conn_counter})
    else:     
        conn.sendall(json_list.encode('utf-8'))
        client_msg = conn.recv(BUF_SIZE_SMALL).decode('utf-8')                              # receive back client's number choice, which is index into list
        options = json.loads(json_list) 
        if int(client_msg) > len(options):                                                  # client chose N/A option
            logger.error("Search unsuccessful. Closing.", extra={'conn_counter': conn_counter})
        else: 

            target_file = options[int(client_msg)-1]
            
            # file request 

            if os.path.isfile(target_dir + target_file):
                file_lock = get_file_lock(target_file)                                      # synchronization: prevent r/w conflicts on the same file
                with file_lock: 
                    try: 
                        with open(target_dir + target_file, 'rb') as file: 
                            data = file.read()                                              # send target file to client
                            conn.sendall(data)
                            logger.info("File sent successfully", extra={'conn_counter': conn_counter})
                    except IOError:
                        logger.error(f"Failed to read file during REQUEST", extra={'conn_counter': conn_counter})
                        return 
            
            # directory request 
            
            elif os.path.isdir(target_dir + target_file[:-1]):
                dirname = target_file[:-1]   
                tempfilename = target_dir + dirname + '.zip'
                dir_lock = get_file_lock(dirname)
                with dir_lock:                                                              # synchronization: prevent r/w conflicts on the same file
                    with zipfile.ZipFile(tempfilename, 'w') as zip:                         # use zipfile API to zip requested directory. This opens a temp zip file
                        for root, dirs, files in os.walk(target_dir + dirname):
                            for file in files:                                              # add every file to zip archive
                                filepath = os.path.join(root, file)
                                arcname = os.path.relpath(filepath, start=target_dir + dirname)   
                                zip.write(filepath, arcname=arcname)                        # use relative path to maintain correct directory structure
                            for dir in dirs:                                                # add every subdirectory to zip archive
                                dirpath = os.path.join(root, dir)
                                arcname = os.path.relpath(dirpath, start=target_dir + dirname)    
                                zip.write(dirpath, arcname=arcname)                         # use relative path to maintain correct directory structure
                    with open(tempfilename, 'rb') as zip_file:                              # open file in binary mode to send it over socket
                        data = zip_file.read()
                        conn.sendall(data)
                        logger.info("Zipped directory sent successfully", extra={'conn_counter': conn_counter})
                    os.remove(tempfilename)                                                 # remove temporary file

# helper functions

def similarity_search(dir_name, keyword, conn_counter):
    logger.debug("Searching directory: " + str(dir_name) + ". Search keyword is: " + str(keyword), extra={'conn_counter': conn_counter})
    file_dict = {}                          
    for root, dirs, files in os.walk(dir_name):                                                                             # walk through all files in server, adding their base names to a dictionary.                                              
        for file in files: 
            filepath = os.path.join(root.replace(dir_name, '', 1), file)
            file_dict.update({filepath:os.path.basename(filepath)})
        for dir in dirs: 
            dirpath = os.path.join(root.replace(dir_name, '', 1), dir)
            file_dict.update({dirpath + '/':os.path.basename(dirpath)})                                                     # add '/' to signify it is a directory
    matches = get_close_matches(keyword, list(file_dict.values()), n=NUM_FILES_RETURNED, cutoff=SIMILARITY_IDX)             # perform search on all file and directory base names
    logger.info("Search for keyword " + str(keyword) + " successful, server returned " + str(len(matches)) + " options.", extra={'conn_counter': conn_counter})
    return [match for match, base_name in file_dict.items() if base_name in matches]                                        # return all matches' full file name in an array
        
def get_file_lock(filename):
    with global_dict_lock:
        if filename not in file_lock_dict:
            file_lock_dict[filename] = threading.Lock()
        return file_lock_dict[filename]
    
def check_ldap_auth(ldap_conn, username, perm, conn_counter):

    logger.debug("verifying permissions for client " + str(username) + "...", extra={'conn_counter': conn_counter})

    # query #1: get DN and nTSecurityDescriptor of client 

    entries = get_ldap_user_info(ldap_conn, username, ['distinguishedName', 'nTSecurityDescriptor'])                        # return both their full DN and their security descriptor
    
    if entries: 
        user_dn = entries[0].distinguishedName.value
        bin_sd = entries[0].ntSecurityDescriptor.raw_values[0]                                                              # get binary data of security descriptor 
        
        # query #2: get all groups that the client is member of

        domain_dn = construct_dn('')

        logger.debug("Scanning for client " + str(username) + " group membership...", extra={'conn_counter': conn_counter})
        ldap_conn.search(search_base=domain_dn,                                                                             
                         search_filter=f'(&(objectCategory=group)(member={user_dn}))',                                      # look for groups that the client is a member of, as they will contain the permissions which the user will inherit
                         attributes=['cn', 'groupType', 'objectSid'])                                                       # return important data about each group
        
        if ldap_conn.entries:
            groups_to_check = []                                                                                            # list of SIDs to be sent to the domain controller for permission checking
            for entry in ldap_conn.entries: 
                if((entry.groupType.value & SEC_GROUP_BITMASK) != 0):                                                       # check if the group is a security group (not a distribution group)
                    logger.debug(str(username) + " is a member of the " + str(entry.cn.value) + " security group", extra={'conn_counter': conn_counter})
                    groups_to_check.append(entry.objectSid.value)                                                           # add SID of security group to the list
            return bool(auth_request(bin_sd, perm, groups_to_check, conn_counter))                                          # send authentication request to domain controller, and return result to main code
        
        else: 
            logger.debug("Client " + str(username) + " is not member of any security group.", extra={'conn_counter': conn_counter})
            return False                                                                                                    # edge case: client is not a member of any group
    
    else:
        logger.debug("Client " + str(username) + " was not found in LDAP server.", extra={'conn_counter': conn_counter}) 
        return False                                                                                                        # edge case: client does not exist in domain

def auth_request(security_desc, target_permission, sid_list, conn_counter):

    logger.debug("Initiating connection with DC for authorization...", extra={'conn_counter': conn_counter})
    
    # set up socket connection with DC
    
    dc_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    dc_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try: 
        dc_socket.settimeout(10)
        dc_socket.connect((domain_controller_ip, port2))
    except socket.error:
        logger.critical(f"Failed to connect to DC", extra={'conn_counter': conn_counter})
        return False
    except socket.timeout:
        logger.critical("Connection timed out. DC unreachable.", extra={'conn_counter': conn_counter})
        return
                                                                                                    
    # Convert binary data to bytes and combine everything into a single message. 

    delimiter = b'\x1F'                                                                                 # This delimiter will not show up in any misc binary data.
    server_msg = delimiter.join([
        security_desc,
        target_permission.encode('utf-8'),
        json.dumps(sid_list).encode('utf-8'),
        str(conn_counter).encode('utf-8')                                                               # pass conn ID to DC for its own logging
    ])

    # send information to the domain controller for processing 
     
    dc_socket.sendall(server_msg)                                                                       # send server message to DC                                        
    dc_socket.shutdown(socket.SHUT_WR)                                                                  # force all buffered data to send (weird bug fix)
    wait_for_server_resp(dc_socket, command_table['AUTHSUCCESS'], "DC", conn_counter)
    resp = int(dc_socket.recv(1).decode('utf-8'))                                                       # DC will return a 1 or 0, 1 is authorized, 0 is not. 
    dc_socket.close()
    return resp                                                                                         # return DC's authentication result to main code 

def initiate_ldap_conn(conn_counter):                                                                   # get DN of full domain
    ldap_server = f'ldap://{domain_controller}'   
    logger.debug("Connecting to LDAP server: " + str(ldap_server), extra={'conn_counter': conn_counter})       
    try:                                                                    
        server = Server(ldap_server, get_info=ALL)                                                      # Connect to the LDAP server using GSSAPI (Kerberos) authentication
        ldap_conn = Connection(server, authentication=SASL, sasl_mechanism=GSSAPI)    
        ldap_conn.bind()   
    except Exception: 
        logger.critical("Error connecting to LDAP server. Ensure you have a valid Kerberos ticket.", extra={'conn_counter': conn_counter})
        return 
    logger.info("Successfully connected to LDAP server: " + str(ldap_server), extra={'conn_counter': conn_counter})
    return ldap_conn

def get_ldap_user_info(ldap_conn, username, attributes):                                                # query to collect attributes from a given user/computer account 
    domain_dn = construct_dn('')
    try: 
        ldap_conn.search(search_base=domain_dn,                                                         # this query works on either user or computer accounts (using AND/OR syntax)
                        search_filter=f'(|(&(objectClass=user)(|(cn={username})(sAMAccountName={username})))(&(objectClass=computer)(cn={username})))',
                        attributes=attributes)
    except Exception:
        return 

    return ldap_conn.entries

def construct_dn(basename):                                                                             # helper function to construct distinguishedName of particular object in domain. 

    for i in range(0, len(dc_array)):
        basename += ('DC=' + dc_array[i])
        if i < len(dc_array) - 1:
            basename += ','
    return basename

def wait_for_server_resp(dc_socket, resp, client_name, conn_counter):                                   # helper function that polls for specific server response
    resp_len = len(resp)
    while True:
        server_resp = dc_socket.recv(resp_len).decode('utf-8')
        if resp in server_resp and resp in command_table.values():
            logger.debug("Received message from " + str(client_name) + ": " + resp, extra={'conn_counter': conn_counter})
            break

def send_server_msg(conn, msg, client_name, conn_counter):
    logger.debug("server -> " + str(client_name) + ": " + msg, extra={'conn_counter': conn_counter})    # log each server message in debug level of logger 
    conn.sendall(command_table[msg].encode())

# main loop 

if __name__ == "__main__":

    conn_counter = 0                                                           
    
    # connection setup

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(('0.0.0.0', port))                                                  
    server_socket.listen(5)

    logger.info("Server is listening...", extra={'conn_counter': conn_counter})

    while True:
        conn, addr = server_socket.accept()                                                             # every time a connection is accepted by server, make a new thread
        logger.info("Connected by " + str(addr), extra={'conn_counter': "N/A"})
        conn_counter += 1                                                                               # increment connection ID every time, passing it to thread for logging.
        client_thread = threading.Thread(target=client_handler, args=(conn,conn_counter))
        client_thread.start()