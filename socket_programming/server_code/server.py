"""
Run the fileserver, including server/client, server/DC, and server/localserver interactions. 

Functions: 

client_handler(conn, conn_counter, conn_addr)
handle_store(conn, filename, client_dir, client_name, conn_counter)
handle_request(conn, filename, client_name, conn_counter)
similarity_search(dir_name, keyword, conn_counter) -> [string]
get_file_lock(filename) -> lock 
send_server_msg(conn, msg, client_name, conn_counter)

"""
import socket
import os
import json
import threading
import zipfile
import configparser
from difflib import get_close_matches
import logging
import sys
from auth import check_ldap_auth, initiate_ldap_conn, get_ldap_user_info
from loghandler import JSONSocketHandler

# logging and metadata

login_name = os.getlogin()                                                                          # base logging and ID based on login
script_dir = os.path.dirname(os.path.abspath(__file__))                                             # make script execution dynamic

logger = logging.getLogger(login_name)
logger.setLevel(logging.DEBUG)

try:                                                                                                # collect config file info
    config = configparser.ConfigParser()                                                                
    config.read(os.path.join(script_dir, 'config.ini'))
    port = int(config['server']['port'])                                                            # port for connection with clients
    port2 = int(config['server']['port2'])                                                          # port for connection with DC (for auth)
    port3 = int(config['server']['port3'])                                                          # port for connection with localserver (for logs)
    domain_controller = config['server']['domain_controller']                                       # FQDN of DC
    domain_controller_ip = config['server']['domain_controller_ip']                                 # ip of DC  
    local_ip = config['server']['local_ip']                                                         # ip of localserver
    target_dir = os.path.join(script_dir, config['server']['target_dir'])                           # target directory of operations
except KeyError:                                                                                    
    logger.critical("Missing or misconfigured config file", extra={'conn_counter': "N/A"})
    sys.exit(1)                                                                                     # stops script execution w/o key info 
dc_array = domain_controller.split('.')[1:]

json_handler = JSONSocketHandler(local_ip, port3)
json_handler.setLevel(logging.DEBUG)
json_handler.setFormatter(logging.Formatter('(%(name)s, ID: %(conn_counter)s) %(levelname)s: %(message)s'))
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

NUM_CLIENT_COMMANDS = 2
NUM_INTERNAL_COMMANDS = 7
BUF_SIZE_SMALL = 1024
BUF_SIZE_LARGE = 4096

# file search params 

NUM_FILES_RETURNED = 10                                                                     
SIMILARITY_IDX = 0.5

# global resources

file_lock_dict = {}
global_dict_lock = threading.Lock()                                                                 # lock for locking the file lock dictionary (make it thread safe as well)                                                                            # counter to keep track of number of connections. Used for logging. 

# main code 

def client_handler(conn, conn_counter, conn_addr):
    """
    Handles a client connection to the server (individual client thread): receives client's message -> requests DC to authenticate client -> handles client request

    Args:
        conn: connection point to client 
        conn_counter: current connection ID (for logging)
    """

    try: 

        # collect connection information

        try: 
            hostname, _, _ = socket.gethostbyaddr(conn_addr[0])                           # reverse DNS lookup on ip address to get hostname
            logger.info("Client host connected: %s", hostname, extra={'conn_counter': conn_counter})
        except socket.herror: 
            logger.critical("DNS server offline. Quitting.", extra={'conn_counter': "N/A"})
            conn.close()
            return 

        client_msg = conn.recv(BUF_SIZE_SMALL).decode('utf-8')                                      # receive and parse initial client message
        name, command, filename = client_msg.split('|')
        logger.info("_______________NEW CONNECTION: %s; COMMAND: %s %s; ID: %s______________", name, command, filename, conn_counter, extra={'conn_counter': conn_counter})
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
                logger.info("Client %s is authorized.", client_name, extra={'conn_counter': conn_counter})
                send_server_msg(conn, 'AUTHSUCCESS', client_name, conn_counter)                     # indicate to client that they are authorized and may proceed
                handle_store(conn, filename, client_dir, client_name, conn_counter)                 # process client request 
            else:                                                                                   # client is not authorized
                logger.error("Client not authorized to make request. Exiting.", extra={'conn_counter': conn_counter})
                send_server_msg(conn, 'AUTHFAIL', client_name, conn_counter)                        # indicate to client that they are not authorized
                conn.close()                                                                        # stop connection
                return
                    
        elif command == 'REQUEST':

            if check_ldap_auth(ldap_conn, client_name, 'read', conn_counter):                       # check if client has write perms
                logger.info("Client %s is authorized.", client_name, extra={'conn_counter': conn_counter})
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
    """
    Handles a client STORE request: checks for overwrite -> receives client's file/dir

    Args:
        conn: connection point to client 
        filename: name of file to store
        client_dir: directory of client (to be allocated, or already exists) on the fileserver's file system
        client_name: name of client making the request 
        conn_counter: current connection ID (for logging)
    """

    # check for overwrite

    basename = os.path.basename(filename)
    if basename == '': 
        basename = os.path.basename(filename[:-1])                                   # weird edge case for dirs

    if os.path.exists(os.path.join(client_dir, basename)): 
        logger.warning("Overwrite detected. Notifying client...", extra={'conn_counter': conn_counter})
        send_server_msg(conn, 'OVERWRITE', client_name, conn_counter)                               # notify client of potential overwrite
        client_msg = conn.recv(BUF_SIZE_SMALL).decode('utf-8')                                      # receive client response to overwrite
        while True: 
            if client_msg in ['ACK', 'QUIT']:                                   # wait for client response to overwrite
                break
        if client_msg == 'QUIT':                                                                    # client decided to abort to avoid overwrite
            logger.info("Client canceled request. Exiting.", extra={'conn_counter': conn_counter})
            conn.close()
            return 
        if client_msg == 'ACK':
            logger.info("Client acknowledged overwrite. Continuing.", extra={'conn_counter': conn_counter})

    # initiate request 

    send_server_msg(conn, 'READY', client_name, conn_counter)                                       # indicate to client that server is ready 

    logger.debug("Checking if STORE request is for a file or a directory...", extra={'conn_counter': conn_counter})
    while True: 
        client_msg = conn.recv(BUF_SIZE_SMALL).decode('utf-8')                                      # wait for client's message of file type to store 
        if client_msg in ['STOREDIRE', 'STOREFILE']:
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
                        logger.info("File %s stored successfully", filename, extra={'conn_counter': conn_counter})
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
                    logger.info("Directory %s unzipped and stored successfully", dirname, extra={'conn_counter': conn_counter})
            os.remove(tempfilename)                                                         # remove temp zip file. 
    
def handle_request(conn, filename, client_name, conn_counter):
    """
    Handles a client REQUEST request: performs search of filesystem -> sends user options -> receives user choice -> sends file/dir to client 

    Args:
        conn: connection point to client 
        filename: name of requested file (key word, not exact path)
        client_name: name of client making the request 
        conn_counter: current connection ID (for logging)
    """

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
                        logger.error("Failed to read file during REQUEST", extra={'conn_counter': conn_counter})
                        return 
            
            # directory request 
            
            elif os.path.isdir(target_dir + target_file[:-1]):
                dirname = target_file[:-1]   
                tempfilename = target_dir + dirname + '.zip'
                dir_lock = get_file_lock(dirname)
                with dir_lock:                                                              # synchronization: prevent r/w conflicts on the same file
                    with zipfile.ZipFile(tempfilename, 'w') as zipFile:                         # use zipfile API to zip requested directory. This opens a temp zip file
                        for root, dirs, files in os.walk(target_dir + dirname):
                            for file in files:                                              # add every file to zip archive
                                filepath = os.path.join(root, file)
                                arcname = os.path.relpath(filepath, start=target_dir + dirname)   
                                zipFile.write(filepath, arcname=arcname)                        # use relative path to maintain correct directory structure
                            for dire in dirs:                                                # add every subdirectory to zip archive
                                dirpath = os.path.join(root, dire)
                                arcname = os.path.relpath(dirpath, start=target_dir + dirname)    
                                zipFile.write(dirpath, arcname=arcname)                         # use relative path to maintain correct directory structure
                    with open(tempfilename, 'rb') as zip_file:                              # open file in binary mode to send it over socket
                        data = zip_file.read()
                        conn.sendall(data)
                        logger.info("Zipped directory sent successfully", extra={'conn_counter': conn_counter})
                    os.remove(tempfilename)                                                 # remove temporary file

# helper functions

def similarity_search(dir_name, keyword, conn_counter):
    """
    Helper function that searches the filesystem of the server (for REQUEST command). Uses fuzzy search (idk what that is tbh)

    Args:
        dir_name: name of directory on server's filesystem to serch  
        keyword: key word to search against 
        conn_counter: current connection ID (for logging)
    
    Returns: 
        Array of matches returned by the search 
    """

    logger.debug("Searching directory: %s. Search keyword is: %s", dir_name, keyword, extra={'conn_counter': conn_counter})
    file_dict = {}                          
    for root, dirs, files in os.walk(dir_name):                                                                             # walk through all files in server, adding their base names to a dictionary.                                              
        for file in files: 
            filepath = os.path.join(root.replace(dir_name, '', 1), file)
            file_dict.update({filepath:os.path.basename(filepath)})
        for dire in dirs: 
            dirpath = os.path.join(root.replace(dir_name, '', 1), dire)
            file_dict.update({dirpath + '/':os.path.basename(dirpath)})                                                     # add '/' to signify it is a directory
    matches = get_close_matches(keyword, list(file_dict.values()), n=NUM_FILES_RETURNED, cutoff=SIMILARITY_IDX)             # perform search on all file and directory base names
    logger.info("Search for keyword %s successful, server returned %s options.", keyword, len(matches), extra={'conn_counter': conn_counter})
    return [match for match, base_name in file_dict.items() if base_name in matches]                                        # return all matches' full file name in an array
        
def get_file_lock(filename):
    """
    Handles a client STORE request: checks for overwrite -> receives client's file/dir

    Args:
        filename: name of file or directory to protect with a lock 
    
    Returns: 
        A new lock for the file/directory 
    """

    with global_dict_lock:
        if filename not in file_lock_dict:
            file_lock_dict[filename] = threading.Lock()
        return file_lock_dict[filename]

def send_server_msg(conn, msg, client_name, conn_counter):
    """
    Sends a message to a client and logs it. 

    Args:
        conn: connection point to client 
        msg: message to send to client
        client_name: name of client to send message to 
        conn_counter: current connection ID (for logging)
    """
    logger.debug("server -> %s: %s", client_name, msg, extra={'conn_counter': conn_counter})                        # log each server message in debug level of logger 
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
        conn, addr = server_socket.accept()                                                                                 # every time a connection is accepted by server, make a new thread
        conn_counter += 1                                                                                                   # increment connection ID every time, passing it to thread for logging.
        logger.info("Connected by %s", addr, extra={'conn_counter': conn_counter})
        client_thread = threading.Thread(target=client_handler, args=(conn,conn_counter,addr))
        client_thread.start()
