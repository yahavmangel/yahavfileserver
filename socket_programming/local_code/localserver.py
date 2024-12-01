"""
Run the localserver, which is responsible for the following: 
- Acts as central logserver (all modes)
- Acts as receiver of user prompts (dev mode)
- Launches "Desktop GUI" that does the following:
    - Display logs (all modes)
    - Display/interact with user prompts (dev mode)
    - Launch client requests (dev/test modes)
    - Launch automated tests (test mode)
"""
import socket
import configparser
import threading
import json
import os
import sys
import queue
from localgui import localGUI
import subprocess

# logging and metadata

script_dir = os.path.dirname(os.path.abspath(__file__))         # make script execution dynamic
log_queue = queue.Queue()                                       # instantiate thread safe log queue
prompt_queue = queue.Queue()
resp_queue = queue.Queue()
event_arr = [threading.Event() for _ in range(4)]

try:
    config = configparser.ConfigParser()
    config.read(os.path.join(script_dir, 'config.ini'))
    port = int(config['local']['port'])                         # port for external communication
    port2 = int(config['local']['port2'])
    # info for local GUI
    domain = config['local']['domain']
    domain_controller_ip = config['local']['domain_controller_ip']
    server_ip = config['local']['server_ip']
    local_ip = config['local']['local_ip']
    ldap_server = config['local']['ldap_server']

except KeyError:                                                # case of misconfigured config file
    log_queue.put(("CRITICAL", "Missing or misconfigured config file",
                   {'loggername': "localserver", 'conn_counter': "N/A"}))
    sys.exit(1)

# magic numbers

BUF_SIZE_LARGE = 4096
MSG_PREFIX_LEN = 3
MSG_PREFIX2_LEN = 5

# main code

def local_handler(conn):
    """
    Main local server code: receives log/user prompt from some source -> processes accordingly: 
        - logs get placed in log queue and then written to aggregate log 
        - user prompts get directed to localserver terminal
    
    Args:
        conn: connection of current thread
    """

    data = b""
    while True:
        chunk = conn.recv(BUF_SIZE_LARGE)
        if not chunk:
            break
        data += chunk
        messages = data.split(b'END')
        for message in messages:
            message = message.decode('utf-8')
            match message[:MSG_PREFIX_LEN]:
                case "LOG":                                     # data has LOG prefix: log entry
                    log_entry = json.loads(message[MSG_PREFIX_LEN:])
                    process_log_entry(log_entry)
                case "USR":                                     # data has USR prefix: user prompt
                    usr_prompt = message[MSG_PREFIX_LEN:]
                    process_usr_prompt(usr_prompt, conn)
    conn.close()

def process_log_entry(log_entry):
    """
    Log entry processing: parses received log and place it in log queue. 
    
    Args:
        log_entry: received log entry.
    """

    loggername = log_entry.get('name')
    conn_counter = log_entry.get('conn_counter', "N/A")         # if attribute DNE, default to N/A
    loggerlevelname = log_entry.get('level')
    message = log_entry.get('message')                          # place in log queue
    log_queue.put((loggerlevelname, message,
                   {'loggername': loggername, 'conn_counter': conn_counter}))

def process_usr_prompt(usr_prompt, conn):
    """
    User prompt processing: parses received user prompt and either prints or 
    prompts local console accordingly.  
    
    Args:
        usr_prompt: the received prompt
        conn: connection to client
    """
    match usr_prompt[:MSG_PREFIX2_LEN]:
        case "INPUT":
            prompt_queue.put("INPUT", usr_prompt[MSG_PREFIX2_LEN:])
            while resp_queue.empty():
                pass
            while not resp_queue.empty():
                to_client = resp_queue.get()
                conn.sendall(to_client.encode('utf-8'))
        case "PRINT":
            prompt_queue.put("PRINT", usr_prompt[MSG_PREFIX2_LEN:])
            
def app_handler(conn):
    while True: 
        status = conn.recv(1).decode('utf-8')
        if status.isdigit():
            event_arr[int(status)].set()
            if(int(status) == 2): # if server connected 
                break
    while not event_arr[3].is_set():
        continue
    if event_arr[3].is_set(): 
        conn.sendall(b'SHUTDOWN')
        conn.close()

def server_loop(local_sock):

    log_queue.put(("INFO", "localserver is listening for logs...",
        {'loggername': "localserver", 'conn_counter': "N/A"}))
    

    local_sock.bind(('0.0.0.0', port))
    local_sock.listen(50)

    while True:
        try: 
            conn, addr = local_sock.accept()
            match addr[0]:
                case "127.0.0.1":   # loopback address: this is the app powershell script communicating app status!
                    app_thread = threading.Thread(target=app_handler, args=(conn,))
                    app_thread.start()
                case _:             # otherwise: clients to the local server. 
                    local_thread = threading.Thread(target=local_handler, args=(conn,))
                    local_thread.start()
        except OSError: # if socket was closed by gui thread
            break

if __name__ == "__main__":

    # set up localserver socket
    local_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # start main localserver loop 
    server_loop_thread = threading.Thread(target=server_loop, args=(local_sock,))
    server_loop_thread.start()

    # launch gui
    gui_static_info_dict = {
        "Domain": domain,
        "Server IP": server_ip,
        "Domain Controller IP": domain_controller_ip,
        "Local Server IP": local_ip,
        "LDAP Server": ldap_server,
        "Ports": "12343-12346"
    }

    gui = localGUI(log_queue, prompt_queue, resp_queue, event_arr, gui_static_info_dict)
    gui.mainloop()
    local_sock.close() # reaches after gui quit 
