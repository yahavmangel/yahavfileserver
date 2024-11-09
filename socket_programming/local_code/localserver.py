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
event_arr = [threading.Event() for _ in range(4)]

try:
    config = configparser.ConfigParser()
    config.read(os.path.join(script_dir, 'config.ini'))
    port = int(config['local']['port'])                         # port for external communication

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
            to_client = input(usr_prompt[MSG_PREFIX2_LEN:])     # if input, prompt user
            conn.sendall(to_client.encode('utf-8'))             # send response back to client
        case "PRINT":
            print(usr_prompt[MSG_PREFIX2_LEN:])                 # if print, print to console

def launch_gui(mode_num, usergui_process, event_arr):
    gui = localGUI(log_queue, None, None, mode_num, domain, server_ip, domain_controller_ip, local_ip, ldap_server, usergui_process, event_arr)
    gui.mainloop()

def app_handler(conn):
    while 1: 
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

if __name__ == "__main__":

    usergui_process = None
    mode_num = int(sys.argv[1])

    if mode_num == 2: # on user mode, launch user gui (comment this out during normal client use)

        log_queue.put(("INFO", "Starting client GUI...",
                   {'loggername': "localserver", 'conn_counter': "N/A"}))

        usergui_process = subprocess.Popen(["python3", os.path.join(script_dir, 'clientgui.py')])

    # launch gui thread

    gui_thread = threading.Thread(target=launch_gui, args=(mode_num, usergui_process, event_arr))
    gui_thread.daemon = True
    gui_thread.start()

    # main localserver loop 
    local_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    local_sock.bind(('0.0.0.0', port))
    local_sock.listen(50)

    log_queue.put(("INFO", "localserver is listening...",
                   {'loggername': "localserver", 'conn_counter': "N/A"}))

    while True:
        conn, addr = local_sock.accept()
        match addr[0]:
            case "127.0.0.1":   # loopback address: this is the app powershell script communicating status!
                app_thread = threading.Thread(target=app_handler, args=(conn,))
                app_thread.start()
            case _:             # otherwise: clients to the local server. 
                local_thread = threading.Thread(target=local_handler, args=(conn,))
                local_thread.start()
