"""
Run the localserver, which is responsible for the following: 
- Acts as central logserver 
- Acts as receiver of user prompts (print and input)
- Launches "Desktop GUI"
"""
import socket
import configparser
import threading
import json
import logging
import os
import sys
import queue
from localgui import localGUI

class CustomFormatter(logging.Formatter):
    """
    Custom logging formatter that either includes/excludes 'conn_counter' attribute from the log.

    The 'conn_counter' attribute is the connection ID, which can be used by admins to distinguish 
    between each server connection in the aggregate log. When a logger does not know what ID their 
    log is associated with, they pass "N/A" to this attribute. This formatter will then remove the 
    attribute entirely.  
    """

    def format(self, record):

        # Exclude conn_counter from the log if it's "N/A"
        if getattr(record, 'conn_counter', 'N/A') == "N/A":
            log_msg = f"({record.loggername}) {record.levelname}: {record.msg}"
        else:
            log_msg = (
                f"({record.loggername}, ID: {record.conn_counter}) "
                f"{record.levelname}: {record.msg}"
            )
        return log_msg

# logging and metadata

script_dir = os.path.dirname(os.path.abspath(__file__))         # make script execution dynamic

log_queue = queue.Queue()                                       # instantiate thread safe log queue
logger = logging.getLogger("YFS")
logger.setLevel(logging.DEBUG)

if logger.hasHandlers():                                        # remove default handler
    logger.handlers.clear()

formatter = CustomFormatter()                                   # instantiate custom formatter
file_handler = logging.FileHandler(os.path.join(script_dir, 'YFS.log'), mode='w')
file_handler.setFormatter(formatter)                            # set formatter to the custom one
logger.addHandler(file_handler)
logger.propagate = False                                        # stop root log from existing

try:
    config = configparser.ConfigParser()
    config.read(os.path.join(script_dir, 'config.ini'))
    port = int(config['local']['port'])                         # port for external communication

    # info for local GUI
    mode_num = int(config['local']['mode'])
    domain = config['local']['domain']
    domain_controller_ip = config['local']['domain_controller_ip']
    server_ip = config['local']['server_ip']
    local_ip = config['local']['local_ip']
    ldap_server = config['local']['ldap_server']

except KeyError:                                                # case of misconfigured config file
    logger.critical("Missing or misconfigured config file", extra={'conn_counter': "N/A"})
    sys.exit(1)

# magic numbers

BUF_SIZE_LARGE = 4096
MSG_PREFIX_LEN = 3
MSG_PREFIX2_LEN = 5

# main code

def logger_thread():
    """
    Extra thread responsible for processing incoming logs in parallel with 
    the local server polling for them. This makes for much faster log processing.
    All incoming logs are placed in the log queue. This thread will then dequeue 
    and write the oldest log. 
    """
    # while True:
    #     level, message, extra = log_queue.get()
    #     if level == "DEBUG":
    #         logger.debug(message, extra=extra)
    #     elif level == "INFO":
    #         logger.info(message, extra=extra)
    #     elif level == "WARNING":
    #         logger.warning(message, extra=extra)
    #     elif level == "ERROR":
    #         logger.error(message, extra=extra)
    #     elif level == "CRITICAL":
    #         logger.critical(message, extra=extra)
    #     log_queue.task_done()


threading.Thread(target=logger_thread, daemon=True).start()     # Start the logger thread

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

def launch_gui():
    gui = localGUI(log_queue, None, None, mode_num, domain, server_ip, domain_controller_ip, local_ip, ldap_server)
    gui.mainloop()

if __name__ == "__main__":

    logger.info("Launching local GUI...",
                extra={'loggername':"localserver", 'conn_counter': "N/A"})
    # launch gui thread

    gui_thread = threading.Thread(target=launch_gui)
    gui_thread.daemon = True
    gui_thread.start()

    # main localserver loop 

    local_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    local_sock.bind(('0.0.0.0', port))
    local_sock.listen(50)

    logger.info("localserver is listening...",
                 extra={'loggername':"localserver", 'conn_counter': "N/A"})

    while True:
        conn, addr = local_sock.accept()
        local_thread = threading.Thread(target=local_handler, args=(conn,))
        local_thread.start()
